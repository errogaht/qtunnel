package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	AuthToken      string `json:"auth_token"`
	Domain         string `json:"domain"`
	ListenAddr     string `json:"listen_addr"`
	ProxyAddr      string `json:"proxy_addr"`
	SSHAddr        string `json:"ssh_addr"`
	TraefikDir     string `json:"traefik_dir"`
	TLSCert        string `json:"tls_cert"`
	TLSKey         string `json:"tls_key"`
}

type Tunnel struct {
	ID             string          `json:"id"`
	Domain         string          `json:"domain"`
	Client         *websocket.Conn `json:"-"`
	LastSeen       time.Time       `json:"last_seen"`
	DisconnectedAt *time.Time      `json:"disconnected_at,omitempty"` // When connection was lost
	Connected      bool            `json:"connected"`                 // Current connection status
	Port           int             `json:"port"`
	WriteMutex     sync.Mutex      `json:"-"` // Prevents concurrent writes
	
	// HTTP/2 specific fields
	Protocol       string          `json:"protocol"`                  // "websocket", "http2", or "ssh"
	HTTP2Writer    io.Writer       `json:"-"`                        // HTTP/2 response writer
	HTTP2Ctx       context.Context `json:"-"`                        // HTTP/2 context
	HTTP2Cancel    context.CancelFunc `json:"-"`                     // HTTP/2 cancellation
	
	// SSH specific fields
	SSHConn        ssh.Conn        `json:"-"`                        // SSH connection
	SSHChannels    map[string]ssh.Channel `json:"-"`                 // SSH channels for requests
	SSHSession     ssh.Channel     `json:"-"`                        // SSH session channel for output
	SSHMutex       sync.RWMutex    `json:"-"`                        // SSH channels mutex
}

type TunnelManager struct {
	tunnels        map[string]*Tunnel
	pendingRequests map[string]chan *http.Response
	clientTunnels  map[string]string // clientID -> tunnelID mapping for stable reconnections
	mutex          sync.RWMutex
	config         *Config
}

type Message struct {
	Type      string `json:"type"`
	TunnelID  string `json:"tunnel_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Data      string `json:"data,omitempty"`
	Error     string `json:"error,omitempty"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // In production, add Origin verification
	},
}

func main() {
	config := loadConfig()
	
	manager := &TunnelManager{
		tunnels:         make(map[string]*Tunnel),
		pendingRequests: make(map[string]chan *http.Response),
		clientTunnels:   make(map[string]string),
		config:          config,
	}

	// Create separate mux for main server
	mainMux := http.NewServeMux()
	
	// WebSocket server for clients
	mainMux.HandleFunc("/ws", manager.handleWebSocket)
	
	// HTTP/2 streaming server for clients  
	mainMux.HandleFunc("/http2", manager.handleHTTP2)
	
	// Health check endpoint
	mainMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","tunnels":%d}`, len(manager.tunnels))
	})
	
	// HTTP proxy for incoming requests
	go startProxyServer(manager)
	
	// SSH server for tunneling
	go startSSHServer(manager)
	
	// Cleanup stale tunnels
	go manager.cleanup()

	log.Printf("QTunnel server starting on %s", config.ListenAddr)
	log.Printf("Proxy server starting on %s", config.ProxyAddr)
	log.Printf("SSH server starting on %s", config.SSHAddr)
	log.Printf("Domain: %s", config.Domain)
	
	if config.TLSCert != "" && config.TLSKey != "" {
		log.Fatal(http.ListenAndServeTLS(config.ListenAddr, config.TLSCert, config.TLSKey, mainMux))
	} else {
		log.Fatal(http.ListenAndServe(config.ListenAddr, mainMux))
	}
}

func loadConfig() *Config {
	config := &Config{
		AuthToken:  getEnv("QTUNNEL_AUTH_TOKEN", "default-secret-token"),
		Domain:     getEnv("QTUNNEL_DOMAIN", "localhost"),
		ListenAddr: getEnv("QTUNNEL_LISTEN", ":8080"),
		ProxyAddr:  getEnv("QTUNNEL_PROXY", ":8081"),
		SSHAddr:    getEnv("QTUNNEL_SSH", ":2222"),
		TraefikDir: getEnv("QTUNNEL_TRAEFIK_DIR", "/etc/traefik/dynamic"),
		TLSCert:    getEnv("QTUNNEL_TLS_CERT", ""),
		TLSKey:     getEnv("QTUNNEL_TLS_KEY", ""),
	}
	
	log.Printf("Config loaded: %+v", config)
	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func (tm *TunnelManager) handleHTTP2(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	log.Printf("[HTTP2] New HTTP/2 streaming connection attempt from %s", clientIP)
	
	// Validate request method
	if r.Method != "POST" {
		log.Printf("[HTTP2] Invalid method %s from client %s", r.Method, clientIP)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Token verification
	authToken := r.Header.Get("Authorization")
	if authToken != "Bearer "+tm.config.AuthToken {
		log.Printf("[HTTP2] Authentication failed for client %s: invalid token", clientIP)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Validate content type
	if r.Header.Get("Content-Type") != "application/x-qtunnel-stream" {
		log.Printf("[HTTP2] Invalid content type from client %s", clientIP)
		http.Error(w, "Invalid content type", http.StatusBadRequest)
		return
	}
	
	log.Printf("[HTTP2] Client %s authenticated successfully", clientIP)
	
	// Get client ID from query params or header
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		clientID = r.Header.Get("X-QTunnel-Client-ID")
	}
	if clientID == "" {
		log.Printf("[HTTP2] Missing client ID from %s", clientIP)
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}
	
	log.Printf("[HTTP2] Client provided ID: %s", clientID)
	
	// Set response headers for streaming
	w.Header().Set("Content-Type", "application/x-qtunnel-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	
	// Enable HTTP/2 server push if supported
	if pusher, ok := w.(http.Pusher); ok {
		log.Printf("[HTTP2] HTTP/2 server push supported for client %s", clientID)
		_ = pusher // Use pusher if needed
	}
	
	// Write initial response to establish connection
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("[HTTP2] Response writer doesn't support flushing for client %s", clientIP)
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	flusher.Flush()
	
	log.Printf("[HTTP2] HTTP/2 streaming connection established with client %s", clientIP)
	
	// Create context for connection lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Try to find or create tunnel for this client
	tunnel := tm.getOrCreateHTTP2Tunnel(w, ctx, cancel, clientID)
	log.Printf("[TUNNEL] HTTP/2 tunnel for client %s: %s -> %s", clientID, tunnel.ID, tunnel.Domain)
	
	// Send tunnel info to client
	err := tm.writeToTunnel(tunnel, Message{
		Type:     "tunnel_created",
		TunnelID: tunnel.ID,
		Data:     tunnel.Domain,
	})
	if err != nil {
		log.Printf("[TUNNEL] Error sending tunnel info to HTTP/2 client %s: %v", tunnel.ID, err)
		http.Error(w, "Failed to send tunnel info", http.StatusInternalServerError)
		return
	}
	
	log.Printf("[TUNNEL] Tunnel info sent to HTTP/2 client %s: %s", tunnel.ID, tunnel.Domain)
	
	// Create Traefik config
	tm.createTraefikConfig(tunnel)
	
	// Process HTTP/2 streaming messages
	tm.processHTTP2Messages(tunnel, r.Body, ctx)
	
	// Cleanup on disconnect
	tm.markTunnelDisconnected(tunnel.ID)
	log.Printf("[TUNNEL] HTTP/2 tunnel marked as disconnected: %s", tunnel.ID)
}

func (tm *TunnelManager) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	log.Printf("[WS] New WebSocket connection attempt from %s", clientIP)
	
	// Token verification
	authToken := r.Header.Get("Authorization")
	if authToken != "Bearer "+tm.config.AuthToken {
		log.Printf("[WS] Authentication failed for client %s: invalid token", clientIP)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	log.Printf("[WS] Client %s authenticated successfully", clientIP)

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] WebSocket upgrade error for client %s: %v", clientIP, err)
		return
	}
	defer conn.Close()

	// Configure connection settings for better stability
	conn.SetReadLimit(1024 * 1024) // 1MB message limit
	conn.SetPongHandler(func(appData string) error {
		log.Printf("[WS] Pong received from client %s", clientIP)
		return nil
	})

	log.Printf("[WS] WebSocket connection established with client %s", clientIP)

	// Check for client ID in query params for stable reconnection
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		// Generate new client ID if none provided
		clientID = generateRandomID()
		log.Printf("[WS] Generated new client ID: %s", clientID)
	} else {
		log.Printf("[WS] Client provided ID: %s", clientID)
	}

	// Try to find or create tunnel for this client
	tunnel := tm.getOrCreateTunnel(conn, clientID)
	log.Printf("[TUNNEL] Tunnel for client %s: %s -> %s", clientID, tunnel.ID, tunnel.Domain)

	// Send domain to client
	err = tm.writeToTunnel(tunnel, Message{
		Type:     "tunnel_created",
		TunnelID: tunnel.ID,
		Data:     tunnel.Domain,
	})
	if err != nil {
		log.Printf("[TUNNEL] Error sending tunnel info to %s: %v", tunnel.ID, err)
		return
	}

	log.Printf("[TUNNEL] Tunnel info sent to client %s: %s", tunnel.ID, tunnel.Domain)

	// Create Traefik config
	tm.createTraefikConfig(tunnel)

	// Process messages from client
	for {
		// Set read deadline for connection health
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			// Enhanced error logging
			errorDetails := map[string]interface{}{
				"client_ip": clientIP,
				"tunnel_id": tunnel.ID,
				"error_type": fmt.Sprintf("%T", err),
				"is_timeout": strings.Contains(err.Error(), "timeout"),
			}
			
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNoStatusReceived) {
				log.Printf("[TUNNEL] Unexpected WebSocket close for tunnel %s: %v (details: %+v)", tunnel.ID, err, errorDetails)
			} else {
				log.Printf("[TUNNEL] Client %s disconnected: %v (details: %+v)", tunnel.ID, err, errorDetails)
			}
			break
		}

		tunnel.LastSeen = time.Now()
		log.Printf("[MSG] Received message from tunnel %s: type=%s", tunnel.ID, msg.Type)
		
		// Handle different message types
		switch msg.Type {
		case "ping":
			log.Printf("[PING] Ping received from tunnel %s, sending pong", tunnel.ID)
			err := tm.writeToTunnel(tunnel, Message{
				Type: "pong",
				TunnelID: tunnel.ID, // Echo back tunnel ID for client verification
			})
			if err != nil {
				log.Printf("[PING] Error sending pong to tunnel %s: %v", tunnel.ID, err)
				// Ping/pong failure often indicates connection issues
				break
			}
		case "http_response":
			log.Printf("[HTTP] HTTP response received for tunnel %s, request %s", tunnel.ID, msg.RequestID)
			tm.handleHTTPResponse(msg)
		default:
			log.Printf("[MSG] Unknown message type '%s' from tunnel %s", msg.Type, tunnel.ID)
		}
	}

	// Mark tunnel as disconnected but preserve for reconnection
	tm.markTunnelDisconnected(tunnel.ID)
	log.Printf("[TUNNEL] Tunnel marked as disconnected: %s (preserved for reconnection)", tunnel.ID)
}

func (tm *TunnelManager) getOrCreateHTTP2Tunnel(w http.ResponseWriter, ctx context.Context, cancel context.CancelFunc, clientID string) *Tunnel {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Check if this client already has a tunnel
	if existingTunnelID, exists := tm.clientTunnels[clientID]; exists {
		if existingTunnel, tunnelExists := tm.tunnels[existingTunnelID]; tunnelExists {
			// Update existing tunnel with new HTTP/2 connection
			log.Printf("[TUNNEL] Reconnecting HTTP/2 client %s to existing tunnel %s (domain: %s, connected: %t)", clientID, existingTunnelID, existingTunnel.Domain, existingTunnel.Connected)
			
			// Close old HTTP/2 connection if it exists
			if existingTunnel.HTTP2Cancel != nil {
				log.Printf("[TUNNEL] Closing old HTTP/2 connection for tunnel %s", existingTunnelID)
				existingTunnel.HTTP2Cancel()
			}
			
			// Restore HTTP/2 connection
			existingTunnel.Protocol = "http2"
			existingTunnel.HTTP2Writer = w
			existingTunnel.HTTP2Ctx = ctx
			existingTunnel.HTTP2Cancel = cancel
			existingTunnel.LastSeen = time.Now()
			existingTunnel.Connected = true
			existingTunnel.DisconnectedAt = nil
			log.Printf("[TUNNEL] Successfully reconnected HTTP/2 to tunnel %s - DOMAIN STABLE: %s", existingTunnelID, existingTunnel.Domain)
			return existingTunnel
		} else {
			// Tunnel was cleaned up, remove stale mapping
			log.Printf("[TUNNEL] Stale tunnel mapping found for HTTP/2 client %s -> %s, removing", clientID, existingTunnelID)
			delete(tm.clientTunnels, clientID)
		}
	}

	// Create new tunnel
	id := generateRandomID()
	domain := fmt.Sprintf("%s-tun.%s", id, tm.config.Domain)

	tunnel := &Tunnel{
		ID:          id,
		Domain:      domain,
		Protocol:    "http2",
		HTTP2Writer: w,
		HTTP2Ctx:    ctx,
		HTTP2Cancel: cancel,
		LastSeen:    time.Now(),
		Connected:   true,
	}

	tm.tunnels[id] = tunnel
	tm.clientTunnels[clientID] = id
	log.Printf("[TUNNEL] Created new HTTP/2 tunnel %s for client %s (domain: %s)", id, clientID, domain)
	return tunnel
}

func (tm *TunnelManager) getOrCreateTunnel(conn *websocket.Conn, clientID string) *Tunnel {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Check if this client already has a tunnel
	if existingTunnelID, exists := tm.clientTunnels[clientID]; exists {
		if existingTunnel, tunnelExists := tm.tunnels[existingTunnelID]; tunnelExists {
			// Update existing tunnel with new connection (may be disconnected)
			log.Printf("[TUNNEL] Reconnecting client %s to existing tunnel %s (domain: %s, connected: %t)", clientID, existingTunnelID, existingTunnel.Domain, existingTunnel.Connected)
			
			// Close old connection if it exists and is different
			if existingTunnel.Client != nil && existingTunnel.Client != conn {
				log.Printf("[TUNNEL] Closing old connection for tunnel %s", existingTunnelID)
				existingTunnel.Client.Close()
			}
			
			// Restore connection
			existingTunnel.Client = conn
			existingTunnel.LastSeen = time.Now()
			existingTunnel.Connected = true
			existingTunnel.DisconnectedAt = nil
			log.Printf("[TUNNEL] Successfully reconnected to tunnel %s - DOMAIN STABLE: %s", existingTunnelID, existingTunnel.Domain)
			return existingTunnel
		} else {
			// Tunnel was cleaned up, remove stale mapping
			log.Printf("[TUNNEL] Stale tunnel mapping found for client %s -> %s, removing", clientID, existingTunnelID)
			delete(tm.clientTunnels, clientID)
		}
	}

	// Create new tunnel
	id := generateRandomID()
	domain := fmt.Sprintf("%s-tun.%s", id, tm.config.Domain)

	tunnel := &Tunnel{
		ID:        id,
		Domain:    domain,
		Protocol:  "websocket",
		Client:    conn,
		LastSeen:  time.Now(),
		Connected: true,
	}

	tm.tunnels[id] = tunnel
	tm.clientTunnels[clientID] = id
	log.Printf("[TUNNEL] Created new tunnel %s for client %s (domain: %s)", id, clientID, domain)
	return tunnel
}

// markTunnelDisconnected marks a tunnel as disconnected but preserves it for reconnection
func (tm *TunnelManager) markTunnelDisconnected(id string) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	
	if tunnel, exists := tm.tunnels[id]; exists {
		now := time.Now()
		tunnel.Connected = false
		tunnel.DisconnectedAt = &now
		tunnel.Client = nil // Clear the connection reference
		log.Printf("[TUNNEL] Marked tunnel %s as disconnected at %v (domain preserved: %s)", id, now, tunnel.Domain)
	}
}

func (tm *TunnelManager) removeTunnel(id string) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	
	// Find and remove client mapping
	for clientID, tunnelID := range tm.clientTunnels {
		if tunnelID == id {
			delete(tm.clientTunnels, clientID)
			log.Printf("[TUNNEL] Removed client mapping %s -> %s", clientID, id)
			break
		}
	}
	
	delete(tm.tunnels, id)
}

// processHTTP2Messages reads and processes messages from HTTP/2 streaming request
func (tm *TunnelManager) processHTTP2Messages(tunnel *Tunnel, requestBody io.Reader, ctx context.Context) {
	log.Printf("[HTTP2] Starting message processing for tunnel %s", tunnel.ID)
	
	reader := bufio.NewReader(requestBody)
	
	for {
		select {
		case <-ctx.Done():
			log.Printf("[HTTP2] Message processing cancelled for tunnel %s", tunnel.ID)
			return
		default:
			// Read line from HTTP/2 request stream
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					log.Printf("[HTTP2] Request stream ended for tunnel %s", tunnel.ID)
					return
				}
				log.Printf("[HTTP2] Error reading from request stream for tunnel %s: %v", tunnel.ID, err)
				return
			}

			// Parse JSON message
			line = strings.TrimSpace(line)
			if line == "" {
				continue // Skip empty lines
			}

			var msg Message
			err = json.Unmarshal([]byte(line), &msg)
			if err != nil {
				log.Printf("[HTTP2] Failed to parse message for tunnel %s: %v (raw: %s)", tunnel.ID, err, line)
				continue
			}

			tunnel.LastSeen = time.Now()
			log.Printf("[MSG] Received HTTP/2 message from tunnel %s: type=%s", tunnel.ID, msg.Type)
			
			// Handle different message types (same as WebSocket)
			switch msg.Type {
			case "ping":
				log.Printf("[PING] HTTP/2 ping received from tunnel %s, sending pong", tunnel.ID)
				err := tm.writeToTunnel(tunnel, Message{
					Type: "pong",
					TunnelID: tunnel.ID,
				})
				if err != nil {
					log.Printf("[PING] Error sending HTTP/2 pong to tunnel %s: %v", tunnel.ID, err)
					return
				}
			case "http_response":
				log.Printf("[HTTP] HTTP/2 response received for tunnel %s, request %s", tunnel.ID, msg.RequestID)
				tm.handleHTTPResponse(msg)
			default:
				log.Printf("[MSG] Unknown HTTP/2 message type '%s' from tunnel %s", msg.Type, tunnel.ID)
			}
		}
	}
}

// writeToTunnel safely writes JSON to tunnel with mutex protection
func (tm *TunnelManager) writeToTunnel(tunnel *Tunnel, msg Message) error {
	tunnel.WriteMutex.Lock()
	defer tunnel.WriteMutex.Unlock()
	
	if !tunnel.Connected {
		return fmt.Errorf("tunnel %s is not connected", tunnel.ID)
	}
	
	log.Printf("[%s-WRITE] Synchronized write to tunnel %s: type=%s, req_id=%s", 
		strings.ToUpper(tunnel.Protocol), tunnel.ID, msg.Type, msg.RequestID)
	
	switch tunnel.Protocol {
	case "websocket":
		if tunnel.Client == nil {
			return fmt.Errorf("WebSocket client is nil for tunnel %s", tunnel.ID)
		}
		return tunnel.Client.WriteJSON(msg)
	case "http2":
		if tunnel.HTTP2Writer == nil {
			return fmt.Errorf("HTTP/2 writer is nil for tunnel %s", tunnel.ID)
		}
		
		// Serialize message to JSON
		data, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("failed to marshal message for tunnel %s: %v", tunnel.ID, err)
		}
		
		// Send as newline-delimited JSON
		_, err = fmt.Fprintf(tunnel.HTTP2Writer, "%s\n", string(data))
		if err != nil {
			return fmt.Errorf("failed to write HTTP/2 message for tunnel %s: %v", tunnel.ID, err)
		}
		
		// Flush the response if possible
		if flusher, ok := tunnel.HTTP2Writer.(http.Flusher); ok {
			flusher.Flush()
		}
		
		return nil
	case "ssh":
		if tunnel.SSHSession == nil {
			// SSH tunnel might not have session channel
			return nil
		}
		
		// For SSH, send domain info to session channel
		if msg.Type == "tunnel_created" {
			_, err := fmt.Fprintf(tunnel.SSHSession, "DOMAIN:https://%s\n", msg.Data)
			if err != nil {
				return fmt.Errorf("failed to write SSH message for tunnel %s: %v", tunnel.ID, err)
			}
			_, err = fmt.Fprintf(tunnel.SSHSession, "STATUS:CONNECTED\n")
			return err
		}
		
		return nil
	default:
		return fmt.Errorf("unknown protocol %s for tunnel %s", tunnel.Protocol, tunnel.ID)
	}
}

func (tm *TunnelManager) getTunnel(id string) *Tunnel {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	return tm.tunnels[id]
}

func generateRandomID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func startProxyServer(manager *TunnelManager) {
	// Create separate mux for proxy server
	proxyMux := http.NewServeMux()
	
	proxyMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		log.Printf("[PROXY] Incoming request from %s: %s %s %s", clientIP, r.Method, r.Host, r.URL.Path)
		
		// Extract tunnel ID from domain
		host := r.Host
		if strings.HasSuffix(host, "-tun."+manager.config.Domain) {
			tunnelID := strings.TrimSuffix(host, "-tun."+manager.config.Domain)
			log.Printf("[PROXY] Request for tunnel %s", tunnelID)
			
			tunnel := manager.getTunnel(tunnelID)
			if tunnel != nil {
				if tunnel.Connected {
					log.Printf("[PROXY] Tunnel %s found and connected, proxying request", tunnelID)
					// Proxy through WebSocket to client
					manager.proxyRequest(tunnel, r, w)
				} else {
					log.Printf("[PROXY] Tunnel %s found but disconnected", tunnelID)
					http.Error(w, "Tunnel temporarily unavailable", http.StatusServiceUnavailable)
				}
			} else {
				log.Printf("[PROXY] Tunnel %s not found", tunnelID)
				http.Error(w, "Tunnel not found", http.StatusNotFound)
			}
		} else {
			log.Printf("[PROXY] Invalid domain: %s (expected suffix: -tun.%s)", host, manager.config.Domain)
			http.Error(w, "Invalid domain", http.StatusBadRequest)
		}
	})

	server := &http.Server{
		Addr: manager.config.ProxyAddr,
		Handler: proxyMux,
	}

	log.Fatal(server.ListenAndServe())
}

func (tm *TunnelManager) proxyRequest(tunnel *Tunnel, req *http.Request, w http.ResponseWriter) {
	// Generate unique request ID
	requestID := generateRandomID()
	log.Printf("[HTTP] Processing request %s for tunnel %s: %s %s", requestID, tunnel.ID, req.Method, req.URL.Path)
	
	// Create response channel
	responseChan := make(chan *http.Response, 1)
	tm.mutex.Lock()
	tm.pendingRequests[requestID] = responseChan
	tm.mutex.Unlock()
	
	log.Printf("[HTTP] Request %s added to pending requests queue", requestID)
	
	// Serialize HTTP request
	reqData, err := httpRequestToJSON(req)
	if err != nil {
		log.Printf("[HTTP] Error serializing request %s: %v", requestID, err)
		http.Error(w, "Request serialization error", http.StatusInternalServerError)
		tm.mutex.Lock()
		delete(tm.pendingRequests, requestID)
		tm.mutex.Unlock()
		return
	}
	
	log.Printf("[HTTP] Request %s serialized, sending to tunnel %s", requestID, tunnel.ID)
	
	// Send to client
	err = tm.writeToTunnel(tunnel, Message{
		Type:      "http_request",
		TunnelID:  tunnel.ID,
		RequestID: requestID,
		Data:      reqData,
	})
	
	if err != nil {
		log.Printf("[HTTP] Error forwarding request %s to tunnel %s: %v", requestID, tunnel.ID, err)
		http.Error(w, "Tunnel error", http.StatusBadGateway)
		tm.mutex.Lock()
		delete(tm.pendingRequests, requestID)
		tm.mutex.Unlock()
		return
	}
	
	log.Printf("[HTTP] Request %s sent to tunnel %s, waiting for response", requestID, tunnel.ID)
	
	// Wait for response from client (with timeout)
	select {
	case response := <-responseChan:
		log.Printf("[HTTP] Response received for request %s from tunnel %s: status=%d", requestID, tunnel.ID, response.StatusCode)
		
		// Copy response headers
		for key, values := range response.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		
		// Set status code
		w.WriteHeader(response.StatusCode)
		
		// Copy response body
		if response.Body != nil {
			bodyBytes, err := io.ReadAll(response.Body)
			if err != nil {
				log.Printf("[HTTP] Error reading response body for request %s: %v", requestID, err)
			} else {
				log.Printf("[HTTP] Sending response for request %s: %d bytes", requestID, len(bodyBytes))
				w.Write(bodyBytes)
			}
			response.Body.Close()
		}
		
	case <-time.After(30 * time.Second):
		log.Printf("[HTTP] Request timeout for tunnel %s, request %s (30s)", tunnel.ID, requestID)
		http.Error(w, "Request timeout", http.StatusGatewayTimeout)
	}
	
	// Cleanup
	tm.mutex.Lock()
	delete(tm.pendingRequests, requestID)
	tm.mutex.Unlock()
	log.Printf("[HTTP] Request %s cleanup completed", requestID)
}

func httpRequestToJSON(req *http.Request) (string, error) {
	// Simple HTTP request serialization
	data := map[string]interface{}{
		"method": req.Method,
		"url":    req.URL.String(),
		"headers": req.Header,
	}
	
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		data["body"] = string(body)
	}
	
	jsonData, err := json.Marshal(data)
	return string(jsonData), err
}

func (tm *TunnelManager) handleHTTPResponse(msg Message) {
	log.Printf("[HTTP] Processing HTTP response for request %s from tunnel %s", msg.RequestID, msg.TunnelID)
	
	tm.mutex.Lock()
	responseChan, exists := tm.pendingRequests[msg.RequestID]
	tm.mutex.Unlock()
	
	if !exists {
		log.Printf("[HTTP] No pending request for ID: %s (already timed out or completed)", msg.RequestID)
		return
	}
	
	log.Printf("[HTTP] Found pending request %s, processing response", msg.RequestID)
	
	// Parse response from client
	var responseData map[string]interface{}
	err := json.Unmarshal([]byte(msg.Data), &responseData)
	if err != nil {
		log.Printf("[HTTP] Error parsing response for request %s: %v", msg.RequestID, err)
		return
	}
	
	status, hasStatus := responseData["status"].(float64)
	if !hasStatus {
		log.Printf("[HTTP] Invalid response format for request %s: missing status", msg.RequestID)
		return
	}
	
	log.Printf("[HTTP] Parsed response for request %s: status=%d", msg.RequestID, int(status))
	
	// Create HTTP response
	response := &http.Response{
		StatusCode: int(status),
		Header:     make(http.Header),
	}
	
	// Copy headers
	headerCount := 0
	if headers, ok := responseData["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if valueSlice, ok := value.([]interface{}); ok {
				for _, v := range valueSlice {
					if vStr, ok := v.(string); ok {
						response.Header.Add(key, vStr)
						headerCount++
					}
				}
			}
		}
	}
	
	// Set response body
	bodySize := 0
	if body, ok := responseData["body"].(string); ok {
		bodySize = len(body)
		response.Body = io.NopCloser(strings.NewReader(body))
	}
	
	log.Printf("[HTTP] Response created for request %s: %d headers, %d bytes body", msg.RequestID, headerCount, bodySize)
	
	// Send response to channel
	select {
	case responseChan <- response:
		log.Printf("[HTTP] Response sent to channel for request %s", msg.RequestID)
	default:
		log.Printf("[HTTP] Failed to send response to channel for request %s (channel full or closed)", msg.RequestID)
	}
}

func (tm *TunnelManager) createTraefikConfig(tunnel *Tunnel) {
	config := map[string]interface{}{
		"http": map[string]interface{}{
			"routers": map[string]interface{}{
				fmt.Sprintf("qtunnel-%s", tunnel.ID): map[string]interface{}{
					"rule":    fmt.Sprintf("Host(`%s`)", tunnel.Domain),
					"service": fmt.Sprintf("qtunnel-%s", tunnel.ID),
					"tls": map[string]interface{}{
						"certResolver": "cloudflare",
					},
				},
			},
			"services": map[string]interface{}{
				fmt.Sprintf("qtunnel-%s", tunnel.ID): map[string]interface{}{
					"loadBalancer": map[string]interface{}{
						"servers": []map[string]interface{}{
							{"url": fmt.Sprintf("http://qtunnel-server:%s", strings.TrimPrefix(tm.config.ProxyAddr, ":"))},
						},
					},
				},
			},
		},
	}

	// Write config to file
	configPath := filepath.Join(tm.config.TraefikDir, fmt.Sprintf("qtunnel-%s.json", tunnel.ID))
	configJSON, _ := json.MarshalIndent(config, "", "  ")
	
	os.WriteFile(configPath, configJSON, 0644)
	log.Printf("Traefik config created: %s", configPath)
}

func (tm *TunnelManager) removeTraefikConfig(tunnel *Tunnel) {
	configPath := filepath.Join(tm.config.TraefikDir, fmt.Sprintf("qtunnel-%s.json", tunnel.ID))
	os.Remove(configPath)
	log.Printf("Traefik config removed: %s", configPath)
}

func (tm *TunnelManager) cleanup() {
	ticker := time.NewTicker(45 * time.Second) // Longer interval
	defer ticker.Stop()
	
	log.Printf("[CLEANUP] Starting tunnel cleanup routine with 5-minute timeout")

	for range ticker.C {
		tm.mutex.Lock()
		tunnelCount := len(tm.tunnels)
		cleanedCount := 0
		
		for id, tunnel := range tm.tunnels {
			shouldCleanup := false
			var reason string
			
			if tunnel.Connected {
				// For connected tunnels, check last activity
				if time.Since(tunnel.LastSeen) > 5*time.Minute {
					shouldCleanup = true
					reason = fmt.Sprintf("connected but inactive for %v", time.Since(tunnel.LastSeen))
				} else if time.Since(tunnel.LastSeen) > 3*time.Minute {
					log.Printf("[CLEANUP] Warning: Connected tunnel %s approaching timeout (last seen: %v ago)", id, time.Since(tunnel.LastSeen))
				}
			} else {
				// For disconnected tunnels, check disconnection time
				if tunnel.DisconnectedAt != nil {
					disconnectedDuration := time.Since(*tunnel.DisconnectedAt)
					if disconnectedDuration > 5*time.Minute {
						shouldCleanup = true
						reason = fmt.Sprintf("disconnected for %v", disconnectedDuration)
					} else if disconnectedDuration > 3*time.Minute {
						log.Printf("[CLEANUP] Warning: Disconnected tunnel %s approaching cleanup (disconnected: %v ago)", id, disconnectedDuration)
					}
				} else {
					// Disconnected tunnel without timestamp - cleanup immediately
					shouldCleanup = true
					reason = "disconnected without timestamp"
				}
			}
			
			if shouldCleanup {
				log.Printf("[CLEANUP] Cleaning up tunnel %s (%s)", id, reason)
				
				// Try to close connection gracefully if still connected
				if tunnel.Client != nil {
					tunnel.Client.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "Server cleanup"))
					time.Sleep(100 * time.Millisecond) // Brief pause for graceful close
					tunnel.Client.Close()
				}
				
				// Remove client mapping
				for clientID, tunnelID := range tm.clientTunnels {
					if tunnelID == id {
						delete(tm.clientTunnels, clientID)
						log.Printf("[CLEANUP] Removed client mapping %s -> %s", clientID, id)
						break
					}
				}
				
				delete(tm.tunnels, id)
				tm.removeTraefikConfig(tunnel)
				cleanedCount++
			}
		}
		tm.mutex.Unlock()
		
		if cleanedCount > 0 {
			log.Printf("[CLEANUP] Cleaned up %d stale tunnels (total tunnels: %d -> %d)", cleanedCount, tunnelCount, tunnelCount-cleanedCount)
		} else {
			log.Printf("[CLEANUP] No stale tunnels found (total tunnels: %d)", tunnelCount)
		}
	}
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP if there are multiple
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return xff
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// SSH Server Functions

func startSSHServer(tm *TunnelManager) {
	// Generate or load SSH host key
	hostKey, err := generateOrLoadHostKey("qtunnel_ssh_host_key")
	if err != nil {
		log.Fatalf("Failed to load SSH host key: %v", err)
	}

	// SSH server configuration
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return tm.authenticateSSHUser(conn.User(), string(password))
		},
		ServerVersion: "SSH-2.0-qtunnel-server",
	}
	sshConfig.AddHostKey(hostKey)

	// Listen on SSH port
	listener, err := net.Listen("tcp", tm.config.SSHAddr)
	if err != nil {
		log.Fatalf("Failed to listen on SSH port %s: %v", tm.config.SSHAddr, err)
	}
	defer listener.Close()

	log.Printf("[SSH] SSH server listening on %s", tm.config.SSHAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[SSH] Failed to accept SSH connection: %v", err)
			continue
		}

		go tm.handleSSHConnection(conn, sshConfig)
	}
}

func generateOrLoadHostKey(keyFile string) (ssh.Signer, error) {
	// Check if key file exists
	if keyData, err := os.ReadFile(keyFile); err == nil {
		// Load existing key
		return ssh.ParsePrivateKey(keyData)
	}

	// Generate new RSA key
	log.Printf("[SSH] Generating new SSH host key: %s", keyFile)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Encode to PEM format
	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	keyData := pem.EncodeToMemory(keyPEM)

	// Save to file
	if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
		return nil, fmt.Errorf("failed to save private key: %v", err)
	}

	return ssh.NewSignerFromKey(privateKey)
}

func (tm *TunnelManager) authenticateSSHUser(username, password string) (*ssh.Permissions, error) {
	// Use existing token authentication
	if password == tm.config.AuthToken {
		log.Printf("[SSH] User authenticated with token: %s", username)
		return &ssh.Permissions{}, nil
	}

	// Also allow username as token (for convenience)
	if username == tm.config.AuthToken {
		log.Printf("[SSH] User authenticated with username as token: %s", username)
		return &ssh.Permissions{}, nil
	}

	log.Printf("[SSH] Authentication failed for user %s", username)
	return nil, fmt.Errorf("invalid authentication")
}

func (tm *TunnelManager) handleSSHConnection(conn net.Conn, sshConfig *ssh.ServerConfig) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[SSH] New SSH connection from %s", clientAddr)

	// SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		log.Printf("[SSH] SSH handshake failed for %s: %v", clientAddr, err)
		return
	}
	defer sshConn.Close()

	log.Printf("[SSH] SSH user %s connected from %s", sshConn.User(), clientAddr)

	// Handle SSH requests (port forwarding)
	go tm.handleSSHRequests(reqs, sshConn)

	// Handle SSH channels (reject shell sessions)
	go tm.handleSSHChannels(chans, sshConn)

	// Wait for connection close
	err = sshConn.Wait()
	if err != nil {
		log.Printf("[SSH] SSH connection closed with error: %v", err)
	} else {
		log.Printf("[SSH] SSH connection closed cleanly for %s", clientAddr)
	}
}

func (tm *TunnelManager) handleSSHRequests(reqs <-chan *ssh.Request, sshConn ssh.Conn) {
	for req := range reqs {
		log.Printf("[SSH] SSH request from %s: type=%s", sshConn.RemoteAddr(), req.Type)
		
		switch req.Type {
		case "tcpip-forward":
			tm.handleTCPIPForward(req, sshConn)
		case "cancel-tcpip-forward":
			tm.handleCancelTCPIPForward(req, sshConn)
		case "keepalive@openssh.com":
			req.Reply(true, nil)
		default:
			log.Printf("[SSH] Rejecting unknown request type: %s", req.Type)
			req.Reply(false, nil)
		}
	}
}

func (tm *TunnelManager) handleSSHChannels(chans <-chan ssh.NewChannel, sshConn ssh.Conn) {
	for newChannel := range chans {
		channelType := newChannel.ChannelType()
		log.Printf("[SSH] SSH channel request from %s: type=%s", sshConn.RemoteAddr(), channelType)
		
		switch channelType {
		case "session":
			// Accept session but don't provide shell - just for status output
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Printf("[SSH] Failed to accept session channel: %v", err)
				continue
			}

			// Handle session requests
			go tm.handleSSHSession(channel, requests, sshConn)
			
		case "direct-tcpip":
			// Handle direct TCP forwarding through SSH
			tm.handleDirectTCPIP(newChannel, sshConn)
			
		default:
			log.Printf("[SSH] Rejecting unknown channel type: %s", channelType)
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func (tm *TunnelManager) handleTCPIPForward(req *ssh.Request, sshConn ssh.Conn) {
	// Parse port forward request
	var portForward struct {
		BindAddr string
		BindPort uint32
	}
	
	if err := ssh.Unmarshal(req.Payload, &portForward); err != nil {
		log.Printf("[SSH] Failed to parse tcpip-forward request: %v", err)
		req.Reply(false, nil)
		return
	}
	
	log.Printf("[SSH] Port forward request: %s:%d", portForward.BindAddr, portForward.BindPort)
	
	// Generate random tunnel domain (same as WebSocket)
	tunnelID := generateRandomID()
	domain := fmt.Sprintf("%s-tun.%s", tunnelID, tm.config.Domain)
	
	// Create tunnel
	tunnel := &Tunnel{
		ID:          tunnelID,
		Domain:      domain,
		Protocol:    "ssh",
		SSHConn:     sshConn,
		SSHChannels: make(map[string]ssh.Channel),
		Port:        int(portForward.BindPort),
		LastSeen:    time.Now(),
		Connected:   true,
	}
	
	// Store tunnel
	tm.mutex.Lock()
	tm.tunnels[tunnelID] = tunnel
	tm.mutex.Unlock()
	
	log.Printf("[SSH] Created SSH tunnel %s: %s", tunnelID, domain)
	
	// Create Traefik config (reuse existing logic)
	tm.createTraefikConfig(tunnel)
	
	// Reply to SSH client with success
	req.Reply(true, ssh.Marshal(struct{ Port uint32 }{portForward.BindPort}))
	
	// Send domain info through writeToTunnel if session exists
	tm.writeToTunnel(tunnel, Message{
		Type:     "tunnel_created", 
		TunnelID: tunnelID,
		Data:     domain,
	})
	
	log.Printf("[SSH] SSH tunnel %s ready: https://%s", tunnelID, domain)
}

func (tm *TunnelManager) handleCancelTCPIPForward(req *ssh.Request, sshConn ssh.Conn) {
	// Parse cancel request
	var cancelForward struct {
		BindAddr string
		BindPort uint32
	}
	
	if err := ssh.Unmarshal(req.Payload, &cancelForward); err != nil {
		req.Reply(false, nil)
		return
	}
	
	log.Printf("[SSH] Cancel port forward: %s:%d", cancelForward.BindAddr, cancelForward.BindPort)
	
	// Find and remove tunnel
	tm.mutex.Lock()
	for id, tunnel := range tm.tunnels {
		if tunnel.Protocol == "ssh" && tunnel.SSHConn == sshConn && tunnel.Port == int(cancelForward.BindPort) {
			delete(tm.tunnels, id)
			tm.removeTraefikConfig(tunnel)
			log.Printf("[SSH] Removed tunnel %s", id)
			break
		}
	}
	tm.mutex.Unlock()
	
	req.Reply(true, nil)
}

func (tm *TunnelManager) handleSSHSession(channel ssh.Channel, requests <-chan *ssh.Request, sshConn ssh.Conn) {
	defer channel.Close()
	
	// Send welcome message
	fmt.Fprintf(channel, "QTunnel SSH Server\n")
	fmt.Fprintf(channel, "Connected from: %s\n", sshConn.RemoteAddr())
	fmt.Fprintf(channel, "Keep this session open to maintain tunnels.\n")
	fmt.Fprintf(channel, "Press Ctrl+C to close.\n\n")
	
	// Handle session requests
	for req := range requests {
		switch req.Type {
		case "pty-req", "shell":
			// Accept but don't actually provide shell
			req.Reply(true, nil)
		case "env":
			req.Reply(true, nil)
		case "exec":
			req.Reply(false, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func (tm *TunnelManager) handleDirectTCPIP(newChannel ssh.NewChannel, sshConn ssh.Conn) {
	// Parse direct TCP request
	var directTCPIP struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	
	if err := ssh.Unmarshal(newChannel.ExtraData(), &directTCPIP); err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "failed to parse direct-tcpip request")
		return
	}
	
	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("[SSH] Failed to accept direct-tcpip channel: %v", err)
		return
	}
	defer channel.Close()
	
	// Discard requests
	go ssh.DiscardRequests(requests)
	
	// Connect to target
	targetAddr := fmt.Sprintf("%s:%d", directTCPIP.Host, directTCPIP.Port)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[SSH] Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()
	
	log.Printf("[SSH] Direct TCP forwarding: %s -> %s", sshConn.RemoteAddr(), targetAddr)
	
	// Bidirectional copy
	go func() {
		io.Copy(channel, targetConn)
		channel.CloseWrite()
	}()
	io.Copy(targetConn, channel)
}