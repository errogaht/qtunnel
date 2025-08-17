package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Config struct {
	AuthToken      string `json:"auth_token"`
	Domain         string `json:"domain"`
	ListenAddr     string `json:"listen_addr"`
	ProxyAddr      string `json:"proxy_addr"`
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
	Protocol       string          `json:"protocol"`                  // "websocket" or "http2"
	HTTP2Writer    io.Writer       `json:"-"`                        // HTTP/2 response writer
	HTTP2Ctx       context.Context `json:"-"`                        // HTTP/2 context
	HTTP2Cancel    context.CancelFunc `json:"-"`                     // HTTP/2 cancellation
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

	// WebSocket server for clients
	http.HandleFunc("/ws", manager.handleWebSocket)
	
	// HTTP/2 streaming server for clients  
	http.HandleFunc("/http2", manager.handleHTTP2)
	
	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","tunnels":%d}`, len(manager.tunnels))
	})
	
	// HTTP proxy for incoming requests
	go startProxyServer(manager)
	
	// Cleanup stale tunnels
	go manager.cleanup()

	log.Printf("QTunnel server starting on %s", config.ListenAddr)
	log.Printf("Proxy server starting on %s", config.ProxyAddr)
	log.Printf("Domain: %s", config.Domain)
	
	if config.TLSCert != "" && config.TLSKey != "" {
		log.Fatal(http.ListenAndServeTLS(config.ListenAddr, config.TLSCert, config.TLSKey, nil))
	} else {
		log.Fatal(http.ListenAndServe(config.ListenAddr, nil))
	}
}

func loadConfig() *Config {
	config := &Config{
		AuthToken:  getEnv("QTUNNEL_AUTH_TOKEN", "default-secret-token"),
		Domain:     getEnv("QTUNNEL_DOMAIN", "localhost"),
		ListenAddr: getEnv("QTUNNEL_LISTEN", ":8080"),
		ProxyAddr:  getEnv("QTUNNEL_PROXY", ":8081"),
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
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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