package main

import (
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
	ID         string          `json:"id"`
	Domain     string          `json:"domain"`
	Client     *websocket.Conn `json:"-"`
	LastSeen   time.Time       `json:"last_seen"`
	Port       int             `json:"port"`
	WriteMutex sync.Mutex      `json:"-"` // Prevents concurrent WebSocket writes
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
		return true // В продакшене добавить проверку Origin
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

	// WebSocket сервер для клиентов
	http.HandleFunc("/ws", manager.handleWebSocket)
	
	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","tunnels":%d}`, len(manager.tunnels))
	})
	
	// HTTP прокси для входящих запросов
	go startProxyServer(manager)
	
	// Cleanup старых туннелей
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

func (tm *TunnelManager) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	log.Printf("[WS] New WebSocket connection attempt from %s", clientIP)
	
	// Проверка токена
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

	// Отправляем домен клиенту
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

	// Создаем Traefik конфиг
	tm.createTraefikConfig(tunnel)

	// Обрабатываем сообщения от клиента
	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[TUNNEL] Unexpected WebSocket close for tunnel %s: %v", tunnel.ID, err)
			} else {
				log.Printf("[TUNNEL] Client %s disconnected: %v", tunnel.ID, err)
			}
			break
		}

		tunnel.LastSeen = time.Now()
		log.Printf("[MSG] Received message from tunnel %s: type=%s", tunnel.ID, msg.Type)
		
		// Обработка разных типов сообщений
		switch msg.Type {
		case "ping":
			log.Printf("[PING] Ping received from tunnel %s, sending pong", tunnel.ID)
			err := tm.writeToTunnel(tunnel, Message{Type: "pong"})
			if err != nil {
				log.Printf("[PING] Error sending pong to tunnel %s: %v", tunnel.ID, err)
			}
		case "http_response":
			log.Printf("[HTTP] HTTP response received for tunnel %s, request %s", tunnel.ID, msg.RequestID)
			tm.handleHTTPResponse(msg)
		default:
			log.Printf("[MSG] Unknown message type '%s' from tunnel %s", msg.Type, tunnel.ID)
		}
	}

	// Cleanup при отключении
	tm.removeTunnel(tunnel.ID)
	tm.removeTraefikConfig(tunnel)
	log.Printf("[TUNNEL] Tunnel removed: %s", tunnel.ID)
}

func (tm *TunnelManager) getOrCreateTunnel(conn *websocket.Conn, clientID string) *Tunnel {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Check if this client already has a tunnel
	if existingTunnelID, exists := tm.clientTunnels[clientID]; exists {
		if existingTunnel, tunnelExists := tm.tunnels[existingTunnelID]; tunnelExists {
			// Update existing tunnel with new connection
			log.Printf("[TUNNEL] Reconnecting client %s to existing tunnel %s", clientID, existingTunnelID)
			existingTunnel.Client = conn
			existingTunnel.LastSeen = time.Now()
			return existingTunnel
		} else {
			// Tunnel was cleaned up, remove stale mapping
			delete(tm.clientTunnels, clientID)
		}
	}

	// Create new tunnel
	id := generateRandomID()
	domain := fmt.Sprintf("%s-tun.%s", id, tm.config.Domain)

	tunnel := &Tunnel{
		ID:       id,
		Domain:   domain,
		Client:   conn,
		LastSeen: time.Now(),
	}

	tm.tunnels[id] = tunnel
	tm.clientTunnels[clientID] = id
	log.Printf("[TUNNEL] Created new tunnel %s for client %s", id, clientID)
	return tunnel
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

// writeToTunnel safely writes JSON to tunnel with mutex protection
func (tm *TunnelManager) writeToTunnel(tunnel *Tunnel, msg Message) error {
	tunnel.WriteMutex.Lock()
	defer tunnel.WriteMutex.Unlock()
	
	log.Printf("[WS-WRITE] Synchronized write to tunnel %s: type=%s, req_id=%s", 
		tunnel.ID, msg.Type, msg.RequestID)
	
	return tunnel.Client.WriteJSON(msg)
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
		
		// Извлекаем tunnel ID из домена
		host := r.Host
		if strings.HasSuffix(host, "-tun."+manager.config.Domain) {
			tunnelID := strings.TrimSuffix(host, "-tun."+manager.config.Domain)
			log.Printf("[PROXY] Request for tunnel %s", tunnelID)
			
			tunnel := manager.getTunnel(tunnelID)
			if tunnel != nil {
				log.Printf("[PROXY] Tunnel %s found, proxying request", tunnelID)
				// Проксируем через WebSocket к клиенту
				manager.proxyRequest(tunnel, r, w)
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
	// Генерируем уникальный ID запроса
	requestID := generateRandomID()
	log.Printf("[HTTP] Processing request %s for tunnel %s: %s %s", requestID, tunnel.ID, req.Method, req.URL.Path)
	
	// Создаем канал для ответа
	responseChan := make(chan *http.Response, 1)
	tm.mutex.Lock()
	tm.pendingRequests[requestID] = responseChan
	tm.mutex.Unlock()
	
	log.Printf("[HTTP] Request %s added to pending requests queue", requestID)
	
	// Сериализуем HTTP запрос
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
	
	// Отправляем клиенту
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
	
	// Ждем ответ от клиента (с таймаутом)
	select {
	case response := <-responseChan:
		log.Printf("[HTTP] Response received for request %s from tunnel %s: status=%d", requestID, tunnel.ID, response.StatusCode)
		
		// Копируем заголовки ответа
		for key, values := range response.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		
		// Устанавливаем статус код
		w.WriteHeader(response.StatusCode)
		
		// Копируем тело ответа
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
	// Простая сериализация HTTP запроса
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
	
	// Парсим ответ от клиента
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
	
	// Создаем HTTP ответ
	response := &http.Response{
		StatusCode: int(status),
		Header:     make(http.Header),
	}
	
	// Копируем заголовки
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
	
	// Устанавливаем тело ответа
	bodySize := 0
	if body, ok := responseData["body"].(string); ok {
		bodySize = len(body)
		response.Body = io.NopCloser(strings.NewReader(body))
	}
	
	log.Printf("[HTTP] Response created for request %s: %d headers, %d bytes body", msg.RequestID, headerCount, bodySize)
	
	// Отправляем ответ в канал
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

	// Записываем конфиг в файл
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
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	log.Printf("[CLEANUP] Starting tunnel cleanup routine")

	for range ticker.C {
		tm.mutex.Lock()
		tunnelCount := len(tm.tunnels)
		cleanedCount := 0
		
		for id, tunnel := range tm.tunnels {
			if time.Since(tunnel.LastSeen) > 2*time.Minute {
				log.Printf("[CLEANUP] Tunnel %s is stale (last seen: %v ago), cleaning up", id, time.Since(tunnel.LastSeen))
				tunnel.Client.Close()
				
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