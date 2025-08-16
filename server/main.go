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
	ID       string          `json:"id"`
	Domain   string          `json:"domain"`
	Client   *websocket.Conn `json:"-"`
	LastSeen time.Time       `json:"last_seen"`
	Port     int             `json:"port"`
}

type TunnelManager struct {
	tunnels        map[string]*Tunnel
	pendingRequests map[string]chan *http.Response
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
	// Проверка токена
	authToken := r.Header.Get("Authorization")
	if authToken != "Bearer "+tm.config.AuthToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// Генерируем новый туннель
	tunnel := tm.createTunnel(conn)
	log.Printf("New tunnel created: %s -> %s", tunnel.ID, tunnel.Domain)

	// Отправляем домен клиенту
	err = conn.WriteJSON(Message{
		Type:     "tunnel_created",
		TunnelID: tunnel.ID,
		Data:     tunnel.Domain,
	})
	if err != nil {
		log.Printf("Error sending tunnel info: %v", err)
		return
	}

	// Создаем Traefik конфиг
	tm.createTraefikConfig(tunnel)

	// Обрабатываем сообщения от клиента
	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Printf("Error reading message: %v", err)
			break
		}

		tunnel.LastSeen = time.Now()
		
		// Обработка разных типов сообщений
		switch msg.Type {
		case "ping":
			conn.WriteJSON(Message{Type: "pong"})
		case "http_response":
			tm.handleHTTPResponse(msg)
		}
	}

	// Cleanup при отключении
	tm.removeTunnel(tunnel.ID)
	tm.removeTraefikConfig(tunnel)
	log.Printf("Tunnel removed: %s", tunnel.ID)
}

func (tm *TunnelManager) createTunnel(conn *websocket.Conn) *Tunnel {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Генерируем уникальный ID
	id := generateRandomID()
	domain := fmt.Sprintf("%s-tun.%s", id, tm.config.Domain)

	tunnel := &Tunnel{
		ID:       id,
		Domain:   domain,
		Client:   conn,
		LastSeen: time.Now(),
	}

	tm.tunnels[id] = tunnel
	return tunnel
}

func (tm *TunnelManager) removeTunnel(id string) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	delete(tm.tunnels, id)
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
		// Извлекаем tunnel ID из домена
		host := r.Host
		if strings.HasSuffix(host, "-tun."+manager.config.Domain) {
			tunnelID := strings.TrimSuffix(host, "-tun."+manager.config.Domain)
			
			tunnel := manager.getTunnel(tunnelID)
			if tunnel != nil {
				// Проксируем через WebSocket к клиенту
				manager.proxyRequest(tunnel, r, w)
			} else {
				http.Error(w, "Tunnel not found", http.StatusNotFound)
			}
		} else {
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
	
	// Создаем канал для ответа
	responseChan := make(chan *http.Response, 1)
	tm.mutex.Lock()
	tm.pendingRequests[requestID] = responseChan
	tm.mutex.Unlock()
	
	// Сериализуем HTTP запрос
	reqData, _ := httpRequestToJSON(req)
	
	// Отправляем клиенту
	err := tunnel.Client.WriteJSON(Message{
		Type:      "http_request",
		TunnelID:  tunnel.ID,
		RequestID: requestID,
		Data:      reqData,
	})
	
	if err != nil {
		log.Printf("Error forwarding request: %v", err)
		http.Error(w, "Tunnel error", http.StatusBadGateway)
		tm.mutex.Lock()
		delete(tm.pendingRequests, requestID)
		tm.mutex.Unlock()
		return
	}
	
	// Ждем ответ от клиента (с таймаутом)
	select {
	case response := <-responseChan:
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
			io.Copy(w, response.Body)
			response.Body.Close()
		}
		
	case <-time.After(30 * time.Second):
		log.Printf("Request timeout for tunnel %s", tunnel.ID)
		http.Error(w, "Request timeout", http.StatusGatewayTimeout)
	}
	
	// Cleanup
	tm.mutex.Lock()
	delete(tm.pendingRequests, requestID)
	tm.mutex.Unlock()
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
	tm.mutex.Lock()
	responseChan, exists := tm.pendingRequests[msg.RequestID]
	tm.mutex.Unlock()
	
	if !exists {
		log.Printf("No pending request for ID: %s", msg.RequestID)
		return
	}
	
	// Парсим ответ от клиента
	var responseData map[string]interface{}
	err := json.Unmarshal([]byte(msg.Data), &responseData)
	if err != nil {
		log.Printf("Error parsing response: %v", err)
		return
	}
	
	// Создаем HTTP ответ
	response := &http.Response{
		StatusCode: int(responseData["status"].(float64)),
		Header:     make(http.Header),
	}
	
	// Копируем заголовки
	if headers, ok := responseData["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if valueSlice, ok := value.([]interface{}); ok {
				for _, v := range valueSlice {
					if vStr, ok := v.(string); ok {
						response.Header.Add(key, vStr)
					}
				}
			}
		}
	}
	
	// Устанавливаем тело ответа
	if body, ok := responseData["body"].(string); ok {
		response.Body = io.NopCloser(strings.NewReader(body))
	}
	
	// Отправляем ответ в канал
	select {
	case responseChan <- response:
	default:
		log.Printf("Failed to send response to channel for request %s", msg.RequestID)
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

	for range ticker.C {
		tm.mutex.Lock()
		for id, tunnel := range tm.tunnels {
			if time.Since(tunnel.LastSeen) > 2*time.Minute {
				tunnel.Client.Close()
				delete(tm.tunnels, id)
				tm.removeTraefikConfig(tunnel)
				log.Printf("Cleaned up stale tunnel: %s", id)
			}
		}
		tm.mutex.Unlock()
	}
}