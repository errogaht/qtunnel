package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

var (
	Version    = "dev"
	CommitHash = "unknown"
	BuildTime  = "unknown"
)

type Config struct {
	ServerURL string
	AuthToken string
	LocalPort int
}

type Message struct {
	Type      string `json:"type"`
	TunnelID  string `json:"tunnel_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Data      string `json:"data,omitempty"`
	Error     string `json:"error,omitempty"`
}

type HTTPRequest struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func main() {
	var (
		serverURL = flag.String("server", "", "QTunnel server WebSocket URL (e.g., wss://qtunnel.example.com/ws)")
		authToken = flag.String("token", "", "Authentication token for the server")
		showVersion = flag.Bool("version", false, "Show version information")
		showHelp = flag.Bool("help", false, "Show help information")
	)
	
	flag.BoolVar(showVersion, "v", false, "Show version information (shorthand)")
	flag.BoolVar(showHelp, "h", false, "Show help information (shorthand)")
	
	flag.Parse()

	if *showVersion {
		fmt.Printf("QTunnel Client %s (commit: %s, built: %s)\n", Version, CommitHash, BuildTime)
		os.Exit(0)
	}

	if *showHelp {
		fmt.Println("QTunnel Client - Secure HTTP Tunneling")
		fmt.Printf("Version: %s\n\n", Version)
		fmt.Println("Usage: qtunnel [options] <local_port>")
		fmt.Println("Example: qtunnel --server wss://qtunnel.example.com/ws --token your-token 8003")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("  --server string    QTunnel server WebSocket URL")
		fmt.Println("  --token string     Authentication token for the server")
		fmt.Println("  -h, --help        Show this help message")
		fmt.Println("  -v, --version     Show version information")
		fmt.Println("")
		fmt.Println("Environment Variables (used as defaults):")
		fmt.Println("  QTUNNEL_SERVER     WebSocket server URL")
		fmt.Println("  QTUNNEL_AUTH_TOKEN Authentication token")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  qtunnel 3000")
		fmt.Println("  qtunnel --server wss://tunnel.example.com/ws --token abc123 8080")
		fmt.Println("  QTUNNEL_SERVER=wss://tunnel.example.com/ws qtunnel 3000")
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) != 1 {
		fmt.Println("Usage: qtunnel [options] <local_port>")
		fmt.Println("Example: qtunnel --server wss://qtunnel.example.com/ws --token your-token 8003")
		fmt.Println("Run 'qtunnel --help' for more information")
		os.Exit(1)
	}

	localPort, err := strconv.Atoi(args[0])
	if err != nil {
		log.Fatalf("Invalid port: %v", err)
	}

	// Use command line arguments, fallback to environment variables, then defaults
	finalServerURL := *serverURL
	if finalServerURL == "" {
		finalServerURL = getEnv("QTUNNEL_SERVER", "wss://localhost:8080/ws")
	}

	finalAuthToken := *authToken
	if finalAuthToken == "" {
		finalAuthToken = getEnv("QTUNNEL_AUTH_TOKEN", "default-secret-token")
	}

	// Validate required parameters
	if finalServerURL == "wss://localhost:8080/ws" && finalAuthToken == "default-secret-token" {
		fmt.Println("Error: You must specify server URL and auth token")
		fmt.Println("")
		fmt.Println("Either use command line arguments:")
		fmt.Println("  qtunnel --server wss://qtunnel.example.com/ws --token your-token", localPort)
		fmt.Println("")
		fmt.Println("Or set environment variables:")
		fmt.Println("  export QTUNNEL_SERVER=\"wss://qtunnel.example.com/ws\"")
		fmt.Println("  export QTUNNEL_AUTH_TOKEN=\"your-token\"")
		fmt.Println("  qtunnel", localPort)
		os.Exit(1)
	}

	config := &Config{
		ServerURL: finalServerURL,
		AuthToken: finalAuthToken,
		LocalPort: localPort,
	}

	client := &TunnelClient{
		config: config,
	}

	log.Printf("Connecting to %s...", config.ServerURL)
	log.Printf("Local port: %d", localPort)

	err = client.Connect()
	if err != nil {
		log.Fatalf("Connection failed: %v", err)
	}
}

type TunnelClient struct {
	config   *Config
	conn     *websocket.Conn
	tunnelID string
	domain   string
}

func (tc *TunnelClient) Connect() error {
	// Парсим URL сервера
	u, err := url.Parse(tc.config.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %v", err)
	}

	// Добавляем заголовок авторизации
	headers := http.Header{}
	headers.Add("Authorization", "Bearer "+tc.config.AuthToken)

	// Подключаемся к серверу
	tc.conn, _, err = websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		return fmt.Errorf("websocket connection failed: %v", err)
	}
	defer tc.conn.Close()

	log.Println("Connected to server!")

	// Обрабатываем сообщения от сервера
	for {
		var msg Message
		err := tc.conn.ReadJSON(&msg)
		if err != nil {
			log.Printf("Error reading message: %v", err)
			break
		}

		err = tc.handleMessage(msg)
		if err != nil {
			log.Printf("Error handling message: %v", err)
		}
	}

	return nil
}

func (tc *TunnelClient) handleMessage(msg Message) error {
	switch msg.Type {
	case "tunnel_created":
		tc.tunnelID = msg.TunnelID
		tc.domain = msg.Data
		fmt.Printf("\n🎉 Tunnel created!\n")
		fmt.Printf("📡 Local port: %d\n", tc.config.LocalPort)
		fmt.Printf("🌐 Public URL: https://%s\n", tc.domain)
		fmt.Printf("⏱️  Tunnel active... (Ctrl+C to stop)\n\n")

	case "http_request":
		return tc.handleHTTPRequest(msg.RequestID, msg.Data)

	case "pong":
		// Игнорируем pong сообщения

	default:
		log.Printf("Unknown message type: %s", msg.Type)
	}

	return nil
}

func (tc *TunnelClient) handleHTTPRequest(requestID, data string) error {
	// Парсим HTTP запрос
	var httpReq HTTPRequest
	err := json.Unmarshal([]byte(data), &httpReq)
	if err != nil {
		return fmt.Errorf("failed to parse HTTP request: %v", err)
	}

	log.Printf("%s %s", httpReq.Method, httpReq.URL)

	// Создаем локальный HTTP запрос
	localURL := fmt.Sprintf("http://localhost:%d%s", tc.config.LocalPort, httpReq.URL)
	
	var bodyReader io.Reader
	if httpReq.Body != "" {
		bodyReader = bytes.NewReader([]byte(httpReq.Body))
	}

	req, err := http.NewRequest(httpReq.Method, localURL, bodyReader)
	if err != nil {
		return tc.sendErrorResponse(requestID, fmt.Sprintf("Failed to create request: %v", err))
	}

	// Копируем заголовки (кроме Host)
	for key, values := range httpReq.Headers {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	// Выполняем запрос к локальному серверу
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return tc.sendErrorResponse(requestID, fmt.Sprintf("Local server error: %v", err))
	}
	defer resp.Body.Close()

	// Читаем ответ
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tc.sendErrorResponse(requestID, fmt.Sprintf("Failed to read response: %v", err))
	}

	// Формируем ответ
	response := map[string]interface{}{
		"status":  resp.StatusCode,
		"headers": resp.Header,
		"body":    string(body),
	}

	responseJSON, _ := json.Marshal(response)

	// Отправляем ответ серверу
	return tc.conn.WriteJSON(Message{
		Type:      "http_response",
		TunnelID:  tc.tunnelID,
		RequestID: requestID,
		Data:      string(responseJSON),
	})
}

func (tc *TunnelClient) sendErrorResponse(requestID, errorMsg string) error {
	response := map[string]interface{}{
		"status": 502,
		"headers": map[string][]string{
			"Content-Type": {"text/plain"},
		},
		"body": errorMsg,
	}

	responseJSON, _ := json.Marshal(response)

	return tc.conn.WriteJSON(Message{
		Type:      "http_response",
		TunnelID:  tc.tunnelID,
		RequestID: requestID,
		Data:      string(responseJSON),
		Error:     errorMsg,
	})
}

func (tc *TunnelClient) startPingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		err := tc.conn.WriteJSON(Message{Type: "ping"})
		if err != nil {
			log.Printf("Ping failed: %v", err)
			return
		}
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}