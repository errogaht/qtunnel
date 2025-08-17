package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	Version    = "dev"
	CommitHash = "unknown"
	BuildTime  = "unknown"
)

type Config struct {
	ServerURL    string
	AuthToken    string
	LocalPort    int
	OutputFormat string
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

type LogEntry struct {
	Timestamp string      `json:"timestamp"`
	Level     string      `json:"level"`
	Message   string      `json:"message"`
	Details   interface{} `json:"details,omitempty"`
}

type TunnelStatus struct {
	TunnelID  string `json:"tunnel_id"`
	Domain    string `json:"domain"`
	LocalPort int    `json:"local_port"`
	Status    string `json:"status"`
}

type RequestLog struct {
	RequestID string `json:"request_id"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Status    int    `json:"status,omitempty"`
	Duration  string `json:"duration,omitempty"`
}

func main() {
	var (
		serverURL    = flag.String("server", "", "QTunnel server WebSocket URL (e.g., wss://qtunnel.example.com/ws)")
		authToken    = flag.String("token", "", "Authentication token for the server")
		outputFormat = flag.String("output-format", "text", "Output format: text or stream.json")
		showVersion  = flag.Bool("version", false, "Show version information")
		showHelp     = flag.Bool("help", false, "Show help information")
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
		fmt.Println("  --server string         QTunnel server WebSocket URL")
		fmt.Println("  --token string          Authentication token for the server")
		fmt.Println("  --output-format string  Output format: text or stream.json (default: text)")
		fmt.Println("  -h, --help             Show this help message")
		fmt.Println("  -v, --version          Show version information")
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

	// Validate output format
	if *outputFormat != "text" && *outputFormat != "stream.json" {
		fmt.Println("Error: Invalid output format. Use 'text' or 'stream.json'")
		os.Exit(1)
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
		ServerURL:    finalServerURL,
		AuthToken:    finalAuthToken,
		LocalPort:    localPort,
		OutputFormat: *outputFormat,
	}

	client := &TunnelClient{
		config:       config,
		clientID:     generateClientID(),
		requestTimes: make(map[string]time.Time),
	}

	client.logInfo("Starting QTunnel client", map[string]interface{}{
		"server_url":    config.ServerURL,
		"local_port":    localPort,
		"output_format": config.OutputFormat,
		"client_id":     client.clientID,
		"process_id":    os.Getpid(),
	})

	err = client.Connect()
	if err != nil {
		client.logError("Connection failed", err, nil)
		os.Exit(1)
	}
}

type TunnelClient struct {
	config        *Config
	conn          *websocket.Conn
	tunnelID      string
	domain        string
	clientID      string // Stable client ID for reconnections
	requestTimes  map[string]time.Time
	requestMutex  sync.RWMutex
	writeMutex    sync.Mutex // Prevents concurrent WebSocket writes
}

func (tc *TunnelClient) logInfo(message string, details interface{}) {
	tc.outputLog("INFO", message, details)
}

func (tc *TunnelClient) logWarn(message string, details interface{}) {
	tc.outputLog("WARN", message, details)
}

func (tc *TunnelClient) logError(message string, err error, details interface{}) {
	errorDetails := details
	if err != nil {
		if errorDetails == nil {
			errorDetails = map[string]interface{}{"error": err.Error()}
		} else if detailsMap, ok := errorDetails.(map[string]interface{}); ok {
			detailsMap["error"] = err.Error()
		}
	}
	tc.outputLog("ERROR", message, errorDetails)
}

// writeJSON safely writes JSON to WebSocket with mutex protection
func (tc *TunnelClient) writeJSON(msg Message) error {
	tc.writeMutex.Lock()
	defer tc.writeMutex.Unlock()
	
	tc.logInfo("WebSocket write", map[string]interface{}{
		"message_type": msg.Type,
		"request_id": msg.RequestID,
		"goroutine": "synchronized",
	})
	
	return tc.conn.WriteJSON(msg)
}

// writeJSONWithDeadline safely writes JSON with deadline and mutex protection
func (tc *TunnelClient) writeJSONWithDeadline(msg Message, timeout time.Duration) error {
	tc.writeMutex.Lock()
	defer tc.writeMutex.Unlock()
	
	tc.conn.SetWriteDeadline(time.Now().Add(timeout))
	return tc.conn.WriteJSON(msg)
}

func (tc *TunnelClient) outputLog(level, message string, details interface{}) {
	if tc.config.OutputFormat == "stream.json" {
		logEntry := LogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     level,
			Message:   message,
			Details:   details,
		}
		
		jsonData, err := json.Marshal(logEntry)
		if err != nil {
			// Fallback to standard logging if JSON marshal fails
			log.Printf("[%s] %s: %v (JSON marshal error: %v)", level, message, details, err)
			return
		}
		
		fmt.Println(string(jsonData))
	} else {
		// Traditional text output
		if details != nil {
			log.Printf("[%s] %s: %v", level, message, details)
		} else {
			log.Printf("[%s] %s", level, message)
		}
	}
}

func (tc *TunnelClient) outputTunnelStatus(status string) {
	if tc.config.OutputFormat == "stream.json" {
		tunnelStatus := TunnelStatus{
			TunnelID:  tc.tunnelID,
			Domain:    tc.domain,
			LocalPort: tc.config.LocalPort,
			Status:    status,
		}
		
		jsonData, err := json.Marshal(tunnelStatus)
		if err != nil {
			tc.logError("Failed to marshal tunnel status", err, nil)
			return
		}
		
		fmt.Println(string(jsonData))
	}
}

func (tc *TunnelClient) Connect() error {
	maxRetries := 5
	retryDelay := 5 * time.Second

	tc.logInfo("Starting connection process", map[string]interface{}{
		"max_retries": maxRetries,
		"initial_delay": retryDelay.String(),
	})

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			tc.logInfo("Retrying connection", map[string]interface{}{
				"attempt": retry + 1,
				"max_attempts": maxRetries,
				"delay": retryDelay.String(),
			})
			time.Sleep(retryDelay)
			retryDelay *= 2 // Exponential backoff
		}

		err := tc.connectOnce()
		if err != nil {
			tc.logError("Connection attempt failed", err, map[string]interface{}{
				"attempt": retry + 1,
				"max_attempts": maxRetries,
			})
			continue
		}

		// If we get here, connection was successful but lost - retry
		tc.logWarn("Connection lost, retrying", map[string]interface{}{
			"attempt": retry + 1,
		})
	}

	tc.logError("Failed to establish stable connection", nil, map[string]interface{}{
		"max_attempts": maxRetries,
	})
	return fmt.Errorf("failed to establish stable connection after %d attempts", maxRetries)
}

func (tc *TunnelClient) connectOnce() error {
	tc.logInfo("Parsing server URL", map[string]interface{}{
		"url": tc.config.ServerURL,
		"client_id": tc.clientID,
	})
	
	// Parse server URL
	u, err := url.Parse(tc.config.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %v", err)
	}
	
	// Add client ID as query parameter for stable reconnection
	q := u.Query()
	q.Set("client_id", tc.clientID)
	u.RawQuery = q.Encode()

	tc.logInfo("Preparing WebSocket connection", map[string]interface{}{
		"scheme": u.Scheme,
		"host": u.Host,
		"path": u.Path,
	})

	// Add authorization header
	headers := http.Header{}
	headers.Add("Authorization", "Bearer "+tc.config.AuthToken)

	tc.logInfo("Attempting WebSocket connection", nil)
	
	// Connect to server
	tc.conn, _, err = websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		return fmt.Errorf("websocket connection failed: %v", err)
	}
	defer tc.conn.Close()

	tc.logInfo("WebSocket connection established", nil)
	tc.outputTunnelStatus("connected")

	// Start ping loop in goroutine
	pingDone := make(chan struct{})
	go tc.startPingLoop(pingDone)
	defer close(pingDone)

	tc.logInfo("Starting message processing loop", nil)
	
	// Process messages from server
	for {
		// Set read deadline to detect dead connections
		tc.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		
		var msg Message
		err := tc.conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				tc.logError("Unexpected WebSocket close", err, nil)
			} else {
				tc.logError("Error reading message from server", err, nil)
			}
			tc.outputTunnelStatus("disconnected")
			break
		}

		tc.logInfo("Received message from server", map[string]interface{}{
			"type": msg.Type,
			"tunnel_id": msg.TunnelID,
			"request_id": msg.RequestID,
		})

		err = tc.handleMessage(msg)
		if err != nil {
			tc.logError("Error handling message", err, map[string]interface{}{
				"message_type": msg.Type,
				"tunnel_id": msg.TunnelID,
				"request_id": msg.RequestID,
			})
		}
	}

	return nil
}

func (tc *TunnelClient) handleMessage(msg Message) error {
	switch msg.Type {
	case "tunnel_created":
		// Check if we're reconnecting to existing tunnel
		previousTunnelID := tc.tunnelID
		previousDomain := tc.domain
		
		tc.tunnelID = msg.TunnelID
		tc.domain = msg.Data
		
		if previousTunnelID != "" && previousTunnelID != tc.tunnelID {
			tc.logWarn("Tunnel URL changed during reconnection", map[string]interface{}{
				"previous_tunnel_id": previousTunnelID,
				"previous_domain": previousDomain,
				"new_tunnel_id": tc.tunnelID,
				"new_domain": tc.domain,
				"reason": "Previous tunnel was cleaned up or client_id changed",
				"client_id": tc.clientID,
			})
		} else if previousTunnelID == tc.tunnelID {
			tc.logInfo("Reconnected to existing tunnel - URL STABLE", map[string]interface{}{
				"tunnel_id": tc.tunnelID,
				"domain": tc.domain,
				"client_id": tc.clientID,
				"message": "Same domain maintained across reconnection",
			})
		} else {
			tc.logInfo("New tunnel created", map[string]interface{}{
				"tunnel_id": tc.tunnelID,
				"domain": tc.domain,
				"local_port": tc.config.LocalPort,
				"client_id": tc.clientID,
				"message": "Fresh tunnel for new client process",
			})
		}
		
		tc.outputTunnelStatus("active")
		
		if tc.config.OutputFormat == "text" {
			fmt.Printf("\n🎉 Tunnel created!\n")
			fmt.Printf("📡 Local port: %d\n", tc.config.LocalPort)
			fmt.Printf("🌐 Public URL: https://%s\n", tc.domain)
			fmt.Printf("⏱️  Tunnel active... (Ctrl+C to stop)\n\n")
		}

	case "http_request":
		return tc.handleHTTPRequest(msg.RequestID, msg.Data)

	case "pong":
		tc.logInfo("Pong received from server", nil)

	default:
		tc.logWarn("Unknown message type received", map[string]interface{}{
			"message_type": msg.Type,
		})
	}

	return nil
}

func (tc *TunnelClient) handleHTTPRequest(requestID, data string) error {
	startTime := time.Now()
	
	// Store request start time for duration tracking
	tc.requestMutex.Lock()
	tc.requestTimes[requestID] = startTime
	tc.requestMutex.Unlock()
	
	tc.logInfo("Processing HTTP request", map[string]interface{}{
		"request_id": requestID,
	})
	
	// Parse HTTP request
	var httpReq HTTPRequest
	err := json.Unmarshal([]byte(data), &httpReq)
	if err != nil {
		tc.logError("Failed to parse HTTP request", err, map[string]interface{}{
			"request_id": requestID,
		})
		return fmt.Errorf("failed to parse HTTP request: %v", err)
	}

	tc.logInfo("HTTP request details", map[string]interface{}{
		"request_id": requestID,
		"method": httpReq.Method,
		"url": httpReq.URL,
		"headers_count": len(httpReq.Headers),
		"body_size": len(httpReq.Body),
	})
	
	// Output request log for JSON format
	if tc.config.OutputFormat == "stream.json" {
		reqLog := RequestLog{
			RequestID: requestID,
			Method:    httpReq.Method,
			URL:       httpReq.URL,
		}
		
		jsonData, _ := json.Marshal(reqLog)
		fmt.Println(string(jsonData))
	} else {
		log.Printf("%s %s", httpReq.Method, httpReq.URL)
	}

	// Create local HTTP request
	localURL := fmt.Sprintf("http://localhost:%d%s", tc.config.LocalPort, httpReq.URL)
	
	tc.logInfo("Creating local HTTP request", map[string]interface{}{
		"request_id": requestID,
		"local_url": localURL,
	})
	
	var bodyReader io.Reader
	if httpReq.Body != "" {
		bodyReader = bytes.NewReader([]byte(httpReq.Body))
	}

	req, err := http.NewRequest(httpReq.Method, localURL, bodyReader)
	if err != nil {
		tc.logError("Failed to create local HTTP request", err, map[string]interface{}{
			"request_id": requestID,
			"local_url": localURL,
		})
		return tc.sendErrorResponse(requestID, fmt.Sprintf("Failed to create request: %v", err))
	}

	// Copy headers (except Host)
	headerCount := 0
	for key, values := range httpReq.Headers {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
				headerCount++
			}
		}
	}
	
	tc.logInfo("Local request prepared", map[string]interface{}{
		"request_id": requestID,
		"headers_copied": headerCount,
	})

	// Execute request to local server
	tc.logInfo("Sending request to local server", map[string]interface{}{
		"request_id": requestID,
		"timeout": "30s",
	})
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		tc.logError("Local server request failed", err, map[string]interface{}{
			"request_id": requestID,
			"local_url": localURL,
		})
		return tc.sendErrorResponse(requestID, fmt.Sprintf("Local server error: %v", err))
	}
	defer resp.Body.Close()

	tc.logInfo("Local server responded", map[string]interface{}{
		"request_id": requestID,
		"status_code": resp.StatusCode,
		"headers_count": len(resp.Header),
	})

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tc.logError("Failed to read response body", err, map[string]interface{}{
			"request_id": requestID,
		})
		return tc.sendErrorResponse(requestID, fmt.Sprintf("Failed to read response: %v", err))
	}

	tc.logInfo("Response body read", map[string]interface{}{
		"request_id": requestID,
		"body_size": len(body),
	})

	// Calculate request duration
	tc.requestMutex.RLock()
	requestStart, exists := tc.requestTimes[requestID]
	tc.requestMutex.RUnlock()
	
	duration := ""
	if exists {
		duration = time.Since(requestStart).String()
	}

	// Format response
	response := map[string]interface{}{
		"status":  resp.StatusCode,
		"headers": resp.Header,
		"body":    string(body),
	}

	responseJSON, _ := json.Marshal(response)

	tc.logInfo("Sending response to server", map[string]interface{}{
		"request_id": requestID,
		"status_code": resp.StatusCode,
		"response_size": len(responseJSON),
		"duration": duration,
	})

	// Output completion log for JSON format
	if tc.config.OutputFormat == "stream.json" && duration != "" {
		reqLog := RequestLog{
			RequestID: requestID,
			Method:    httpReq.Method,
			URL:       httpReq.URL,
			Status:    resp.StatusCode,
			Duration:  duration,
		}
		
		jsonData, _ := json.Marshal(reqLog)
		fmt.Println(string(jsonData))
	}
	
	// Clean up request time tracking
	tc.requestMutex.Lock()
	delete(tc.requestTimes, requestID)
	tc.requestMutex.Unlock()

	// Send response to server
	return tc.writeJSON(Message{
		Type:      "http_response",
		TunnelID:  tc.tunnelID,
		RequestID: requestID,
		Data:      string(responseJSON),
	})
}

func (tc *TunnelClient) sendErrorResponse(requestID, errorMsg string) error {
	tc.logError("Sending error response", nil, map[string]interface{}{
		"request_id": requestID,
		"error_message": errorMsg,
	})
	
	// Calculate request duration if available
	tc.requestMutex.RLock()
	requestStart, exists := tc.requestTimes[requestID]
	tc.requestMutex.RUnlock()
	
	duration := ""
	if exists {
		duration = time.Since(requestStart).String()
	}
	
	response := map[string]interface{}{
		"status": 502,
		"headers": map[string][]string{
			"Content-Type": {"text/plain"},
		},
		"body": errorMsg,
	}

	responseJSON, _ := json.Marshal(response)

	// Output error log for JSON format
	if tc.config.OutputFormat == "stream.json" && duration != "" {
		reqLog := RequestLog{
			RequestID: requestID,
			Status:    502,
			Duration:  duration,
		}
		
		jsonData, _ := json.Marshal(reqLog)
		fmt.Println(string(jsonData))
	}
	
	// Clean up request time tracking
	tc.requestMutex.Lock()
	delete(tc.requestTimes, requestID)
	tc.requestMutex.Unlock()

	return tc.writeJSON(Message{
		Type:      "http_response",
		TunnelID:  tc.tunnelID,
		RequestID: requestID,
		Data:      string(responseJSON),
		Error:     errorMsg,
	})
}

func (tc *TunnelClient) startPingLoop(done chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	tc.logInfo("Starting ping loop", map[string]interface{}{
		"interval": "30s",
	})

	for {
		select {
		case <-done:
			tc.logInfo("Ping loop stopped", nil)
			return
		case <-ticker.C:
			if tc.conn == nil {
				tc.logWarn("Ping attempted but connection is nil", nil)
				return
			}
			
			tc.logInfo("Sending ping to server", nil)
			
			// Send ping with write synchronization
			err := tc.writeJSONWithDeadline(Message{Type: "ping"}, 10*time.Second)
			if err != nil {
				tc.logError("Ping failed", err, nil)
				return
			}
			tc.logInfo("Ping sent successfully", nil)
		}
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func generateClientID() string {
	// Generate unique client ID for this process instance
	// New process = new clientID = new tunnel domain
	// Same process reconnecting = same clientID = same tunnel domain
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	
	processID := os.Getpid()
	timestamp := time.Now().UnixNano() // Use nanoseconds for better uniqueness
	randomBytes := make([]byte, 8)     // Use more random bytes
	rand.Read(randomBytes)
	
	return fmt.Sprintf("%s-%d-%d-%x", hostname, processID, timestamp, randomBytes)
}