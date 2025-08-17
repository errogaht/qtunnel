package main

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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
	ServerURL     string
	AuthToken     string
	LocalPort     int
	OutputFormat  string
	Protocol      string // "websocket", "http2", "sse", "polling"
	AutoFallback  bool   // Enable automatic protocol fallback
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
		serverURL    = flag.String("server", "", "QTunnel server URL (e.g., wss://qtunnel.example.com/ws)")
		authToken    = flag.String("token", "", "Authentication token for the server")
		outputFormat = flag.String("output-format", "text", "Output format: text or stream.json")
		protocol     = flag.String("protocol", "auto", "Connection protocol: websocket, http2, sse, polling, auto")
		autoFallback = flag.Bool("auto-fallback", true, "Enable automatic protocol fallback on connection issues")
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
		fmt.Println("  --server string         QTunnel server URL")
		fmt.Println("  --token string          Authentication token for the server")
		fmt.Println("  --output-format string  Output format: text or stream.json (default: text)")
		fmt.Println("  --protocol string       Connection protocol: websocket, http2, sse, polling, auto (default: auto)")
		fmt.Println("  --auto-fallback        Enable automatic protocol fallback (default: true)")
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

	// Validate protocol
	validProtocols := map[string]bool{
		"auto": true, "websocket": true, "http2": true, "sse": true, "polling": true,
	}
	if !validProtocols[*protocol] {
		fmt.Println("Error: Invalid protocol. Use 'websocket', 'http2', 'sse', 'polling', or 'auto'")
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
		ServerURL:     finalServerURL,
		AuthToken:     finalAuthToken,
		LocalPort:     localPort,
		OutputFormat:  *outputFormat,
		Protocol:      *protocol,
		AutoFallback:  *autoFallback,
	}

	// Create HTTP client for alternative protocols (HTTP/1.1 compatible)
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
		Timeout: 30 * time.Second,
	}

	client := &TunnelClient{
		config:       config,
		httpClient:   httpClient,
		clientID:     generateClientID(),
		requestTimes: make(map[string]time.Time),
	}

	client.logInfo("Starting QTunnel client", map[string]interface{}{
		"server_url":     config.ServerURL,
		"local_port":     localPort,
		"output_format":  config.OutputFormat,
		"protocol":       config.Protocol,
		"auto_fallback":  config.AutoFallback,
		"client_id":      client.clientID,
		"process_id":     os.Getpid(),
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
	httpClient    *http.Client     // For HTTP/2, SSE, polling
	currentProto  string           // Currently active protocol
	tunnelID      string
	domain        string
	clientID      string           // Stable client ID for reconnections
	requestTimes  map[string]time.Time
	requestMutex  sync.RWMutex
	writeMutex    sync.Mutex       // Prevents concurrent writes
	
	// HTTP/2 specific fields
	http2Reader   *bufio.Reader    // HTTP/2 response reader
	http2Writer   io.WriteCloser   // HTTP/2 request writer  
	http2Ctx      context.Context  // HTTP/2 context
	http2Cancel   context.CancelFunc // HTTP/2 cancellation
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

// writeJSON safely writes JSON using current protocol with mutex protection
func (tc *TunnelClient) writeJSON(msg Message) error {
	tc.writeMutex.Lock()
	defer tc.writeMutex.Unlock()
	
	tc.logInfo("Protocol write", map[string]interface{}{
		"protocol": tc.currentProto,
		"message_type": msg.Type,
		"request_id": msg.RequestID,
		"goroutine": "synchronized",
	})
	
	switch tc.currentProto {
	case "websocket":
		if tc.conn == nil {
			return fmt.Errorf("WebSocket connection is nil")
		}
		return tc.conn.WriteJSON(msg)
	case "http2":
		return tc.http2WriteMessage(msg)
	case "sse", "polling":
		// TODO: Implement SSE and polling message sending
		return fmt.Errorf("%s message sending not yet implemented", tc.currentProto)
	default:
		return fmt.Errorf("unknown protocol: %s", tc.currentProto)
	}
}

// writeJSONWithDeadline safely writes JSON with deadline and mutex protection
func (tc *TunnelClient) writeJSONWithDeadline(msg Message, timeout time.Duration) error {
	tc.writeMutex.Lock()
	defer tc.writeMutex.Unlock()
	
	switch tc.currentProto {
	case "websocket":
		if tc.conn == nil {
			return fmt.Errorf("WebSocket connection is nil")
		}
		tc.conn.SetWriteDeadline(time.Now().Add(timeout))
		return tc.conn.WriteJSON(msg)
	case "http2":
		// HTTP/2 doesn't support write deadlines in the same way
		// Use context timeout instead
		ctx, cancel := context.WithTimeout(tc.http2Ctx, timeout)
		defer cancel()
		
		done := make(chan error, 1)
		go func() {
			done <- tc.http2WriteMessage(msg)
		}()
		
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case "sse", "polling":
		return fmt.Errorf("%s deadline writes not yet implemented", tc.currentProto)
	default:
		return fmt.Errorf("unknown protocol: %s", tc.currentProto)
	}
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
	retryCount := 0
	maxRetries := 10 // Increased from 5
	baseDelay := 2 * time.Second // Reduced initial delay
	maxDelay := 30 * time.Second // Cap maximum delay

	// Determine protocols to try
	protocols := tc.getProtocolsToTry()
	
	tc.logInfo("Starting connection process", map[string]interface{}{
		"max_retries": maxRetries,
		"base_delay": baseDelay.String(),
		"max_delay": maxDelay.String(),
		"protocols": protocols,
		"auto_fallback": tc.config.AutoFallback,
	})

	for {
		// Try each protocol in sequence
		for _, protocol := range protocols {
			if retryCount > 0 {
				// Calculate delay with exponential backoff and jitter
				multiplier := 1 << uint(retryCount-1) // Exponential backoff: 1, 2, 4, 8, etc.
				delay := time.Duration(int64(baseDelay) * int64(multiplier))
				if delay > maxDelay {
					delay = maxDelay
				}
				// Add jitter to prevent thundering herd
				jitter := time.Duration(rand.Int63n(int64(delay / 4)))
				finalDelay := delay + jitter
				
				tc.logInfo("Retrying connection", map[string]interface{}{
					"attempt": retryCount + 1,
					"max_attempts": maxRetries,
					"protocol": protocol,
					"delay": finalDelay.String(),
					"client_id": tc.clientID,
				})
				time.Sleep(finalDelay)
			}

			tc.currentProto = protocol
			err := tc.connectWithProtocol(protocol)
			if err != nil {
				tc.logError("Connection attempt failed", err, map[string]interface{}{
					"protocol": protocol,
					"attempt": retryCount + 1,
					"max_attempts": maxRetries,
					"error_type": fmt.Sprintf("%T", err),
				})
				
				// If auto-fallback enabled, try next protocol
				if tc.config.AutoFallback && len(protocols) > 1 {
					tc.logInfo("Trying next protocol", map[string]interface{}{
						"failed_protocol": protocol,
						"remaining_protocols": len(protocols) - 1,
					})
					continue // Try next protocol
				}
			} else {
				// Success! Connection established
				tc.logInfo("Protocol established successfully", map[string]interface{}{
					"protocol": protocol,
					"attempt": retryCount + 1,
				})
				break // Exit protocol loop on success
			}
		}
		
		retryCount++
		// Check if we should stop retrying
		if retryCount >= maxRetries {
			tc.logError("Max retry attempts exceeded", nil, map[string]interface{}{
				"total_attempts": retryCount,
				"protocols_tried": protocols,
			})
			return fmt.Errorf("failed to establish stable connection after %d attempts with protocols %v", retryCount, protocols)
		}

		// Connection was successful but was lost - reset retry count for faster reconnection
		if retryCount > 3 {
			retryCount = 3 // Reset but keep some backoff
		}
		tc.logWarn("Connection lost, retrying with all protocols", map[string]interface{}{
			"previous_attempts": retryCount,
			"client_id": tc.clientID,
			"protocols": protocols,
		})
	}
}

// connectWithProtocol attempts connection using specified protocol
func (tc *TunnelClient) connectWithProtocol(protocol string) error {
	tc.logInfo("Attempting connection", map[string]interface{}{
		"protocol": protocol,
		"client_id": tc.clientID,
	})

	switch protocol {
	case "websocket":
		return tc.connectWebSocket()
	case "http2":
		return tc.connectHTTP2()
	case "sse":
		return tc.connectSSE()
	case "polling":
		return tc.connectPolling()
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (tc *TunnelClient) connectWebSocket() error {
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
		"query": u.RawQuery,
	})

	// Add authorization header
	headers := http.Header{}
	headers.Add("Authorization", "Bearer "+tc.config.AuthToken)

	// Configure dialer with timeouts
	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
	}

	tc.logInfo("Attempting WebSocket connection", map[string]interface{}{
		"handshake_timeout": "15s",
	})
	
	// Connect to server
	tc.conn, _, err = dialer.Dial(u.String(), headers)
	if err != nil {
		return fmt.Errorf("websocket connection failed: %v", err)
	}
	defer tc.conn.Close()

	// Set connection timeouts and limits
	tc.conn.SetReadLimit(1024 * 1024) // 1MB message limit
	tc.conn.SetPongHandler(func(appData string) error {
		tc.logInfo("Pong handler triggered", map[string]interface{}{
			"app_data": appData,
		})
		return nil
	})

	tc.logInfo("WebSocket connection established", nil)
	tc.outputTunnelStatus("connected")

	// Start ping loop in goroutine
	pingDone := make(chan struct{})
	go tc.startPingLoop(pingDone)
	defer close(pingDone)

	tc.logInfo("Starting message processing loop", nil)
	
	// Process messages from server
	for {
		// Set read deadline with longer timeout for better stability
		tc.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		
		var msg Message
		err := tc.conn.ReadJSON(&msg)
		if err != nil {
			// Enhanced error classification
			closeCode := websocket.CloseNoStatusReceived
			if closeErr, ok := err.(*websocket.CloseError); ok {
				closeCode = closeErr.Code
			}
			
			errorDetails := map[string]interface{}{
				"error_type": fmt.Sprintf("%T", err),
				"close_code": closeCode,
				"is_timeout": strings.Contains(err.Error(), "timeout"),
				"is_network": strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "network"),
			}
			
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNoStatusReceived) {
				tc.logError("Unexpected WebSocket close", err, errorDetails)
			} else {
				tc.logError("WebSocket connection error", err, errorDetails)
			}
			tc.outputTunnelStatus("disconnected")
			
			// Return different error types for better retry logic
			if strings.Contains(err.Error(), "i/o timeout") {
				return fmt.Errorf("network timeout: %v", err)
			}
			return err
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
	ticker := time.NewTicker(25 * time.Second) // Slightly more frequent
	defer ticker.Stop()

	tc.logInfo("Starting ping loop", map[string]interface{}{
		"interval": "25s",
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
			
			tc.logInfo("Sending ping to server", map[string]interface{}{
				"client_id": tc.clientID,
				"tunnel_id": tc.tunnelID,
			})
			
			// Send ping with write synchronization and longer timeout
			err := tc.writeJSONWithDeadline(Message{
				Type: "ping",
				TunnelID: tc.tunnelID, // Include tunnel ID to help server correlate
			}, 15*time.Second)
			if err != nil {
				tc.logError("Ping failed", err, map[string]interface{}{
					"client_id": tc.clientID,
					"error_type": fmt.Sprintf("%T", err),
				})
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

var (
	// Global client ID generated once per process
	processClientID string
	clientIDOnce    sync.Once
)

func generateClientID() string {
	clientIDOnce.Do(func() {
		// Generate unique client ID for this process instance
		// New process = new clientID = new tunnel domain  
		// Same process reconnecting = same clientID = same tunnel domain
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "unknown"
		}
		
		processID := os.Getpid()
		startTime := time.Now().UnixNano() // Process start time for uniqueness
		randomBytes := make([]byte, 8)
		cryptorand.Read(randomBytes)
		
		processClientID = fmt.Sprintf("%s-%d-%d-%x", hostname, processID, startTime, randomBytes)
	})
	
	return processClientID
}

// connectHTTP2 establishes connection using HTTP/2 streaming
func (tc *TunnelClient) connectHTTP2() error {
	tc.logInfo("Starting HTTP/2 connection", map[string]interface{}{
		"server_url": tc.config.ServerURL,
		"client_id": tc.clientID,
	})
	
	// Convert WebSocket URL to HTTP/2 URL
	serverURL := tc.config.ServerURL
	if strings.HasPrefix(serverURL, "ws://") {
		serverURL = strings.Replace(serverURL, "ws://", "http://", 1)
	} else if strings.HasPrefix(serverURL, "wss://") {
		serverURL = strings.Replace(serverURL, "wss://", "https://", 1)
	}
	
	// Replace /ws endpoint with /http2
	serverURL = strings.Replace(serverURL, "/ws", "/http2", 1)
	
	// Add client ID as query parameter
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %v", err)
	}
	
	q := u.Query()
	q.Set("client_id", tc.clientID)
	u.RawQuery = q.Encode()
	
	tc.logInfo("HTTP/2 endpoint", map[string]interface{}{
		"url": u.String(),
	})
	
	// Create context for HTTP/2 connection
	tc.http2Ctx, tc.http2Cancel = context.WithCancel(context.Background())
	defer func() {
		if tc.http2Cancel != nil {
			tc.http2Cancel()
		}
	}()
	
	// Create pipe for bidirectional communication
	pipeReader, pipeWriter := io.Pipe()
	tc.http2Writer = pipeWriter
	
	// Create HTTP/2 request with streaming body
	req, err := http.NewRequestWithContext(tc.http2Ctx, "POST", u.String(), pipeReader)
	if err != nil {
		return fmt.Errorf("failed to create HTTP/2 request: %v", err)
	}
	
	// Set headers for streaming and authentication
	req.Header.Set("Content-Type", "application/x-qtunnel-stream")
	req.Header.Set("Authorization", "Bearer "+tc.config.AuthToken)
	req.Header.Set("X-QTunnel-Protocol", "http2")
	req.Header.Set("X-QTunnel-Client-ID", tc.clientID)
	
	tc.logInfo("HTTP/2 request configured", map[string]interface{}{
		"method": req.Method,
		"headers": len(req.Header),
	})
	
	// Start HTTP/2 request in goroutine to avoid deadlock
	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)
	
	go func() {
		resp, err := tc.httpClient.Do(req)
		if err != nil {
			errChan <- fmt.Errorf("HTTP/2 request failed: %v", err)
			return
		}
		respChan <- resp
	}()
	
	// Send initial ping immediately to start communication
	err = tc.http2WriteMessage(Message{
		Type:     "ping",
		TunnelID: "", // Will be set by server
	})
	if err != nil {
		return fmt.Errorf("failed to send initial HTTP/2 ping: %v", err)
	}
	
	tc.logInfo("HTTP/2 ping sent, waiting for response", nil)
	
	// Wait for HTTP response
	var resp *http.Response
	select {
	case resp = <-respChan:
		defer resp.Body.Close()
		
		// Check response status
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("HTTP/2 connection failed with status %d: %s", resp.StatusCode, string(body))
		}
		
		tc.logInfo("HTTP/2 connection established", map[string]interface{}{
			"status": resp.StatusCode,
			"proto": resp.Proto,
		})
		
		// Create response reader
		tc.http2Reader = bufio.NewReader(resp.Body)
		
		// Output tunnel status
		tc.outputTunnelStatus("connected")
		
	case err := <-errChan:
		return err
	case <-tc.http2Ctx.Done():
		return fmt.Errorf("HTTP/2 connection timeout")
	}
	
	// Start message processing goroutines
	processErrChan := make(chan error, 2)
	
	// Start reading messages from server
	go func() {
		processErrChan <- tc.http2ReadLoop()
	}()
	
	// Start ping loop
	go func() {
		processErrChan <- tc.http2PingLoop()
	}()
	
	// Wait for error or context cancellation
	select {
	case err := <-processErrChan:
		tc.logError("HTTP/2 connection error", err, nil)
		tc.outputTunnelStatus("disconnected")
		return err
	case <-tc.http2Ctx.Done():
		tc.logInfo("HTTP/2 connection cancelled", nil)
		tc.outputTunnelStatus("disconnected")
		return tc.http2Ctx.Err()
	}
}

// http2WriteMessage sends a message through HTTP/2 streaming
func (tc *TunnelClient) http2WriteMessage(msg Message) error {
	if tc.http2Writer == nil {
		return fmt.Errorf("HTTP/2 writer not initialized")
	}

	// Serialize message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	// Send as newline-delimited JSON
	_, err = fmt.Fprintf(tc.http2Writer, "%s\n", string(data))
	if err != nil {
		return fmt.Errorf("failed to write HTTP/2 message: %v", err)
	}

	tc.logInfo("HTTP/2 message sent", map[string]interface{}{
		"message_type": msg.Type,
		"request_id": msg.RequestID,
	})

	return nil
}

// http2ReadLoop reads messages from HTTP/2 response stream
func (tc *TunnelClient) http2ReadLoop() error {
	tc.logInfo("Starting HTTP/2 read loop", nil)

	for {
		select {
		case <-tc.http2Ctx.Done():
			tc.logInfo("HTTP/2 read loop cancelled", nil)
			return tc.http2Ctx.Err()
		default:
			// Read line from HTTP/2 response stream
			line, err := tc.http2Reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					tc.logInfo("HTTP/2 stream ended", nil)
					return err
				}
				tc.logError("HTTP/2 read error", err, nil)
				return err
			}

			// Parse JSON message
			line = strings.TrimSpace(line)
			if line == "" {
				continue // Skip empty lines
			}

			var msg Message
			err = json.Unmarshal([]byte(line), &msg)
			if err != nil {
				tc.logError("Failed to parse HTTP/2 message", err, map[string]interface{}{
					"raw_message": line,
				})
				continue
			}

			tc.logInfo("Received HTTP/2 message", map[string]interface{}{
				"type": msg.Type,
				"tunnel_id": msg.TunnelID,
				"request_id": msg.RequestID,
			})

			// Handle message (reuse existing WebSocket message handling)
			err = tc.handleMessage(msg)
			if err != nil {
				tc.logError("Error handling HTTP/2 message", err, map[string]interface{}{
					"message_type": msg.Type,
					"tunnel_id": msg.TunnelID,
					"request_id": msg.RequestID,
				})
			}
		}
	}
}

// http2PingLoop sends periodic ping messages through HTTP/2
func (tc *TunnelClient) http2PingLoop() error {
	tc.logInfo("Starting HTTP/2 ping loop", map[string]interface{}{
		"interval": "25s",
	})

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tc.http2Ctx.Done():
			tc.logInfo("HTTP/2 ping loop cancelled", nil)
			return tc.http2Ctx.Err()
		case <-ticker.C:
			tc.logInfo("Sending HTTP/2 ping", map[string]interface{}{
				"client_id": tc.clientID,
				"tunnel_id": tc.tunnelID,
			})

			err := tc.http2WriteMessage(Message{
				Type:     "ping",
				TunnelID: tc.tunnelID,
			})
			if err != nil {
				tc.logError("HTTP/2 ping failed", err, map[string]interface{}{
					"client_id": tc.clientID,
				})
				return err
			}
			tc.logInfo("HTTP/2 ping sent successfully", nil)
		}
	}
}

// connectSSE establishes connection using Server-Sent Events
func (tc *TunnelClient) connectSSE() error {
	tc.logInfo("Starting SSE connection", map[string]interface{}{
		"server_url": tc.config.ServerURL,
		"client_id": tc.clientID,
	})
	
	// TODO: Implement SSE connection
	return fmt.Errorf("SSE protocol not yet implemented - falling back to next protocol")
}

// connectPolling establishes connection using HTTP polling
func (tc *TunnelClient) connectPolling() error {
	tc.logInfo("Starting HTTP polling connection", map[string]interface{}{
		"server_url": tc.config.ServerURL,
		"client_id": tc.clientID,
	})
	
	// TODO: Implement HTTP polling connection
	return fmt.Errorf("HTTP polling protocol not yet implemented - falling back to next protocol")
}

// getProtocolsToTry returns list of protocols to attempt based on config
func (tc *TunnelClient) getProtocolsToTry() []string {
	switch tc.config.Protocol {
	case "websocket":
		return []string{"websocket"}
	case "http2":
		return []string{"http2"}
	case "sse":
		return []string{"sse"}
	case "polling":
		return []string{"polling"}
	case "auto":
		if tc.config.AutoFallback {
			// Try protocols in order of preference for VPN compatibility
			return []string{"http2", "websocket", "sse", "polling"}
		} else {
			// Default to WebSocket for backward compatibility
			return []string{"websocket"}
		}
	default:
		return []string{"websocket"}
	}
}