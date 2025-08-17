# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o qtunnel-server ./server

# Build client
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o qtunnel-client ./client

# Final image
FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Copy binaries
COPY --from=builder /app/qtunnel-server .
COPY --from=builder /app/qtunnel-client .

# Create directory for Traefik configurations
RUN mkdir -p /etc/traefik/dynamic

# Expose ports
EXPOSE 8080 8081

# Start server
CMD ["./qtunnel-server"]