# Сборка
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Копируем go.mod и go.sum
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем сервер
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o qtunnel-server ./server

# Собираем клиент
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o qtunnel-client ./client

# Финальный образ
FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Копируем бинарники
COPY --from=builder /app/qtunnel-server .
COPY --from=builder /app/qtunnel-client .

# Создаем директорию для Traefik конфигов
RUN mkdir -p /etc/traefik/dynamic

# Открываем порты
EXPOSE 8080 8081

# Запускаем сервер
CMD ["./qtunnel-server"]