# --- build stage ---
FROM golang:1.23 AS builder
WORKDIR /app

# установим git (для go mod), ca-certificates
RUN apk add --no-cache git ca-certificates

# копируем go.mod/go.sum и качаем зависимости
COPY go.mod go.sum ./
RUN go mod download

# копируем весь код и собираем бинарник
COPY . .
RUN go build -o server ./cmd/server

# --- run stage ---
FROM alpine:3.19
WORKDIR /app
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/server .
EXPOSE 8081

CMD ["./server"]
