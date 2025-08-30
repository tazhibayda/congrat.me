# --- builder ---
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src

# кеш зависимостей
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# сборка
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /out/congrats ./cmd/server

# --- runtime ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /out/congrats /usr/local/bin/congrats
EXPOSE 8081
ENTRYPOINT ["congrats"]
