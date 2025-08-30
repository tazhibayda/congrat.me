# --- build stage ---
FROM golang:1.23 AS builder
WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o server ./cmd/server

# --- run stage ---
FROM alpine:3.19
WORKDIR /app
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/server .
CMD ["./server"]
