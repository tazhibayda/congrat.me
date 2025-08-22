# ---------- Build stage ----------
FROM golang:1.23 AS build
WORKDIR /src

# 1) Модульный кэш
COPY go.mod go.sum ./
RUN go mod download

# 2) Копируем исходники
COPY . .

# 3) Вставим версию и commit в бинарь
ARG VERSION=dev
ARG REV=local
ARG BUILD_DATE
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w \
      -X main.version=${VERSION} \
      -X main.commit=${REV} \
      -X main.buildDate=${BUILD_DATE}" \
    -o /bin/auth ./cmd/server

# ---------- Runtime stage ----------
# distroless: нет shell, минимальный attack surface
FROM gcr.io/distroless/base-debian12

# Без shell → никаких RUN/apt. Всё, что нужно — в бинаре.
WORKDIR /
ENV APP_PORT=8080
EXPOSE 8080

# (опционально) зафиксировать часовой пояс:
# ENV TZ=Etc/UTC

# Копируем только бинарь
COPY --from=build /bin/auth /bin/auth

# Запуск под nonroot (есть в distroless)
USER nonroot:nonroot

# Если используешь TLS‑ключи/JWT‑ключи — МОНТИРУЙ томом:
# -v ./keys:/run/keys:ro
# ENV JWT_ACTIVE_PRIVATE_PATH=/run/keys/active.pem
# ENV JWT_NEXT_PRIVATE_PATH=/run/keys/next.pem

ENTRYPOINT ["/bin/auth"]
