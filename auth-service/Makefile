IMAGE ?= auth-service
TAG   ?= $(shell git rev-parse --short HEAD)

build:
	docker build \
	  --build-arg VERSION=$(TAG) \
	  --build-arg REV=$(TAG) \
	  --build-arg BUILD_DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
	  -t $(IMAGE):$(TAG) .

run:
	docker run --rm -p 8080:8080 \
	  -e APP_PORT=8080 \
	  -e MONGO_URI="mongodb://host.docker.internal:27017" \
	  -e MONGO_DB="auth_db" \
	  -e REDIS_ADDR="host.docker.internal:6379" \
	  -e RABBIT_URL="amqp://guest:guest@host.docker.internal:5672/" \
	  -e JWT_ACTIVE_KID="kid-dev-A" \
	  -e JWT_ACTIVE_PRIVATE_PATH="/run/keys/active.pem" \
	  -e JWT_NEXT_KID="kid-dev-N" \
	  -e JWT_NEXT_PRIVATE_PATH="/run/keys/next.pem" \
	  -v $(PWD)/keys:/run/keys:ro \
	  --name auth $(IMAGE):$(TAG)

compose:
	docker compose up --build
