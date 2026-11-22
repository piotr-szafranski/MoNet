# Obraz produkcyjny MoNet: frontend (Vite) + backend (Go, statyczna binarka) + nmap.
FROM node:20-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/api/webdist ./internal/api/webdist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/asi ./cmd/asi

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/asi /usr/local/bin/asi
ENV ASI_DATA=/data ASI_ADDR=:8080 TZ=Europe/Warsaw
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/asi", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/asi"]
