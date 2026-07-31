FROM golang:1.26.5-alpine3.23 AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/auth-cli ./cmd/auth-cli

FROM alpine:3.23.5

WORKDIR /app
COPY --from=build /out/auth-cli /usr/local/bin/auth-cli
RUN adduser -D -H -u 10001 appuser && mkdir -p /data && chown -R appuser:appuser /data
USER appuser

ENV DB_PATH=/data/auth.db
ENV SESSION_TIMEOUT=30m
ENV MAX_FAILED_ATTEMPTS=5
ENV LOCKOUT_DURATION=15m

VOLUME ["/data"]
ENTRYPOINT ["auth-cli"]
