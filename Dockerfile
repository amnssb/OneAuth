# 编译阶段
FROM golang:1.22-alpine AS builder

WORKDIR /build
RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /bin/oneauth ./cmd/server/

# 运行阶段
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app

COPY --from=builder /bin/oneauth /app/oneauth

VOLUME ["/data"]
EXPOSE 9000

ENV TZ=Asia/Shanghai
ENV PORT=9000
ENV DB_PATH=/data/oneauth.db
ENV KEY_PATH=/data/oneauth_rsa.pem

ENTRYPOINT ["/app/oneauth"]
