# syntax=docker/dockerfile:1
# 与仓库根目录 Dockerfile 保持一致；推荐在项目根目录构建：
#   docker build -t kubeconfig-ui:latest .

FROM node:20-alpine AS frontend-builder
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --registry=https://registry.npmmirror.com
COPY frontend/ ./
RUN npm run build

FROM golang:1.22-alpine AS backend-builder
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /out/kubeconfig-ui ./cmd/server

FROM alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata \
  && adduser -D -H -u 10001 appuser
COPY --from=backend-builder /out/kubeconfig-ui /app/kubeconfig-ui
COPY --from=frontend-builder /src/frontend/dist /app/frontend/dist
COPY config.example.yaml /app/config.yaml
USER 10001
EXPOSE 8080
ENV CONFIG_FILE=/app/config.yaml
ENV TZ=Asia/Shanghai
ENTRYPOINT ["/app/kubeconfig-ui"]
