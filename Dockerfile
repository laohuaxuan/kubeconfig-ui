########################
# Frontend build stage #
########################
FROM acr-openxlab-prod-registry-vpc.cn-shanghai.cr.aliyuncs.com/public/node:18.20 AS frontend-builder

WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --registry=https://registry.npmmirror.com
COPY frontend/ ./
RUN npm run build

#######################
# Backend build stage #
#######################
FROM acr-openxlab-prod-registry-vpc.cn-shanghai.cr.aliyuncs.com/public/golang:1.23-alpine AS backend-builder

WORKDIR /src
# COPY go.mod go.sum ./
# RUN go mod download
# COPY cmd/ ./cmd/
# COPY internal/ ./internal/
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct && go build -o /out/kubeconfig-ui ./cmd/server

#################
# Runtime stage #
#################
FROM acr-openxlab-prod-registry-vpc.cn-shanghai.cr.aliyuncs.com/public/nginx:1.27-alpine

WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY --from=backend-builder /out/kubeconfig-ui /app/kubeconfig-ui
COPY --from=frontend-builder /src/frontend/dist /usr/share/nginx/html
COPY deploy/nginx/nginx.conf /etc/nginx/nginx.conf
COPY deploy/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY docker/start.sh /start.sh && chmod +x /start.sh

EXPOSE 8080
ENV TZ=Asia/Shanghai
ENTRYPOINT ["/start.sh"]
