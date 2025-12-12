#!/bin/bash

set -e

echo "🚀 Luser Platform 生产环境部署脚本"
echo "=================================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查是否以root用户运行
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}错误: 此脚本必须以root用户运行${NC}"
    exit 1
fi

# 函数：打印步骤
step() {
    echo -e "\n${GREEN}▶ $1${NC}"
}

# 函数：检查命令是否存在
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}错误: 未找到 $1 命令${NC}"
        echo "请安装: $2"
        exit 1
    fi
}

# 检查必要命令
step "检查系统依赖..."
check_command "docker" "Docker Engine"
check_command "docker-compose" "Docker Compose"
check_command "curl" "curl"
check_command "openssl" "OpenSSL"

# 检查Docker是否运行
if ! docker info &> /dev/null; then
    echo -e "${RED}错误: Docker未运行${NC}"
    exit 1
fi

# 加载环境变量
step "加载环境变量..."
if [[ -f .env ]]; then
    source .env
    echo "✓ 从 .env 文件加载环境变量"
else
    echo -e "${YELLOW}警告: 未找到 .env 文件，使用默认值${NC}"
fi

# 设置默认值
DB_NAME=${DB_NAME:-luser_prod}
DB_USER=${DB_USER:-luser_admin}
DB_PASSWORD=${DB_PASSWORD:-$(openssl rand -base64 32)}
REDIS_PASSWORD=${REDIS_PASSWORD:-$(openssl rand -base64 32)}
JWT_SECRET=${JWT_SECRET:-$(openssl rand -base64 64)}
ENCRYPTION_KEY=${ENCRYPTION_KEY:-$(openssl rand -base64 32)}
API_PORT=${API_PORT:-3000}
ADMIN_PORT=${ADMIN_PORT:-3001}
GRAFANA_PORT=${GRAFANA_PORT:-3002}
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}

# 创建目录
step "创建必要的目录..."
mkdir -p ./data/{postgres,redis,prometheus,grafana}
mkdir -p ./logs/{api,admin,nginx}
mkdir -p ./backup/{database,logs,configs}
mkdir -p ./

# 设置目录权限
chmod 755 ./data ./logs ./backup ./ssl
chown -R 1000:1000 ./data/grafana
chown -R 65534:65534 ./data/prometheus

# 生成SSL证书（如果不存在）
step "生成SSL证书..."
if [[ ! -f ./ssl/luser.key || ! -f ./ssl/luser.crt ]]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout ./ssl/luser.key \
        -out ./ssl/luser.crt \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=luser/CN=luser.example.com"
    echo "✓ SSL证书已生成"
else
    echo "✓ 使用现有的SSL证书"
fi

# 创建生产环境配置文件
step "创建生产环境配置文件..."
cat > .env.production << EOF
# Luser Platform 生产环境配置
# =============================

# 数据库配置
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}

# Redis配置
REDIS_PASSWORD=${REDIS_PASSWORD}

# JWT配置
JWT_SECRET=${JWT_SECRET}
JWT_EXPIRATION_HOURS=24
JWT_REFRESH_EXPIRATION_DAYS=30

# 加密配置
ENCRYPTION_KEY=${ENCRYPTION_KEY}

# 服务器配置
API_HOST=0.0.0.0
API_PORT=${API_PORT}
ADMIN_API_PORT=${ADMIN_PORT}
RUN_MODE=production

# 腾讯云VOD配置（可选）
TENCENT_VOD_SECRET_ID=${TENCENT_VOD_SECRET_ID:-}
TENCENT_VOD_SECRET_KEY=${TENCENT_VOD_SECRET_KEY:-}
TENCENT_VOD_REGION=${TENCENT_VOD_REGION:-ap-guangzhou}

# 阿里云VOD配置（可选）
ALIYUN_VOD_ACCESS_KEY_ID=${ALIYUN_VOD_ACCESS_KEY_ID:-}
ALIYUN_VOD_ACCESS_KEY_SECRET=${ALIYUN_VOD_ACCESS_KEY_SECRET:-}
ALIYUN_VOD_REGION=${ALIYUN_VOD_REGION:-cn-shanghai}

# 支付宝配置（可选）
ALIPAY_APP_ID=${ALIPAY_APP_ID:-}
ALIPAY_PRIVATE_KEY=${ALIPAY_PRIVATE_KEY:-}
ALIPAY_PUBLIC_KEY=${ALIPAY_PUBLIC_KEY:-}
ALIPAY_NOTIFY_URL=${ALIPAY_NOTIFY_URL:-}

# 微信支付配置（可选）
WECHATPAY_MCH_ID=${WECHATPAY_MCH_ID:-}
WECHATPAY_API_KEY=${WECHATPAY_API_KEY:-}
WECHATPAY_CERT_SERIAL_NO=${WECHATPAY_CERT_SERIAL_NO:-}
WECHATPAY_PRIVATE_KEY=${WECHATPAY_PRIVATE_KEY:-}

# 监控配置
PROMETHEUS_PORT=${PROMETHEUS_PORT}
GRAFANA_PORT=${GRAFANA_PORT}

# 时区
TZ=Asia/Shanghai
EOF

echo "✓ 生产环境配置文件已创建"

# 创建Nginx配置文件
step "配置Nginx..."
cat > nginx/nginx.conf << 'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # 日志格式
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    '$request_time $upstream_response_time';

    access_log /var/log/nginx/access.log main;

    # 基础配置
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    # Gzip压缩
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/atom+xml image/svg+xml;

    # 上传限制
    client_max_body_size 2G;
    client_body_buffer_size 128k;
    client_body_timeout 300s;
    client_header_timeout 300s;

    # 代理设置
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 300s;
    proxy_connect_timeout 75s;
    proxy_send_timeout 300s;
    proxy_buffer_size 128k;
    proxy_buffers 4 256k;
    proxy_busy_buffers_size 256k;

    # 包含服务器配置
    include /etc/nginx/conf.d/*.conf;
}
EOF

cat > nginx/conf.d/api.conf << EOF
# API服务器配置
upstream luser_api {
    least_conn;
    server luser-api:3000 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

server {
    listen 80;
    server_name api.luser.example.com;
    
    # 重定向到HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.luser.example.com;

    # SSL配置
    ssl_certificate /etc/nginx/ssl/luser.crt;
    ssl_certificate_key /etc/nginx/ssl/luser.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # 安全头
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # API路由
    location / {
        proxy_pass http://luser_api;
        
        # WebSocket支持
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # CORS头
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods 'GET, POST, PUT, DELETE, OPTIONS';
        add_header Access-Control-Allow-Headers 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
        add_header Access-Control-Expose-Headers 'Content-Length,Content-Range';
        
        if (\$request_method = 'OPTIONS') {
            add_header Access-Control-Allow-Origin *;
            add_header Access-Control-Allow-Methods 'GET, POST, PUT, DELETE, OPTIONS';
            add_header Access-Control-Allow-Headers 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
            add_header Access-Control-Max-Age 1728000;
            add_header Content-Type 'text/plain; charset=utf-8';
            add_header Content-Length 0;
            return 204;
        }
    }

    # 健康检查
    location /health {
        access_log off;
        proxy_pass http://luser_api/health;
    }

    # API文档
    location /docs {
        proxy_pass http://luser_api/docs;
    }

    # 错误页面
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}
EOF

cat > nginx/conf.d/admin.conf << EOF
# 管理后台配置
upstream luser_admin {
    least_conn;
    server luser-admin:3001 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

server {
    listen 80;
    server_name admin.luser.example.com;
    
    # 重定向到HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name admin.luser.example.com;

    # SSL配置
    ssl_certificate /etc/nginx/ssl/luser.crt;
    ssl_certificate_key /etc/nginx/ssl/luser.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # 安全头
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;";

    # 管理后台路由
    location / {
        proxy_pass http://luser_admin;
        
        # IP限制（仅允许内网访问）
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
        
        # 认证头
        proxy_set_header X-Admin-Access true;
    }

    # 健康检查
    location /health {
        access_log off;
        proxy_pass http://luser_admin/health;
        
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
    }

    # 错误页面
    error_page 403 /403.html;
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    
    location = /403.html {
        root /usr/share/nginx/html;
        internal;
    }
    
    location = /404.html {
        root /usr/share/nginx/html;
        internal;
    }
    
    location = /50x.html {
        root /usr/share/nginx/html;
        internal;
    }
}
EOF

echo "✓ Nginx配置完成"

# 创建Prometheus配置
step "配置Prometheus监控..."
cat > prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  scrape_timeout: 10s

rule_files:
  - "alert.rules"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          # - alertmanager:9093

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: /metrics

  - job_name: 'luser-api'
    static_configs:
      - targets: ['luser-api:3000']
    metrics_path: /metrics
    scrape_interval: 10s

  - job_name: 'luser-admin'
    static_configs:
      - targets: ['luser-admin:3001']
    metrics_path: /metrics
    scrape_interval: 10s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
    scrape_interval: 15s

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']
    scrape_interval: 15s

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis-exporter:9121']
    scrape_interval: 15s
EOF

echo "✓ Prometheus配置完成"

# 创建Grafana配置
step "配置Grafana仪表板..."
mkdir -p grafana/provisioning/{dashboards,datasources}

cat > grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
    jsonData:
      timeInterval: 15s
EOF

cat > grafana/provisioning/dashboards/dashboards.yml << EOF
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

echo "✓ Grafana配置完成"

# 创建备份脚本
step "创建数据库备份脚本..."
cat > scripts/backup-database.sh << 'EOF'
#!/bin/bash

set -e

# 配置
BACKUP_DIR="/app/backup/database"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份数据库
echo "备份数据库..."
docker exec luser-postgres pg_dump -U luser_admin luser_prod | gzip > $BACKUP_DIR/luser_db_$DATE.sql.gz

# 备份Redis
echo "备份Redis..."
docker exec luser-redis redis-cli -a $REDIS_PASSWORD --rdb /data/dump.rdb
docker cp luser-redis:/data/dump.rdb $BACKUP_DIR/redis_$DATE.rdb
docker exec luser-redis rm /data/dump.rdb

# 清理旧备份
echo "清理旧备份..."
find $BACKUP_DIR -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.rdb" -mtime +$RETENTION_DAYS -delete

echo "备份完成: $BACKUP_DIR/luser_db_$DATE.sql.gz"
EOF

chmod +x scripts/backup-database.sh

# 创建监控脚本
step "创建服务监控脚本..."
cat > scripts/monitor-services.sh << 'EOF'
#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 检查服务状态
check_service() {
    local service=$1
    local port=$2
    
    if curl -s -f http://localhost:$port/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ $service 运行正常${NC}"
        return 0
    else
        echo -e "${RED}✗ $service 服务异常${NC}"
        return 1
    fi
}

# 检查磁盘空间
check_disk_space() {
    local usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
    
    if [ $usage -lt 80 ]; then
        echo -e "${GREEN}✓ 磁盘空间充足: $usage%${NC}"
    elif [ $usage -lt 90 ]; then
        echo -e "${YELLOW}⚠ 磁盘空间警告: $usage%${NC}"
    else
        echo -e "${RED}✗ 磁盘空间严重不足: $usage%${NC}"
    fi
}

# 检查内存使用
check_memory() {
    local total=$(free -m | awk 'NR==2 {print $2}')
    local used=$(free -m | awk 'NR==2 {print $3}')
    local percentage=$((used * 100 / total))
    
    if [ $percentage -lt 70 ]; then
        echo -e "${GREEN}✓ 内存使用正常: $percentage%${NC}"
    elif [ $percentage -lt 85 ]; then
        echo -e "${YELLOW}⚠ 内存使用较高: $percentage%${NC}"
    else
        echo -e "${RED}✗ 内存使用过高: $percentage%${NC}"
    fi
}

# 检查容器状态
check_containers() {
    echo "检查容器状态..."
    
    if docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "(luser-|postgres|redis|prometheus|grafana)"; then
        echo -e "${GREEN}✓ 所有容器运行正常${NC}"
    else
        echo -e "${RED}✗ 有容器异常${NC}"
    fi
}

# 主函数
main() {
    echo "luser Platform 服务监控"
    echo "========================"
    
    # 检查服务
    check_service "API服务" 3000
    check_service "管理后台" 3001
    check_service "Prometheus" 9090
    check_service "Grafana" 3002
    
    # 检查系统资源
    echo -e "\n系统资源状态:"
    check_disk_space
    check_memory
    
    # 检查容器
    echo -e "\n容器状态:"
    check_containers
    
    # 检查日志错误
    echo -e "\n日志错误检查:"
    for log in ./logs/api/*.log ./logs/admin/*.log; do
        if [ -f "$log" ]; then
            errors=$(tail -100 "$log" | grep -i "error\|exception\|failed" | wc -l)
            if [ $errors -gt 0 ]; then
                echo -e "${YELLOW}⚠ $log 中有 $errors 个错误${NC}"
            fi
        fi
    done
}

main
EOF

chmod +x scripts/monitor-services.sh

# 启动服务
step "启动luser Platform服务..."
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d

# 等待服务启动
step "等待服务启动..."
sleep 30

# 检查服务状态
step "检查服务状态..."
if curl -s -f http://localhost:$API_PORT/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ API服务启动成功${NC}"
else
    echo -e "${RED}✗ API服务启动失败${NC}"
    docker-compose -f docker-compose.prod.yml logs luser-api
    exit 1
fi

if curl -s -f http://localhost:$ADMIN_PORT/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 管理后台启动成功${NC}"
else
    echo -e "${RED}✗ 管理后台启动失败${NC}"
    docker-compose -f docker-compose.prod.yml logs luser-admin
    exit 1
fi

# 显示部署信息
step "部署完成!"
echo -e "\n${GREEN}✅ luser Platform 已成功部署!${NC}"
echo -e "\n访问地址:"
echo -e "  API服务:      https://api.luser.example.com (端口: $API_PORT)"
echo -e "  管理后台:     https://admin.luser.example.com (端口: $ADMIN_PORT)"
echo -e "  Grafana监控:  http://localhost:$GRAFANA_PORT (用户名: admin, 密码: admin)"
echo -e "  Prometheus:   http://localhost:$PROMETHEUS_PORT"
echo -e "\n管理脚本:"
echo -e "  监控服务:     ./scripts/monitor-services.sh"
echo -e "  备份数据库:   ./scripts/backup-database.sh"
echo -e "  查看日志:     docker-compose -f docker-compose.prod.yml logs -f"
echo -e "  停止服务:     docker-compose -f docker-compose.prod.yml down"
echo -e "  重启服务:     docker-compose -f docker-compose.prod.yml restart"
echo -e "\n重要提示:"
echo -e "  1. 请立即修改默认密码!"
echo -e "  2. 配置正确的域名和SSL证书"
echo -e "  3. 定期备份数据库"
echo -e "  4. 监控系统资源和日志"
echo -e "\n默认管理员账户:"
echo -e "  用户名: admin"
echo -e "  密码: Admin123!@# (首次登录后请立即修改)"