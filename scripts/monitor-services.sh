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