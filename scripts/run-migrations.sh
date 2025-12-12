#!/bin/bash

set -e

echo "运行数据库迁移..."

# 加载环境变量
if [[ -f .env ]]; then
    source .env
else
    echo "错误: 未找到 .env 文件"
    exit 1
fi

# 运行迁移
cd crates/luser-db

# 使用SQLx CLI运行迁移
if command -v sqlx &> /dev/null; then
    sqlx database create
    sqlx migrate run
else
    # 使用cargo运行
    cargo run --package luser-db -- migrate
fi

echo "数据库迁移完成!"