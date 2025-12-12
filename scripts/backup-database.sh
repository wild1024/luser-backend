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