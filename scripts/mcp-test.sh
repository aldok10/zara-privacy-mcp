#!/bin/sh
# Test wrapper — uses docker-compose services
export ZARA_ENCRYPTION_KEY="test-key-32-bytes-long-for-dev!!"

# PostgreSQL (docker-compose)
export ZARA_DB_POSTGRES_DRIVER=postgres
export ZARA_DB_POSTGRES_DSN="postgres://zara:zara_secret@127.0.0.1:5432/testdb?sslmode=disable"

# MySQL (docker-compose)
export ZARA_DB_MYSQL_DRIVER=mysql
export ZARA_DB_MYSQL_DSN="zara:zara_secret@tcp(127.0.0.1:3306)/testdb?charset=utf8mb4"

# Redis (docker-compose)
export ZARA_REDIS_LOCAL_ADDR="127.0.0.1:6379"
export ZARA_REDIS_LOCAL_PASSWORD="zara_secret"
export ZARA_REDIS_LOCAL_DB=0

# MongoDB (docker-compose)
export ZARA_MONGO_LOCAL_URI="mongodb://zara:zara_secret@127.0.0.1:27017"
export ZARA_MONGO_LOCAL_DATABASE="testdb"

exec "$(dirname "$0")/../zara-privacy-mcp" --stdio
