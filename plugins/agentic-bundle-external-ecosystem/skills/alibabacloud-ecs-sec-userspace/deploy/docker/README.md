# Docker 部署

使用 Docker 容器化运行 sec-userspace。

## 构建镜像

```bash
cd /path/to/sec-userspace
docker build -t sec-userspace:latest -f deploy/docker/Dockerfile .
```

## 运行扫描

```bash
# 查看帮助
docker run --rm sec-userspace:latest --help

# 执行扫描（挂载主机信息）
docker run --rm \
  --pid=host \
  --network=host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -v /etc:/host/etc:ro \
  -v /var/log:/host/var/log:ro \
  -v $(pwd)/output:/data/sec-userspace/workspace \
  sec-userspace:latest --output /data/sec-userspace/workspace
```

## 使用 docker-compose

```bash
cd deploy/docker
docker-compose up
```

## 说明

- 基于 `python:3.12-slim`，零 pip install
- 使用非 root 用户运行
- 只读文件系统，最小权限
- 需要 `--pid=host` 以检测宿主机进程
