# Standalone 部署

直接在目标服务器上运行 sec-userspace，无需容器或服务管理。

## 前置要求

- Python 3.11+（仅标准库，无需 pip install）
- Linux 操作系统

## 使用方法

```bash
# 复制项目到目标服务器
scp -r sec-userspace/ target:/data/sec-userspace/

# 执行扫描
cd /data/sec-userspace
bash deploy/standalone/run.sh

# 静默模式（适合脚本调用）
bash deploy/standalone/run.sh --quiet

# 指定输出目录
bash deploy/standalone/run.sh --output /tmp/sec-report
```

## 说明

- 零外部依赖，开箱即用
- 脚本会自动检查 Python 版本
- 所有参数透传给 `python3 -m scripts.main`
