# Python Runtime Usage Guide | Python 运行时使用指南

## 问题现象

当执行 `python3 scripts/main.pyz` 出现以下错误时：
```
ImportError: bad magic number in 'scripts': b'\xa7\r\r\n'
zipimport.ZipImportError: module load failed: bad magic number
```

**说明系统 Python 版本与 pyz 编译版本不兼容（pyz 需要 Python 3.11）。**

## 解决方案

```bash
# 1. 下载 Python 3.11 standalone (~30MB)
PYTHON_URL="https://github.com/indygreg/python-build-standalone/releases/download/20241206/cpython-3.11.11+20241206-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"

# 2. 解压到 workspace/python311/（如果不存在）
if [ ! -x workspace/python311/bin/python3 ]; then
    mkdir -p workspace/python311
    curl -fsSL -o /tmp/python311.tar.gz "$PYTHON_URL"
    tar -xzf /tmp/python311.tar.gz -C workspace/python311 --strip-components=1
    rm -f /tmp/python311.tar.gz
fi

# 3. 验证版本
workspace/python311/bin/python3 --version  # Python 3.11.11

# 4. 使用下载的 Python 运行扫描
sudo workspace/python311/bin/python3 scripts/main.pyz --output-dir workspace
```

## 备选方案

直接使用 plain 模式（源码版），无版本兼容性问题：

```bash
cd /data/sec-userspace && sudo python3 -m scripts.main --output-dir /data/sec-userspace/workspace
```

## AI Agent Checklist

- [ ] 首先尝试 `python3 scripts/main.pyz`
- [ ] 出现 "bad magic number" → 下载 Python 3.11 或改用 plain 模式
- [ ] 解压到 `workspace/python311/`
- [ ] 使用 `workspace/python311/bin/python3` 重新运行
- [ ] 如果下载失败（无网络），改用 `python3 -m scripts.main` plain 模式
