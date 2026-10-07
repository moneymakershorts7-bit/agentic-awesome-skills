#!/bin/bash
# sec-userspace 环境初始化脚本
# 用法: bash scripts/setup.sh [--workspace DIR] [--help]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_ROOT="$(dirname "$SCRIPT_DIR")"
WORKSPACE="${WORKSPACE:-/data/sec-userspace/workspace}"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=11

# === 日志函数 ===
log_info()  { echo "[INFO] $*" >&2; }
log_ok()    { echo "[OK] $*"; }
log_warn()  { echo "[WARN] $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

# === 参数解析 ===
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --workspace)
                shift
                WORKSPACE="${1:?'--workspace 需要指定目录'}"
                ;;
            --help|-h)
                echo "用法: bash scripts/setup.sh [选项]"
                echo ""
                echo "选项:"
                echo "  --workspace DIR   指定工作目录 (默认: /data/sec-userspace/workspace)"
                echo "  --help, -h        显示帮助信息"
                echo ""
                echo "环境变量:"
                echo "  WORKSPACE         工作目录路径 (等同 --workspace)"
                echo ""
                echo "说明:"
                echo "  自动检测/安装 Python >= 3.11，创建虚拟环境"
                echo "  仅支持 x86_64 架构"
                exit 0
                ;;
            *)
                log_error "未知参数: $1"
                exit 1
                ;;
        esac
        shift
    done
}

# === 架构检测 ===
check_arch() {
    local arch
    arch="$(uname -m)"
    if [ "$arch" != "x86_64" ]; then
        log_error "当前仅支持 x86_64 架构，检测到: $arch"
        log_error "如需其他架构支持，请联系开发团队"
        exit 1
    fi
    log_info "架构检测通过: $arch"
}

# === Python 查找 ===
find_python() {
    # 1. 检查系统 Python >= 3.11
    local cmd ver major minor
    for cmd in python3.11 python3.12 python3.13 python3; do
        if command -v "$cmd" &>/dev/null; then
            ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null) || continue
            major="${ver%%.*}"
            minor="${ver#*.}"
            if [ "$major" -ge "$PYTHON_MIN_MAJOR" ] && [ "$minor" -ge "$PYTHON_MIN_MINOR" ]; then
                log_info "找到系统 Python: $cmd ($ver)"
                echo "$cmd"
                return 0
            fi
        fi
    done

    # 2. 检查 workspace 中已安装的 standalone Python
    if [ -x "$WORKSPACE/python/bin/python3" ]; then
        ver=$("$WORKSPACE/python/bin/python3" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null) || true
        log_info "找到 workspace Python: $WORKSPACE/python/bin/python3 ($ver)"
        echo "$WORKSPACE/python/bin/python3"
        return 0
    fi

    return 1
}

# === 下载安装 Python ===
install_python() {
    local install_dir="$WORKSPACE/python"
    local python_url="https://github.com/indygreg/python-build-standalone/releases/download/20241206/cpython-3.11.11+20241206-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
    local python_pkg="$WORKSPACE/python-3.11-linux-x86_64.tar.gz"

    # 如果已经安装过，跳过
    if [ -x "$install_dir/bin/python3" ]; then
        log_info "Python 已安装: $("$install_dir/bin/python3" --version 2>&1)"
        return 0
    fi

    log_info "下载 Python 3.11 standalone..."
    log_info "URL: $python_url"
    log_info "安装目录: $install_dir"

    # 下载（优先 curl，备选 wget）
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$python_pkg" "$python_url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$python_pkg" "$python_url"
    else
        log_error "未找到 curl 或 wget，无法下载 Python"
        log_error "请手动安装 Python >= 3.11 或手动下载: $python_url"
        return 1
    fi

    if [ ! -f "$python_pkg" ]; then
        log_error "Python 下载失败"
        return 1
    fi

    mkdir -p "$install_dir"
    tar xzf "$python_pkg" -C "$install_dir" --strip-components=1

    # 清理下载文件
    rm -f "$python_pkg"

    if [ -x "$install_dir/bin/python3" ]; then
        log_ok "Python 安装成功: $("$install_dir/bin/python3" --version 2>&1)"
        return 0
    fi

    log_error "Python 安装失败: $install_dir/bin/python3 不可执行"
    return 1
}

# === 创建虚拟环境 ===
setup_venv() {
    local python_bin="$1"
    local venv_dir="$WORKSPACE/.venv"

    # 如果 venv 已存在，检查 Python 版本是否一致
    if [ -d "$venv_dir" ]; then
        local existing_python="$venv_dir/bin/python3"
        if [ -x "$existing_python" ]; then
            local existing_ver new_ver
            existing_ver=$("$existing_python" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>/dev/null) || existing_ver="unknown"
            new_ver=$("$python_bin" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>/dev/null) || new_ver="unknown"
            if [ "$existing_ver" = "$new_ver" ]; then
                log_info "虚拟环境已存在且版本一致 ($existing_ver)，跳过创建"
                inject_thirdparties "$python_bin" "$venv_dir"
                return 0
            fi
            log_warn "虚拟环境 Python 版本不一致 ($existing_ver vs $new_ver)，重新创建"
            rm -rf "$venv_dir"
        fi
    fi

    log_info "创建虚拟环境: $venv_dir"
    "$python_bin" -m venv "$venv_dir"

    if [ ! -x "$venv_dir/bin/python3" ]; then
        log_error "虚拟环境创建失败"
        return 1
    fi

    # 注入 PYTHONPYCACHEPREFIX 到 venv activate 脚本
    echo "export PYTHONPYCACHEPREFIX=\"$WORKSPACE/.pycache\"" >> "$venv_dir/bin/activate"
    log_info "PYTHONPYCACHEPREFIX 已注入到 venv activate 脚本"

    inject_thirdparties "$python_bin" "$venv_dir"
    log_ok "虚拟环境创建成功: $venv_dir"
}

# === 注入 thirdparties 路径 ===
inject_thirdparties() {
    local python_bin="$1"
    local venv_dir="$2"
    local thirdparties_dir="$SKILL_ROOT/scripts/thirdparties"

    if [ ! -d "$thirdparties_dir" ]; then
        log_warn "thirdparties 目录不存在: $thirdparties_dir，跳过路径注入"
        return 0
    fi

    # 获取 site-packages 路径
    local site_packages
    site_packages=$("$venv_dir/bin/python3" -c "import site; print(site.getsitepackages()[0])" 2>/dev/null)

    if [ -n "$site_packages" ] && [ -d "$site_packages" ]; then
        echo "$thirdparties_dir" > "$site_packages/sec-userspace-thirdparties.pth"
        log_info "thirdparties 路径已注入: $thirdparties_dir"
    else
        log_warn "无法获取 site-packages 路径，thirdparties 注入跳过"
    fi
}

# === 初始化 workspace ===
init_workspace() {
    log_info "初始化工作目录: $WORKSPACE"
    mkdir -p "$WORKSPACE"
    mkdir -p "$WORKSPACE/logs"
    mkdir -p "$WORKSPACE/.pycache"

    # 设置 __pycache__ 重定向到 workspace，避免污染源码目录
    export PYTHONPYCACHEPREFIX="$WORKSPACE/.pycache"
    log_info "__pycache__ 重定向到: $WORKSPACE/.pycache"
}

# === 同步默认白名单 ===
sync_default_whitelist() {
    local assets_whitelist="$SKILL_ROOT/assets/whitelist"
    local assets_ioc="$SKILL_ROOT/assets/ioc"
    local origin_whitelist="$SKILL_ROOT/assets-origin/whitelist"
    local origin_ioc="$SKILL_ROOT/assets-origin/ioc"

    # 同步白名单（仅当 assets/whitelist/ 为空时）
    if [ ! -f "$assets_whitelist/manifest.json" ]; then
        log_info "从 assets-origin 部署默认白名单..."
        mkdir -p "$assets_whitelist"
        if [ -d "$origin_whitelist" ]; then
            cp -r "$origin_whitelist/"* "$assets_whitelist/"
            log_ok "默认白名单已部署: $assets_whitelist"
        else
            log_warn "未找到 assets-origin/whitelist/，白名单将为空"
        fi
    fi

    # 同步 IoC 数据（仅当 assets/ioc/ 为空时）
    if [ ! -f "$assets_ioc/manifest.json" ]; then
        log_info "从 assets-origin 部署默认 IoC 数据..."
        mkdir -p "$assets_ioc"
        if [ -d "$origin_ioc" ]; then
            cp -r "$origin_ioc/"* "$assets_ioc/"
            log_ok "默认 IoC 数据已部署: $assets_ioc"
        fi
    fi
}

# === 主流程 ===
main() {
    parse_args "$@"

    log_info "sec-userspace 环境初始化开始"
    log_info "SKILL_ROOT: $SKILL_ROOT"
    log_info "WORKSPACE: $WORKSPACE"

    check_arch
    init_workspace
    sync_default_whitelist

    local python_bin
    python_bin=$(find_python) || true

    if [ -z "$python_bin" ]; then
        log_info "系统未找到 Python >= ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}，从网络下载安装..."
        install_python
        python_bin="$WORKSPACE/python/bin/python3"
    fi

    setup_venv "$python_bin"

    log_ok "sec-userspace 环境初始化完成"
    log_ok "Python: $python_bin"
    log_ok "Workspace: $WORKSPACE"
    log_ok "虚拟环境: $WORKSPACE/.venv"
    log_info "激活虚拟环境: source $WORKSPACE/.venv/bin/activate"
}

main "$@"
