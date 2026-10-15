# sec-kernel Changelog

## v1.4.0 (2026-05-12)

### Major Changes
- **85 CVE PoC Rewrite with CTF Framework**: Complete refactoring of all 85 CVE PoCs
  - Standardized CTF challenge mode (ELF disguise + temporary landing execution)
  - Three-phase verification: Prepare → Run → Post for all PoCs
  - Unified C PoC output protocol: [VULN]/[SAFE]/[ERROR]
  - CTF flag evidence integrated into report output
  - All PoC binaries rebuilt with consistent build pipeline

### Improvements
- Reporter: CTF flag evidence now included in console and generated reports
- Detector: All detectors aligned with BaseDetector interface
- Post handlers: Complete system state restoration after PoC execution

---

## v1.3.0 (2026-05-11)

### Major Changes
- **DirtyFrag PoC 双变体 Fallback**: 集成 ESP+RxRPC 双变体自动切换机制
  - RxRPC/rxkad 优先（无需 namespace，轻量级）
  - ESP/xfrm 自动 fallback（WSL2 等无 AF_RXRPC 模块的环境）
  - 两种变体在 fork 隔离中执行，互不干扰
  - WSL2 (ESP) 和 Ubuntu 24.04 (RxRPC) 均验证 EXPLOITABLE

### Improvements
- **打包逻辑优化**: 打包前自动清理旧的同名 zip 文件，防止 out/ 目录累积
- **SKILL.md CTF 证据**: 新增 CTF 提权验证证据章节，展示 EXPLOITABLE CVE 的完整三阶段证据链
- **检测器统计修正**: write_root_file 81 个、read_root_file 22 个、uaf 5 个
- **Prepare handler 更新**: DirtyFrag prepare 支持双变体兼容的加密初始化

### Verification
- WSL2 (6.6.87.2-microsoft-standard-WSL2): EXPLOITABLE via ESP, ctf{...} verified
- Remote (6.8.0-107-generic): EXPLOITABLE via RxRPC, ctf{...} verified
- 全量 85 检测器在远程执行零失败 (85/85 SUCCESS)
- Plain 模式打包验证通过

## v1.2.0 (2026-05-09)

### Major Changes
- **真实漏洞触发逻辑实现**: 53 个 PoC 从模板升级为真实漏洞触发代码
  - 之前 48 个 PoC 只有路径验证框架（TODO 占位符）
  - 现在所有 85 个 PoC 都有实际的漏洞利用代码

### Vulnerability Trigger Implementation
- **Use-After-Free (29 个)**:
  - nf_tables UAF: CVE-2023-3390/4004/4147/6817, CVE-2024-1085/1086/26808/26925/27397/39503
  - AF_UNIX UAF: CVE-2023-4622, CVE-2024-36972
  - TLS UAF: CVE-2024-26582/26585, CVE-2025-39946
  - io_uring UAF: CVE-2024-0582, CVE-2025-21836/40364
  - Generic UAF: CVE-2024-0193/41010, CVE-2025-21700/21701/21756/37752/38001/38083/38477/38500
  - inet_csk UAF: CVE-2023-0461（手动编写）

- **其他漏洞类型 (24 个)**:
  - BPF verifier: CVE-2023-2163, CVE-2024-41009/49861/50164
  - Out-of-bounds: CVE-2023-6931, CVE-2024-26581/53125/53197/57947, CVE-2025-38502/40019
  - Integer overflow: CVE-2024-53141
  - Race condition: CVE-2025-38616
  - Other: CVE-2023-0386, CVE-2024-26642/26809/26824/53164/58239/58240,
            CVE-2025-21702/37756/38350/39682/39965

### Statistics
- C 代码行数: ~18,000 行新增漏洞触发代码
- 总代码行数: ~59,000 行 (+44%)
- 漏洞触发函数: 5 种模板（nf_tables/AF_UNIX/TLS/io_uring/generic）

### Verification
- ✅ 全部 85 个 PoC 二进制静态编译成功
- ✅ 全部 85 个 detector 加载成功
- ✅ post_dev_check.sh 验证通过

## v1.1.0 (2026-05-09)

### Major Changes
- **CVE 数量大幅扩展**: 从 37 个增加到 **85 个**内核漏洞检测器 (+130%)
  - 新增 48 个 CVE 检测器和 PoC 验证模块
  - 覆盖 2023-2025 年最新内核漏洞
  - 包括 use-after-free、race condition、out-of-bounds、BPF verifier 等漏洞类型

### New CVEs Added (48 total)
- **2023**: CVE-2023-0461, CVE-2023-3390, CVE-2023-4004, CVE-2023-4147, CVE-2023-4622, CVE-2023-6817, CVE-2023-6931
- **2024**: CVE-2024-0582, CVE-2024-1085, CVE-2024-26581/2/5, CVE-2024-26642, CVE-2024-26808/9/24/25, CVE-2024-27397, CVE-2024-36972, CVE-2024-39503, CVE-2024-41009/10, CVE-2024-49861, CVE-2024-50164, CVE-2024-53125/41/64, CVE-2024-57947, CVE-2024-58239/40
- **2025**: CVE-2025-21700/1/2, CVE-2025-21836, CVE-2025-37752/6, CVE-2025-38001/83, CVE-2025-38350/477/500/502/616, CVE-2025-39682/9946/9965/40019/40364

### Improvements
- **完整 CTF 三阶段验证**: 所有 85 个 CVE 现在都有完整的 Prepare/Post handler
- **代码质量提升**: 修复 24 个 PoC 源文件的中文注释为纯英文
- **文档完善**: SKILL.md 更新 CVE 列表从 37 到 85 个
- **项目清理**: 移除 32 个已完成的 todo 需求文档

### Statistics
- Python 文件: ~330 个 (+230%)
- C PoC 源文件: 85 个
- PoC 二进制: 85 个（全部静态编译）
- 总代码行数: ~41,000 行 (+173%)
- 包大小: 33 MB (+136%)

### Verification
- ✅ 全部 85 个 PoC 二进制静态编译成功
- ✅ 全部 85 个 detector 加载成功
- ✅ post_dev_check.sh 验证通过
- ✅ 打包验证通过（sec-kernel-1.1.0-2026-05-09.zip, 623 文件）

## v1.0.1 (2026-05-09)

### Improvements
- 版本号升级 1.0.0 → 1.0.1
- 同步更新 VERSION、__init__.py、main.py 中的版本标识

## v1.0.0 (2026-05-08)

### Major Changes
- **架构简化**: 打包模式从双模式简化为仅 plain 模式
  - 移除 zipapp 打包支持
  - 包名格式简化: `{skill_name}-{version}-{date}.zip`
  - 减少验证步骤，提升打包效率 50%
- **新增 CVE**: Dirty Frag (CVE-2026-PENDING-DIRTYFRAG)
  - xfrm-ESP Page-Cache Write + RxRPC Page-Cache Write 漏洞链
  - 双 variant 检测策略（ESP + RxRPC fallback）
  - 影响范围：2017-01-17 至最新版本（约 9 年）
  - 测试通过：WSL2 kernel 6.6.87.2
- **PoC 数量**: 从 36 个增加到 37 个

### Improvements
- 更新研发规范文档
- 移除 zipapp 双模式相关文档和验证流程
- 简化 pack-config.yaml 配置（移除 {code_type} 字段）
- 精简文档 26 行（移除 zipapp 兼容性章节）

### Verification
- ✅ Dirty Frag PoC 验证通过（VULNERABLE [EXPLOITABLE]）
- ✅ post_dev_check.sh 全部通过
- ✅ 六维深度审计完成
- ✅ Plain 模式打包验证通过

## v0.2.0 (2026-05-06)

- **新增**：三阶段 PoC 验证机制 — Prepare(root) → Run(nobody) → Post(root)
  - Prepare 阶段：自动加载内核模块、创建测试目录、记录系统状态快照
  - Run 阶段：强制降权到普通用户（nobody）执行 PoC，验证 LPV 实际威胁
  - Post 阶段：Self-Check 残留检查 + Global Verify 系统恢复验证
- **新增**：`PrivilegeManager` — 安全的用户降权执行框架
- **新增**：`ConclusionEngine` — 精确结论计算（USER_EXPLOITABLE / NOT_EXPLOITABLE）
- **新增**：CLI 参数 `--poc-user`
- **新增**：CVE-2026-31431 专用 Prepare/Post handler
- **改进**：证据文件增加三阶段执行详情（Prepare 操作列表、Run 用户、Post 验证结果）
- **改进**：`PoCResult` 数据结构扩展，支持三阶段字段（prepare/post/final_conclusion）
- **设计**：三阶段验证始终完整执行，不提供跳过选项，确保验证结果可靠性

## v0.1.1 (2026-05-06)

### Bug Fixes
- **PoC Loader**: 修复 memfd_create 在 WSL2/受限环境下执行失败的问题
  - 新增 tmpfile fallback 模式（/dev/shm 内存文件系统）
  - 执行后立即覆写零字节 + unlink 确保安全清理
  - 移除不兼容的 unlink-before-exec 策略
- **CLI**: 集成 ReportGenerator，修复报告文件未生成的问题

### Improvements  
- PoC 执行器自动检测环境能力，fileless → tmpfile 无缝降级
- 报告自动保存到 --output-dir 指定目录

### Lessons Learned (反思)
- WSL2 不完全兼容 Linux 的 memfd_create + /proc/self/fd 执行路径
- WSL2 不支持 unlink-before-exec（已删除文件无法通过原路径执行）
- 生产级工具必须有 graceful degradation 策略，不能假设单一执行路径可用
- /dev/shm (tmpfs) 是良好的折中方案：仍在内存中，但兼容所有 Linux 环境
