# CONTRIBUTOR.md — 学术引用与致谢

本项目中的 PoC（概念验证代码）基于以下公开的安全研究成果进行了 CTF 模式改造与集成。
我们在此向所有原始研究者致以诚挚的感谢与学术致意。

> **统计**: 共 88 个 CVE PoC，其中 84 个有明确来源引用，4 个为独立实现。

---

## 目录

1. [Google security-research (kernelCTF)](#google-security-research-kernelctf) (47 CVEs)
2. [SecWiki/linux-kernel-exploits](#secwikilinux-kernel-exploits) (9 CVEs)
4. [bcoles/kernel-exploits](#bcoleskernel-exploits) (4 CVEs)
6. [V4bel/dirtyfrag](#v4beldirtyfrag) (3 CVEs)
7. [Exploit-DB](#exploit-db) (2 CVEs)
8. [xairy/kernel-exploits](#xairykernel-exploits) (2 CVEs)
9. [Rapid7/Metasploit](#rapid7metasploit) (2 CVEs)
10. [ysanatomic](#ysanatomic) (2 CVEs)
11. [0xdea/exploits](#0xdeaexploits) (1 CVEs)
12. [cloudsec/exploit](#cloudsecexploit) (1 CVEs)
13. [elongl](#elongl) (1 CVEs)
14. [luan0ap](#luan0ap) (1 CVEs)
15. [Notselwyn](#notselwyn) (1 CVEs)
16. [CVE.org (Official)](#cve.org-official) (1 CVEs)
17. [hoefler02](#hoefler02) (1 CVEs)
18. [theori-io](#theori-io) (1 CVEs)

---

## Google security-research (kernelCTF)

- **仓库**: [https://github.com/google/security-research](https://github.com/google/security-research)
- **说明**: Google Security Research 团队发布的 kernelCTF 挑战赛 PoC，涵盖 2023-2025 年最新内核漏洞

| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2021-22555 | 8.1 | CRITICAL | [https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/exploit.c](https://github.com/google/security-research/blob/master/pocs/linux/cve-2021-22555/exploit.c) |
| CVE-2023-2163 | 7.8 | CRITICAL | [https://github.com/google/security-research/tree/master/pocs/linux/cve-2023-2163](https://github.com/google/security-research/tree/master/pocs/linux/cve-2023-2163) |
| CVE-2023-4004 | 7.8 | CRITICAL | [https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-4004_lts_cos_mitigation/exploit/mitigation-6.1/exploit.c](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-4004_lts_cos_mitigation/exploit/mitigation-6.1/exploit.c) |
| CVE-2023-4622 | 7.8 | CRITICAL | [https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-4622_lts/docs/exploit.md](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-4622_lts/docs/exploit.md) |
| CVE-2023-6817 | 7.8 | CRITICAL | [https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-6817_mitigation/docs/exploit.md](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-6817_mitigation/docs/exploit.md) |
| CVE-2023-6931 | 7.8 | HIGH | [https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-6931_lts_cos/docs/exploit.md](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-6931_lts_cos/docs/exploit.md) |
| CVE-2024-0193 | 7.8 | HIGH | [https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2024-0193_lts/](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2024-0193_lts/) |
| CVE-2024-1085 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-1085_lts](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-1085_lts) |
| CVE-2024-26581 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26581_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26581_mitigation) |
| CVE-2024-26582 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26582_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26582_mitigation) |
| CVE-2024-26585 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26585_lts_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26585_lts_cos) |
| CVE-2024-26642 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26642_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26642_cos) |
| CVE-2024-26808 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26808_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26808_cos) |
| CVE-2024-26809 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26809_lts_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26809_lts_cos) |
| CVE-2024-26824 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26824_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26824_mitigation) |
| CVE-2024-26925 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26925_lts_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-26925_lts_cos) |
| CVE-2024-27397 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-27397_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-27397_mitigation) |
| CVE-2024-36972 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-36972_lts_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-36972_lts_cos) |
| CVE-2024-39503 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-39503_lts_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-39503_lts_cos) |
| CVE-2024-41009 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-41009_lts_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-41009_lts_cos) |
| CVE-2024-41010 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-41010_lts](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-41010_lts) |
| CVE-2024-49861 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-49861_lts](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-49861_lts) |
| CVE-2024-50164 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-50164_lts](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-50164_lts) |
| CVE-2024-53125 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-53125_lts](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-53125_lts) |
| CVE-2024-53141 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-53141_cos_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-53141_cos_mitigation) |
| CVE-2024-53164 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-53164_lts_cos_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-53164_lts_cos_mitigation) |
| CVE-2024-57947 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-57947_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-57947_mitigation) |
| CVE-2024-58239 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-58239_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-58239_mitigation) |
| CVE-2024-58240 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-58240_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-58240_cos) |
| CVE-2025-21700 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-21700_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-21700_mitigation) |
| CVE-2025-21701 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-21701_lts_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-21701_lts_cos) |
| CVE-2025-21702 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-21702_lts_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-21702_lts_cos) |
| CVE-2025-21836 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-21836_lts](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-21836_lts) |
| CVE-2025-37752 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-37752_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-37752_mitigation) |
| CVE-2025-37756 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-37756_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-37756_mitigation) |
| CVE-2025-38001 | 8.4 | CRITICAL | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38001_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38001_mitigation) |
| CVE-2025-38083 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38083_cos_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38083_cos_mitigation) |
| CVE-2025-38350 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38350_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38350_cos) |
| CVE-2025-38477 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38477_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38477_cos) |
| CVE-2025-38500 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38500_lts_cos_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38500_lts_cos_mitigation) |
| CVE-2025-38502 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38502_lts](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38502_lts) |
| CVE-2025-38616 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38616_lts_cos_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38616_lts_cos_mitigation) |
| CVE-2025-39682 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-39682_lts_cos_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-39682_lts_cos_mitigation) |
| CVE-2025-39946 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-39946_lts_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-39946_lts_cos) |
| CVE-2025-39965 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-39965_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-39965_cos) |
| CVE-2025-40019 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-40019_lts_cos_mitigation](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-40019_lts_cos_mitigation) |
| CVE-2025-40364 | 7.8 | HIGH | [https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-40364_lts_cos](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-40364_lts_cos) |

---

## SecWiki/linux-kernel-exploits

- **仓库**: [https://github.com/SecWiki/linux-kernel-exploits](https://github.com/SecWiki/linux-kernel-exploits)
- **说明**: SecWiki 维护的 Linux 内核漏洞利用集合，涵盖 2003-2016 年间的经典内核漏洞

| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2004-0077 | 9.0 | CRITICAL | [https://github.com/SecWiki/linux-kernel-exploits/blob/master/2004/CVE-2004-0077/160.c](https://github.com/SecWiki/linux-kernel-exploits/blob/master/2004/CVE-2004-0077/160.c) |
| CVE-2004-1235 | 8.0 | CRITICAL | [https://github.com/SecWiki/linux-kernel-exploits/blob/master/2004/CVE-2004-1235/744.c](https://github.com/SecWiki/linux-kernel-exploits/blob/master/2004/CVE-2004-1235/744.c) |
| CVE-2006-3626 | 8.0 | CRITICAL | [https://github.com/SecWiki/linux-kernel-exploits/tree/master/2006/CVE-2006-3626](https://github.com/SecWiki/linux-kernel-exploits/tree/master/2006/CVE-2006-3626) |
| CVE-2008-0600 | 9.0 | CRITICAL | [https://github.com/SecWiki/linux-kernel-exploits/blob/master/2008/CVE-2008-0600/5093.c](https://github.com/SecWiki/linux-kernel-exploits/blob/master/2008/CVE-2008-0600/5093.c) |
| CVE-2010-3904 | 8.0 | CRITICAL | [https://github.com/SecWiki/linux-kernel-exploits/tree/master/2010/CVE-2010-3904](https://github.com/SecWiki/linux-kernel-exploits/tree/master/2010/CVE-2010-3904) |
| CVE-2013-2094 | 8.0 | CRITICAL | [https://github.com/SecWiki/linux-kernel-exploits/blob/master/2013/CVE-2013-2094/perf_swevent](https://github.com/SecWiki/linux-kernel-exploits/blob/master/2013/CVE-2013-2094/perf_swevent) |
| CVE-2015-1328 | 7.8 | HIGH | [https://github.com/SecWiki/linux-kernel-exploits/blob/master/2015/CVE-2015-1328/37292.c](https://github.com/SecWiki/linux-kernel-exploits/blob/master/2015/CVE-2015-1328/37292.c) |
| CVE-2016-0728 | 7.8 | CRITICAL | [https://github.com/SecWiki/linux-kernel-exploits/blob/master/2016/CVE-2016-0728/cve-2016-0728.c](https://github.com/SecWiki/linux-kernel-exploits/blob/master/2016/CVE-2016-0728/cve-2016-0728.c) |
| CVE-2016-5195 | 7.0 | HIGH | [https://github.com/SecWiki/linux-kernel-exploits/blob/master/2016/CVE-2016-5195/pokemon.c](https://github.com/SecWiki/linux-kernel-exploits/blob/master/2016/CVE-2016-5195/pokemon.c) |

---

## bcoles/kernel-exploits

- **仓库**: [https://github.com/bcoles/kernel-exploits](https://github.com/bcoles/kernel-exploits)

| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2016-8655 | 7.8 | CRITICAL | [https://github.com/bcoles/kernel-exploits/blob/master/CVE-2016-8655/chocobo_root.c](https://github.com/bcoles/kernel-exploits/blob/master/CVE-2016-8655/chocobo_root.c) |
| CVE-2017-1000112 | 7.8 | HIGH | [https://github.com/bcoles/kernel-exploits/blob/master/CVE-2017-1000112/poc.c](https://github.com/bcoles/kernel-exploits/blob/master/CVE-2017-1000112/poc.c) |
| CVE-2017-7308 | 7.8 | HIGH | [https://github.com/bcoles/kernel-exploits/blob/master/CVE-2017-7308/poc.c](https://github.com/bcoles/kernel-exploits/blob/master/CVE-2017-7308/poc.c) |
| CVE-2018-18955 | 7.8 | CRITICAL | [https://github.com/bcoles/kernel-exploits/blob/master/CVE-2018-18955/poc.c](https://github.com/bcoles/kernel-exploits/blob/master/CVE-2018-18955/poc.c) |

---

## V4bel/dirtyfrag

- **仓库**: [https://github.com/V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag)
- **说明**: DirtyFrag 漏洞的原始 PoC 实现，支持 ESP + RxRPC 双变体

| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2026-43284 | 7.8 | CRITICAL | [https://github.com/V4bel/dirtyfrag/blob/master/exp.c](https://github.com/V4bel/dirtyfrag/blob/master/exp.c) |
| CVE-2026-43500 | 7.8 | CRITICAL | [https://github.com/V4bel/dirtyfrag/blob/master/exp.c](https://github.com/V4bel/dirtyfrag/blob/master/exp.c) |
| CVE-2026-PENDING-DIRTYFRAG | 7.8 | CRITICAL | [https://github.com/V4bel/dirtyfrag/blob/master/exp.c](https://github.com/V4bel/dirtyfrag/blob/master/exp.c) |

---

## Exploit-DB

- **来源**: [Exploit-DB](https://www.exploit-db.com/)

| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2003-0127 | 9.0 | CRITICAL | [https://www.exploit-db.com/exploits/3](https://www.exploit-db.com/exploits/3) |
| CVE-2016-4557 | 7.0 | CRITICAL | [https://www.exploit-db.com/exploits/40759](https://www.exploit-db.com/exploits/40759) |

---

## xairy/kernel-exploits

- **仓库**: [https://github.com/xairy/kernel-exploits](https://github.com/xairy/kernel-exploits)

| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2016-9793 | 7.8 | CRITICAL | [https://github.com/xairy/kernel-exploits/blob/master/CVE-2016-9793/poc.c](https://github.com/xairy/kernel-exploits/blob/master/CVE-2016-9793/poc.c) |
| CVE-2017-6074 | 7.8 | CRITICAL | [https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-6074/poc.c](https://github.com/xairy/kernel-exploits/blob/master/CVE-2017-6074/poc.c) |

---

## Rapid7/Metasploit


| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2017-16995 | 7.8 | CRITICAL | [https://github.com/rapid7/metasploit-framework/blob/master/data/exploits/cve-2017-16995/exploit.c](https://github.com/rapid7/metasploit-framework/blob/master/data/exploits/cve-2017-16995/exploit.c) |
| CVE-2019-13272 | 7.8 | CRITICAL | [https://github.com/rapid7/metasploit-framework/blob/master/data/exploits/CVE-2019-13272/poc.c](https://github.com/rapid7/metasploit-framework/blob/master/data/exploits/CVE-2019-13272/poc.c) |

---

## ysanatomic


| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2022-32250 | 7.8 | CRITICAL | [https://github.com/ysanatomic/CVE-2022-32250-LPE/blob/main/exploit.c](https://github.com/ysanatomic/CVE-2022-32250-LPE/blob/main/exploit.c) |
| CVE-2024-0582 | 7.8 | HIGH | [https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582/blob/main/exploit.c](https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582/blob/main/exploit.c) |

---

## 0xdea/exploits


| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2006-2451 | 7.2 | HIGH | [https://github.com/0xdea/exploits/blob/master/linux/raptor_prctl2.c](https://github.com/0xdea/exploits/blob/master/linux/raptor_prctl2.c) |

---

## cloudsec/exploit


| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2009-2692 | 9.0 | CRITICAL | [https://github.com/cloudsec/exploit/blob/master/CVE-2009-2692-sock_sendpage.c](https://github.com/cloudsec/exploit/blob/master/CVE-2009-2692-sock_sendpage.c) |

---

## elongl


| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2014-3153 | 7.2 | CRITICAL | [https://github.com/elongl/CVE-2014-3153](https://github.com/elongl/CVE-2014-3153) |

---

## luan0ap


| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2018-14634 | 7.8 | HIGH | [https://github.com/luan0ap/cve-2018-14634/blob/master/exploit.c](https://github.com/luan0ap/cve-2018-14634/blob/master/exploit.c) |

---

## Notselwyn


| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2024-1086 | 7.8 | HIGH | [https://github.com/Notselwyn/CVE-2024-1086/blob/main/src/main.c](https://github.com/Notselwyn/CVE-2024-1086/blob/main/src/main.c) |

---

## CVE.org (Official)


| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2024-53197 | 7.8 | HIGH | [https://www.cve.org/CVERecord?id=CVE-2024-53197](https://www.cve.org/CVERecord?id=CVE-2024-53197) |

---

## hoefler02


| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2025-21756 | 7.8 | HIGH | [https://github.com/hoefler02/CVE-2025-21756/blob/main/exploit.c](https://github.com/hoefler02/CVE-2025-21756/blob/main/exploit.c) |

---

## theori-io


| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2026-31431 | 7.8 | CRITICAL | [https://github.com/theori-io/copy-fail-CVE-2026-31431](https://github.com/theori-io/copy-fail-CVE-2026-31431) |

---

## 独立实现 / 其他来源

以下 CVE 的 PoC 为独立实现或来源分散，未归类到上述主要来源：

| CVE ID | CVSS | 严重等级 | 引用来源 |
|--------|------|----------|----------|
| CVE-2020-14386 | 8.1 | CRITICAL | https://github.com/chompie1337/cve-2020-14386-poc/blob/master/poc.c |
| CVE-2020-8835 | 7.8 | CRITICAL | https://github.com/zilong3033/CVE-2020-8835/blob/main/poc.c |
| CVE-2022-0847 | 7.8 | HIGH | https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/blob/main/exploit-1.c |
| CVE-2023-0386 | 7.8 | HIGH | https://github.com/xkaneiki/CVE-2023-0386/blob/main/exp.c |
| CVE-2023-0461 | 7.8 | CRITICAL | 独立实现 |
| CVE-2023-32233 | 7.8 | CRITICAL | https://github.com/oferchen/POC-CVE-2023-32233/blob/main/poc.c |
| CVE-2023-3390 | 7.8 | CRITICAL | 独立实现 |
| CVE-2023-4147 | 8.1 | CRITICAL | 独立实现 |
| CVE_2026_PENDING_FRAGNESIA | 7.8 | CRITICAL | 独立实现 |

---

## 学术引用声明

本项目的 PoC 代码基于上述公开研究成果进行了 CTF（Capture The Flag）挑战模式改造：

1. **三阶段验证框架**: Prepare (root) → Run (nobody) → Post (root)
2. **CTF Flag 机制**: 每次执行随机生成 flag，通过文件读写客观验证漏洞是否可被利用
3. **降权执行**: PoC 以 nobody 身份运行，验证 LPE（本地提权）路径的实际威胁
4. **完整恢复**: Post 阶段确保系统状态恢复到执行前

所有原始 PoC 的版权归原作者所有。本项目的改造工作遵循合理使用原则，仅用于安全研究和教育目的。
若您是原始作者并希望对引用方式进行调整，请联系我们。

---

*文档生成时间: 2026-06-01 | 基于 88 个 CVE README 自动汇聚*
