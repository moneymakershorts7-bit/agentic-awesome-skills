---
name: nvidia-gpu-confidential-security
description: Deploy NVIDIA Confidential Computing on H100/H200/Blackwell architectures, verify remote attestation reports, secure driver integrity, and enforce GPU memory isolation.
license: Apache-2.0
risk: safe
source: official
allowed-tools:
  - bash
  - read
  - write
  - glob
  - grep
  - run_command
  - view_file
  - write_to_file
---

# nvidia-gpu-confidential-security

**Vendor**: NVIDIA  
**Category**: Confidential Computing & Hardware Security

## Overview
Deploy NVIDIA Confidential Computing on H100/H200/Blackwell architectures, verify remote attestation reports, secure driver integrity, and enforce GPU memory isolation.

## Workflow & Capabilities

1. **GPU Confidential Computing Verification**:
   - Verify hardware-based isolation for tenant VMs and AI workloads executing on NVIDIA Hopper and Blackwell GPUs.
2. **Remote Attestation & Identity Verification**:
   - Query and validate GPU attestation tokens against NVIDIA Remote Attestation Service (NRAS).
   - Ensure firmware and driver measurements match golden PCR values before injecting sensitive LLM weights or customer data.
3. **Protected PCIe & NVLink Cryptography**:
   - Verify APM (Authenticated Protected Mode) and encryption across PCIe/NVLink interconnects.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
