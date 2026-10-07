---
name: nvidia-morpheus-cybersecurity
description: Construct GPU-accelerated cybersecurity pipelines, DGA detection, phishing email NLP classification, sensitive data exfiltration monitoring, and digital fingerprinting.
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

# nvidia-morpheus-cybersecurity

**Vendor**: NVIDIA  
**Category**: AI-Accelerated Cybersecurity Analytics

## Overview
Construct GPU-accelerated cybersecurity pipelines, DGA detection, phishing email NLP classification, sensitive data exfiltration monitoring, and digital fingerprinting.

## Workflow & Capabilities

1. **Morpheus Pipeline Construction**:
   - Assemble high-throughput GPU inference pipelines processing millions of syslog/JSON events per second.
2. **AI Pre-Trained Security Models**:
   - Deploy deep learning models for Domain Generation Algorithm (DGA) detection, NLP email phishing classification, and anomalous payload discovery.
3. **Digital Fingerprinting (DFP)**:
   - Establish per-user and per-machine behavioral profiles across AWS CloudTrail and Linux audit logs to detect credential theft and insider threats in real time.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
