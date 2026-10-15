---
name: microsoft-purview-dlp
description: Audit Data Security Posture Management (DSPM), design sensitive information types (SIT), author Data Loss Prevention (DLP) policies, and configure insider risk controls.
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

# microsoft-purview-dlp

**Vendor**: Microsoft  
**Category**: Data Security Posture & Loss Prevention (DSPM / DLP)

## Overview
Audit Data Security Posture Management (DSPM), design sensitive information types (SIT), author Data Loss Prevention (DLP) policies, and configure insider risk controls.

## Workflow & Capabilities

1. **Sensitive Information Type (SIT) Design**:
   - Create custom regex-based and Exact Data Match (EDM) classifiers with proximity keywords and checksum validation.
   - Validate SIT detection accuracy and confidence levels across structured and unstructured content.
2. **DLP Policy Architecture**:
   - Configure DLP rules covering Exchange Online, SharePoint Online, OneDrive for Business, Microsoft Teams, and Windows/macOS Endpoints.
   - Define policy actions: user notification tips, incident reports, and block with business justification overrides.
3. **Information Protection & Sensitivity Labels**:
   - Define sensitivity labeling schema with automatic watermarking, header/footer stamping, and Azure Rights Management (RMS) encryption.
4. **Data Security Posture Management (DSPM)**:
   - Discover dark data and sensitive data exposures in multi-cloud storage (Azure Blob, AWS S3) and SaaS apps.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
