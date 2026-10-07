# NVIDIA Confidential Computing Attestation Reference

## CLI Verification Commands
```bash
# Check GPU CC mode status
nvidia-smi --query-gpu=confidential_computing.mode --format=csv

# Verify attestation token with Local Attestation Verifier
nv-attestation-verifier --token-file /path/to/attestation_token.json --spdm-report /path/to/spdm_report.bin
```