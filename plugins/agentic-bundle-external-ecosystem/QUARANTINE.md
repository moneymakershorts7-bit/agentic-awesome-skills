# External Ecosystem Skills: Security Quarantine Ledger

The following third-party skills were detected in the local environment but are **quarantined from the repository bundle** due to findings triggered in the pre-commit **Cisco AI Defense / DevSecOps Security Gate** (High or Critical severity).

| Skill ID | Security Finding / Reason | Upstream Source |
| :--- | :--- | :--- |
| `alibabacloud-openclaw-skill-security-scan` | Active execution scan scripts with dynamic evaluation | `official` |
| `amc-run-rtsp-calibration` | Infinite loop pattern and sensitive source reaches network sink | `explicit uploaded settings file, user-provided asset directory, or UI Step 3.` |
| `amc-run-video-calibration` | Infinite loop pattern and sensitive source reaches network sink | `external` |
| `bionemo-boltz2-nim` | NGC API credential handling reaching outbound network sink | `external` |
| `bionemo-diffdock-nim` | NGC API credential handling reaching outbound network sink | `external` |
| `bionemo-evo2-nim` | NGC API credential handling reaching outbound network sink | `external` |
| `bionemo-genmol-nim` | NGC API credential handling reaching outbound network sink | `external` |
| `bionemo-kermt-add-cmim-pretrain` | Shell command execution with unescaped string formatting | `built_fresh` |
| `bionemo-kermt-continue-pretrain` | Shell command execution with unescaped string formatting | `user_provided` |
| `bionemo-kermt-embed` | Shell command execution with unescaped string formatting | `external` |
| `bionemo-kermt-finetune` | Shell command execution with unescaped string formatting | `external` |
| `bionemo-kermt-infer` | Shell command execution with unescaped string formatting | `external` |
| `bionemo-kermt-pretrain-scratch` | Shell command execution with unescaped string formatting | `built_fresh` |
| `bionemo-molmim-nim` | NGC API credential handling reaching outbound network sink | `external` |
| `bionemo-msa-search-nim` | NGC API credential handling reaching outbound network sink | `external` |
| `bionemo-openfold2-nim` | NGC API credential handling reaching outbound network sink | `external` |
| `bionemo-openfold3-nim` | NGC API credential handling reaching outbound network sink | `external` |
| `bionemo-proteinmpnn-nim` | NGC API credential handling reaching outbound network sink | `external` |
| `bionemo-rfdiffusion-nim` | NGC API credential handling reaching outbound network sink | `external` |
| `deepstream-import-vision-model` | Network fetch followed by dynamic execution | `huggingface` |
| `deepstream-sop` | Network fetch followed by dynamic execution | `check `file_path.startswith(` |
| `doca-telemetry-exporter` | Adversarial prompt injection pattern in documentation | `external` |
| `earth2studio-create-diagnostic` | Dynamic code execution functions (eval/exec) | `external` |
| `earth2studio-create-prognostic` | Dynamic code execution functions (eval/exec) | `external` |
| `holoscan-install-conda` | Remote fetch followed by execution | `external` |
| `holoscan-install-wheel` | Remote fetch followed by execution | `no such file: ~/holoscan/venv/bin/activate` in a new shell.** Venv wasn` |
| `jetson-headless-mode` | System permission modification commands | `external` |
| `libreoffice-impress` | Unbounded subprocess execution pipeline | `personal` |
| `libreoffice-writer` | Unbounded subprocess execution pipeline | `personal` |
| `local-ai-use` | Active instruction acquires and executes remote content | `external` |
| `nemotron-voice-agent-builder` | Adversarial prompt injection pattern in prompt template | `external` |
| `nv-generate-vae-finetune` | Unbounded loop without exit condition | `external` |
| `nv-reason-ct` | Unbounded loop without exit condition | `external` |
| `nv-reason-cxr` | Unbounded loop without exit condition | `external` |
| `nvflare-autofl` | Dynamic script generation pipeline | `external` |
| `nvflare-convert-lightning` | Dynamic script generation pipeline | `external` |
| `nvflare-convert-pytorch` | Dynamic script generation pipeline | `external` |
| `nvflare-diagnose-job` | Adversarial prompt injection pattern in log parser | `external` |
| `nvflare-fed-stats` | Dangerous data flow in command pipeline | `external` |
| `omniverse-cad-to-simready` | Sensitive source reaches network sink | `external` |
| `paidf-orchestration-setup` | Dynamic DAG construction with eval | `external` |
| `physical-ai-infrastructure-setup-and-resilient-scaling` | System permission modification commands | `external` |
| `physical-ai-video-data-augmentation` | Remote fetch followed by execution | `external` |
| `rtvi-cv-scaffold-vss-service` | Shell command execution with string formatting | `external` |
| `serving-llms-on-epyc` | System hardware configuration commands | `external` |
| `serving-llms-on-instinct` | System hardware configuration commands | `external` |
| `tao-finetune-cosmos-reason` | Dangerous data flow in pipeline | `external` |
| `tao-run-deft-pas` | Dangerous data flow in pipeline | `external` |
| `tao-run-on-brev` | Remote fetch followed by execution | `external` |
| `tao-run-on-virtualenv` | Remote fetch followed by execution | `external` |
| `tao-setup-nvidia-gpu-host` | System permission modification commands | `external` |
| `tao-train-action-recognition` | Dangerous data flow in pipeline | `external` |
| `tilegym-cutile-python` | Dynamic C-types compilation and execution | `external` |
| `tracelens-analysis-orchestrator` | Dynamic LLM eval execution framework | `external` |
| `vss-deploy-profile` | Network fetch followed by execution | `external` |
| `vss-generate-video-calibration` | Dangerous data flow in pipeline | `external` |

## Remediation Playbook
1. **Credential Exfiltration / Outbound Sinks:** Declare explicit `allowed-domains` and update `.skillspector-baseline.json`.
2. **Shell String Formatting:** Replace `f"cmd {arg}"` with parameterized lists `["cmd", arg]` without `shell=True`.
3. **Prompt Injection Test Patterns:** Sanitize test prompt strings and YARA injection payloads in documentation.
