---
name: youtube-safe-autopilot
description: Autonomous YouTube channel manager and publishing orchestrator with strict
  anti-ban safeguards, quota ledger enforcement, 12h unlisted copyright clearance,
  and 2026 AI content disclosures.
category: automation
risk: safe
allowed-tools:
- bash
- read
- edit
- write
source: community
---
# YouTube Safe Autopilot (`youtube-safe-autopilot`)

Autonomous channel management and publishing engine designed with **Anti-Ban Primacy**. It eliminates risk of account suspension, shadowbans, and API quota revocations by enforcing deterministic quota budgets, human-paced velocity throttling, mandatory 2026 AI content disclosures, and an unlisted incubation quarantine.

---

## 1. Hybrid 3-Tier Architecture

To achieve $0 cost, unlimited large video uploads, and zero third-party token leakage:

```
[Agent / Antigravity CLI]
         │
         ▼
[Anti-Ban Governor Layer] ──► Enforces Quota Ledger (<8,500 units/day) & 30m Upload Cooldown
         │
         ├─► Tier 1: Local YouTube MCP (`youtube-safe-local`)
         │     • Chunked resumable local file upload (supports multi-GB files)
         │     • Dedicated 100% free Google Cloud OAuth 2.0 (10,000 units/day)
         │     • Staged publishing (unlisted incubation for Content ID clearance)
         │
         ├─► Tier 2: Zero-Quota Ingestion (`youtube-full`)
         │     • TranscriptAPI / yt-dlp for transcripts and competitor monitoring
         │     • Consumes 0 Google API quota units
         │
         └─► Tier 3: Composio Rube Fallback (`composio-rube`)
               • Remote endpoint: https://rube.app/mcp
               • Zero-setup browser OAuth for metadata, playlists, and subscriptions
```

---

## 2. Non-Negotiable Anti-Ban Invariants

Every automated action through this skill must respect these 6 invariants:

1. **Deterministic Quota Ledger:**
   - Hard cap of **8,500 quota units/day** (maintains a 1,500 buffer below Google's 10,000 ceiling).
   - Operations halt automatically if daily limits are reached, preventing Google Cloud API abuse flags.

2. **Upload Velocity & Pacing:**
   - **Maximum 3 automated uploads per rolling 24 hours**.
   - **Minimum 30-minute cooling interval** between consecutive video uploads.
   - Immediate burst uploading is blocked by the governor.

3. **The Unlisted Incubation Protocol:**
   - Automated video uploads **must never land directly in public visibility**.
   - Uploads are created as `privacyStatus: unlisted` (or `private`).
   - A minimum 12-hour incubation window allows YouTube's automated Content ID and copyright algorithms to clear cleanly without exposing the public channel to sudden copyright strikes.
   - Promotion to `public` requires the `publish_staged_video` Human-in-the-Loop promotion gate.

4. **Strict Metadata Sanitization:**
   - Titles are strictly capped at 100 characters.
   - HTML tags and angle brackets (`< >`) are automatically stripped.
   - Keyword tag dumps in the video description are forbidden (violates YouTube Spam Policies).
   - Total length of all tags combined must stay under 400 characters (YouTube allows 500 max).

5. **Mandatory 2026 AI Content Disclosure:**
   - In compliance with YouTube's Altered or Synthetic Content Policy, all AI-synthesized videos must include the standard disclosure footer:
     `Synthetic/Altered Media Disclosure: In compliance with YouTube's Altered or Synthetic Content Guidelines, portions of the narration, visual generation, or editing were assisted by AI tools.`
   - `selfDeclaredMadeForKids` is explicitly set to `false`.

6. **Network & Session Consistency:**
   - API calls originate locally from the creator's machine.
   - Never route through rotating proxies or suspicious data-center VPNs.

---

## 3. Core Commands & Workflows

### A. Check Daily Quota & Health
```bash
# Check current quota ledger and anti-ban cooldown status
python3 -c "import youtube_safe_mcp; print(youtube_safe_mcp.QuotaGovernor.get_status())"
```

### B. Safe Video Upload (Local Resumable Streaming)
Tool: `upload_video_safe`
- `file_path`: Absolute path to rendered MP4/MKV file on disk.
- `title`: Video title (max 100 chars, sanitized).
- `description`: Prose description (AI disclosure injected automatically).
- `tags`: List of keyword tags (max 400 chars total).
- `category_id`: YouTube category ID (default: '22' People & Blogs, '27' Education, '28' Science & Tech).
- `privacy_status`: Defaults to `'unlisted'`.

### C. Human-in-the-Loop Staged Release
Tool: `publish_staged_video`
- `video_id`: 11-character YouTube video ID.
- Promotes the video from `unlisted` to `public` once copyright checks have cleared.

### D. Update Metadata or Custom Thumbnail
- Tool: `update_video_metadata` (50 units)
- Tool: `set_custom_thumbnail` (50 units)

---

## 4. References & Documentation

- [Google Cloud OAuth 2.0 Free Setup Guide](references/google_cloud_setup.md)
- [Anti-Ban Security Handbook & ToS Guidelines](references/anti_ban_handbook.md)
