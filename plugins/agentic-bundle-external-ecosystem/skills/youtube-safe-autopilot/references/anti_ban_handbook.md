# YouTube Anti-Ban Security Handbook & Terms of Service Compliance

Operating automated publishing pipelines on YouTube requires uncompromising adherence to Google’s abuse-detection boundaries. This handbook outlines why accounts get flagged and how our architecture prevents it.

---

## 1. Primary Algorithmic Vectors of Account Bans

### Vector 1: BotGuard Heuristics & Velocity Bursts
- **The Threat:** Uploading multiple videos in rapid succession (e.g. 10 videos in 5 minutes) or making rapid bursts of API write requests triggers Google's BotGuard defense.
- **The Consequence:** The channel is labeled an automated content spam farm. Videos receive 0 impressions (shadowban) or the channel is terminated under YouTube's Spam Policy.
- **Our Defense:** Hard cap of 3 uploads per 24 hours + minimum 30-minute randomized cooling interval enforced by `youtube_safe_mcp.py`.

### Vector 2: The Unlisted Incubation Protocol
- **The Threat:** Uploading directly to `public` exposes the video to immediate automated Content ID claims and public community strikes before the creator can review them.
- **The Consequence:** Accumulating 3 strikes within 90 days causes permanent channel termination.
- **Our Defense:** All automated uploads must land in `unlisted` or `private`. A 12-hour holding window allows YouTube's automated Content ID and copyright checks to complete cleanly in YouTube Studio without striking the channel.

### Vector 3: Misleading Metadata & Keyword Stuffing
- **The Threat:** Copy-pasting long lists of comma-separated tags into the video description to game SEO.
- **The Consequence:** Automated spam strike under YouTube Community Guidelines § 4.
- **Our Defense:** The metadata sanitizer strips angle brackets, enforces prose descriptions, and strictly limits tags to the designated `tags` field with a combined character limit under 400.

### Vector 4: Mandatory 2026 AI Content Disclosure
- **The Threat:** Uploading synthetic voiceover, digital avatars, or AI-generated video without informing YouTube.
- **The Consequence:** Penalties under YouTube's Altered or Synthetic Content Policy, demonetization, or automated video removal.
- **Our Defense:** The skill automatically appends the required Altered Media disclosure to video descriptions and flags `selfDeclaredMadeForKids: false`.

### Vector 5: Cookie Scraping vs. Official API
- **The Threat:** Using browser cookies (`cookies.txt`) with `yt-dlp` or headless browsers to upload videos or interact.
- **The Consequence:** Google analyzes TLS fingerprints (JA4, HTTP/2 frames) and flags session hijacking, locking the Google account for "Suspicious Activity".
- **Our Defense:** Strict use of official YouTube Data API v3 over OAuth 2.0.
