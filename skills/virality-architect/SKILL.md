---
name: virality-architect
description: Master skill for behavioral psychology, algorithmic retention engineering, and adversarial virality architecture across short-form (Shorts, Reels, TikTok), long-form YouTube, and automated video clipping.
allowed-tools:
  - run_command
  - view_file
  - write_to_file
permissions:
  - file_read
---

# Virality Architect: Behavioral Psychology & Algorithmic Retention Master

The `virality-architect` skill synthesizes academic behavioral neuroscience, social media recommendation engine mechanics, and the adversarial stress-testing doctrine of **El Décimo Hombre** to engineer high-retention, algorithm-proof video assets for YouTube (Shorts & Long-form), TikTok, Instagram Reels, and automated clipping systems.

---

## 1. Core Operating Foundations

Virality is a deterministic convergence of six neuro-cognitive and algorithmic vectors:

1. **Autonomic Arousal (Berger & Milkman)**: High-arousal positive (Awe, Amusement) and high-arousal negative (Anger, Anxiety, Outrage) emotions trigger sympathetic nervous system mobilization ($\beta_{\text{arousal}} > 0$). Low-arousal states (Sadness, Contentment) depress social transmission ($\beta < 0$).
2. **System 1 Cognitive Fluency & Loss Aversion (Kahneman)**: Mobile feed decision gates occur within $150-300\text{ ms}$. High contrast, instant visual parsing, and Loss Aversion ($\lambda \approx 2.25$, where losses loom $>2\times$ larger than gains) prevent thumb-skips.
3. **Information Gap Theory (Loewenstein & Zeigarnik)**: Curiosity is an aversive drive produced by an epistemic deficit ($\Delta I = I_{\text{target}} - I_{\text{current}}$). Nested open loops hold working memory hostage until resolution.
4. **Dopaminergic Prediction Error & Variable Ratio (Schultz & Skinner)**: Unpredictable rewards ($p \approx 0.5$) generate maximal sustained dopamine elevation, driving compulsive watch loops and re-watches.
5. **Heuristic Influence Levers (Cialdini)**: Pre-suasion, privileged moments, social proof, and authority heuristics anchor immediate viewer compliance.
6. **Action Line Simplicity (Fogg $B = M \cdot A \cdot P$)**: Reducing cognitive friction ($A_{\text{brain}} \to 0$) lowers the threshold required for passive viewers to engage, share, or follow.

---

## 2. Platform Algorithmic Hierarchies

### A. Short-Form Video (TikTok, YouTube Shorts, Meta Reels)
- **TikTok Monolith (Real-time Stream Ranker)**: Progressive qualification through 4 cohort gates: Tier 1 Sandbox ($200-300$ views) $\to$ Tier 2 Expansion ($1\text{k}-2.5\text{k}$) $\to$ Tier 3 High Velocity ($10\text{k}-50\text{k}$) $\to$ Tier 4 Mass Virality ($100\text{k}-1\text{M}+$ views).
  - *Primary Ranking Weight*: Rewatch / Loop Rate & Shares $\gg$ Completion Rate $>$ Average Watch Time $\gg$ Comments $>$ Likes.
- **YouTube Shorts**:
  - **VVSA ("Viewed vs. Swiped Away")**: Gatekeeper metric evaluated at $0.0-3.5\text{s}$. Must achieve $\ge 75\%$ to escape algorithmic decay.
  - **APV (Average Percentage Viewed)**: Videos $\le 15\text{s}$ require $\text{APV} \ge 120-140\%$ (loops); videos $30-60\text{s}$ require $\ge 80-100\%$.
- **Meta Reels (DLRM)**: Primary ranking signal is **Sends per Reach (DM Shares)** $>3\%$, followed by VTR and Audio Graph velocity.

### B. YouTube Long-Form (VOD)
- **Expected Watch Time**: $\mathbb{E}[\text{WatchTime}] = \text{pCTR} \times \text{Predicted AVD}$.
- **Retention Milestones**:
  - First 30s: $\ge 70-75\%$ retention (MrBeast benchmark).
  - Midpoint: $\ge 50-55\%$.
  - End: $\ge 40-45\%$.
  - Linear decay gradient: $<1.2\%$ loss per minute after minute 1.

---

## 3. Structural Video Anatomy (0–60s Short-Form)

```
0s        2s               15s                              45s            60s
├─────────┼────────────────┼────────────────────────────────┼──────────────┤
│  HOOK   │ CONTEXT SETUP  │    ESCALATION & RESET PEAKS    │ CLIMAX/LOOP  │
│ WINDOW  │  Stakes + CDQ  │    The 2.5s Stimulus Engine    │ Syntactic    │
│  (V0)   │      (V1)      │              (V2)              │ Circularity  │
└─────────┴────────────────┴────────────────────────────────┴──────────────┘
```

1. **0–2s Hook Window**: High visual contrast delta ($\Delta \text{Frame} > 85\%$), in-medias-res crisis opening, audio riser + sub-bass hit, zero greeting fluff.
2. **2–15s Context Setup**: Deliver premise in $\le 8$ seconds; inject Three-Pillar Stakes (Financial, Existential, Epistemic); articulate Central Dramatic Question (CDQ) before 0:15; strip all dead air $>0.1\text{s}$.
3. **15–45s Escalation & Retention Peaks**: Habituation reset cadence every 2.5–3.5s (scale punch-ins 1.0x to 1.15x, kinetic typography accents, vector momentum cuts, Mayer signaling spotlight).
4. **45–60s Climax & Invisible Loop**: Syntactic circularity connecting closing clause to opening syllable; frame-matched visual coordinates; zero pre-outro cadence slowdown.

---

## 4. El Décimo Hombre: 5 Non-Negotiable Kill Criteria

Under the *Ipcha Mistabra* doctrine, halt generation or publishing if any clip triggers these failure vectors:

1. **Derivative Visual Carrier**: Background consists of generic gameplay (Minecraft, Subway Surfers), soap cutting, or uncontextualized loops. (Triggers vector clustering demotion & shadowbans).
2. **Commodity Voice Fingerprint**: Uses default, uncalibrated ElevenLabs presets (e.g., standard `Adam`/`Antoni`) without human variation or emotional audio engineering.
3. **Context-Free Pattern Bombardment**: Cuts, zooms, and sound effects occur on a mechanical timer without synchrony to emotional shift or narrative progression.
4. **Reused Content & Hash Redundancy**: Perceptual audio/video fingerprint (pHash/SSIM) shares $>50\%$ unedited continuous run with indexed public sources. (Fails YPP Reused Content & TikTok Unoriginal Content gates).
5. **Zero-Intent / Zero-Moat Proposition**: Relies purely on shock value or celebrity soundbites without proprietary thesis, clear avatar, or owned asset off-ramp.

---

## 5. Tooling & CLI Verification

Execute the bundled deterministic viral scorer script:
```bash
python3 scripts/viral_scorer.py --script "path/to/script.txt"
```
Evaluates input across the 6-pillar **Viral Potential Rubric (VPR-100)** and executes the 5 El Décimo Hombre kill checks.

---

## 6. Progressive Disclosure Documentation

- In-depth Behavioral Neuroscience & Mental Models: [behavioral-neuroscience.md](references/behavioral-neuroscience.md)
- Social Media Algorithm Mechanics (Monolith, MMoE, DLRM): [algorithm-mechanics.md](references/algorithm-mechanics.md)
- El Décimo Hombre Adversarial Stress-Test & Invariants: [decimo-hombre-invariants.md](references/decimo-hombre-invariants.md)
- 10 Psychological Hook Blueprints & VPR-100 Rubric: [hook-blueprints-and-rubric.md](references/hook-blueprints-and-rubric.md)
- Long-Form Pacing & Clipping Cross-Pollination Playbook: [long-form-and-clipping-playbook.md](references/long-form-and-clipping-playbook.md)
