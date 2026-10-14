# Social Media Algorithm Mechanics & Distribution Architectures

This reference documents the empirical ranking systems and mathematical optimization targets of YouTube (Shorts & Long-form), TikTok, and Instagram Reels.

---

## 1. TikTok Monolith Architecture & Distribution Funnel

ByteDance’s Monolith deep learning recommendation system (*Zhu et al., 2022*) operates on collisionless embedding tables and streaming real-time parameter updates.

### Leaked Core Ranking Scoring Equation:
$$\text{Score}_{\text{TikTok}} = w_1 \cdot \mathbb{E}[\text{play\_time}] + w_2 \cdot P(\text{finish}) + w_3 \cdot P(\text{rewatch}) + w_4 \cdot P(\text{share}) + w_5 \cdot P(\text{comment}) + w_6 \cdot P(\text{like}) - w_7 \cdot P(\text{skip})$$

*Relative Weights*:
$$w_{\text{share}} \approx w_{\text{rewatch}} > w_{\text{finish}} > w_{\text{play\_time}} \gg w_{\text{comment}} > w_{\text{like}}$$

### The 4-Tier Cohort Distribution Gates:
1. **Tier 1: The Sandbox (200 – 300 views)**:
   - Target: Core followers + micro-interest cluster.
   - Requirements: Completion Rate $\ge 65-70\%$ (videos $\le 15\text{s}$) or $\ge 45-50\%$ (videos $\ge 60\text{s}$); 2s Skip Rate $< 30\%$.
2. **Tier 2: Semantic Expansion (1,000 – 2,500 views)**:
   - Target: Cross-topic lookalike users.
   - Requirements: Average Percentage Viewed (APV) $\ge 85-90\%$; Like-to-View $\ge 8-10\%$.
3. **Tier 3: Regional Velocity (10,000 – 50,000 views)**:
   - Target: Broad national/language category feed.
   - Requirements: Share-to-View ratio $\ge 1:100$ (1%); Loop/Rewatch Rate $\ge 15\%$; APV $\ge 100\%$.
4. **Tier 4: Mass Virality (100,000 – 1,000,000+ views)**:
   - Target: Mass unfiltered cold traffic.
   - Requirements: Share-to-View $\ge 1:50$ (2%); Completion $\ge 50\%$ across non-niche users; Comment velocity $\ge 100/\text{hr}$.

---

## 2. YouTube Shorts vs. Long-Form Algorithmic Divergence

### A. YouTube Shorts Ranking Signals
1. **VVSA ("Viewed vs. Swiped Away")**:
   - Primary gatekeeper measured in the first 0.0 – 3.5 seconds.
   - **$\ge 75-80\%$**: Elite viral candidate.
   - **$65 - 74\%$**: Steady linear distribution.
   - **$< 50\%$**: Swift impression throttling.
2. **APV (Average Percentage Viewed)**:
   - $\le 15\text{s}$ videos: Target $\text{APV} \ge 120-140\%$ (must loop).
   - $30 - 60\text{s}$ videos: Target $\text{APV} \ge 80-100\%$.

### B. YouTube Long-Form (MMoE Ranker)
- **Optimization Target**: Expected Watch Time ($\mathbb{E}[\text{WatchTime}] = \text{pCTR} \times \text{Predicted AVD}$).
- **MMoE (Multi-gate Mixture-of-Experts)**: Predicts multiple tasks simultaneously (click probability, satisfaction survey, session initiation duration, dismissal penalty).
- **Session Continuity**: Rewards videos that act as session starters, driving viewers into multi-video binges.

---

## 3. Instagram Reels Ranking Signals (Meta DLRM)
Meta Head Adam Mosseri confirmed the empirical hierarchy:
1. **Sends per Reach (DM Shares)**: The #1 signal. Private message sharing represents high-intent personal validation. Requires $>3\%$ sends-per-reach for massive Explore tab distribution.
2. **Watch-Through Rate (VCR)**: Completion rate and re-watch counts.
3. **Audio Resonance**: High adoption velocity of linked audio tracks gives up to a $1.3\times$ discovery boost.
4. **Likes & Comments**: Baseline hygiene; insufficient on their own for viral breakouts.
