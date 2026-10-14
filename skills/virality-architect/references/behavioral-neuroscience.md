# Behavioral Neuroscience & Cognitive Foundations of Virality

This reference documents the neurobiological and cognitive architectures governing human attention, social transmission, and compulsive content consumption.

---

## 1. Autonomic Arousal vs. Valence (Jonah Berger & Katherine Milkman 2012)

In *What Makes Online Content Viral?* (*Journal of Marketing Research*), Berger and Milkman demonstrated that social transmission is primarily activated by **physiological arousal (autonomic activation)** rather than emotional positivity:

```
                   HIGH AROUSAL (Mobilizing / Autonomic Activation)
                                      ▲
                                      │
              NEGATIVE VALENCE        │         POSITIVE VALENCE
            ┌─────────────────────────┼─────────────────────────┐
            │ Anger                   │ Awe                     │
            │ Anxiety / Fear          │ Excitement / Elation    │
            │ Outrage                 │ Amusement / Humor       │
            ├─────────────────────────┼─────────────────────────┤
            │ Sadness                 │ Contentment             │
            │ Depression              │ Serenity                │
            │ Melancholy              │ Relaxation              │
            └─────────────────────────┼─────────────────────────┘
                                      │
                                      ▼
                    LOW AROUSAL (Deactivating / Quiescent)
```

- **High-Arousal Mobilizers**:
  - *Positive*: Awe, Excitement, Amusement ($\beta > 0, p < 0.001$). Awe increases sharing probability by $+30\%$.
  - *Negative*: Anger, Anxiety, Outrage ($\beta > 0, p < 0.01$). Anger acts as an exceptionally potent catalyst for comment velocity and debate.
- **Low-Arousal Deactivators**:
  - *Negative*: Sadness ($\beta < 0, p < 0.01$). Sadness suppresses virality by $-16\%$, inducing inward withdrawal and behavioral inertia.
  - *Positive*: Contentment, Relaxation ($\beta < 0$).

### Berger's STEPPS Framework:
1. **Social Currency**: Content that confers status, taste, or insider access.
2. **Triggers**: Environmental cues in the user's daily life that provoke passive memory retrieval.
3. **Emotion**: Focus on high autonomic arousal; eliminate neutralizing tones.
4. **Public**: High observability accelerates social imitation.
5. **Practical Value**: Useful, altruistic shortcuts. The Rule of 100: display percentage under \$100 ($30\%$ off), absolute dollar amount above \$100 (\$250 off).
6. **Stories**: The Trojan Horse; the viral payload/brand insight must be inseparable from the narrative climax.

---

## 2. Dual-Process Cognitive Architecture (Daniel Kahneman)

- **System 1 (Fast, Automatic, Heuristic)**: Operates within $10-50\text{ ms}$. Governs thumb-stopping in mobile feeds ($150-300\text{ ms}$ evaluation window).
- **System 2 (Slow, Analytical, Effortful)**: Recruited only when System 1 detects an anomaly, conflict, or high personal relevance.
- **Cognitive Ease (Fluency)**: High visual contrast, clean typography, repetitive melodic cadence, and clear vocal plosives induce positive affective priming and perceived veracity.
- **Loss Aversion ($\lambda \approx 2.25$)**: Under Kahneman & Tversky's Prospect Theory:
  $$|V(-\$X)| \approx 2.25 \times V(+\$X)$$
  Hooks framed around preventing loss (*"Stop making this 1 mistake that destroys your X"*) outperform gain-framed hooks (*"How to improve your X"*) by $200-300\%$.

---

## 3. Information Gap Theory (George Loewenstein 1994)

Curiosity is an aversive, drive-like state arising from perceived knowledge deficits:
$$\Delta I = I_{\text{target}} - I_{\text{current}}$$
- **The Inverted-U Knowledge Law**: Zero prior knowledge produces apathy; complete knowledge produces disinterest. Peak curiosity occurs at moderate prior knowledge with an explicit, tantalizing deficit.
- **Zeigarnik Effect (1927)**: Interrupted and incomplete cognitive sequences occupy working memory up to $90\%$ longer than resolved ones. Viral retention relies on opening Story Loop B before Story Loop A closes.

---

## 4. Mesolimbic Dopaminergic Transmission (Wolfram Schultz & Nir Eyal)

- **Reward Prediction Error (RPE)**:
  $$\delta(t) = r(t) + \gamma V(S_{t+1}) - V(S_t)$$
  Dopamine is not a pleasure molecule; it is an **anticipatory learning and motivation molecule**.
- **Variable Ratio Schedules ($p \approx 0.5$)**: Under fixed, predictable schedules, dopamine response shifts entirely to the trigger and vanishes during delivery. Under uncertain reward schedules (infinite vertical scroll feeds), tonic dopamine remains continuously elevated, creating compulsive foraging behavior.
- **The Eyal Hook Cycle**: Trigger (internal boredom/anxiety) $\to$ Action (frictionless swipe) $\to$ Variable Reward (Tribe, Hunt, Self) $\to$ Investment (comment, share, follow).

---

## 5. Influence & Pre-Suasion (Robert Cialdini)

- **The 7 Levers**: Scarcity, Authority, Social Proof, Commitment/Consistency, Reciprocity, Liking, Unity.
- **Pre-Suasion Privileged Moments**: The psychological window created *immediately before* a claim. The feature brought to attention first dictates how the subsequent message is interpreted.
- **Perceptual Contrast Principle**: Exaggerating differences by placing contrasting states in immediate succession (State A: broken/chaotic $\to$ State B: pristine/flawless).

---

## 6. Behavior Architecture (B.J. Fogg $B = M \cdot A \cdot P$)

A target behavior occurs when Motivation ($M$), Ability ($A$), and a Prompt ($P$) converge above the Action Line.
- **Simplicity Outweighs Motivation**: In mobile feeds, users have variable, often low motivation. Increasing Ability ($A_{\text{time}} \to 0, A_{\text{brain}} \to 0, A_{\text{effort}} \to 0$) lowers the action line so any subtle prompt triggers the desired engagement.
