# SPROUT & Verifier-Guided Backtracking Academic Formulations

## Academic Citations

```bibtex
@article{rohatgi2025taming,
  title={Taming Imperfect Process Verifiers: A Sampling Perspective on Backtracking},
  author={Rohatgi, Deven and Shetty, Anay and Saless, Danial and Li, Yilun and Moitra, Ankur and Risteski, Andrej and Foster, Dylan J},
  journal={arXiv preprint arXiv:2510.03314},
  year={2025},
  institution={MIT, CMU, Microsoft Research}
}

@article{sprout2025agentic,
  title={SPROUT: SnaPshot-based RollOUT for Agentic Reinforcement Learning and Verifier-Guided Backtracking},
  journal={OpenReview},
  year={2025}
}
```

## Abstract & Mathematical Mechanism

Traditional autoregressive sampling is modeled as a standard Markov chain. When generating long sequences of code edits $\tau = (s_0, a_0, s_1, a_1, \dots, s_T)$, any error introduced at time $t$ shifts the state distribution $P(s_t)$ into out-of-distribution (OOD) territory.

**Verifier-Guided Backtracking (VGB)** defines a *Rewinding Markov Chain*:
At each transition $(s_t, a_t)$, a Process Reward Model outputs verification confidence $r_t = \text{PRM}(s_t, a_t) \in [0, 1]$.
The transition rule is:
$$s_{t+1} = \begin{cases} s_{\text{next}} & \text{with probability } \sigma(r_t) \\ s_{\text{checkpoint}} & \text{with probability } 1 - \sigma(r_t) \end{cases}$$

## Benchmark Achievements

- **SWE-bench Pro v2 Hard:** Achieved a **+34% increase in task resolution rate** compared to standard linear ReAct agents.
- **Token Efficiency:** Reduced token consumption by **29–49%** by eliminating repeated full-trajectory restarts.
