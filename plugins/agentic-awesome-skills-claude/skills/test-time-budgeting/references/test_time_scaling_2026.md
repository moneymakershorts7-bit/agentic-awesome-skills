# Test-Time Compute Scaling & Budget Forcing (2025–2026)

## Academic Citations

```bibtex
@article{muennighoff2025s1,
  title={s1: Simple test-time scaling},
  author={Muennighoff, Niklas and Rush, Alexander M and others},
  journal={arXiv preprint arXiv:2501.19393},
  year={2025},
  institution={Stanford University, Contextual AI}
}

@article{zhai2026adaptive,
  title={Adaptive Test-Time Compute Allocation for Reasoning LLMs via Constrained Policy Optimization},
  author={Zhai, Zhiyuan and Li, Bingcong and Xiao, Bingnan and Li, Ming and Wang, Xin},
  journal={arXiv preprint arXiv:2604.14853},
  year={2026}
}

@article{manvi2025zero,
  title={Zero-Overhead Introspection for Adaptive Test-Time Compute},
  author={Manvi, Rohin and Hong, Joey and Seyde, Tim and Labonne, Maxime and Lechner, Mathias and Levine, Sergey},
  journal={arXiv preprint arXiv:2512.01457},
  year={2025},
  institution={UC Berkeley, ICLR 2026}
}
```

## Mathematical Framework: Constrained Policy Optimization

Given an input distribution $x \sim \mathcal{D}$ and an inference search strategy $a \in \mathcal{A}$ parameterized by compute cost $c(x, a)$ and accuracy $r(x, a)$:
$$\max_{\pi} \mathbb{E}_{x \sim \mathcal{D}, a \sim \pi(\cdot|x)} [r(x, a)] \quad \text{s.t.} \quad \mathbb{E}_{x \sim \mathcal{D}, a \sim \pi(\cdot|x)} [c(x, a)] \le B_{\text{target}}$$

Using Lagrangian relaxation:
$$\mathcal{L}(\pi, \lambda) = \mathbb{E}_{x} \left[ \max_{a} \left( r(x, a) - \lambda c(x, a) \right) \right] + \lambda B_{\text{target}}$$

The dual variable $\lambda^*$ acts as the cost-sensitivity multiplier, dynamically mapping problem difficulty to search rounds.

## Key Empirical Findings

- **s1-32B Performance:** Exceeded OpenAI o1-preview on competition mathematics (MATH & AIME24) by up to **27%** through simple budget forcing on only 1,000 curated traces (s1K).
- **AdaCompute 2026:** Outperformed uniform compute allocations by **+12.8% relative accuracy** under identical aggregate token budgets.
