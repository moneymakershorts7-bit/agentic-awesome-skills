# Cumulative Reasoning (CR) Theory & Formulations

## Academic Citation

```bibtex
@article{zhang2023cumulative,
  title={Cumulative Reasoning with Large Language Models},
  author={Zhang, Yifan and Yuan, Jingqin and Yang, Min and Li, Yue and Zhang, Dong and Zhang, Zhaoxiang},
  journal={arXiv preprint arXiv:2308.04371},
  year={2023},
  institution={Tsinghua University, Harvard University, ByteDance Research}
}
```

## Abstract & Graph Formulation

Cumulative Reasoning frames problem solving as building a Directed Acyclic Graph $\mathcal{G} = (\mathcal{V}, \mathcal{E})$, where:
- $\mathcal{V}_0 \subset \mathcal{V}$ are initial premise nodes (axioms).
- Each new node $v_k \in \mathcal{V}$ represents a verified lemma deduced from parent premises $\text{Parents}(v_k) \subset \mathcal{V}$.
- Directed edge $(u, v) \in \mathcal{E}$ indicates that lemma $u$ was necessary to deduce lemma $v$.

```
P01 (Axiom) ──┐
              ├──► L03 (Intermediate Lemma) ──┐
P02 (Axiom) ──┘                               ├──► L04 (Final Goal Theorem)
                                              │
P03 (Axiom) ──────────────────────────────────┘
```

## Key Empirical Findings

- **MATH Dataset (Hard Competition Mathematics):** Cumulative Reasoning boosted GPT-4 accuracy from **54.3%** (standard CoT) to **72.2%** (+17.9% improvement).
- **Game of 24:** Solved **98%** of tasks, demonstrating zero cascading error propagation.
