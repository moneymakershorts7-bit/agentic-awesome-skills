# Language Agent Tree Search (LATS) Architecture & Bounds

## Academic Citation

```bibtex
@article{zhou2023language,
  title={Language Agent Tree Search Unifies Reasoning, Acting, and Planning in Language Models},
  author={Zhou, Andy and Yan, Kai and Shlapentokh-Rothman, Michal and Wang, Haohan and Wang, Yue},
  journal={arXiv preprint arXiv:2310.04406},
  year={2023},
  institution={UIUC, MIT, Princeton University}
}
```

## Comparative Framework

| Dimension | ReAct / Standard CoT | Reflexion | Tree of Thoughts (ToT) | LATS |
| :--- | :---: | :---: | :---: | :---: |
| **Search Paradigm** | Linear | Linear Iterative | Tree Breadth/Depth | MCTS (Heuristic Tree Search) |
| **Backtracking** | ❌ No | ⚠️ Across trials only | ✅ Yes | ✅ Yes (Within trial) |
| **Value Function** | ❌ None | ❌ Binary | ⚠️ LLM Prompts | ✅ Q-value Backpropagation |
| **External Feedback** | Observations | Verbal self-critique | None (Pure LM) | Environment + Self-Reflection |
| **Exploration/Exploitation** | Greedy | Greedy + Memory | Heuristic beam | Formal UCB1 / PUCT |

## Performance on Coding & Reasoning Benchmarks

- **HumanEval (Python):** LATS achieved **94.4% pass@1** with GPT-4, establishing state-of-the-art across agent search methods.
- **WebShop & AlfWorld:** Outperformed Reflexion by **+18.2%** on complex multi-step interactive decision tasks.
