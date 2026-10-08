# Semantic Entropy & Uncertainty Calibration Academic Formulation

## Academic Citation

```bibtex
@article{kuhn2023semantic,
  title={Semantic Uncertainty: Linguistic Invariances for Uncertainty Estimation in Large Language Models},
  author={Kuhn, Lorenz and Gal, Yarin and Farquhar, Sebastian},
  journal={Nature},
  volume={630},
  pages={526--533},
  year={2023},
  institution={University of Oxford, Cambridge University}
}
```

## Key Mathematical Derivation

Standard sequence entropy $H(Y|x) = -\sum_y p(y|x) \log p(y|x)$ is dominated by lexical variability (synonyms, phrasing).

Lorenz Kuhn et al. introduced **Semantic Entropy**:
Given an equivalence relation $\sim$ defined such that $y_1 \sim y_2$ if both sequences express identical semantic meaning:
$$P(c|x) = \sum_{y \in c} p(y|x)$$
The semantic entropy is defined as:
$$H_{\text{sem}}(x) = -\sum_{c \in \mathcal{C}} P(c|x) \log P(c|x)$$

## Experimental Findings

- On CoQA, TriviaQA, and BioASQ question answering benchmarks, semantic entropy achieved an **AUROC of 0.88–0.93** for predicting model errors and hallucinations.
- Outperformed raw token perplexity, length-normalized probabilities, and self-reported verbal confidence by **+25–35%**.
