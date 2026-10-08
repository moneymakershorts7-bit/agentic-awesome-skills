# Chain-of-Verification (CoVe) Academic Summary & Proofs

## Academic Citation

```bibtex
@article{dhuliawala2023chain,
  title={Chain-of-Verification Reduces Hallucination in Large Language Models},
  author={Dhuliawala, Shehzaad and Komeili, Mojtaba and Xu, Jing and Raileanu, Roberta and Li, Xian and Celikyilmaz, Asli and Weston, Jason},
  journal={arXiv preprint arXiv:2309.11495},
  year={2023},
  institution={Meta AI & FAIR}
}
```

## Abstract & Key Insights

Chain-of-Verification (CoVe) addresses the hallucination problem in language models by factoring generation into four disjoint steps:

1. **Generate Baseline Response:** Given a query, generate the candidate response using standard sampling.
2. **Plan Verifications:** Given both query and baseline response, generate a list of verification questions that help assess if any factual assertions in the baseline are incorrect.
3. **Execute Verifications:** Answer each verification question in turn. The crucial insight from Dhuliawala et al. is that answering questions in **isolation** (without the baseline response in prompt context) prevents the model from hallucinating consistent falsehoods.
4. **Generate Final Output:** Given the initial query and the verified question-answer pairs, generate a refined, hallucination-free final response.

## Benchmark Results

On open-domain question answering, fact-checking benchmarks (Wikidata, MultiSpanQA), and biography generation:
- Factored (isolated) CoVe achieved up to **+28% increase in precision** over standard direct generation.
- Hallucination rates decreased by **63%** on entity attributions and date references.
