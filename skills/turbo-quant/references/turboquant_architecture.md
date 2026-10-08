# TurboQuant & TurboVec Technical Architecture & Mathematical Specification

## 1. Executive Summary

TurboQuant (ICLR 2026 / Google Research / arXiv:2504.19874) solves the fundamental precision-vs-compression trade-off in dense vector embeddings and key-value cache tensors for Large Language Models and AI Agents.

By combining an orthogonal randomized rotation (**PolarQuant**) with a 1-bit **Quantized Johnson-Lindenstrauss (QJL)** residual sketch, TurboQuant provides:
1. **Zero-training / data-oblivious quantization** (no expensive codebook clustering or calibration dataset required).
2. **Strictly unbiased inner-product estimation** ($\mathbb{E}[\widehat{\langle y, x \rangle}] = \langle y, x \rangle$).
3. **4x to 9x RAM compression** with $>98\%$ cosine similarity accuracy.
4. **Sub-millisecond latency** on vector routing and memory retrieval.

---

## 2. Mathematical Formulation

### 2.1 PolarQuant (Stage 1: Coordinate Regularization & Lloyd-Max MSE Quantization)

Given a target vector $x \in \mathbb{R}^d$ with unit norm $\|x\|_2 = 1$:
1. Apply a random Haar-distributed orthogonal matrix $R \in O(d)$ generated via QR decomposition of a standard Gaussian matrix.
2. The rotated vector $x_{\text{rot}} = R x$ maps to points uniformly distributed on the unit sphere $\mathbb{S}^{d-1}$. By the concentration of measure on high-dimensional spheres, the marginal distribution of each coordinate satisfies:
   $$\sqrt{d} \cdot (x_{\text{rot}})_i \xrightarrow{d \to \infty} \mathcal{N}(0, 1)$$
3. Coordinate-wise scalar quantization is applied using precomputed Lloyd-Max optimal centroids $C = \{c_1, \dots, c_{2^b}\}$ for $\mathcal{N}(0, 1)$:
   $$\hat{x}_{\text{mse}} = \frac{1}{\sqrt{d}} Q_{\text{mse}}(\sqrt{d} \cdot x_{\text{rot}})$$

### 2.2 QJL Residual Correction (Stage 2: 1-Bit Sign Sketch)

The MSE quantization leaves an error residual:
$$r = x_{\text{rot}} - \hat{x}_{\text{mse}}$$
To capture the directional residual without ballooning memory:
1. Generate an oblivious Gaussian sign matrix $S \in \mathbb{R}^{m \times d}$ where $S_{ij} \sim \mathcal{N}(0, 1/m)$ or Rademacher signs $\pm 1/\sqrt{m}$.
2. Project and binarize the residual:
   $$z = \text{sign}(S r) \in \{-1, +1\}^m$$
3. Store the binary vector $z$ alongside the scalar residual norm $\|r\|_2$.

### 2.3 Unbiased Inner Product Estimator

For any query vector $y \in \mathbb{R}^d$:
1. Rotate query: $y_{\text{rot}} = R y$.
2. Compute MSE stage inner product: $\langle y_{\text{rot}}, \hat{x}_{\text{mse}} \rangle$.
3. Compute QJL residual projection:
   $$\widehat{\langle y_{\text{rot}}, r \rangle} = \sqrt{\frac{\pi}{2}} \cdot \frac{\|r\|_2}{\sqrt{m}} \cdot (S y_{\text{rot}})^\top z$$
4. Total estimated inner product:
   $$\widehat{\langle y, x \rangle} = \langle y_{\text{rot}}, \hat{x}_{\text{mse}} \rangle + \sqrt{\frac{\pi}{2}} \cdot \frac{\|r\|_2}{\sqrt{m}} \cdot (S y_{\text{rot}})^\top z$$

Because the expected value of the sign product under the Grothendieck / Sheppard identity satisfies $\mathbb{E}[\text{sign}(S r)^\top (S y_{\text{rot}})] = \sqrt{2/\pi} \cdot \frac{\langle r, y_{\text{rot}} \rangle}{\|r\|_2}$, the estimator is strictly unbiased:
$$\mathbb{E}[\widehat{\langle y, x \rangle}] = \langle y, x \rangle$$

---

## 3. Comparison with Alternative Quantization Schemes

| Metric | Flat FP32 | FP16 | Int8 Scalar | Product Quantization (PQ) | TurboQuant (3-bit + QJL) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Bits per Dimension** | 32 | 16 | 8 | 2–4 | **3 + 1 residual** |
| **Compression Ratio (128-d)** | 1.0x | 2.0x | 4.0x | 8.0x–16.0x | **7.11x** |
| **Training / Calibration** | None | None | Min/Max range | k-means clustering | **None (Oblivious)** |
| **Inner Product Bias** | 0 | 0 | Small | Significant | **Strictly 0 (Unbiased)** |
| **Cosine Accuracy** | 100% | 99.99% | 99.5% | 91.0%–94.0% | **98.40%** |
| **Crash-Safe Dynamic Updates** | Yes | Yes | Yes | No (requires retrain) | **Yes (Online)** |

---

## 4. Integration into AI Agent Workflows

```
                          ┌───────────────────────────┐
                          │    Incoming User Task     │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │   Query Dense Projection  │
                          └─────────────┬─────────────┘
                                        │
              ┌─────────────────────────┴─────────────────────────┐
              ▼                                                   ▼
┌───────────────────────────┐                       ┌───────────────────────────┐
│   TurboVec Skill Router   │                       │ Agent Long-Horizon Memory │
│  (2,771 AAS Skills / 3-bit)│                       │  (KV-Cache & Trajectories)│
├───────────────────────────┤                       ├───────────────────────────┤
│  Top-k tool/skill ranking │                       │  Episodic state recall    │
│  Latency: < 0.5 ms        │                       │  Memory savings: 7.11x    │
└───────────────────────────┘                       └───────────────────────────┘
```

---

## 5. Antagonist Analysis & Mitigations

1. **Low Dimensions ($d < 64$):**
   - *Risk:* PolarQuant relies on concentration on high-dimensional spheres. For low $d$, the coordinate distribution deviates from Gaussian.
   - *Mitigation:* The engine automatically uses 4-bit scalar quantization or uncompressed FP16 when $d < 64$.
2. **CPU Dequantization Overhead:**
   - *Risk:* Looping through thousands of vectors individually in Python incurs interpreter overhead.
   - *Mitigation:* Query rotation is precomputed once per search ($O(d^2)$ query prep), followed by vectorized batch SIMD dot products ($O(N \cdot d)$).
