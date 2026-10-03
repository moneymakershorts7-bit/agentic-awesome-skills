# Fact-Checking & Academic Verification Protocol

Rigorous fact-checking is what separates amateur content generation from professional, authoritative book publishing. This protocol defines the operational verification rules for the `book-editor-writer` skill.

---

## 1. The Fact-Checking Tiers of Evidence

When verifying claims from manuscripts, research notes, or PDFs, prioritize evidence according to this hierarchy:

| Tier | Source Category | Examples | Trust Level |
| :---: | :--- | :--- | :---: |
| **Tier 1** | Primary Archival & Official Records | National archives, treaty texts, patent filings, corporate financial 10-K filings, direct trial transcripts | Highest (Definitive) |
| **Tier 2** | Peer-Reviewed Research & Reference Compendiums | Science/Nature/Lancet papers, university press monographs, standard encyclopedias (Britannica), official statistical bureaus | High (Authoritative) |
| **Tier 3** | Reputable Investigative Journalism & Industry Reports | Reuters, AP, Bloomberg, Financial Times, specialized technical journals | Moderate-High (Corroborated) |
| **Tier 4** | Secondary Commentary & Non-Academic Memoirs | Blog posts, trade press opinion pieces, unauthorized biographies | Requires cross-verification |
| **Tier 5** | Unverified Online Anecdotes / Secondary Citations | Forum posts, general social media claims, undocumented hearsay | Unacceptable without primary proof |

---

## 2. Claim Classification & Verification Rules

Identify and categorize claims into three primary classes:

### A. Hard Factual Data (Dates, Figures, Names, Locations)
* **Rule:** Must be verified 1:1 against primary or secondary authoritative sources.
* **Tolerance:** Zero tolerance for invented dates, distorted casualty figures, altered statistics, or misspelled proper nouns.
* **Resolution:** If the source document contains an error (e.g., claiming the Fall of Constantinople occurred in 1492 instead of 1453), correct the error and add an editorial note if necessary.

### B. Attributed Quotes & Speeches
* **Rule:** Confirm exact wording from verbatim transcripts, correspondence, or established historical archives.
* **Misattributions:** Watch for commonly misattributed quotes (e.g., Einstein, Churchill, Voltaire, Mark Twain). If apocryphal, state clearly: *"Often attributed to X, though modern scholars trace the formulation to Y..."*

### C. Scientific, Technical, and Theological Theses
* **Rule:** Distinguish between consensus findings, minority hypotheses, and speculative propositions.
* **Nuance:** Never present a contested theoretical hypothesis as an undisputed law. Represent the current consensus alongside valid alternative perspectives.

---

## 3. Handling Contradictions and Gaps in Source Material

When input documents contain gaps, ambiguities, or contradictions:

1. **Flag Immediately:** Mark the passage in the chapter draft with an explicit editorial bracket:
   ```markdown
   > [!NOTE] Fact-Checking Note
   > The primary notes state [X], however peer-reviewed historical consensus indicates [Y]. The text has been framed to reflect [Y] while acknowledging [X].
   ```
2. **Search External Repositories:** Use web search or domain documentation to find the consensus or primary record.
3. **Escalate to Author/User:** If an ambiguity fundamentally alters a chapter's premise, present the two conflicting accounts to the user during the chapter review checkpoint.

---

## 4. Citation & Reference Formatting Standards

Every chapter must end with a formal reference section formatted cleanly in Markdown:

### Footnote Notation within Chapter Body:
```markdown
The alliance was ratified during the autumn of 1526[^1], altering the strategic balance...

[^1]: Smith, John A. *Diplomatic Treaties of the Early Modern Era*. Oxford University Press, 2018, pp. 112–115.
```

### Chapter-End Bibliographic Register:
```markdown
---
### 📚 Chapter References & Verified Sources
1. **Primary Documentation:** Archive Ref. #4410, National Historical Collection.
2. **Peer-Reviewed Reference:** Doe, J. (2021). "Quantitative Analysis of Trade Routes". *Journal of Economic History*, 45(2), 201–224.
3. **External Validation:** World Bank Statistical Database (2024 indicator release).
```
