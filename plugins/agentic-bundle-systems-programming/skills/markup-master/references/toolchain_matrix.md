# 38+ FOSS Markup & Notation Toolchain Matrix

This reference provides exact installation and invocation recipes for the 38+ open-source markup, schema, and notation tools cataloged by `markup-master`.

---

## 1. HTML Validation, Accessibility & Quality

| Tool Name | Binary | Install Command | Canonical Invocation | AST Fallback |
| :--- | :--- | :--- | :--- | :--- |
| **vnu** | `vnu` | `npm install -g vnu-jar` | `vnu --Werror public/index.html` | `HtmlDocInspector` |
| **axe-core** | `axe` | `npm install -g @axe-core/cli` | `axe public/index.html --tags wcag2a,wcag2aa` | `HtmlA11yArchitectAgent` |
| **htmlhint** | `htmlhint` | `npm install -g htmlhint` | `htmlhint public/**/*.html` | `HtmlDocInspector` |
| **pa11y** | `pa11y` | `npm install -g pa11y` | `pa11y http://localhost:8080` | `HtmlA11yArchitectAgent` |
| **DOMPurify** | `dompurify` | `npm install -g dompurify` | `dompurify < input.html > sanitized.html` | Native AST Sanitizer |
| **html-validate** | `html-validate` | `npm install -g html-validate` | `html-validate public/**/*.html` | `HtmlDocInspector` |
| **HTML Tidy** | `tidy` | `apt-get install tidy` | `tidy -q -e public/index.html` | Native Formatter |

---

## 2. JSON, OpenAPI & Schema Validation

| Tool Name | Binary | Install Command | Canonical Invocation | AST Fallback |
| :--- | :--- | :--- | :--- | :--- |
| **ajv-cli** | `ajv` | `npm install -g ajv-cli ajv-formats` | `ajv validate -s schema.json -d data.json --spec=draft2020` | `jsonschema` (Python) |
| **spectral-cli**| `spectral` | `npm install -g @stoplight/spectral-cli` | `spectral lint openapi.yaml` | `SchemaDataEngineerAgent` |
| **jq** | `jq` | `apt-get install jq` | `jq '.' data.json` | `json.loads` (Python) |
| **check-jsonschema**| `check-jsonschema` | `pip install check-jsonschema` | `check-jsonschema --schemafile schema.json data.json` | `jsonschema` (Python) |
| **fx** | `fx` | `npm install -g fx` | `fx data.json` | - |
| **jless** | `jless` | `cargo install jless` | `jless data.json` | - |
| **openapi-generator-cli** | `openapi-generator-cli` | `npm install -g @openapitools/openapi-generator-cli` | `openapi-generator-cli validate -i openapi.yaml` | `SchemaDataEngineerAgent` |

---

## 3. XML & SVG Processing

| Tool Name | Binary | Install Command | Canonical Invocation | AST Fallback |
| :--- | :--- | :--- | :--- | :--- |
| **xmllint** | `xmllint` | `apt-get install libxml2-utils` | `xmllint --schema schema.xsd data.xml --noout` | `xml.etree.ElementTree` |
| **jing** | `jing` | `apt-get install jing` | `jing schema.rng data.xml` | - |
| **svgo** | `svgo` | `npm install -g svgo` | `svgo input.svg -o output.svg` | `XmlSvgSpecialistAgent` |
| **xmlstarlet** | `xmlstarlet` | `apt-get install xmlstarlet` | `xmlstarlet val -e data.xml` | `xml.etree.ElementTree` |
| **defusedxml** | `defusedxml` | `pip install defusedxml` | `python3 -m defusedxml data.xml` | `XmlSvgSpecialistAgent` |
| **xmlformat** | `xmlformat` | `npm install -g xml-formatter-cli` | `xmlformat data.xml` | `xml.etree.ElementTree` |
| **trang** | `trang` | `apt-get install trang` | `trang schema.dtd schema.xsd` | - |

---

## 4. Markdown & Documentation Quality

| Tool Name | Binary | Install Command | Canonical Invocation | AST Fallback |
| :--- | :--- | :--- | :--- | :--- |
| **markdownlint-cli2** | `markdownlint-cli2` | `npm install -g markdownlint-cli2` | `markdownlint-cli2 "**/*.md"` | `MarkdownAstEngineerAgent` |
| **remark-cli** | `remark` | `npm install -g remark-cli` | `remark doc.md` | `MarkdownAstEngineerAgent` |
| **lychee** | `lychee` | `cargo install lychee` | `lychee "**/*.md"` | Anchor Slug Inspector |
| **prettier** | `prettier` | `npm install -g prettier` | `prettier --check "**/*.md"` | Native Formatter |
| **biome** | `biome` | `npm install -g @biomejs/biome` | `biome check data.json` | Native Formatter |
| **mdbook** | `mdbook` | `cargo install mdbook` | `mdbook build` | - |
| **vale** | `vale` | `brew install vale` | `vale docs/` | - |
| **mdformat** | `mdformat` | `pip install mdformat` | `mdformat --check doc.md` | Native Formatter |

---

## 5. YAML & TOML Linters

| Tool Name | Binary | Install Command | Canonical Invocation | AST Fallback |
| :--- | :--- | :--- | :--- | :--- |
| **yamllint** | `yamllint` | `pip install yamllint` | `yamllint -d relaxed config.yaml` | `yaml.safe_load` |
| **taplo** | `taplo` | `cargo install taplo-cli --locked` | `taplo check config.toml` | `tomllib` (Python stdlib) |
| **yq** | `yq` | `apt-get install yq` | `yq eval '.' config.yaml` | `yaml.safe_load` |
| **yaml-validator** | `yaml-validator` | `npm install -g yaml-validator` | `yaml-validator config.yaml` | `yaml.safe_load` |
| **toml-sort** | `toml-sort` | `pip install toml-sort` | `toml-sort --check config.toml` | `tomllib` (Python stdlib) |
| **actionlint** | `actionlint` | `go install github.com/rhysd/actionlint/cmd/actionlint@latest` | `actionlint .github/workflows/*.yml` | YAML Workflow Guard |

---

## 6. Tabular Data & Security Scanners

| Tool Name | Binary | Install Command | Canonical Invocation | AST Fallback |
| :--- | :--- | :--- | :--- | :--- |
| **csvkit** | `csvclean` | `pip install csvkit` | `csvclean -n data.csv` | `csv.reader` (Python stdlib) |
| **xsv** | `xsv` | `cargo install xsv` | `xsv stats data.csv` | `csv.reader` (Python stdlib) |
| **safe-regex2** | `safe-regex2` | `npm install -g safe-regex2` | `safe-regex2 "<pattern>"` | Regex AST Analyzer |
| **trivy** | `trivy` | `apt-get install trivy` | `trivy config .` | - |
| **gitleaks** | `gitleaks` | `brew install gitleaks` | `gitleaks detect --no-git` | - |
| **semgrep** | `semgrep` | `pip install semgrep` | `semgrep scan --config auto .` | - |
