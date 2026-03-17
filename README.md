# 🛡️ SSPM Policy Mapper — Complete Reference Guide

Maps organizational security standards to SaaS Security Posture Management (SSPM)
out-of-the-box (OOTB) policies using **SecBERT** semantic AI. Runs 100% locally.

---

## 📁 Project Files

```
sspm_v4/
├── sspm_mapper.py          # Main program — do NOT edit for configuration
├── sspm_config.py          # ALL configuration — edit this file only
├── download_secbert.py     # Run once to download SecBERT model
├── domain_pairs.json       # Optional: external domain pairing file
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── secbert_clean/          # SecBERT model folder (after download)
├── sample_controls.csv     # Sample controls file
├── sample_policies_m365.csv# Sample policies file
└── policy_cache/           # Auto-created embedding cache
```

**Key principle:** `sspm_mapper.py` is the engine. `sspm_config.py` is the config.
You should **only ever edit `sspm_config.py`** — never `sspm_mapper.py`.

---

## ⚙️ Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Download SecBERT (once, needs internet)
python download_secbert.py
# → saves to ./secbert_clean/

# 3. Set model path in sspm_config.py (line 1)
SECBERT_MODEL_PATH = "./secbert_clean"

# 4. Run with sample data
python sspm_mapper.py
```

---

## 🚀 Running

```bash
# Basic run
python sspm_mapper.py \
  --controls  your_controls.csv \
  --policies  your_policies.csv \
  --app       "Salesforce"

# With custom domain pairs file
python sspm_mapper.py \
  --controls  your_controls.csv \
  --policies  your_policies.csv \
  --app       "Salesforce" \
  --domain-pairs domain_pairs.json

# Disable domain filter (all vs all)
python sspm_mapper.py ... --no-domain-filter

# Force re-encode (after editing sspm_config.py)
python sspm_mapper.py ... --clear-cache

# All arguments
python sspm_mapper.py --help
```

### All CLI arguments

| Argument | Short | Default | Description |
|---|---|---|---|
| `--controls` | `-c` | sample data | Controls/standards CSV or JSON |
| `--policies` | `-p` | sample data | OOTB policies CSV or JSON |
| `--app` | `-a` | from filename | App name — report title + output prefix |
| `--out` | `-o` | from app name | Output file prefix |
| `--model` | `-m` | from config | Local SecBERT model folder path |
| `--threshold` | `-t` | `0.40` | Minimum similarity score |
| `--topk` | `-k` | `5` | Max policy matches per control |
| `--verbose` | `-v` | off | Show all match details in console |
| `--domain-pairs` | `-d` | built-in | JSON file with custom domain pairing |
| `--no-domain-filter` | | off | Disable domain filtering |
| `--clear-cache` | | off | Delete cached embeddings before run |

---

## 📥 Input File Formats

### Controls CSV

```csv
control_id,control_text,domain,framework,subdomain,description
ISO-AC-001,All users must authenticate using MFA,Identity and Access Management,ISO 27001,A.9.4.2,
ISO-DP-001,Data in transit must be encrypted using TLS,Data Protection,ISO 27001,A.10.1.1,
```

| Column | Required | Description |
|---|---|---|
| `control_id` | ✅ | Your ID — any format (`ISO-AC-001`, `A.9.4.2`, `CTR-001`) |
| `control_text` | ✅ | The actual requirement statement |
| `domain` | ✅ | Security domain — must match `sspm_config.py` DOMAIN_PAIRS keys |
| `framework` | ✅ | `ISO 27001`, `NIST CSF`, `GDPR` etc. |
| `subdomain` | ❌ | Optional sub-reference e.g. `A.9.4.2` |
| `description` | ❌ | Extra detail — improves matching quality |

### Policies CSV

```csv
policy_id,policy_name,category,description,impact
SF-001,Trusted IP Ranges Configuration,Access Control,Restricts IP addresses...,HIGH
SF-002,Enable SSO,Identity,Enable Single Sign-On via SAML...,HIGH
```

| Column | Required | Description |
|---|---|---|
| `policy_id` | ✅ | Your ID — any format |
| `policy_name` | ✅ | OOTB policy name |
| `category` | ❌ | Policy domain — must match DOMAIN_PAIRS values |
| `description` | ❌ | **Highly recommended** — significantly improves matching |
| `impact` | ❌ | `HIGH`, `MEDIUM`, `LOW` |

> ⚠️ **Excel BOM:** If your CSV was saved from Excel, the code handles the BOM
> automatically. No action needed.

> ⚠️ **No `app_name` column needed** for single-app files. The `--app` argument
> is a display label only.

---

## 📤 Output Files

| File | Description |
|---|---|
| `<app>_report.xlsx` | **Excel workbook — 9 sheets** |
| `<app>_report.json` | Full structured JSON report |
| `<app>_control_mappings.csv` | Every control → matched policies |
| `<app>_policy_mappings.csv` | Every policy → matched controls |
| `<app>_uncovered_controls.csv` | Controls with no matching policy |
| `<app>_orphan_policies.csv` | Policies not required by any control |
| `<app>_domain_summary.csv` | Coverage % per security domain |

### Excel Sheets (9)

| # | Sheet | What's in it |
|---|---|---|
| 1 | **Summary** | KPI counts + domain coverage % with FULL/PARTIAL/INDIRECT breakdown |
| 2 | **Control Mappings** | Every control → every matched policy, one row per pair |
| 3 | **Policy Mappings** | Every policy → every matched control |
| 4 | **Uncovered Controls** | Standards with no OOTB policy match |
| 5 | **Orphan Policies** | OOTB policies not required by any standard |
| 6 | **Relationships** | 1:1, 1:many, many:1, many:many mapping groups |
| 7 | **One-to-Many** | Controls that matched multiple policies (detailed) |
| 8 | **Mind Map** | Visual tree: Domain → Control → Policy Name → Description → Coverage |
| 9 | **Domain Graph** | Tree: Security Domain → Policy Domain → Policies |

### Match Source column (Control Mappings sheet)

| Colour | Value | Meaning |
|---|---|---|
| 🟢 Green | `domain_paired` | Found via domain pairing (Pass 1 — expected match) |
| 🟡 Yellow | `cross_domain` | Found via cross-domain scan (Pass 2 — cross-boundary match) |

---

## 🧠 How Matching Works

```
Your Control Text
        │
        ▼
  expand_synonyms()    ← abbreviation expansion (MFA → multi-factor...)
  expand_concepts()    ← vocabulary bridging (geofencing → conditional access...)
        │
        ▼
  SecBERT Encoder  ──→  768-dimensional vector

OOTB Policy Text
        │
        ▼  (same pipeline + enrich_policy_from_library() if no description)
  SecBERT Encoder  ──→  768-dimensional vector (cached)

        │
        ▼
  Domain Filter (Pass 1):  only score allowed domain pairs
  Cross-Domain (Pass 2):   scan blocked pairs at higher threshold (0.65)

        │
        ▼
  Cosine Similarity Matrix  (N controls × M policies)

        │
        ▼
  hybrid_score():
    base_cosine_score
    + keyword_group_boost    (shared security term groups)
    + jaccard_token_boost    (shared technical vocabulary)
    + domain_category_boost  (structural alignment)
    - nonsense_penalty       (zero keyword overlap)
    - conflict_penalty       (e.g. at-rest vs in-transit detected)

        │
        ▼
  FULL ≥ 0.82  |  PARTIAL ≥ 0.60  |  INDIRECT ≥ 0.40  |  < 0.40 = no match
```

---

## ⚙️ Configuration Reference (`sspm_config.py`)

### Section 1 — Model Path
```python
SECBERT_MODEL_PATH = "./secbert_clean"
```

### Section 2 — Thresholds
```python
THRESHOLD_FULL     = 0.82   # Strong match
THRESHOLD_PARTIAL  = 0.60   # Moderate match
THRESHOLD_INDIRECT = 0.40   # Weak match
THRESHOLD_MIN      = 0.40   # Minimum to include in output
```

### Section 3 — Scoring Constants
```python
KEYWORD_BOOST    = 0.08   # Per shared keyword group
DOMAIN_BOOST     = 0.05   # When domains align
NONSENSE_PENALTY = 0.20   # When zero keyword overlap
CONFLICT_PENALTY = 0.25   # When conflicting sub-groups detected
```

---

## 🔍 Troubleshooting Guide

### A — Finding and Fixing False Positives

A **false positive** is when a control incorrectly matches a policy that isn't relevant.

**Example from production:** "Data in transit encryption" control was matching
`[Shield] Encryption – Encrypt Event Bus Data` (an at-rest policy).

#### Step 1 — Identify the false positive

Run with `--verbose` flag and look for unexpected matches:
```bash
python sspm_mapper.py --controls ... --policies ... --app "..." --verbose
```

Or check the `Control Mappings` sheet in the Excel output — look for matches
that don't make sense.

#### Step 2 — Use explain_match() to diagnose

```python
from sspm_mapper import SSPMMapper

mapper = SSPMMapper()
mapper.load_controls("your_controls.csv")
mapper.load_policies("your_policies.csv", app="Salesforce")

# Call BEFORE run() to see keyword group assignments
mapper.explain_match("your_control_id", "your_policy_id")
```

Output shows:
```
Control keyword groups : ['encryption_general', 'encryption_in_transit']
Policy  keyword groups : ['encryption_at_rest', 'encryption_general']
Shared groups          : ['encryption_general']  → boost = +0.08
Total boost            : +0.28
```

#### Step 3 — Fix it

**Option A — Add a CONFLICT_PAIR** (best for structural opposites like at-rest vs in-transit):

Open `sspm_config.py` → Section 4 → `CONFLICT_PAIRS`:
```python
CONFLICT_PAIRS = [
    ("encryption_at_rest",   "encryption_in_transit"),   # already exists
    ("your_group_a",         "your_group_b"),             # add this
]
```

**Option B — Add wrong terms to a keyword group** so penalty fires:

If the control is matching because both share a generic group (e.g. `encryption_general`),
make the groups more specific. Open `sspm_config.py` → Section 8 → add the
specific term to the correct sub-group.

**Option C — Add a CONCEPT_BRIDGE** to explicitly disambiguate:

```python
CONCEPT_BRIDGES = [
    ...
    ("your_ambiguous_term",
     "specific vocabulary that only matches the RIGHT policy"),
]
```

#### Step 4 — Clear cache and re-run

```bash
rm -rf policy_cache/
python sspm_mapper.py ... --clear-cache
```

---

### B — Finding and Fixing Missed Matches

A **missed match** is when a control SHOULD map to a policy but doesn't.

**Example:** "Geofencing access controls" not matching "Trusted IP Ranges Configuration".

#### Step 1 — Run explain_match() to diagnose

```python
mapper.explain_match("your_ctrl_id", "policy_that_should_match")
```

Look at:
- **Shared groups**: If empty → no keyword overlap → no boost
- **Encoded control text**: Does it contain the right vocabulary?
- **Encoded policy text**: Does it contain the right vocabulary?

#### Step 2 — Fix it

**Option A — Add a CONCEPT_BRIDGE** (best fix for vocabulary mismatch):

Open `sspm_config.py` → Section 7 → `CONCEPT_BRIDGES`:
```python
("your_control_term",
 "vocabulary that appears in the matching policy"),
```

Example that was added for geofencing:
```python
("geofenc",
 "geofencing location-based access conditional access trusted location "
 "ip range network location restriction country block"),
```

**Option B — Add to POLICY_NAME_LIBRARY** (for short policy names with no description):

Open `sspm_config.py` → Section 9 → `POLICY_NAME_LIBRARY`:
```python
"your policy name here": (
    "description using vocabulary from your control standards"
),
```

**Option C — Add terms to KEYWORD_GROUPS**:

If the control and policy are in the same security concept but the keyword
group doesn't include their specific terms, add them:
```python
"access_control": [
    ...,
    "your_new_term",
    "another_synonym",
],
```

**Option D — Adjust domain pairing** if the policy is in a different domain:

Check `domain_pairs.json` — the policy's category may not be in the allowed
list for the control's domain. Either add it to Pass 1 pairs or it will be
found in Pass 2 (cross-domain) automatically if the semantic score is ≥ 0.65.

#### Step 3 — Clear cache and re-run

```bash
rm -rf policy_cache/
python sspm_mapper.py ... --clear-cache
```

---

### C — Encryption At-Rest vs In-Transit Issue

This is a known challenging case. The fix is already built in:

**How it works:**
- `encryption_at_rest` group: `"at rest"`, `"storage encrypt"`, `"shield encrypt"`,
  `"event bus"`, `"search index"`, `"field history"`, `"deterministic"` etc.
- `encryption_in_transit` group: `"in transit"`, `"tls"`, `"ssl"`, `"https"`,
  `"transport"`, `"network encrypt"` etc.
- `CONFLICT_PAIRS` has `("encryption_at_rest", "encryption_in_transit")`

**If still getting false matches:**
1. Run `explain_match()` to see which groups are firing
2. Check if the problematic term is in the wrong group in `sspm_config.py`
3. Add the vendor-specific at-rest term to `encryption_at_rest`:

```python
"encryption_at_rest": [
    ...,
    "your vendor at-rest term",   # add here
],
```

---

### D — New Policy Domain Not Being Paired

When you run the mapper, it will warn you about unknown policy domains:
```
⚠️  NEW POLICY DOMAINS DETECTED — not in domain_pairs.json:
    → 'Mobile Security'  (add to domain_pairs.json to control pairing)
```

Unknown domains are **allowed through automatically** so nothing is lost.
To add them to proper domain pairing, open `sspm_config.py` → Section 5:

```python
DOMAIN_PAIRS = {
    "identity and access management": [
        "mfa",
        "access control",
        "mobile security",   # ← add the new domain here
    ],
    ...
}
```

Or update `domain_pairs.json` if you're using that:
```json
{
  "identity and access management": [
    "mfa",
    "access control",
    "mobile security"
  ]
}
```

---

### E — IDs Showing as CTR-001 / POL-001 Instead of Your IDs

**Cause:** Your CSV was saved from Excel and has a BOM character that corrupts
the first column name.

**Fix:** Already handled automatically. The code uses `utf-8-sig` encoding.

**To verify:** Look for the `Sample IDs` line in the console output:
```
📋  Controls loaded : 18 controls
     Sample IDs     : ['ISO-AC-001', 'ISO-AC-002']  ← from your file
```

If you still see `CTR-001`, your column is named something unexpected. Run:
```bash
python -c "import csv; r=csv.DictReader(open('your_controls.csv',encoding='utf-8-sig')); print(r.fieldnames)"
```
And use one of the accepted column names: `control_id`, `id`, `control_no`, `ref`, `no`, `number`.

---

### F — Score Too Low (Valid Match Missed)

Lower the threshold:
```bash
python sspm_mapper.py ... --threshold 0.35
```

Or reduce `THRESHOLD_MIN` in `sspm_config.py` Section 2 permanently.

---

### G — Too Many Low-Quality Matches

Raise the threshold:
```bash
python sspm_mapper.py ... --threshold 0.50
```

Or increase `NONSENSE_PENALTY` in `sspm_config.py` Section 3.

---

### H — SecBERT Not Loading (Falls Back to TF-IDF)

```bash
pip install torch transformers tokenizers protobuf
```

If HuggingFace is blocked:
```bash
# On internet machine
python download_secbert.py
# Copy secbert_clean/ folder to work machine
# Set in sspm_config.py:
SECBERT_MODEL_PATH = "./secbert_clean"
```

---

### I — Cache Issues After Config Change

Any time you edit `sspm_config.py` (keyword groups, concept bridges, synonyms),
you **must clear the cache** — otherwise old vectors are used:

```bash
rm -rf policy_cache/
# OR use the flag:
python sspm_mapper.py ... --clear-cache
```

---

## 📋 Quick Cheat Sheet

```bash
# First time setup
pip install -r requirements.txt
python download_secbert.py
# Edit sspm_config.py: SECBERT_MODEL_PATH = "./secbert_clean"

# Run with your data
python sspm_mapper.py \
  --controls  your_controls.csv \
  --policies  your_policies.csv \
  --app       "Salesforce" \
  --clear-cache

# Debug a specific match
python -c "
from sspm_mapper import SSPMMapper
m = SSPMMapper()
m.load_controls('your_controls.csv')
m.load_policies('your_policies.csv', app='Salesforce')
m.explain_match('CTRL-ID', 'POL-ID')
"

# After editing sspm_config.py
rm -rf policy_cache/
python sspm_mapper.py ... --clear-cache

# Disable domain filter to see all possible matches
python sspm_mapper.py ... --no-domain-filter

# Multiple apps
for app in Salesforce "Microsoft 365" Okta; do
  python sspm_mapper.py \
    --controls controls.csv \
    --policies ${app// /_}_policies.csv \
    --app "$app" \
    --clear-cache
done
```

---

## 🗂️ sspm_config.py Section Quick Reference

| Section | What to Edit | When |
|---|---|---|
| 1 Model Path | `SECBERT_MODEL_PATH` | Once after download |
| 2 Thresholds | `THRESHOLD_*` | If too many/few matches |
| 3 Scoring | `*_BOOST`, `*_PENALTY` | Fine-tuning match quality |
| 4 Conflict Pairs | `CONFLICT_PAIRS` | When false positive found |
| 5 Domain Pairs | `DOMAIN_PAIRS` | New domains / changed pairing |
| 6 Synonym Map | `SYNONYM_MAP` | New abbreviation not recognized |
| 7 Concept Bridges | `CONCEPT_BRIDGES` | Missed match due to vocabulary gap |
| 8 Keyword Groups | `KEYWORD_GROUPS` | New security term not in any group |
| 9 Policy Library | `POLICY_NAME_LIBRARY` | New app with short policy names |

**After ANY edit to sspm_config.py:**
```bash
rm -rf policy_cache/ && python sspm_mapper.py ... --clear-cache
```
