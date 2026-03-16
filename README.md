# 🛡️ SSPM Policy Mapper v4

Maps organizational security standards/controls to SaaS Security Posture Management (SSPM) out-of-the-box policies using **SecBERT** — a BERT model pre-trained on cybersecurity text.

- ✅ No API keys. No internet after first model download.
- ✅ One SaaS app analysed at a time
- ✅ Supports 300+ apps via CSV/JSON input
- ✅ Detects 1:1, 1:many, many:1, many:many relationships
- ✅ Flags uncovered controls and orphan policies
- ✅ Security domain tracked from input to output

---

## 📁 Project Structure

```
sspm_v4/
├── sspm_mapper.py            # Main program
├── requirements.txt          # Python dependencies
├── README.md                 # This file
│
├── (auto-generated on first run)
│   ├── sample_controls.csv       # 18 sample controls across 6 domains
│   ├── sample_policies_m365.csv  # 20 sample Microsoft 365 OOTB policies
│   ├── mapping_report.json       # Output report
│   └── policy_cache/             # Cached SecBERT embeddings (speeds up re-runs)
```

---

## ⚙️ Setup

### Step 1 — Install Python dependencies

```bash
pip install -r requirements.txt
```

> **Requirements:** Python 3.10+, ~2GB disk space for SecBERT model.

---

### Step 2 — Download SecBERT model (one time)

Run this once on any machine that has internet access:

```bash
python download_secbert.py
```

This saves the model to `./secbert_model/` in your project folder.

Or download manually in Python:

```python
from transformers import AutoTokenizer, AutoModel
AutoTokenizer.from_pretrained("jackaduma/SecBERT", cache_dir="./secbert_model")
AutoModel.from_pretrained("jackaduma/SecBERT",     cache_dir="./secbert_model")
print("Done — model saved to ./secbert_model/")
```

> **Offline / air-gapped machines:** Download on an internet-connected machine,
> copy the `./secbert_model/` folder to the target machine, and set the path (see below).

---

### Step 3 — Point the code to your local model

Open `sspm_mapper.py` and set `SECBERT_MODEL_PATH` near the top of the file:

```python
# Line ~243 in sspm_mapper.py
SECBERT_MODEL_PATH = "./secbert_model"   # ← set this to your folder
```

Or pass it at runtime:

```python
from sspm_mapper import SSPMMapper
mapper = SSPMMapper(model_path="./secbert_model")
```

---

### Step 4 — Run

```bash
python sspm_mapper.py
```

On first run the program will:
1. Load SecBERT from your local folder
2. Auto-generate `sample_controls.csv` and `sample_policies_m365.csv` as working examples
3. Run the mapping and print the report to console
4. Save full output to `mapping_report.json`

---

## 🚀 How to Run

### Standard report
```bash
python sspm_mapper.py
```

### Verbose report (shows every control → policy match)
```bash
python sspm_mapper.py --verbose
python sspm_mapper.py -v
```

### Show API/library usage help
```bash
python sspm_mapper.py --help
```

---

## 📥 Input Files

### 1. Controls File (your org security standards)

**CSV format** — `sample_controls.csv`

| Column | Required | Description |
|---|---|---|
| `control_id` | ✅ | Unique ID e.g. `CTR-001`, `A.9.4.2` |
| `control_text` | ✅ | The actual control/requirement statement |
| `domain` | ✅ | Security domain e.g. `Access Control`, `Data Protection` |
| `framework` | ✅ | Standard name e.g. `ISO 27001`, `NIST CSF`, `GDPR` |
| `subdomain` | ❌ | Optional sub-reference e.g. `A.9.4.2` |
| `description` | ❌ | Optional extra detail for the control |

**Example:**
```csv
control_id,control_text,domain,framework,subdomain,description
CTR-001,All users must authenticate using MFA before accessing any SaaS application,Access Control,ISO 27001,A.9.4.2,
CTR-002,Sensitive PII must not be shared with external parties without approval,Data Protection,ISO 27001,A.8.2.3,
CTR-003,All user authentication events must be logged for minimum 12 months,Logging & Monitoring,ISO 27001,A.12.4.1,
```

**JSON format** — flat list:
```json
[
  {
    "control_id": "CTR-001",
    "control_text": "All users must authenticate using MFA",
    "domain": "Access Control",
    "framework": "ISO 27001",
    "subdomain": "A.9.4.2"
  }
]
```

**JSON format** — grouped by domain:
```json
{
  "Access Control": [
    { "control_id": "CTR-001", "control_text": "All users must use MFA", "framework": "ISO 27001" }
  ],
  "Data Protection": [
    { "control_id": "CTR-006", "control_text": "PII must not leave the org", "framework": "GDPR" }
  ]
}
```

---

### 2. Policies File (your OOTB policies for the app)

**CSV format** — `sample_policies_m365.csv`

| Column | Required | Description |
|---|---|---|
| `policy_id` | ✅ | Unique ID e.g. `POL-001` |
| `policy_name` | ✅ | The OOTB policy name |
| `category` | ❌ | Vendor category e.g. `Identity`, `Data Protection` |
| `description` | ❌ | Vendor description of what the policy does |
| `app_name` | ❌ | Required only if the file contains policies for multiple apps |

> ⚠️ **Important:** Policies must NOT contain framework references (ISO/NIST control numbers).
> The mapper's job is to discover those relationships — don't pre-bake them in.

> ℹ️ **No `app_name` column needed.** If your CSV is a single-app file (all rows belong to one app),
> just omit the `app_name` column entirely. The `app=` parameter in `load_policies()` is used
> as a display label only — it does not filter rows when no `app_name` column is present.

**Example — single app file:**
```csv
policy_id,policy_name,category,description
POL-001,Enable Multi-Factor Authentication for all users,Identity,Require MFA at every login
POL-002,Block legacy authentication protocols,Identity,Disable Basic Auth SMTP Auth IMAP POP3
POL-003,Enable audit log search and retention,Logging,Retain unified audit log for 90 days
POL-004,Enable Microsoft 365 DLP policies,Data Protection,Detect sensitive data in email and files
```

**Example — multi-app file (use `app_name` column):**
```csv
app_name,policy_id,policy_name,category,description
Microsoft 365,POL-001,Enable MFA for all users,Identity,MFA at every login
Salesforce,POL-050,Enforce MFA for Salesforce users,Identity,MFA required at Salesforce login
Okta,POL-100,Enable Okta MFA,Identity,MFA via Okta for all users
```

**JSON format:**
```json
[
  { "policy_id": "POL-001", "policy_name": "Enable MFA", "category": "Identity", "description": "..." },
  { "policy_id": "POL-002", "policy_name": "Block legacy auth", "category": "Identity", "description": "..." }
]
```

---

## 📤 Output

### Console output sections

```
═══════════════════════════════════════════════════════════════════════
  SSPM MAPPING REPORT  —  Microsoft 365
═══════════════════════════════════════════════════════════════════════
  Controls    : 18     Policies : 20
  Covered     : 14     Uncovered : 4     Orphan policies : 3
  FULL matches: 9      PARTIAL: 8        INDIRECT: 5

───────────────────────────────────────────────────────────────────────
  DOMAIN COVERAGE SUMMARY
───────────────────────────────────────────────────────────────────────
  Access Control        ████████████░░░░░░░░  60%   (3/5) ⚠ 2 HIGH risk
  Data Protection       ████████████████░░░░  75%   (3/4)
  Logging & Monitoring  ████████████████████ 100%   (3/3)
  Identity Management   ████████████████░░░░  75%   (3/4)
  Incident Response     ████████████████████ 100%   (2/2)
  Compliance            ████████░░░░░░░░░░░░  50%   (1/2)

───────────────────────────────────────────────────────────────────────
  MAPPING RELATIONSHIPS
───────────────────────────────────────────────────────────────────────
  1-to-1 : 6     1-to-many : 4     many-to-1 : 3     many-to-many : 2

───────────────────────────────────────────────────────────────────────
  UNCOVERED CONTROLS — Standards with no matching OOTB policy
───────────────────────────────────────────────────────────────────────
  ✘ [CTR-018] HIGH  Compliance / Art.46  GDPR
     Data residency requirements must be enforced — EU data must not leave EU

───────────────────────────────────────────────────────────────────────
  ORPHAN POLICIES — OOTB policies not required by any standard
───────────────────────────────────────────────────────────────────────
  ○ [POL-006] Enable Safe Links and Safe Attachments [Threat Protection]
```

### JSON output — `mapping_report.json`

```json
{
  "app": "Microsoft 365",
  "summary": {
    "total_controls": 18,
    "total_policies": 20,
    "covered_controls": 14,
    "uncovered_controls": 4,
    "orphan_policies": 3,
    "full_matches": 9,
    "partial_matches": 8,
    "indirect_matches": 5
  },
  "domain_summary": [
    {
      "domain": "Access Control",
      "total_controls": 5,
      "covered_controls": 3,
      "uncovered_controls": 2,
      "coverage_pct": 60,
      "high_risk_controls": 2,
      "coverage_status": "PARTIAL",
      "uncovered_control_ids": ["CTR-003", "CTR-005"]
    }
  ],
  "relationships": {
    "one_to_one":   [{ "control": "CTR-001", "policy": "POL-001" }],
    "one_to_many":  [{ "control": "CTR-009", "policies": ["POL-004", "POL-013"] }],
    "many_to_one":  [{ "policy": "POL-001", "controls": ["CTR-001", "CTR-002"] }],
    "many_to_many": [{ "controls": ["CTR-001","CTR-002"], "policies": ["POL-001","POL-017"] }]
  },
  "control_mappings": [
    {
      "control_id": "CTR-001",
      "control_text": "All users must authenticate using MFA...",
      "domain": "Access Control",
      "framework": "ISO 27001",
      "subdomain": "A.9.4.2",
      "risk_level": "HIGH",
      "is_covered": true,
      "match_count": 2,
      "matches": [
        {
          "policy_id": "POL-001",
          "policy_name": "Enable Multi-Factor Authentication for all users",
          "policy_category": "Identity",
          "similarity_score": 0.9124,
          "coverage": "FULL"
        }
      ]
    }
  ],
  "policy_mappings": [
    {
      "policy_id": "POL-001",
      "policy_name": "Enable Multi-Factor Authentication for all users",
      "policy_category": "Identity",
      "matched_controls": ["CTR-001", "CTR-002"],
      "match_count": 2,
      "is_orphan": false
    }
  ],
  "uncovered_controls": [
    {
      "control_id": "CTR-018",
      "control_text": "Data residency requirements must be enforced...",
      "domain": "Compliance",
      "framework": "GDPR",
      "subdomain": "Art.46",
      "risk_level": "HIGH",
      "reason": "No OOTB policy matches at or above threshold"
    }
  ],
  "orphan_policies": [
    {
      "policy_id": "POL-006",
      "policy_name": "Enable Safe Links and Safe Attachments",
      "policy_category": "Threat Protection",
      "reason": "No org control maps to this OOTB policy"
    }
  ]
}
```

---

## 🔁 Running for Multiple Apps

Run the mapper once per app. Each produces its own report:

```bash
# Edit main() in sspm_mapper.py to point to your files, OR use as a library:

python - <<EOF
from sspm_mapper import SSPMMapper

mapper = SSPMMapper()
mapper.load_controls("my_controls.csv")

for app, policy_file in [
    ("Microsoft 365",  "policies_m365.csv"),
    ("Salesforce",     "policies_salesforce.csv"),
    ("Google Workspace","policies_gws.csv"),
    ("Okta",           "policies_okta.csv"),
]:
    mapper.load_policies(policy_file, app=app)
    report = mapper.run()
    mapper.print_report(report)
    mapper.save_report(report, f"report_{app.replace(' ','_').lower()}.json")
EOF
```

---

## 🧠 How the Matching Works

```
Your Control Text
      │
      ▼
SecBERT Encoder → 768-dim vector

OOTB Policy Text (name + description + category)
      │
      ▼
SecBERT Encoder → 768-dim vector (cached after first run)

      │
      ▼
Cosine Similarity Matrix  (N controls × M policies)

      │
      ▼
Threshold filtering:
  ≥ 0.82  →  FULL      (strong semantic match)
  ≥ 0.60  →  PARTIAL   (moderate match)
  ≥ 0.40  →  INDIRECT  (weak / related match)
  < 0.40  →  no match

      │
      ▼
Relationship classification + gap analysis
```

SecBERT understands cybersecurity vocabulary natively so `"step-up authentication"` in your control maps correctly to `"Enable MFA"` in a policy — no training required.

---

## ⚡ Performance Notes

| Scenario | Time |
|---|---|
| First run (encode 20 policies) | ~30 seconds on CPU |
| Subsequent runs (cache hit) | ~3 seconds |
| 300 policies, first run | ~5 minutes on CPU |
| 300 policies, subsequent runs | ~5 seconds |

Policy vectors are cached in `policy_cache/` keyed by a hash of the policy text. Re-encoding only happens when policy content changes.

---

## 🛠️ Troubleshooting

**`transformers` not found → falls back to TF-IDF**
```bash
pip install torch transformers
```

**Slow on large policy sets**
- Run once to build the cache, subsequent runs are fast
- Use `force_rebuild=False` (default) to always use cache

**Low match scores across the board**
- Add `description` column to your policies file — short policy names alone give less signal
- Lower the threshold: `mapper.run(threshold=0.35)`

**Model download fails (no internet)**
- Pre-download on a machine with internet: `python -c "from transformers import AutoModel; AutoModel.from_pretrained('jackaduma/SecBERT')"`
- Copy `~/.cache/huggingface/` to the air-gapped machine
