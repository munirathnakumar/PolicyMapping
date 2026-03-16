# 🛡️ SSPM Policy Mapper

Maps organizational security standards/controls to SaaS Security Posture Management (SSPM) out-of-the-box (OOTB) policies using **SecBERT** — a BERT model pre-trained on cybersecurity text. Runs 100% locally. No API keys required.

---

## ✅ What It Does

- Maps org security controls (ISO 27001 / NIST CSF / GDPR etc.) to SSPM OOTB policies
- Detects **1:1, 1:many, many:1, many:many** mapping relationships
- Flags **uncovered controls** (standards with no matching policy)
- Flags **orphan policies** (policies not required by any standard)
- Tracks **security domain** from input through to output
- Includes **INDIRECT matches** in coverage % (since direct mapping is not always possible)
- Exports results to **Excel (.xlsx) with 8 sheets**, CSV files, and JSON

---

## 📁 Project Structure

```
your-project/
├── sspm_mapper.py              # Main program — run this
├── download_secbert.py         # Run once to download the model
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── secbert_clean/              # SecBERT model folder (after download)
│   ├── config.json
│   ├── vocab.txt
│   ├── tokenizer.json
│   ├── tokenizer_config.json
│   ├── special_tokens_map.json
│   └── model.safetensors       # ~318 MB model weights
├── your_controls.csv           # Your org security standards (you provide)
├── your_policies.csv           # Your OOTB policies for one app (you provide)
│
└── (auto-created at runtime)
    ├── sample_controls.csv         # Sample data — generated on first run
    ├── sample_policies_m365.csv    # Sample data — generated on first run
    ├── policy_cache/               # Cached embeddings — speeds up re-runs
    ├── <app>_report.xlsx           # Excel output — 8 sheets
    ├── <app>_report.json           # Full JSON output
    ├── <app>_control_mappings.csv
    ├── <app>_policy_mappings.csv
    ├── <app>_uncovered_controls.csv
    ├── <app>_orphan_policies.csv
    └── <app>_domain_summary.csv
```

---

## ⚙️ Setup — Do This Once

### Step 1 — Install dependencies

```bash
pip install -r requirements.txt
```

Requirements: Python 3.10+, ~500MB disk for model.

---

### Step 2 — Download SecBERT model

Run on a machine with internet access (one time only):

```bash
python download_secbert.py
```

This saves the model to `./secbert_clean/`. You will see:
```
Downloading tokenizer...   ✓
Downloading model weights (~318MB) ...   ✓

Files created:
  config.json                    0.001 MB
  model.safetensors            318.351 MB   ← the main weights file
  tokenizer.json                 1.146 MB
  tokenizer_config.json          0.001 MB
  special_tokens_map.json        0.000 MB
  vocab.txt                      0.360 MB
```

> **HuggingFace blocked in your org?**
> Download on a personal machine → copy `secbert_clean/` folder to work machine via USB, shared drive, or Git LFS.

---

### Step 3 — Point the code to your model folder

Open `sspm_mapper.py` and set this line near the top (~line 243):

```python
SECBERT_MODEL_PATH = "./secbert_clean"
```

---

### Step 4 — Prepare your input files

You need two CSV files. See **Input Files** section below for full column details.

---

## 🚀 How to Run

### Basic syntax

```bash
python sspm_mapper.py \
  --controls  your_controls.csv \
  --policies  your_policies.csv \
  --app       "Microsoft 365"
```

### All available arguments

| Argument | Short | Default | Description |
|---|---|---|---|
| `--controls` | `-c` | sample data | Path to your controls/standards CSV or JSON |
| `--policies` | `-p` | sample data | Path to your OOTB policies CSV or JSON |
| `--app` | `-a` | derived from filename | App name — used as report title and output file prefix |
| `--out` | `-o` | derived from app name | Output file prefix e.g. `--out salesforce` |
| `--model` | `-m` | value in SECBERT_MODEL_PATH | Path to local SecBERT model folder |
| `--threshold` | `-t` | `0.40` | Minimum similarity score to include a match |
| `--topk` | `-k` | `5` | Max policy matches returned per control |
| `--verbose` | `-v` | off | Show every control→policy match detail in console |

---

### Run examples

**Run with your own files:**
```bash
python sspm_mapper.py \
  --controls  my_controls.csv \
  --policies  m365_policies.csv \
  --app       "Microsoft 365" \
  --out       microsoft_365
```

**Run with sample data (no files needed — auto-generated):**
```bash
python sspm_mapper.py
```

**Verbose output (shows every match in console):**
```bash
python sspm_mapper.py \
  --controls  my_controls.csv \
  --policies  m365_policies.csv \
  --app       "Microsoft 365" \
  --verbose
```

**Custom model path at runtime:**
```bash
python sspm_mapper.py \
  --controls  my_controls.csv \
  --policies  m365_policies.csv \
  --app       "Salesforce" \
  --model     /opt/models/secbert_clean
```

**Lower threshold to catch more indirect matches:**
```bash
python sspm_mapper.py \
  --controls  my_controls.csv \
  --policies  m365_policies.csv \
  --app       "Microsoft 365" \
  --threshold 0.35
```

**Run for multiple apps (one at a time):**
```bash
python sspm_mapper.py --controls controls.csv --policies m365_policies.csv    --app "Microsoft 365"    --out microsoft_365
python sspm_mapper.py --controls controls.csv --policies salesforce_policies.csv --app "Salesforce"       --out salesforce
python sspm_mapper.py --controls controls.csv --policies okta_policies.csv       --app "Okta"             --out okta
python sspm_mapper.py --controls controls.csv --policies slack_policies.csv      --app "Slack"            --out slack
```

Each run produces its own set of output files prefixed with the app name.

---

## 📥 Input Files

### 1. Controls File — your org security standards

**CSV columns:**

| Column | Required | Accepted names | Description |
|---|---|---|---|
| `control_id` | ✅ | `control_id`, `id`, `control_no` | Unique ID e.g. `CTR-001`, `A.9.4.2` |
| `control_text` | ✅ | `control_text`, `control`, `requirement` | The actual control statement |
| `domain` | ✅ | `domain`, `security_domain`, `category` | Security domain e.g. `Access Control` |
| `framework` | ✅ | `framework`, `standard` | Standard name e.g. `ISO 27001`, `NIST CSF` |
| `subdomain` | ❌ | `subdomain`, `sub_domain` | Sub-reference e.g. `A.9.4.2` |
| `description` | ❌ | `description`, `notes` | Extra detail for the control |

**Example:**
```csv
control_id,control_text,domain,framework,subdomain
CTR-001,All users must authenticate using MFA before accessing any SaaS application,Access Control,ISO 27001,A.9.4.2
CTR-002,Sensitive PII must not be shared externally without approval,Data Protection,ISO 27001,A.8.2.3
CTR-003,All authentication events must be logged and retained for 12 months,Logging & Monitoring,ISO 27001,A.12.4.1
CTR-004,Anomalous login behaviour must trigger automated alerts,Incident Response,NIST CSF,DE.AE-2
```

---

### 2. Policies File — your OOTB policies for one app

**CSV columns:**

| Column | Required | Accepted names | Description |
|---|---|---|---|
| `policy_id` | ✅ | `policy_id`, `id` | Unique ID e.g. `POL-001` |
| `policy_name` | ✅ | `policy_name`, `policy`, `name` | The OOTB policy name |
| `category` | ❌ | `category`, `type` | Vendor category e.g. `Identity`, `Data Protection` |
| `description` | ❌ | `description`, `desc` | What the policy does — **improves match quality** |
| `impact` | ❌ | `impact`, `impact_level`, `severity`, `priority` | Impact level e.g. `HIGH`, `MEDIUM`, `LOW` |

> ⚠️ **Do NOT include ISO/NIST control numbers in your policy file.**
> The mapper's job is to discover those relationships from the text.

> ℹ️ **No `app_name` column needed** for single-app files. Just omit it.
> The `--app` argument is a display label — not a filter.

**Example — single app file (recommended):**
```csv
policy_id,policy_name,category,description,impact
POL-001,Enable Multi-Factor Authentication for all users,Identity,Require MFA at every login for all accounts,HIGH
POL-002,Block legacy authentication protocols,Identity,Disable Basic Auth SMTP Auth IMAP POP3,HIGH
POL-003,Configure Conditional Access policies,Access Control,Risk-based access based on location and device,HIGH
POL-004,Enable audit log search and retention,Logging,Retain unified audit log minimum 90 days,MEDIUM
POL-005,Enable Microsoft 365 DLP policies,Data Protection,Detect and block sensitive data in email and files,HIGH
```

**Example — multi-app file (optional `app_name` column):**
```csv
app_name,policy_id,policy_name,category,description,impact
Microsoft 365,POL-001,Enable MFA for all users,Identity,MFA at every login,HIGH
Salesforce,POL-050,Enforce MFA for Salesforce users,Identity,MFA required at login,HIGH
Okta,POL-100,Enable Okta MFA,Identity,MFA enforced via Okta,HIGH
```

---

## 📤 Output Files

Every run produces these files, all prefixed with your app name:

| File | Description |
|---|---|
| `<app>_report.xlsx` | **Excel workbook — 8 sheets** (main deliverable) |
| `<app>_report.json` | Full structured JSON report |
| `<app>_control_mappings.csv` | Every control with all matched policies |
| `<app>_policy_mappings.csv` | Every policy with all matched controls |
| `<app>_uncovered_controls.csv` | Controls with NO matching policy |
| `<app>_orphan_policies.csv` | Policies not required by any control |
| `<app>_domain_summary.csv` | Coverage % per security domain |

---

### Excel Workbook — 8 Sheets

| # | Sheet | What's in it |
|---|---|---|
| 1 | **Summary** | KPI counts + domain coverage table with FULL/PARTIAL/INDIRECT breakdown |
| 2 | **Control Mappings** | Every control → every matched policy, one row per pair |
| 3 | **Policy Mappings** | Every policy → every matched control, one row per pair |
| 4 | **Uncovered Controls** | Standards with no matching OOTB policy |
| 5 | **Orphan Policies** | OOTB policies not required by any standard |
| 6 | **Relationships** | 1:1, 1:many, many:1, many:many mapping groups |
| 7 | **One-to-Many** | Controls that matched multiple policies (with separator rows) |
| 8 | **Mind Map** | Visual tree — Domain → Control → Policies, colour coded by coverage |

---

### Coverage % Calculation

Coverage % **includes INDIRECT matches** because direct mapping is not always possible with OOTB policies.

| Match Type | Score | Counted in Coverage % |
|---|---|---|
| FULL | ≥ 0.82 | ✅ Yes |
| PARTIAL | ≥ 0.60 | ✅ Yes |
| INDIRECT | ≥ 0.40 | ✅ Yes |
| No match | < 0.40 | ❌ No |

The Summary sheet shows a breakdown per domain:

```
Domain               Total  Covered  Uncovered  Coverage%  FULL  PARTIAL  INDIRECT  Status
Access Control           5        3          2        60%     2        1         0    GOOD
Data Protection          4        4          0       100%     1        2         1    FULL
Logging & Monitoring     3        3          0       100%     2        1         0    FULL
Identity Management      3        2          1        67%     1        1         0    GOOD
Incident Response        2        1          1        50%     0        1         0  PARTIAL
Compliance               2        1          1        50%     0        0         1  PARTIAL  ← INDIRECT counted
```

The **Note** column flags when INDIRECT is contributing to the coverage %.

---

### Console Output

```
══════════════════════════════════════════════════════════════════════
  SSPM MAPPING REPORT  —  Microsoft 365
══════════════════════════════════════════════════════════════════════
  Controls : 18     Policies : 20
  Covered  : 14     Uncovered : 4     Orphan policies : 3
  FULL : 9   PARTIAL : 8   INDIRECT : 5   (all 3 count toward coverage %)

  DOMAIN COVERAGE SUMMARY
  Access Control       ████████████░░░░░░░░  60%  (3/5)  F:2 P:1 I:0  ⚠ 1 HIGH
  Data Protection      ████████████████████ 100%  (4/4)  F:1 P:2 I:1
  Logging & Monitoring ████████████████████ 100%  (3/3)  F:2 P:1 I:0

  MAPPING RELATIONSHIPS
  1-to-1 : 6     1-to-many : 4     many-to-1 : 3     many-to-many : 2

  UNCOVERED CONTROLS — Standards with no matching OOTB policy
  ✘ [CTR-018] HIGH  Compliance / Art.46  GDPR
     Data residency requirements — EU data must not leave EU region

  ORPHAN POLICIES — OOTB policies not required by any standard
  ○ [POL-006] Enable Safe Links and Safe Attachments [Threat Protection]
══════════════════════════════════════════════════════════════════════
```

---

## 🧠 How the Matching Works

```
Control Text (your org standard)
        │
        ▼
  SecBERT Encoder  ──→  768-dimensional vector

OOTB Policy Text (name + description + category)
        │
        ▼
  SecBERT Encoder  ──→  768-dimensional vector
        │
        └─── cached to policy_cache/ after first run

        │
        ▼
  Cosine Similarity Matrix  (N controls × M policies)
        │
        ▼
  Score thresholds:
    ≥ 0.82  →  FULL      strong semantic match
    ≥ 0.60  →  PARTIAL   moderate match
    ≥ 0.40  →  INDIRECT  weak / related match  ← counted in coverage %
    < 0.40  →  no match

        │
        ▼
  Relationship detection  +  Gap analysis  +  Domain summary
```

**Why SecBERT?**
Standard BERT is trained on Wikipedia. SecBERT is trained on cybersecurity text — CVEs, threat reports, security advisories — so it natively understands terms like `MFA`, `OAuth`, `RBAC`, `DLP`, `audit trail`, `privilege escalation`, `ISO 27001 A.9`, `NIST CSF PR.AC`. This makes semantic matching far more accurate for security controls.

---

## ⚡ Performance

| Scenario | First Run | Subsequent Runs |
|---|---|---|
| Load SecBERT model | 5–10 sec | 5–10 sec |
| Encode 20 policies | ~20–40 sec | instant (cache) |
| Encode 18 controls | ~15–25 sec | ~15–25 sec |
| Mapping + report | < 1 sec | < 1 sec |
| **Total (20 policies)** | **~60 sec** | **~20 sec** |
| 300 policies, first run | ~5 min | ~20 sec |

Policy vectors are cached in `policy_cache/` keyed by a hash of the policy text. Only re-encodes when policies change.

**Clear cache manually:**
```bash
rm -rf policy_cache/
```

---

## 🛠️ Troubleshooting

**SecBERT unavailable → falls back to TF-IDF**
```bash
pip install torch transformers tokenizers protobuf
```

**`Could not instantiate the backend tokenizer`**
```bash
pip install tokenizers
```

**`requires protobuf`**
```bash
pip install protobuf
```

**`input operand has mismatch in core dimension` (numpy error)**
```bash
# Clear old cache — it may have TF-IDF vectors from a previous run
rm -rf policy_cache/
# Then re-run
python sspm_mapper.py --controls ... --policies ... --app "..."
```

**0 policies loaded**

Your CSV has no `app_name` column (single-app file) — this is fine. The code auto-retries without the filter. If still 0, check that your CSV has a `policy_name` or `policy` column.

**Excel file not generated**
```bash
pip install openpyxl
```

**Low match scores across the board**
- Add a `description` column to your policies CSV — short policy names alone give little signal to SecBERT
- Lower the threshold: `--threshold 0.35`
- Ensure SecBERT loaded (not TF-IDF) — check the `Encoder:` line in the console output

**Model not found**
```bash
# Verify model folder contents
ls -lh secbert_clean/
# Must contain model.safetensors (~318 MB)
# Then confirm sspm_mapper.py has:
SECBERT_MODEL_PATH = "./secbert_clean"
```

---

## 📋 Quick Reference Card

```
# First time setup
pip install -r requirements.txt
python download_secbert.py
# Set SECBERT_MODEL_PATH = "./secbert_clean" in sspm_mapper.py

# Run with sample data (no input files needed)
python sspm_mapper.py

# Run with your files
python sspm_mapper.py \
  --controls  your_controls.csv \
  --policies  your_policies.csv \
  --app       "Your App Name"

# Verbose (show all matches in console)
python sspm_mapper.py -c controls.csv -p policies.csv -a "App" -v

# Multiple apps
python sspm_mapper.py -c controls.csv -p m365.csv     -a "Microsoft 365" -o microsoft_365
python sspm_mapper.py -c controls.csv -p sf.csv       -a "Salesforce"    -o salesforce
python sspm_mapper.py -c controls.csv -p okta.csv     -a "Okta"          -o okta

# Output files produced per run
<app>_report.xlsx                ← open this first (8 sheets)
<app>_report.json
<app>_control_mappings.csv
<app>_policy_mappings.csv
<app>_uncovered_controls.csv
<app>_orphan_policies.csv
<app>_domain_summary.csv
```