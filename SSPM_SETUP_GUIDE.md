# SSPM Policy Mapper — Complete Setup & Run Guide

Everything you need to go from raw CSV files to a reviewed, corrected, downloadable
mapping report.

---

## What you have

```
sspm_v4/                        ← AI mapping engine (Python)
├── sspm_mapper.py              Main program
├── sspm_config.py              All configuration (edit this, not mapper.py)
├── download_secbert.py         Download SecBERT model once
├── requirements.txt            Python dependencies
├── domain_pairs.json           Domain pairing rules
├── sample_controls.csv         Sample controls file
├── sample_policies_m365.csv    Sample policies file
└── README.md                   Detailed config reference

sspm_ui2/                       ← Review & correction UI (browser)
├── index.html                  Open this in browser
├── styles.css                  Styles
├── app.js                      Application logic
└── serve.py                    Local web server (one command)
```

---

## Prerequisites

| Requirement | Version | Check |
|---|---|---|
| Python | 3.10 or higher | `python --version` |
| pip | any | `pip --version` |
| Modern browser | Chrome / Firefox / Safari / Edge | — |
| Internet (first time only) | For SecBERT download | — |

---

## Full Setup (do once)

### Step 1 — Install Python dependencies

```bash
cd sspm_v4
pip install -r requirements.txt
```

This installs: `torch`, `transformers`, `numpy`, `scikit-learn`, `openpyxl`, and related packages.

---

### Step 2 — Download the SecBERT AI model

Run this once on a machine with internet access:

```bash
cd sspm_v4
python download_secbert.py
```

Output:
```
Downloading tokenizer...   ✓
Downloading model weights (~318MB) ...   ✓
Files saved to: ./secbert_clean/
```

> If your machine has no internet, run this on another machine, copy the
> `secbert_clean/` folder to your work machine, and set the path in
> `sspm_config.py` (see Step 3).

---

### Step 3 — Set your model path

Open `sspm_config.py` and confirm line 1 points to your model folder:

```python
SECBERT_MODEL_PATH = "./secbert_clean"
```

> If you saved it elsewhere, change this path. Example:
> `SECBERT_MODEL_PATH = "/opt/models/secbert_clean"`

---

## Running the Mapper (Every Time)

### Step 4 — Prepare your input files

**controls.csv** — your org security standards:
```
control_id,control_text,domain,framework,subdomain,description
IAM-001,All users must authenticate using MFA,Identity and Access Management,ISO 27001,A.9.4.2,
IAM-002,All SaaS apps must federate via SSO,Identity and Access Management,ISO 27001,A.9.4.1,
DP-001,Data in transit must use TLS encryption,Data Protection,ISO 27001,A.10.1.1,
```

**policies.csv** — your OOTB policies for one app (e.g. Salesforce):
```
policy_id,policy_name,category,description,impact
SF-001,Enable SSO,Identity,Enforce Single Sign-On via SAML,HIGH
SF-002,Trusted IP Ranges Configuration,Access Control,Restrict login to approved IP ranges,HIGH
SF-003,Inactive Sessions Logout Timeout,Access Control,Auto-logout after inactivity,MEDIUM
```

> Column names are flexible — `control_id` or `id` or `ref` all work.
> BOM from Excel saves is handled automatically.

---

### Step 5 — Run the AI mapper

```bash
cd sspm_v4

python sspm_mapper.py \
  --controls  your_controls.csv \
  --policies  your_policies.csv \
  --app       "Salesforce" \
  --clear-cache
```

**What you see:**
```
◈  SSPM Policy Mapper v4
App      : Salesforce
Controls : your_controls.csv
Policies : your_policies.csv

🔄  Loading SecBERT from local folder: ./secbert_clean
✅  SecBERT ready.

📋  Controls loaded : 18 controls
     Sample IDs     : ['IAM-001', 'IAM-002', 'DP-001']  ← from your file

📂  Policies loaded : 45 policies  [app: Salesforce]
     Sample IDs     : ['SF-001', 'SF-002', 'SF-003']  ← from your file

     Pass 1 (domain-paired):  720 pairs (89% of matrix)
     Pass 2 (cross-domain):    90 pairs (11% of matrix)

✅  Encoding complete in 12.3s

═══════════════════════════════════════════════════════
  SSPM MAPPING REPORT  —  Salesforce
═══════════════════════════════════════════════════════
  Controls : 18     Policies : 45
  Covered  : 15     Uncovered : 3     Orphan : 28
  FULL : 8   PARTIAL : 12   INDIRECT : 7

  ACCESS CONTROL     ████████████████░░░░  80%  (4/5)
  DATA PROTECTION    ████████████████████ 100%  (3/3)
  IDENTITY AND IAM   ████████████░░░░░░░░  60%  (6/10)
═══════════════════════════════════════════════════════

📊  Excel report saved → salesforce_report.xlsx
📁  JSON  report saved → salesforce_report.json
```

**Output files produced:**
```
salesforce_report.json               ← load this into the UI
salesforce_report.xlsx               ← open directly in Excel (9 sheets)
salesforce_control_mappings.csv
salesforce_policy_mappings.csv
salesforce_uncovered_controls.csv
salesforce_orphan_policies.csv
salesforce_domain_summary.csv
```

---

### Step 6 — Open the Review UI

In a separate terminal:

```bash
cd sspm_ui2
python serve.py
```

Output:
```
  ◈  SSPM Policy Mapper UI  →  http://localhost:8080
  Ctrl+C to stop
```

Your browser opens automatically at `http://localhost:8080`.

---

### Step 7 — Load the mapper report into the UI

1. On the upload screen, drag `salesforce_report.json` onto the
   **"Drop sspm_mapper.py JSON output here"** zone
2. The review screen opens automatically

---

### Step 8 — Review and correct mappings

The screen has three columns:

```
┌─────────────────┐  ←bezier lines→  ┌─────────────────┐
│  STANDARDS      │                  │  POLICIES        │
│                 │                  │                  │
│  [IAM-001]      │ ─────────────→  │  ● Enable SSO    │
│  ┌─────────┐   │                  │    (FULL)        │
│  │Enable   │   │ - - - - - - - →  │  ● Trusted IP    │
│  │SSO  [✕] │   │                  │    (PARTIAL)     │
│  │TrustdIP │   │                  │                  │
│  │[✕]      │   │                  │  ● Session TO    │
│  └─────────┘   │                  │    (unassigned)  │
└─────────────────┘                  └─────────────────┘
        ───── [ ORPHAN TRAY — drag to assign ] ─────
```

**To remove a wrong mapping:**
Click the **✕** on any policy chip inside a standard card.
The policy moves to the Orphan Tray at the bottom.

**To move a policy to a different standard:**
Drag the policy chip from one standard card and drop it onto another.

**To assign an orphan policy:**
Drag a chip from the Orphan Tray and drop it onto any standard card.

**SVG lines colour guide:**
- Solid green = FULL match
- Dashed amber = PARTIAL match
- Dotted blue = INDIRECT match
- Solid pink = Manually assigned

---

### Step 9 — Download corrected results

Click **Mind map CSV** in the top bar to download a hierarchical CSV:

```
Level 1: Security Domain
  Level 2: Control ID
    Level 3: Control Text
      Level 4: Policy ID
        Level 5: Policy Name
          Level 6: Policy Category
            Level 7: Coverage
              Level 8: Match Source
                Level 9: Impact
```

Open in Excel → the hierarchical structure makes it easy to build a pivot or SmartArt mind map.

Click **JSON report** to download the structured JSON with:
- All kept mappings
- `removed_mappings` per control (policies you marked wrong)
- Full orphan list including manually removed ones

---

## All CLI Options

```bash
python sspm_mapper.py \
  --controls    your_controls.csv   \   # Controls/standards file
  --policies    your_policies.csv   \   # Policies file
  --app         "Salesforce"        \   # App name for report title
  --out         salesforce          \   # Output file prefix
  --model       ./secbert_clean     \   # Override model path
  --threshold   0.40                \   # Min similarity score (0.0–1.0)
  --topk        5                   \   # Max policy matches per control
  --domain-pairs domain_pairs.json  \   # Custom domain pairing file
  --no-domain-filter                \   # Disable domain filtering
  --clear-cache                     \   # Force re-encode (after config changes)
  --verbose                             # Show all match details in console
```

---

## Multiple Apps

Run once per app — each produces its own output files:

```bash
python sspm_mapper.py --controls controls.csv --policies salesforce_policies.csv --app "Salesforce"       --out sf
python sspm_mapper.py --controls controls.csv --policies m365_policies.csv       --app "Microsoft 365"   --out m365
python sspm_mapper.py --controls controls.csv --policies okta_policies.csv       --app "Okta"             --out okta
python sspm_mapper.py --controls controls.csv --policies slack_policies.csv      --app "Slack"            --out slack
```

Load each `*_report.json` into the UI separately to review.

---

## Troubleshooting

**SecBERT not loading → TF-IDF fallback**
```bash
pip install torch transformers tokenizers protobuf
```

**IDs showing as CTR-001 / POL-001 instead of your IDs**

Check the `Sample IDs` line when the mapper runs:
```
Sample IDs : ['IAM-001', 'IAM-002']  ← from your file
```
If you see `CTR-001`, your ID column name is not recognised.
Accepted column names: `control_id`, `id`, `ref`, `no`, `number`, `control_no`

**Matching quality poor / wrong matches**

```bash
# Debug a specific pair from Python
python3 -c "
from sspm_mapper import SSPMMapper
m = SSPMMapper()
m.load_controls('your_controls.csv')
m.load_policies('your_policies.csv', app='Salesforce')
m.explain_match('IAM-001', 'SF-001')
"
```

This prints the exact keyword groups and boost/penalty breakdown for any pair.

**After editing sspm_config.py — always clear cache**
```bash
rm -rf policy_cache/
python sspm_mapper.py ... --clear-cache
```

**UI uploads not working when opening index.html directly**

Some browsers block file access via `file://`. Always use the server:
```bash
python serve.py
```

**Custom port for the UI**
```bash
python serve.py --port 3000
# Open http://localhost:3000
```

---

## Quick Reference Card

```bash
# ── First time setup ──────────────────────────────────
pip install -r requirements.txt          # install dependencies
python download_secbert.py               # download AI model (~318MB)
# Edit sspm_config.py line 1:
# SECBERT_MODEL_PATH = "./secbert_clean"

# ── Run mapper ────────────────────────────────────────
python sspm_mapper.py \
  --controls  controls.csv \
  --policies  salesforce_policies.csv \
  --app       "Salesforce" \
  --clear-cache

# ── Open UI ───────────────────────────────────────────
cd ../sspm_ui2
python serve.py
# → http://localhost:8080
# → Drag salesforce_report.json into the UI

# ── In the UI ─────────────────────────────────────────
# ✕ on a chip     → remove wrong mapping → goes to orphan tray
# drag chip       → move to correct standard
# drag from tray  → assign orphan to a standard
# Mind map CSV    → download hierarchical mapping
# JSON report     → download corrected full report
```

---

## File Reference

| File | Purpose | Edit? |
|---|---|---|
| `sspm_mapper.py` | AI mapping engine | Never |
| `sspm_config.py` | All configuration | Yes — your main config file |
| `download_secbert.py` | Model downloader | Never |
| `domain_pairs.json` | Domain pairing rules | Yes — add new domains here |
| `requirements.txt` | Python packages | Never |
| `sspm_ui2/index.html` | UI entry point | Never |
| `sspm_ui2/app.js` | UI logic | Never |
| `sspm_ui2/styles.css` | UI styles | Never |
| `sspm_ui2/serve.py` | Local web server | Never |
