"""
SSPM Policy Mapper — v4
========================================================
Key design decisions:
  - Pure semantic matching: NO framework tags injected into policy text
    (policies don't contain framework references — that's the point of this tool)
  - One app analysed at a time
  - Full relationship tracking: 1→many, many→1, many→many
  - Bidirectional gap analysis:
      * Controls with NO matching policy  → "Uncovered Controls"
      * Policies with NO matching control → "Orphan Policies"
  - Security domain flows through from input to output
"""

import json, csv, pickle, hashlib, warnings
import numpy as np
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
warnings.filterwarnings("ignore")

CACHE_DIR = Path("policy_cache")
CACHE_DIR.mkdir(exist_ok=True)

# ── Thresholds ────────────────────────────────────────────────────────────────
THRESHOLD_FULL     = 0.82   # Strong match → FULL coverage
THRESHOLD_PARTIAL  = 0.60   # Moderate match → PARTIAL coverage
THRESHOLD_INDIRECT = 0.40   # Weak match → INDIRECT coverage
THRESHOLD_MIN      = 0.40   # Below this → no match at all

# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class Control:
    """One row from the standards/controls input."""
    control_id:   str
    control_text: str
    domain:       str          # e.g. "Access Control", "Cryptography"
    framework:    str          # e.g. "ISO 27001", "NIST CSF"
    subdomain:    str = ""     # optional finer grain, e.g. "A.9.4"
    description:  str = ""     # optional longer description

@dataclass
class Policy:
    """One row from the OOTB policy input for a given app."""
    policy_id:    str
    policy_name:  str
    category:     str = ""     # vendor category if available (not framework)
    description:  str = ""     # vendor description if available
    impact:       str = ""     # impact level or description from policy file

@dataclass
class PolicyMatch:
    """A single (control → policy) match."""
    policy_id:        str
    policy_name:      str
    policy_category:  str
    similarity_score: float
    coverage:         str      # FULL / PARTIAL / INDIRECT
    impact:           str = "" # impact value carried from policy file

@dataclass
class ControlResult:
    """Mapping result for one control."""
    control_id:    str
    control_text:  str
    domain:        str
    framework:     str
    subdomain:     str
    risk_level:    str
    matches:       list = field(default_factory=list)   # list of PolicyMatch
    is_covered:    bool = False   # True if at least one FULL, PARTIAL or INDIRECT match

@dataclass
class PolicyResult:
    """Reverse-mapping result for one policy."""
    policy_id:       str
    policy_name:     str
    policy_category: str
    matched_controls: list = field(default_factory=list)  # list of control_ids
    is_orphan:       bool = True   # True if no control maps to this policy


# ── Loaders ───────────────────────────────────────────────────────────────────

class ControlLoader:
    """
    Load controls/standards from CSV or JSON.

    CSV columns (flexible naming):
      control_id, control_text, domain, framework, [subdomain], [description]

    JSON: list of objects with same fields, or
          { "domain": [...controls...] } grouped format
    """

    @staticmethod
    def from_csv(path: str) -> list[Control]:
        controls = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            # Detect ID column name once from headers
            id_col = None
            id_candidates = ["control_id","id","control_no","ctrl_id","ctr_id",
                             "no","number","ref","reference","control_ref",
                             "standard_id","req_id","requirement_id","ctrl_no"]
            fnames_lower = [f.strip().lower() for f in (reader.fieldnames or [])]
            for cand in id_candidates:
                if cand in fnames_lower:
                    id_col = cand
                    break
            if not id_col:
                print(f"ℹ️   Controls: no ID column found — will auto-generate IDs.")
                print(f"    Add one of these columns to use your own IDs:")
                print(f"    {id_candidates[:6]}")

            for i, row in enumerate(reader):
                row = {k.strip().lower(): v.strip() for k, v in row.items()}
                text = (row.get("control_text") or row.get("control") or
                        row.get("requirement") or row.get("description") or "")
                if not text or text.startswith("#"):
                    continue
                # Use detected ID column, else auto-generate
                if id_col:
                    ctrl_id = row.get(id_col) or f"CTR-{i+1:03d}"
                else:
                    ctrl_id = f"CTR-{i+1:03d}"
                controls.append(Control(
                    control_id   = ctrl_id,
                    control_text = text,
                    domain       = (row.get("domain") or row.get("security_domain") or
                                    row.get("category") or "General"),
                    framework    = (row.get("framework") or row.get("standard") or ""),
                    subdomain    = row.get("subdomain", row.get("sub_domain", "")),
                    description  = row.get("detail", row.get("notes", "")),
                ))
        return controls

    @staticmethod
    def from_json(path: str) -> list[Control]:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        controls = []
        if isinstance(raw, list):
            for i, item in enumerate(raw):
                # Try all accepted ID field names
                ctrl_id_val = (item.get("control_id") or item.get("id") or
                               item.get("control_no") or item.get("ctrl_id") or
                               item.get("no") or item.get("number") or
                               item.get("ref") or item.get("reference") or
                               f"CTR-{i+1:03d}")
                controls.append(Control(
                    control_id   = ctrl_id_val,
                    control_text = item.get("control_text", item.get("control", item.get("text", ""))),
                    domain       = item.get("domain", item.get("security_domain", "General")),
                    framework    = item.get("framework", item.get("standard", "")),
                    subdomain    = item.get("subdomain", ""),
                    description  = item.get("description", ""),
                ))
        elif isinstance(raw, dict):
            # { "Access Control": [{"control_id":..., "control_text":...}, ...] }
            for domain, items in raw.items():
                for i, item in enumerate(items):
                    controls.append(Control(
                        control_id   = (item.get("control_id") or item.get("id") or
                                        item.get("control_no") or item.get("ref") or
                                        f"{domain[:3].upper()}-{i+1:03d}"),
                        control_text = item.get("control_text", item.get("control", "")),
                        domain       = domain,
                        framework    = item.get("framework", ""),
                        subdomain    = item.get("subdomain", ""),
                        description  = item.get("description", ""),
                    ))
        return [c for c in controls if c.control_text]

    @staticmethod
    def load(path: str) -> list[Control]:
        ext = Path(path).suffix.lower()
        if ext == ".csv":  return ControlLoader.from_csv(path)
        if ext == ".json": return ControlLoader.from_json(path)
        raise ValueError(f"Unsupported format '{ext}'")


class PolicyLoader:
    """
    Load OOTB policies for ONE app from CSV or JSON.
    Policies must NOT contain framework references — pure vendor policy text only.
    """

    @staticmethod
    def from_csv(path: str, app_filter: Optional[str] = None) -> list[Policy]:
        policies = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            # Detect once from headers
            fieldnames_lower = [f.strip().lower() for f in (reader.fieldnames or [])]
            has_app_col = any(c in fieldnames_lower for c in ("app_name","app","application"))

            # Detect policy ID column name
            pol_id_col = None
            pol_id_candidates = ["policy_id","id","pol_id","policy_no","pol_no",
                                  "no","number","ref","policy_ref","ootb_id",
                                  "control_id","rule_id","check_id","finding_id"]
            for cand in pol_id_candidates:
                if cand in fieldnames_lower:
                    pol_id_col = cand
                    break
            if not pol_id_col:
                print(f"ℹ️   Policies: no ID column found — will auto-generate IDs.")
                print(f"    Add one of these columns to use your own IDs:")
                print(f"    {pol_id_candidates[:6]}")

            # Detect policy name column name
            pol_name_candidates = ["policy_name","policy","name","control",
                                   "rule","check","finding","title","description"]

            for i, row in enumerate(reader):
                row = {k.strip().lower(): v.strip() for k, v in row.items()}
                # Only filter by app name when the CSV actually has an app column
                if app_filter and has_app_col:
                    app_col = (row.get("app_name") or row.get("app") or
                               row.get("application") or "")
                    if app_col.lower() != app_filter.lower():
                        continue
                name = ""
                for nc in pol_name_candidates:
                    name = row.get(nc, "")
                    if name:
                        break
                if not name or name.startswith("#"):
                    continue
                # Use detected ID column, else auto-generate
                if pol_id_col:
                    pol_id = row.get(pol_id_col) or f"POL-{i+1:03d}"
                else:
                    pol_id = f"POL-{i+1:03d}"
                policies.append(Policy(
                    policy_id   = pol_id,
                    policy_name = name,
                    category    = row.get("category", row.get("type", "")),
                    description = row.get("description", row.get("desc", "")),
                    impact      = row.get("impact", row.get("impact_level",
                                  row.get("severity", row.get("priority", "")))),
                ))
        return policies

    @staticmethod
    def from_json(path: str, app_filter: Optional[str] = None) -> list[Policy]:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        policies = []
        items = []
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            if app_filter and app_filter in raw:
                items = raw[app_filter]
            elif app_filter:
                # Try case-insensitive match
                for k, v in raw.items():
                    if k.lower() == app_filter.lower():
                        items = v
                        break
            else:
                # Flatten all
                for v in raw.values():
                    items.extend(v if isinstance(v, list) else [v])
        for i, item in enumerate(items):
            if isinstance(item, str):
                policies.append(Policy(
                    policy_id=f"POL-{i+1:03d}", policy_name=item,
                    category="", description=""))
            else:
                pol_id_val = (item.get("policy_id") or item.get("id") or
                              item.get("pol_id") or item.get("policy_no") or
                              item.get("no") or item.get("number") or
                              item.get("ref") or item.get("rule_id") or
                              f"POL-{i+1:03d}")
                policies.append(Policy(
                    policy_id   = pol_id_val,
                    policy_name = item.get("policy_name", item.get("policy", item.get("name", ""))),
                    category    = item.get("category", ""),
                    description = item.get("description", ""),
                    impact      = item.get("impact", item.get("impact_level",
                                  item.get("severity", item.get("priority", "")))),
                ))
        return [p for p in policies if p.policy_name]

    @staticmethod
    def load(path: str, app_filter: Optional[str] = None) -> list[Policy]:
        ext = Path(path).suffix.lower()
        if ext == ".csv":  return PolicyLoader.from_csv(path, app_filter)
        if ext == ".json": return PolicyLoader.from_json(path, app_filter)
        raise ValueError(f"Unsupported format '{ext}'")


# ── Encoder ───────────────────────────────────────────────────────────────────

# ── SET THIS to your local model folder — NEVER leave as None in production ──
# Run python download_secbert.py once to download the model locally.
# Then set this path so the program NEVER contacts HuggingFace again.
#
# Examples:
#   SECBERT_MODEL_PATH = "./secbert_clean"        # relative to project folder
#   SECBERT_MODEL_PATH = "./secbert_model"        # if you used download_secbert.py
#   SECBERT_MODEL_PATH = "/opt/models/secbert"    # absolute path
#
# If None → attempts HuggingFace download (requires internet)
SECBERT_MODEL_PATH = "./secbert_model"   # ← SET THIS TO YOUR FOLDER


def _find_model_path(base_path: str) -> str:
    """
    Resolve the actual model directory from a given base path.

    Handles two folder structures:
      1. Flat (save_pretrained output):
             secbert_clean/
               config.json
               model.safetensors / pytorch_model.bin
               tokenizer.json
               vocab.txt

      2. HuggingFace cache structure (cache_dir output):
             secbert_model/
               models--jackaduma--SecBERT/
                 snapshots/
                   <hash>/
                     config.json ...

    Returns the path that actually contains config.json.
    Raises FileNotFoundError with a clear message if nothing found.
    """
    import os
    from pathlib import Path

    base = Path(base_path)

    # ── Check if base itself is a flat model folder ───────────────────────────
    if (base / "config.json").exists():
        return str(base)

    # ── Check HuggingFace cache structure ─────────────────────────────────────
    # Pattern: base/models--<org>--<model>/snapshots/<hash>/config.json
    for snapshots_dir in base.rglob("snapshots"):
        if snapshots_dir.is_dir():
            # Get the most recent snapshot (sorted by name)
            snapshots = sorted(snapshots_dir.iterdir(), reverse=True)
            for snap in snapshots:
                if (snap / "config.json").exists():
                    return str(snap)

    # ── Check one level deep (user may have pointed to parent folder) ─────────
    for child in base.iterdir():
        if child.is_dir() and (child / "config.json").exists():
            return str(child)

    # ── Nothing found ─────────────────────────────────────────────────────────
    raise FileNotFoundError(
        f"\n\n  ❌  SecBERT model not found at: {base_path}"
        f"\n     Expected to find config.json inside this folder."
        f"\n     Run:  python download_secbert.py"
        f"\n     Then set SECBERT_MODEL_PATH = \"./secbert_clean\" in sspm_mapper.py"
    )


class SecBERTEncoder:
    """
    Encodes text using SecBERT.

    Loading priority:
      1. model_path argument (passed at runtime via --model)
      2. SECBERT_MODEL_PATH constant set at top of this file
      3. HuggingFace download — ONLY if both above are None/empty

    Automatically handles both flat (save_pretrained) and
    HuggingFace cache_dir folder structures.
    Falls back to TF-IDF if transformers/torch unavailable.
    """

    def __init__(self, model_path: str = None):
        self.mode = None
        # Priority: runtime arg > file constant > HuggingFace (last resort)
        raw_path = model_path or SECBERT_MODEL_PATH or None
        self.model_path = raw_path   # may be None if no local path configured
        self._load()

    def _load(self):
        try:
            from transformers import AutoTokenizer, AutoModel
            import torch

            if self.model_path:
                # ── Local folder — resolve exact path, never hit network ──────
                resolved = _find_model_path(self.model_path)
                print(f"🔄  Loading SecBERT from local folder: {resolved}")
                self.tokenizer = AutoTokenizer.from_pretrained(
                    resolved, local_files_only=True)
                self.model = AutoModel.from_pretrained(
                    resolved, local_files_only=True)
            else:
                # ── No local path set — download from HuggingFace ─────────────
                print(f"⚠️   SECBERT_MODEL_PATH is not set.")
                print(f"     Downloading from HuggingFace (requires internet)...")
                print(f"     To avoid this, run: python download_secbert.py")
                print(f"     Then set SECBERT_MODEL_PATH = \"./secbert_clean\" in sspm_mapper.py\n")
                self.tokenizer = AutoTokenizer.from_pretrained("jackaduma/SecBERT")
                self.model     = AutoModel.from_pretrained("jackaduma/SecBERT")

            self.model.eval()
            self.torch = torch
            self.mode  = "secbert"
            print("✅  SecBERT ready.\n")

        except FileNotFoundError as e:
            print(e)
            print("\n    → Falling back to TF-IDF mode\n")
            self.mode = "tfidf"
        except Exception as e:
            print(f"⚠️  SecBERT unavailable ({e})\n    → TF-IDF fallback mode\n")
            self.mode = "tfidf"

    def fit_tfidf(self, corpus: list[str]):
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 3), stop_words="english")
        self.vectorizer.fit(corpus)

    def encode(self, texts: list[str]) -> np.ndarray:
        if self.mode == "secbert":
            return self._encode_secbert(texts)
        return self.vectorizer.transform(texts).toarray()

    def _encode_secbert(self, texts: list[str]) -> np.ndarray:
        import torch
        embeddings = []
        with torch.no_grad():
            for text in texts:
                inputs  = self.tokenizer(
                    text, return_tensors="pt",
                    truncation=True, max_length=256, padding=True)
                outputs = self.model(**inputs)
                hidden  = outputs.last_hidden_state
                mask    = inputs["attention_mask"].unsqueeze(-1).float()
                pooled  = (hidden * mask).sum(1) / mask.sum(1)
                # reshape(-1) guarantees 1D vector regardless of batch size
                # squeeze() can collapse dimensions incorrectly for single tokens
                vec = pooled.squeeze(0).reshape(-1).numpy()
                embeddings.append(vec)
        return np.array(embeddings)


# ── Cache ─────────────────────────────────────────────────────────────────────

class EmbeddingCache:
    def _key(self, label: str, texts: list[str]) -> str:
        # Hash includes label + all policy text content
        # This means cache auto-invalidates when policy content changes
        return hashlib.sha256((label + "||".join(texts)).encode()).hexdigest()[:16]

    def get(self, label: str, texts: list[str]) -> Optional[np.ndarray]:
        p = CACHE_DIR / f"{self._key(label, texts)}.pkl"
        return pickle.load(open(p, "rb")) if p.exists() else None

    def set(self, label: str, texts: list[str], vecs: np.ndarray):
        pickle.dump(vecs, open(CACHE_DIR / f"{self._key(label, texts)}.pkl", "wb"))

    def clear(self):
        """Delete all cached embeddings. Run when switching model or policy files."""
        deleted = 0
        for p in CACHE_DIR.glob("*.pkl"):
            p.unlink()
            deleted += 1
        print(f"🗑️   Cache cleared ({deleted} files deleted).")


# ── Policy Text Builder ───────────────────────────────────────────────────────

def policy_encode_text(policy: Policy) -> str:
    """
    Build the text to encode for a policy.
    Uses ONLY vendor-supplied text — name + description + category.
    No framework tags, no artificial keyword injection.
    """
    parts = [policy.policy_name]
    if policy.description:
        parts.append(policy.description)
    if policy.category:
        parts.append(policy.category)
    return " . ".join(parts)


def control_encode_text(control: Control) -> str:
    """
    Build the text to encode for a control.
    Uses control text + description. Domain is NOT added here
    (domain is metadata, not semantic content for matching).
    """
    parts = [control.control_text]
    if control.description:
        parts.append(control.description)
    return " . ".join(parts)


# ── Core Mapper ───────────────────────────────────────────────────────────────

class SSPMMapper:
    """
    Maps org security controls to OOTB policies for ONE SaaS app at a time.

    Workflow:
        mapper = SSPMMapper()
        mapper.load_controls("controls.csv")
        mapper.load_policies("policies.csv", app="Microsoft 365")
        report = mapper.run()
        mapper.print_report(report)
        mapper.save_report(report, "output.json")
    """

    def __init__(self, model_path: str = None):
        self.encoder   = SecBERTEncoder(model_path=model_path)
        self.cache     = EmbeddingCache()
        self.controls: list[Control] = []
        self.policies: list[Policy]  = []
        self.app_name: str = ""

    # ── Loaders ───────────────────────────────────────────────────────────────

    def load_controls(self, path: str):
        self.controls = ControlLoader.load(path)
        domains = sorted(set(c.domain for c in self.controls))
        print(f"📋  Controls loaded : {len(self.controls)} controls  [from: {path}]")
        print(f"     Domains        : {', '.join(domains)}")
        print(f"     Frameworks     : {', '.join(sorted(set(c.framework for c in self.controls if c.framework)))}")
        # Show first 3 IDs so user can confirm IDs are read from their file
        sample_ids = [c.control_id for c in self.controls[:3]]
        print(f"     Sample IDs     : {sample_ids}  ← from your file")
        print()

    def load_controls_from_list(self, controls: list[Control]):
        self.controls = controls
        print(f"📋  Controls loaded : {len(self.controls)}\n")

    def load_policies(self, path: str, app: str = ""):
        """
        Load OOTB policies from a CSV or JSON file.

        app parameter is used as a label only (stored in report).
        If your CSV has an app_name column, rows are filtered to match app.
        If your CSV has NO app_name column (single-app file), all rows are loaded.
        """
        self.app_name = app
        # Always try loading all rows first for single-app files
        self.policies = PolicyLoader.load(path, app_filter=None)
        # If multi-app file AND app specified, filter down
        if app and self.policies:
            has_app_col = any(
                hasattr(p, "_app_col") or
                True  # we rely on from_csv internal detection
                for p in self.policies[:1]
            )
            # Check if CSV actually had an app_name column by re-examining
            filtered = PolicyLoader.load(path, app_filter=app)
            if len(filtered) > 0:
                self.policies = filtered
                print(f"📂  Policies loaded : {len(self.policies)} policies  [app: {app}  (filtered from {path})]")
                sample_ids = [p.policy_id for p in self.policies[:3]]
                print(f"     Sample IDs     : {sample_ids}  ← from your file")
            else:
                # No app_name column — single-app file, keep all rows
                print(f"📂  Policies loaded : {len(self.policies)} policies  [app: {app}  (single-app file: {path})]")
                sample_ids = [p.policy_id for p in self.policies[:3]]
                print(f"     Sample IDs     : {sample_ids}  ← from your file")
        else:
            print(f"📂  Policies loaded : {len(self.policies)} policies  [app: {app or 'all'}  from: {path}]")
            sample_ids = [p.policy_id for p in self.policies[:3]]
            print(f"     Sample IDs     : {sample_ids}  ← from your file")
        if len(self.policies) == 0:
            print(f"⚠️   0 policies loaded — check your file path and column names.")
            return
        cats = sorted(set(p.category for p in self.policies if p.category))
        if cats:
            print(f"     Categories     : {', '.join(cats)}\n")

    def load_policies_from_list(self, policies: list[Policy], app: str = ""):
        self.policies = policies
        self.app_name = app

    # ── Run Mapping ───────────────────────────────────────────────────────────

    def run(self,
            top_k:     int   = 5,
            threshold: float = THRESHOLD_MIN) -> dict:
        """
        Run the full bidirectional mapping and return a structured report.
        """
        if not self.controls:
            raise RuntimeError("No controls loaded. Call load_controls() first.")
        if not self.policies:
            raise RuntimeError("No policies loaded. Call load_policies() first.")

        print(f"🔄  Encoding {len(self.controls)} controls and {len(self.policies)} policies...")

        # Build encode texts
        ctrl_texts   = [control_encode_text(c) for c in self.controls]
        policy_texts = [policy_encode_text(p)  for p in self.policies]

        # Fit TF-IDF if needed
        if self.encoder.mode == "tfidf":
            self.encoder.fit_tfidf(ctrl_texts + policy_texts)

        # Encode — use cache for policies (they don't change per run)
        cache_label = self.app_name or "policies"
        ctrl_vecs   = self.encoder.encode(ctrl_texts)

        policy_vecs = self.cache.get(cache_label, policy_texts)
        if policy_vecs is None:
            policy_vecs = self.encoder.encode(policy_texts)
            self.cache.set(cache_label, policy_texts, policy_vecs)
            print(f"     Policy vectors encoded and cached.")
        else:
            print(f"     Policy vectors loaded from cache.")

        print(f"✅  Encoding complete.\n")

        # ── Build similarity matrix ───────────────────────────────────────────
        # Shape: (n_controls, n_policies)
        # Ensure both matrices are 2D before matrix multiply
        ctrl_vecs   = np.atleast_2d(ctrl_vecs)
        policy_vecs = np.atleast_2d(policy_vecs)

        # Ensure same embedding dimension
        if ctrl_vecs.shape[1] != policy_vecs.shape[1]:
            raise RuntimeError(
                f"Embedding dimension mismatch: controls={ctrl_vecs.shape[1]} "
                f"vs policies={policy_vecs.shape[1]}. "
                f"Clear policy_cache/ and re-run."
            )

        def norm(vecs):
            norms = np.linalg.norm(vecs, axis=1, keepdims=True) + 1e-9
            return vecs / norms

        sim_matrix = norm(ctrl_vecs) @ norm(policy_vecs).T
        # sim_matrix[i][j] = cosine similarity between control i and policy j

        # ── Forward pass: control → policies ─────────────────────────────────
        control_results: list[ControlResult] = []
        # Track which policies got matched (for orphan detection)
        matched_policy_ids = set()

        for i, ctrl in enumerate(self.controls):
            sims    = sim_matrix[i]
            ranked  = np.argsort(sims)[::-1]
            matches = []

            for j in ranked[:top_k]:
                score = float(sims[j])
                if score < threshold:
                    break
                coverage = (
                    "FULL"     if score >= THRESHOLD_FULL     else
                    "PARTIAL"  if score >= THRESHOLD_PARTIAL  else
                    "INDIRECT"
                )
                pol = self.policies[j]
                matches.append(PolicyMatch(
                    policy_id        = pol.policy_id,
                    policy_name      = pol.policy_name,
                    policy_category  = pol.category,
                    similarity_score = round(score, 4),
                    coverage         = coverage,
                    impact           = pol.impact,
                ))
                matched_policy_ids.add(pol.policy_id)

            is_covered = any(m.coverage in ("FULL", "PARTIAL", "INDIRECT") for m in matches)

            control_results.append(ControlResult(
                control_id   = ctrl.control_id,
                control_text = ctrl.control_text,
                domain       = ctrl.domain,
                framework    = ctrl.framework,
                subdomain    = ctrl.subdomain,
                risk_level   = self._assess_risk(ctrl.control_text),
                matches      = matches,
                is_covered   = is_covered,
            ))

        # ── Reverse pass: policy → controls ──────────────────────────────────
        policy_results: list[PolicyResult] = []

        for j, pol in enumerate(self.policies):
            sims = sim_matrix[:, j]   # all controls vs this policy
            matched_ctrl_ids = []

            for i, ctrl in enumerate(self.controls):
                score = float(sims[i])
                if score >= THRESHOLD_INDIRECT:
                    matched_ctrl_ids.append(ctrl.control_id)

            is_orphan = len(matched_ctrl_ids) == 0
            policy_results.append(PolicyResult(
                policy_id        = pol.policy_id,
                policy_name      = pol.policy_name,
                policy_category  = pol.category,
                matched_controls = matched_ctrl_ids,
                is_orphan        = is_orphan,
            ))

        # ── Relationship classification ───────────────────────────────────────
        relationships = self._classify_relationships(control_results, policy_results)

        # ── Domain summary ────────────────────────────────────────────────────
        domain_summary = self._domain_summary(control_results)

        # ── Build final report ────────────────────────────────────────────────
        uncovered_controls = [r for r in control_results if not r.is_covered]
        orphan_policies    = [r for r in policy_results  if r.is_orphan]

        report = {
            "app":              self.app_name or "Unknown App",
            "encoder_mode":     self.encoder.mode,
            "summary": {
                "total_controls":       len(self.controls),
                "total_policies":       len(self.policies),
                "covered_controls":     len([r for r in control_results if r.is_covered]),
                "uncovered_controls":   len(uncovered_controls),
                "orphan_policies":      len(orphan_policies),
                "full_matches":         sum(1 for r in control_results
                                           for m in r.matches if m.coverage == "FULL"),
                "partial_matches":      sum(1 for r in control_results
                                           for m in r.matches if m.coverage == "PARTIAL"),
                "indirect_matches":     sum(1 for r in control_results
                                           for m in r.matches if m.coverage == "INDIRECT"),
            },
            "domain_summary":   domain_summary,
            "relationships":    relationships,
            "control_mappings": [self._serialize_ctrl(r) for r in control_results],
            "policy_mappings":  [self._serialize_pol(r)  for r in policy_results],
            "uncovered_controls": [
                {
                    "control_id":   r.control_id,
                    "control_text": r.control_text,
                    "domain":       r.domain,
                    "framework":    r.framework,
                    "subdomain":    r.subdomain,
                    "risk_level":   r.risk_level,
                    "reason":       "No OOTB policy matches at or above threshold",
                }
                for r in uncovered_controls
            ],
            "orphan_policies": [
                {
                    "policy_id":       r.policy_id,
                    "policy_name":     r.policy_name,
                    "policy_category": r.policy_category,
                    "reason":          "No org control maps to this OOTB policy",
                }
                for r in orphan_policies
            ],
        }
        return report

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _classify_relationships(self,
                                 ctrl_results: list[ControlResult],
                                 pol_results:  list[PolicyResult]) -> dict:
        """
        Classify all mapping relationships into:
          one_to_one    : 1 control  → exactly 1 policy
          one_to_many   : 1 control  → 2+ policies
          many_to_one   : 2+ controls → same 1 policy
          many_to_many  : 2+ controls share 2+ overlapping policies

        Includes ALL match types: FULL, PARTIAL, INDIRECT.
        """
        # ── Build control → policies map (ALL coverage types) ────────────────
        ctrl_to_pols = {}
        for r in ctrl_results:
            pol_ids = set(
                m.policy_id for m in r.matches
                if m.coverage in ("FULL", "PARTIAL", "INDIRECT")
            )
            if pol_ids:
                ctrl_to_pols[r.control_id] = pol_ids

        # ── Build policy → controls map (ALL coverage types) ─────────────────
        # Re-derive from ctrl_to_pols so it's consistent (not from reverse pass
        # which used a different threshold)
        pol_to_ctrls = {}
        for ctrl_id, pol_ids in ctrl_to_pols.items():
            for pid in pol_ids:
                pol_to_ctrls.setdefault(pid, set()).add(ctrl_id)

        one_to_one   = []
        one_to_many  = []
        many_to_one  = []
        many_to_many = []
        seen_m2m_clusters = set()
        # Track policies already classified as many_to_one to avoid duplicates
        seen_m2o_policies = set()

        for ctrl_id, pol_ids in ctrl_to_pols.items():
            n_pols = len(pol_ids)

            if n_pols == 1:
                # ── This control maps to exactly 1 policy ─────────────────────
                pid = next(iter(pol_ids))
                n_ctrls_for_this_pol = len(pol_to_ctrls.get(pid, set()))

                if n_ctrls_for_this_pol == 1:
                    # 1 control ↔ 1 policy
                    one_to_one.append({
                        "control": ctrl_id,
                        "policy":  pid,
                    })
                else:
                    # Multiple controls → same 1 policy (many-to-1)
                    if pid not in seen_m2o_policies:
                        seen_m2o_policies.add(pid)
                        many_to_one.append({
                            "policy":   pid,
                            "controls": sorted(pol_to_ctrls[pid]),
                        })

            else:
                # ── This control maps to 2+ policies ─────────────────────────
                # Check if any of those policies are ALSO hit by other controls
                other_controls_exist = any(
                    len(pol_to_ctrls.get(pid, set())) > 1
                    for pid in pol_ids
                )

                if other_controls_exist:
                    # Overlapping cluster → many-to-many
                    # Expand cluster to its maximal connected set
                    cluster_ctrls = set([ctrl_id])
                    cluster_pols  = set(pol_ids)
                    # Keep expanding until stable
                    prev_size = 0
                    while prev_size != len(cluster_ctrls) + len(cluster_pols):
                        prev_size = len(cluster_ctrls) + len(cluster_pols)
                        for pid in list(cluster_pols):
                            cluster_ctrls.update(pol_to_ctrls.get(pid, set()))
                        for cid in list(cluster_ctrls):
                            cluster_pols.update(ctrl_to_pols.get(cid, set()))

                    # Use frozenset of controls as dedup key
                    cluster_key = frozenset(cluster_ctrls)
                    if cluster_key not in seen_m2m_clusters:
                        seen_m2m_clusters.add(cluster_key)
                        many_to_many.append({
                            "controls": sorted(cluster_ctrls),
                            "policies": sorted(cluster_pols),
                        })
                else:
                    # Only this control hits these policies → genuine 1-to-many
                    one_to_many.append({
                        "control":  ctrl_id,
                        "policies": sorted(pol_ids),
                    })

        return {
            "one_to_one":   one_to_one,
            "one_to_many":  one_to_many,
            "many_to_one":  many_to_one,
            "many_to_many": many_to_many,
        }

    def _domain_summary(self, ctrl_results: list[ControlResult]) -> list[dict]:
        """Summarise coverage per security domain."""
        from collections import defaultdict
        domains = defaultdict(lambda: {"total": 0, "covered": 0,
                                        "uncovered": [], "high_risk": 0})
        for r in ctrl_results:
            d = domains[r.domain]
            d["total"] += 1
            # Covered = any match (FULL, PARTIAL, or INDIRECT)
            if r.is_covered:
                d["covered"] += 1
            else:
                d["uncovered"].append(r.control_id)
            # Track coverage breakdown
            for m in r.matches:
                d[m["coverage"] if isinstance(m, dict) else m.coverage] =                     d.get(m["coverage"] if isinstance(m, dict) else m.coverage, 0) + 1
            if r.risk_level == "HIGH":
                d["high_risk"] += 1

        summary = []
        for domain, stats in sorted(domains.items()):
            total    = stats["total"]
            covered  = stats["covered"]
            pct      = round(covered / total * 100) if total else 0
            n_full     = stats.get("FULL", 0)
            n_partial  = stats.get("PARTIAL", 0)
            n_indirect = stats.get("INDIRECT", 0)
            summary.append({
                "domain":               domain,
                "total_controls":       total,
                "covered_controls":     covered,
                "uncovered_controls":   total - covered,
                "coverage_pct":         pct,
                "full_matches":         n_full,
                "partial_matches":      n_partial,
                "indirect_matches":     n_indirect,
                "high_risk_controls":   stats["high_risk"],
                "uncovered_control_ids": stats["uncovered"],
                "coverage_status":     (
                    "FULL"    if pct == 100 else
                    "GOOD"    if pct >= 75  else
                    "PARTIAL" if pct >= 50  else
                    "POOR"
                ),
                "coverage_note": (
                    "Includes INDIRECT matches in coverage %" 
                    if n_indirect > 0 else ""
                ),
            })
        return summary

    def _assess_risk(self, text: str) -> str:
        t = text.lower()
        high = sum(1 for k in [
            "admin","privilege","mfa","multi-factor","password","encrypt",
            "credential","authentication","pii","phi","audit","gdpr","hipaa","root"
        ] if k in t)
        med = sum(1 for k in [
            "log","monitor","share","external","third-party","session","backup","patch"
        ] if k in t)
        return "HIGH" if high >= 2 else "MEDIUM" if (high == 1 or med >= 2) else "LOW"

    def _serialize_ctrl(self, r: ControlResult) -> dict:
        return {
            "control_id":   r.control_id,
            "control_text": r.control_text,
            "domain":       r.domain,
            "framework":    r.framework,
            "subdomain":    r.subdomain,
            "risk_level":   r.risk_level,
            "is_covered":   r.is_covered,
            "match_count":  len(r.matches),
            "matches": [
                {
                    "policy_id":        m.policy_id,
                    "policy_name":      m.policy_name,
                    "policy_category":  m.policy_category,
                    "similarity_score": m.similarity_score,
                    "coverage":         m.coverage,
                    "impact":           m.impact,
                }
                for m in r.matches
            ],
        }

    def _serialize_pol(self, r: PolicyResult) -> dict:
        return {
            "policy_id":         r.policy_id,
            "policy_name":       r.policy_name,
            "policy_category":   r.policy_category,
            "matched_controls":  r.matched_controls,
            "match_count":       len(r.matched_controls),
            "is_orphan":         r.is_orphan,
        }

    # ── Report Printer ────────────────────────────────────────────────────────

    def print_report(self, report: dict, verbose: bool = False):
        R="\033[0m"; B="\033[1m"
        RED="\033[91m"; YEL="\033[93m"; GRN="\033[92m"
        CYN="\033[96m"; BLU="\033[94m"; DIM="\033[2m"; MAG="\033[95m"

        s = report["summary"]
        print(f"\n{'═'*70}")
        print(f"{B}{CYN}  SSPM MAPPING REPORT  —  {report['app']}{R}")
        print(f"{'═'*70}")
        print(f"  Encoder     : {DIM}{report['encoder_mode']}{R}")
        print(f"  Controls    : {s['total_controls']}   Policies : {s['total_policies']}")
        print(f"  Covered     : {GRN}{s['covered_controls']}{R}   "
              f"Uncovered : {RED}{s['uncovered_controls']}{R}   "
              f"Orphan policies : {YEL}{s['orphan_policies']}{R}")
        print(f"  FULL        : {GRN}{s['full_matches']}{R}   "
              f"PARTIAL : {YEL}{s['partial_matches']}{R}   "
              f"INDIRECT : {DIM}{s['indirect_matches']}{R}   "
              f"{DIM}(all 3 count toward coverage %){R}")

        # ── Domain Summary ────────────────────────────────────────────────────
        print(f"\n{'─'*70}")
        print(f"  {B}{BLU}DOMAIN COVERAGE SUMMARY{R}")
        print(f"{'─'*70}")
        sc = {"FULL":GRN, "GOOD":GRN, "PARTIAL":YEL, "POOR":RED}
        for d in report["domain_summary"]:
            bar_len = int(d["coverage_pct"] / 5)
            bar = "█"*bar_len + "░"*(20-bar_len)
            col = sc.get(d["coverage_status"], R)
            hr  = f"  {RED}⚠ {d['high_risk_controls']} HIGH{R}" if d["high_risk_controls"] else ""
            # Show breakdown: F=FULL P=PARTIAL I=INDIRECT
            breakdown = (f"{GRN}F:{d.get('full_matches',0)}{R} "
                         f"{YEL}P:{d.get('partial_matches',0)}{R} "
                         f"{DIM}I:{d.get('indirect_matches',0)}{R}")
            print(f"  {B}{d['domain']:<28}{R} "
                  f"{col}{bar}{R} {d['coverage_pct']:>3}%  "
                  f"({d['covered_controls']}/{d['total_controls']})  "
                  f"{breakdown}{hr}")

        # ── Relationship types ────────────────────────────────────────────────
        rel = report["relationships"]
        print(f"\n{'─'*70}")
        print(f"  {B}{MAG}MAPPING RELATIONSHIPS{R}")
        print(f"{'─'*70}")
        print(f"  1-to-1   : {len(rel['one_to_one']):<4} "
              f"  1-to-many : {len(rel['one_to_many']):<4} "
              f"  many-to-1 : {len(rel['many_to_one']):<4} "
              f"  many-to-many : {len(rel['many_to_many'])}")

        # ── Control Mappings ──────────────────────────────────────────────────
        if verbose:
            print(f"\n{'─'*70}")
            print(f"  {B}{CYN}CONTROL → POLICY MAPPINGS{R}")
            print(f"{'─'*70}")
            for cm in report["control_mappings"]:
                cov_icon = f"{GRN}✔{R}" if cm["is_covered"] else f"{RED}✘{R}"
                rc = {"HIGH":RED,"MEDIUM":YEL,"LOW":GRN}.get(cm["risk_level"], R)
                print(f"\n  {cov_icon} [{cm['control_id']}] {rc}{cm['risk_level']}{R}  "
                      f"{DIM}{cm['domain']}{R}  {cm['framework']}")
                print(f"     {cm['control_text'][:90]}")
                if cm["matches"]:
                    for m in cm["matches"]:
                        cc = {"FULL":GRN,"PARTIAL":YEL,"INDIRECT":DIM}.get(m["coverage"],R)
                        cat = f" [{m['policy_category']}]" if m["policy_category"] else ""
                        print(f"       {cc}→ {m['policy_name']}{cat}  "
                              f"({m['similarity_score']:.3f} {m['coverage']}){R}")
                else:
                    print(f"       {RED}→ No matches{R}")

        # ── Uncovered Controls ────────────────────────────────────────────────
        print(f"\n{'─'*70}")
        print(f"  {B}{RED}UNCOVERED CONTROLS "
              f"({len(report['uncovered_controls'])}) "
              f"— Standards with no matching OOTB policy{R}")
        print(f"{'─'*70}")
        if not report["uncovered_controls"]:
            print(f"  {GRN}✔ All controls have at least one matching policy.{R}")
        else:
            for uc in report["uncovered_controls"]:
                rc = {"HIGH":RED,"MEDIUM":YEL,"LOW":GRN}.get(uc["risk_level"],R)
                sub = f" / {uc['subdomain']}" if uc["subdomain"] else ""
                print(f"  {RED}✘{R} [{uc['control_id']}] "
                      f"{rc}{uc['risk_level']}{R}  "
                      f"{DIM}{uc['domain']}{sub}  {uc['framework']}{R}")
                print(f"     {uc['control_text'][:100]}")

        # ── Orphan Policies ───────────────────────────────────────────────────
        print(f"\n{'─'*70}")
        print(f"  {B}{YEL}ORPHAN POLICIES "
              f"({len(report['orphan_policies'])}) "
              f"— OOTB policies not required by any standard{R}")
        print(f"{'─'*70}")
        if not report["orphan_policies"]:
            print(f"  {GRN}✔ All policies are referenced by at least one control.{R}")
        else:
            for op in report["orphan_policies"]:
                cat = f" [{op['policy_category']}]" if op["policy_category"] else ""
                print(f"  {YEL}○{R} [{op['policy_id']}] {op['policy_name']}{DIM}{cat}{R}")

        print(f"\n{'═'*70}\n")

    def save_report(self, report: dict, path: str = "mapping_report.json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"📁  Report saved to {path}")

    def save_xlsx(self, report: dict, path: str = "mapping_report.xlsx"):
        """
        Export all mapping results to a single Excel workbook with 6 sheets:
          1. Summary          — overall counts + domain coverage table
          2. Control Mappings — every control with all matched policies (one row per pair)
          3. Policy Mappings  — every policy with all matched controls (one row per pair)
          4. Uncovered Controls — controls with NO matching OOTB policy
          5. Orphan Policies  — policies with NO matching control
          6. Relationships    — 1:1, 1:N, N:1, N:N mapping types
        """
        from openpyxl import Workbook
        from openpyxl.styles import (Font, PatternFill, Alignment,
                                      Border, Side, GradientFill)
        from openpyxl.utils import get_column_letter

        wb = Workbook()
        app = report.get("app", "")

        # ── Colour palette ────────────────────────────────────────────────────
        C_HEADER_DARK   = "1F3864"   # dark navy  — sheet headers
        C_HEADER_MID    = "2E75B6"   # mid blue   — section headers
        C_HEADER_LIGHT  = "D6E4F0"   # light blue — column headers
        C_FULL          = "C6EFCE"   # green bg   — FULL coverage
        C_FULL_FG       = "276221"
        C_PARTIAL       = "FFEB9C"   # amber bg   — PARTIAL
        C_PARTIAL_FG    = "9C5700"
        C_INDIRECT      = "EDEDED"   # grey bg    — INDIRECT
        C_INDIRECT_FG   = "595959"
        C_UNCOVERED     = "FCE4D6"   # red-ish bg — uncovered / orphan
        C_UNCOVERED_FG  = "843C0C"
        C_HIGH          = "FFC7CE"   # risk HIGH
        C_HIGH_FG       = "9C0006"
        C_MEDIUM        = "FFEB9C"
        C_MEDIUM_FG     = "9C5700"
        C_LOW           = "C6EFCE"
        C_LOW_FG        = "276221"
        C_ALT_ROW       = "F2F7FC"   # alternating row tint

        thin = Side(style="thin", color="BFBFBF")
        border = Border(left=thin, right=thin, top=thin, bottom=thin)

        def hdr_font(size=11, bold=True, color="FFFFFF"):
            return Font(name="Arial", size=size, bold=bold, color=color)

        def body_font(size=10, bold=False, color="000000"):
            return Font(name="Arial", size=size, bold=bold, color=color)

        def fill(hex_color):
            return PatternFill("solid", fgColor=hex_color)

        def wrap_align(horizontal="left"):
            return Alignment(horizontal=horizontal, vertical="top",
                             wrap_text=True)

        def set_col_widths(ws, widths: dict):
            for col_letter, w in widths.items():
                ws.column_dimensions[col_letter].width = w

        def freeze(ws, cell="A2"):
            ws.freeze_panes = cell

        def write_header_row(ws, row_num, headers, bg=C_HEADER_LIGHT, fg="1F3864"):
            for col, h in enumerate(headers, 1):
                c = ws.cell(row=row_num, column=col, value=h)
                c.font      = hdr_font(size=10, color=fg)
                c.fill      = fill(bg)
                c.alignment = Alignment(horizontal="center", vertical="center",
                                        wrap_text=True)
                c.border    = border

        def write_data_row(ws, row_num, values, alt=False):
            bg = C_ALT_ROW if alt else "FFFFFF"
            for col, v in enumerate(values, 1):
                c = ws.cell(row=row_num, column=col, value=v)
                c.font      = body_font()
                c.fill      = fill(bg)
                c.alignment = wrap_align()
                c.border    = border

        def color_cell(cell, bg, fg):
            cell.fill = fill(bg)
            cell.font = Font(name="Arial", size=10, bold=True, color=fg)

        def title_row(ws, text, ncols, row=1):
            ws.merge_cells(start_row=row, start_column=1,
                           end_row=row, end_column=ncols)
            c = ws.cell(row=row, column=1, value=text)
            c.font      = Font(name="Arial", size=13, bold=True, color="FFFFFF")
            c.fill      = fill(C_HEADER_DARK)
            c.alignment = Alignment(horizontal="left", vertical="center")
            ws.row_dimensions[row].height = 28

        # ═══════════════════════════════════════════════════════════════════════
        # SHEET 1 — Summary
        # ═══════════════════════════════════════════════════════════════════════
        ws1 = wb.active
        ws1.title = "Summary"
        s = report["summary"]

        title_row(ws1, f"SSPM Mapping Report  —  {app}", 6)

        # KPI block
        kpis = [
            ("Total Controls",     s["total_controls"]),
            ("Total Policies",     s["total_policies"]),
            ("Covered Controls",   s["covered_controls"]),
            ("Uncovered Controls", s["uncovered_controls"]),
            ("Orphan Policies",    s["orphan_policies"]),
            ("FULL Matches",       s["full_matches"]),
            ("PARTIAL Matches",    s["partial_matches"]),
            ("INDIRECT Matches",   s["indirect_matches"]),
        ]
        ws1.cell(row=3, column=1, value="Metric").font  = hdr_font(color="1F3864")
        ws1.cell(row=3, column=2, value="Value").font   = hdr_font(color="1F3864")
        ws1.cell(row=3, column=1).fill = fill(C_HEADER_LIGHT)
        ws1.cell(row=3, column=2).fill = fill(C_HEADER_LIGHT)
        for i, (label, val) in enumerate(kpis, 4):
            ws1.cell(row=i, column=1, value=label).font  = body_font(bold=True)
            ws1.cell(row=i, column=2, value=val).font    = body_font()
            ws1.cell(row=i, column=1).fill = fill(C_ALT_ROW if i % 2 == 0 else "FFFFFF")
            ws1.cell(row=i, column=2).fill = fill(C_ALT_ROW if i % 2 == 0 else "FFFFFF")
            ws1.cell(row=i, column=1).border = border
            ws1.cell(row=i, column=2).border = border

        # Domain summary table
        start_row = 14
        ws1.cell(row=start_row, column=1,
                 value="Domain Coverage  (Coverage % includes FULL + PARTIAL + INDIRECT)").font = hdr_font(size=11, color="1F3864")
        ws1.cell(row=start_row, column=1).fill = fill(C_HEADER_LIGHT)

        hdr = ["Domain", "Total", "Covered", "Uncovered",
               "Coverage %", "FULL", "PARTIAL", "INDIRECT", "Status", "Note"]
        write_header_row(ws1, start_row + 1, hdr)
        sc_map = {"FULL":"C6EFCE","GOOD":"C6EFCE","PARTIAL":"FFEB9C","POOR":"FFC7CE"}
        for i, d in enumerate(report["domain_summary"]):
            r = start_row + 2 + i
            vals = [
                d["domain"],
                d["total_controls"],
                d["covered_controls"],
                d["uncovered_controls"],
                d["coverage_pct"] / 100,
                d.get("full_matches", 0),
                d.get("partial_matches", 0),
                d.get("indirect_matches", 0),
                d["coverage_status"],
                d.get("coverage_note", ""),
            ]
            write_data_row(ws1, r, vals, alt=(i % 2 == 1))
            # Status cell colour
            sc = ws1.cell(row=r, column=9)
            bg = sc_map.get(d["coverage_status"], "FFFFFF")
            sc.fill = fill(bg)
            sc.font = body_font(bold=True)
            # Percentage format
            ws1.cell(row=r, column=5).number_format = "0%"
            # Colour FULL cell green
            fc = ws1.cell(row=r, column=6)
            if d.get("full_matches", 0) > 0:
                fc.fill = fill("C6EFCE")
                fc.font = body_font(bold=True, color="276221")
            # Colour PARTIAL amber
            pc = ws1.cell(row=r, column=7)
            if d.get("partial_matches", 0) > 0:
                pc.fill = fill("FFEB9C")
                pc.font = body_font(bold=True, color="9C5700")
            # Colour INDIRECT grey
            ic = ws1.cell(row=r, column=8)
            if d.get("indirect_matches", 0) > 0:
                ic.fill = fill("EDEDED")
                ic.font = body_font(bold=True, color="595959")

        set_col_widths(ws1, {"A":30,"B":8,"C":10,"D":12,
                              "E":12,"F":8,"G":10,"H":11,"I":12,"J":38})
        ws1.column_dimensions["A"].width = 30
        freeze(ws1, "A2")
        # Extend domain section merge to 10 cols
        ws1.merge_cells(start_row=start_row, start_column=1,
                        end_row=start_row, end_column=10)

        # ═══════════════════════════════════════════════════════════════════════
        # SHEET 2 — Control Mappings
        # ═══════════════════════════════════════════════════════════════════════
        ws2 = wb.create_sheet("Control Mappings")
        title_row(ws2, f"Control → Policy Mappings  |  {app}", 14)
        hdrs = ["Control ID","Control Text","Domain","Framework","Subdomain",
                "Risk Level","Is Covered","Policy ID","Policy Name",
                "Policy Category","Impact","Similarity Score","Coverage","Relevance"]
        write_header_row(ws2, 2, hdrs)
        freeze(ws2, "A3")

        row = 3
        for cm in report["control_mappings"]:
            if cm["matches"]:
                for m in cm["matches"]:
                    relevance = ("HIGH"   if m["similarity_score"] >= 0.82 else
                                 "MEDIUM" if m["similarity_score"] >= 0.60 else "LOW")
                    vals = [cm["control_id"], cm["control_text"], cm["domain"],
                            cm["framework"], cm.get("subdomain",""),
                            cm["risk_level"], "Yes" if cm["is_covered"] else "No",
                            m["policy_id"], m["policy_name"],
                            m.get("policy_category",""),
                            m.get("impact",""),
                            m["similarity_score"], m["coverage"], relevance]
                    write_data_row(ws2, row, vals, alt=(row % 2 == 0))
                    # Coverage colour — now column 13 (impact added)
                    cov_cell = ws2.cell(row=row, column=13)
                    if m["coverage"] == "FULL":
                        color_cell(cov_cell, C_FULL, C_FULL_FG)
                    elif m["coverage"] == "PARTIAL":
                        color_cell(cov_cell, C_PARTIAL, C_PARTIAL_FG)
                    else:
                        color_cell(cov_cell, C_INDIRECT, C_INDIRECT_FG)
                    # Risk colour
                    risk_cell = ws2.cell(row=row, column=6)
                    if cm["risk_level"] == "HIGH":
                        color_cell(risk_cell, C_HIGH, C_HIGH_FG)
                    elif cm["risk_level"] == "MEDIUM":
                        color_cell(risk_cell, C_MEDIUM, C_MEDIUM_FG)
                    else:
                        color_cell(risk_cell, C_LOW, C_LOW_FG)
                    # Score number format
                    ws2.cell(row=row, column=11).number_format = "0.0000"
                    row += 1
            else:
                vals = [cm["control_id"], cm["control_text"], cm["domain"],
                        cm["framework"], cm.get("subdomain",""),
                        cm["risk_level"], "No",
                        "","","","","",""]
                write_data_row(ws2, row, vals, alt=(row % 2 == 0))
                # Highlight whole row as uncovered
                for col in range(1, 14):
                    c = ws2.cell(row=row, column=col)
                    c.fill = fill(C_UNCOVERED)
                row += 1

        set_col_widths(ws2, {"A":12,"B":45,"C":20,"D":12,"E":12,"F":11,
                              "G":11,"H":10,"I":40,"J":18,"K":15,"L":14,"M":12,"N":11})
        ws2.auto_filter.ref = f"A2:N{row-1}"

        # ═══════════════════════════════════════════════════════════════════════
        # SHEET 3 — Policy Mappings
        # ═══════════════════════════════════════════════════════════════════════
        ws3 = wb.create_sheet("Policy Mappings")
        title_row(ws3, f"Policy → Control Mappings  |  {app}", 7)
        write_header_row(ws3, 2,
            ["Policy ID","Policy Name","Policy Category",
             "Is Orphan","Matched Control ID","Match Count"])
        freeze(ws3, "A3")

        row = 3
        for pm in report["policy_mappings"]:
            if pm["matched_controls"]:
                for ctrl_id in pm["matched_controls"]:
                    vals = [pm["policy_id"], pm["policy_name"],
                            pm.get("policy_category",""),
                            "No", ctrl_id, pm["match_count"]]
                    write_data_row(ws3, row, vals, alt=(row % 2 == 0))
                    row += 1
            else:
                vals = [pm["policy_id"], pm["policy_name"],
                        pm.get("policy_category",""), "Yes", "", 0]
                write_data_row(ws3, row, vals, alt=(row % 2 == 0))
                orphan_cell = ws3.cell(row=row, column=4)
                color_cell(orphan_cell, C_UNCOVERED, C_UNCOVERED_FG)
                row += 1

        set_col_widths(ws3, {"A":12,"B":45,"C":20,"D":11,"E":20,"F":13})
        ws3.auto_filter.ref = f"A2:F{row-1}"

        # ═══════════════════════════════════════════════════════════════════════
        # SHEET 4 — Uncovered Controls
        # ═══════════════════════════════════════════════════════════════════════
        ws4 = wb.create_sheet("Uncovered Controls")
        title_row(ws4, f"Uncovered Controls — No Matching OOTB Policy  |  {app}", 8)
        write_header_row(ws4, 2,
            ["Control ID","Control Text","Domain","Framework",
             "Subdomain","Risk Level","Reason"])
        freeze(ws4, "A3")

        row = 3
        for i, uc in enumerate(report["uncovered_controls"]):
            vals = [uc["control_id"], uc["control_text"], uc["domain"],
                    uc["framework"], uc.get("subdomain",""),
                    uc["risk_level"],
                    uc.get("reason","No OOTB policy matches at or above threshold")]
            write_data_row(ws4, row, vals, alt=(i % 2 == 1))
            risk_cell = ws4.cell(row=row, column=6)
            if uc["risk_level"] == "HIGH":
                color_cell(risk_cell, C_HIGH, C_HIGH_FG)
            elif uc["risk_level"] == "MEDIUM":
                color_cell(risk_cell, C_MEDIUM, C_MEDIUM_FG)
            else:
                color_cell(risk_cell, C_LOW, C_LOW_FG)
            row += 1

        if len(report["uncovered_controls"]) == 0:
            ws4.cell(row=3, column=1,
                     value="✅  All controls have at least one matching policy.").font = body_font(bold=True, color="276221")

        set_col_widths(ws4, {"A":12,"B":50,"C":22,"D":12,"E":12,"F":11,"G":45})
        ws4.auto_filter.ref = f"A2:G{max(row-1, 3)}"

        # ═══════════════════════════════════════════════════════════════════════
        # SHEET 5 — Orphan Policies
        # ═══════════════════════════════════════════════════════════════════════
        ws5 = wb.create_sheet("Orphan Policies")
        title_row(ws5, f"Orphan Policies — Not Required by Any Standard  |  {app}", 5)
        write_header_row(ws5, 2,
            ["Policy ID","Policy Name","Policy Category","Reason"])
        freeze(ws5, "A3")

        row = 3
        for i, op in enumerate(report["orphan_policies"]):
            vals = [op["policy_id"], op["policy_name"],
                    op.get("policy_category",""),
                    op.get("reason","No org control maps to this OOTB policy")]
            write_data_row(ws5, row, vals, alt=(i % 2 == 1))
            row += 1

        if len(report["orphan_policies"]) == 0:
            ws5.cell(row=3, column=1,
                     value="✅  All policies are referenced by at least one control.").font = body_font(bold=True, color="276221")

        set_col_widths(ws5, {"A":12,"B":45,"C":20,"D":50})
        ws5.auto_filter.ref = f"A2:D{max(row-1, 3)}"

        # ═══════════════════════════════════════════════════════════════════════
        # SHEET 6 — Relationships
        # ═══════════════════════════════════════════════════════════════════════
        ws6 = wb.create_sheet("Relationships")
        title_row(ws6, f"Mapping Relationship Types  |  {app}", 3)
        rel = report["relationships"]

        r_types = [
            ("1-to-1",    "one_to_one",   "1 control maps to exactly 1 policy",
             ["Control ID","Policy ID"]),
            ("1-to-Many", "one_to_many",  "1 control maps to multiple policies",
             ["Control ID","Policy IDs"]),
            ("Many-to-1", "many_to_one",  "Multiple controls map to the same policy",
             ["Policy ID","Control IDs"]),
            ("Many-to-Many","many_to_many","Cluster of controls maps to cluster of policies",
             ["Control IDs","Policy IDs"]),
        ]

        current_row = 3
        for label, key, description, col_hdrs in r_types:
            items = rel.get(key, [])
            # Section title
            ws6.merge_cells(start_row=current_row, start_column=1,
                            end_row=current_row, end_column=3)
            c = ws6.cell(row=current_row, column=1,
                         value=f"{label}  ({len(items)})  —  {description}")
            c.font  = hdr_font(size=11, color="FFFFFF")
            c.fill  = fill(C_HEADER_MID)
            c.alignment = Alignment(horizontal="left", vertical="center")
            ws6.row_dimensions[current_row].height = 22
            current_row += 1

            write_header_row(ws6, current_row, col_hdrs + ["Count"])
            current_row += 1

            if not items:
                ws6.cell(row=current_row, column=1,
                         value="No relationships of this type.").font = body_font(color="595959")
                current_row += 1
            else:
                for i, item in enumerate(items):
                    alt = (i % 2 == 1)
                    if key == "one_to_one":
                        vals = [item["control"], item["policy"], 1]
                    elif key == "one_to_many":
                        vals = [item["control"],
                                ", ".join(item["policies"]),
                                len(item["policies"])]
                    elif key == "many_to_one":
                        vals = [item["policy"],
                                ", ".join(item["controls"]),
                                len(item["controls"])]
                    else:
                        vals = [", ".join(item["controls"]),
                                ", ".join(item["policies"]),
                                f"{len(item['controls'])} x {len(item['policies'])}"]
                    write_data_row(ws6, current_row, vals, alt=alt)
                    current_row += 1

            current_row += 1  # blank spacer row

        set_col_widths(ws6, {"A":25,"B":55,"C":12})

        # ═══════════════════════════════════════════════════════════════════════
        # SHEET 7 — One-to-Many (controls that map to multiple policies)
        # ═══════════════════════════════════════════════════════════════════════
        ws7 = wb.create_sheet("One-to-Many")
        title_row(ws7, f"One Control → Multiple Policies  |  {app}", 6)
        write_header_row(ws7, 2,
            ["Control ID", "Control Text", "Domain", "Framework",
             "Policy ID", "Policy Name", "Policy Category", "Impact",
             "Similarity Score", "Coverage", "Match Rank"])
        freeze(ws7, "A3")

        row = 3
        # Only controls that matched MORE than one policy
        multi_match = [cm for cm in report["control_mappings"] if len(cm["matches"]) > 1]
        for cm in multi_match:
            for rank, m in enumerate(cm["matches"], 1):
                relevance = ("HIGH"   if m["similarity_score"] >= 0.82 else
                             "MEDIUM" if m["similarity_score"] >= 0.60 else "LOW")
                vals = [
                    cm["control_id"],
                    cm["control_text"],
                    cm["domain"],
                    cm["framework"],
                    m["policy_id"],
                    m["policy_name"],
                    m.get("policy_category", ""),
                    m.get("impact", ""),
                    m["similarity_score"],
                    m["coverage"],
                    f"#{rank}",
                ]
                write_data_row(ws7, row, vals, alt=(row % 2 == 0))
                # Coverage colour — now column 10 (impact added)
                cov_cell = ws7.cell(row=row, column=10)
                if m["coverage"] == "FULL":
                    color_cell(cov_cell, C_FULL, C_FULL_FG)
                elif m["coverage"] == "PARTIAL":
                    color_cell(cov_cell, C_PARTIAL, C_PARTIAL_FG)
                else:
                    color_cell(cov_cell, C_INDIRECT, C_INDIRECT_FG)
                ws7.cell(row=row, column=8).number_format = "0.0000"
                row += 1
            # Blank separator row between controls
            row += 1

        if not multi_match:
            ws7.cell(row=3, column=1,
                     value="No controls matched more than one policy.").font = body_font(color="595959")

        set_col_widths(ws7, {"A":12,"B":45,"C":22,"D":12,
                              "E":12,"F":40,"G":18,"H":15,"I":14,"J":12,"K":10})
        ws7.auto_filter.ref = f"A2:K{max(row-1, 3)}"

        # ═══════════════════════════════════════════════════════════════════════
        # SHEET 8 — Mind Map (text-based tree layout in Excel)
        # ═══════════════════════════════════════════════════════════════════════
        ws8 = wb.create_sheet("Mind Map")
        title_row(ws8, f"Control → Policy Mind Map  |  {app}", 8)

        # Colour palette for mind map levels
        C_DOMAIN    = "1F3864"   # navy   — domain root
        C_DOMAIN_FG = "FFFFFF"
        C_CONTROL   = "2E75B6"   # blue   — control node
        C_CTRL_FG   = "FFFFFF"
        C_FULL_N    = "375623"   # dark green — FULL match node
        C_FULL_NFG  = "FFFFFF"
        C_PART_N    = "7F6000"   # dark amber — PARTIAL match node
        C_PART_NFG  = "FFFFFF"
        C_IND_N     = "595959"   # grey — INDIRECT node
        C_IND_NFG   = "FFFFFF"
        C_UNMAP     = "843C0C"   # red-brown — unmapped
        C_UNMAP_FG  = "FFFFFF"

        # Column layout:
        # A        = Domain
        # B        = Control ID
        # C        = Control Text (truncated)
        # D        = connector arrow
        # E        = Policy ID
        # F        = Policy Name
        # G        = Coverage badge

        # Header row — 8 columns now (added Impact)
        # Col: A=indent  B=ControlID  C=ControlText  D=arrow
        #      E=PolicyID  F=PolicyName  G=Coverage  H=Impact
        mm_hdrs = ["", "Control ID", "Control Text",
                   "", "Policy ID", "Policy Name", "Coverage", "Impact"]
        write_header_row(ws8, 2, mm_hdrs, bg=C_HEADER_DARK, fg="FFFFFF")
        ws8.row_dimensions[2].height = 20

        # Group controls by domain
        from collections import defaultdict
        domain_map = defaultdict(list)
        for cm in report["control_mappings"]:
            domain_map[cm["domain"]].append(cm)

        mm_row = 3
        for domain, controls in sorted(domain_map.items()):
            # Domain header row — spans all columns
            ws8.merge_cells(start_row=mm_row, start_column=1,
                            end_row=mm_row, end_column=8)
            dc = ws8.cell(row=mm_row, column=1,
                          value=f"▶  {domain.upper()}")
            dc.font      = Font(name="Arial", size=11, bold=True, color=C_DOMAIN_FG)
            dc.fill      = fill(C_DOMAIN)
            dc.alignment = Alignment(horizontal="left", vertical="center",
                                     indent=1)
            ws8.row_dimensions[mm_row].height = 22
            mm_row += 1

            for cm in controls:
                n_matches = len(cm["matches"])

                if n_matches == 0:
                    # Unmapped control — single row
                    ws8.cell(row=mm_row, column=1, value="")
                    ctrl_id_cell = ws8.cell(row=mm_row, column=2,
                                            value=cm["control_id"])
                    ctrl_id_cell.font = Font(name="Arial", size=10,
                                             bold=True, color=C_UNMAP_FG)
                    ctrl_id_cell.fill = fill(C_UNMAP)
                    ctrl_id_cell.alignment = wrap_align("center")

                    ctrl_txt = ws8.cell(row=mm_row, column=3,
                                        value=cm["control_text"][:80])
                    ctrl_txt.font = body_font(color=C_UNMAP)
                    ctrl_txt.alignment = wrap_align()

                    ws8.cell(row=mm_row, column=4, value="✘ NO MATCH").font =                         Font(name="Arial", size=10, bold=True, color=C_UNMAP)
                    mm_row += 1

                else:
                    # One row per matched policy
                    for idx, m in enumerate(cm["matches"]):
                        # Control ID + text only on first match row
                        if idx == 0:
                            ctrl_id_cell = ws8.cell(row=mm_row, column=2,
                                                    value=cm["control_id"])
                            ctrl_id_cell.font      = Font(name="Arial", size=10,
                                                          bold=True, color=C_CTRL_FG)
                            ctrl_id_cell.fill      = fill(C_CONTROL)
                            ctrl_id_cell.alignment = wrap_align("center")

                            ctrl_txt = ws8.cell(row=mm_row, column=3,
                                                value=cm["control_text"][:80])
                            ctrl_txt.font      = body_font(bold=True)
                            ctrl_txt.alignment = wrap_align()

                            # Merge control text cell vertically if multiple matches
                            if n_matches > 1:
                                try:
                                    ws8.merge_cells(
                                        start_row=mm_row, start_column=2,
                                        end_row=mm_row + n_matches - 1,
                                        end_column=2)
                                    ws8.merge_cells(
                                        start_row=mm_row, start_column=3,
                                        end_row=mm_row + n_matches - 1,
                                        end_column=3)
                                except Exception:
                                    pass  # skip merge errors

                        # Connector arrow
                        arrow = ws8.cell(row=mm_row, column=4,
                                         value="──►" if idx == 0 else "   ►")
                        arrow.font      = Font(name="Arial", size=10, color="2E75B6")
                        arrow.alignment = Alignment(horizontal="center",
                                                    vertical="center")

                        # Policy ID
                        pol_id_cell = ws8.cell(row=mm_row, column=5,
                                               value=m["policy_id"])
                        pol_id_cell.font      = body_font(bold=True)
                        pol_id_cell.alignment = wrap_align("center")

                        # Policy name
                        pol_name_cell = ws8.cell(row=mm_row, column=6,
                                                 value=m["policy_name"])
                        pol_name_cell.font      = body_font()
                        pol_name_cell.alignment = wrap_align()

                        # Coverage badge
                        cov_val = m["coverage"]
                        cov_cell = ws8.cell(row=mm_row, column=7, value=cov_val)
                        if cov_val == "FULL":
                            color_cell(cov_cell, C_FULL_N, C_FULL_NFG)
                        elif cov_val == "PARTIAL":
                            color_cell(cov_cell, C_PART_N, C_PART_NFG)
                        else:
                            color_cell(cov_cell, C_IND_N, C_IND_NFG)
                        cov_cell.alignment = Alignment(horizontal="center",
                                                       vertical="center")

                        # Impact cell — col 8
                        impact_val = m.get("impact", "")
                        imp_cell = ws8.cell(row=mm_row, column=8, value=impact_val)
                        imp_cell.font      = body_font(bold=bool(impact_val))
                        imp_cell.alignment = Alignment(horizontal="center",
                                                       vertical="center")
                        # Colour impact by severity if value present
                        if impact_val:
                            iv = impact_val.upper()
                            if any(x in iv for x in ("HIGH","CRITICAL","SEVERE")):
                                imp_cell.fill = fill(C_HIGH)
                                imp_cell.font = Font(name="Arial", size=10,
                                                     bold=True, color=C_HIGH_FG)
                            elif any(x in iv for x in ("MEDIUM","MODERATE")):
                                imp_cell.fill = fill(C_MEDIUM)
                                imp_cell.font = Font(name="Arial", size=10,
                                                     bold=True, color=C_MEDIUM_FG)
                            elif any(x in iv for x in ("LOW","MINOR","INFO")):
                                imp_cell.fill = fill(C_LOW)
                                imp_cell.font = Font(name="Arial", size=10,
                                                     bold=True, color=C_LOW_FG)

                        # Alt row shading for non-coloured cells
                        for col in [1, 4, 5, 6]:
                            c = ws8.cell(row=mm_row, column=col)
                            if not c.value:
                                c.fill = fill(C_ALT_ROW if mm_row % 2 == 0
                                              else "FFFFFF")
                            c.border = border

                        ws8.row_dimensions[mm_row].height = 18
                        mm_row += 1

            # Spacer between domains
            mm_row += 1

        set_col_widths(ws8, {"A":3, "B":13, "C":42,
                              "D":6, "E":13, "F":42, "G":11, "H":14})
        ws8.freeze_panes = "A3"

        # ── Save ──────────────────────────────────────────────────────────────
        wb.save(path)
        print(f"📊  Excel report saved to {path}")
        print(f"     Sheets: Summary | Control Mappings | Policy Mappings |")
        print(f"             Uncovered Controls | Orphan Policies | Relationships |")
        print(f"             One-to-Many | Mind Map")


    def save_csv(self, report: dict, prefix: str = "mapping"):
        """
        Export mapping results to 4 CSV files:

          {prefix}_control_mappings.csv   — every control with all its matched policies
          {prefix}_policy_mappings.csv    — every policy with all its matched controls
          {prefix}_uncovered_controls.csv — controls that have NO matching policy
          {prefix}_orphan_policies.csv    — policies that have NO matching control

        All files include the security domain from the input controls.
        """
        import csv
        app = report.get("app", "")

        # ── 1. Control Mappings ───────────────────────────────────────────────
        # One row per (control, matched_policy) pair.
        # If a control has 3 matches → 3 rows, all with same control fields.
        path1 = f"{prefix}_control_mappings.csv"
        with open(path1, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "app",
                "control_id",
                "control_text",
                "domain",
                "framework",
                "subdomain",
                "risk_level",
                "is_covered",
                "policy_id",
                "policy_name",
                "policy_category",
                "similarity_score",
                "coverage",
                "relevance",
            ])
            for cm in report["control_mappings"]:
                if cm["matches"]:
                    for m in cm["matches"]:
                        relevance = (
                            "HIGH"   if m["similarity_score"] >= 0.82 else
                            "MEDIUM" if m["similarity_score"] >= 0.60 else
                            "LOW"
                        )
                        writer.writerow([
                            app,
                            cm["control_id"],
                            cm["control_text"],
                            cm["domain"],
                            cm["framework"],
                            cm.get("subdomain", ""),
                            cm["risk_level"],
                            cm["is_covered"],
                            m["policy_id"],
                            m["policy_name"],
                            m.get("policy_category", ""),
                            m["similarity_score"],
                            m["coverage"],
                            relevance,
                        ])
                else:
                    # Control has no matches — still include as a row with blanks
                    writer.writerow([
                        app,
                        cm["control_id"],
                        cm["control_text"],
                        cm["domain"],
                        cm["framework"],
                        cm.get("subdomain", ""),
                        cm["risk_level"],
                        False,
                        "", "", "", "", "", "",
                    ])
        print(f"📄  Saved: {path1}")

        # ── 2. Policy Mappings ────────────────────────────────────────────────
        # One row per (policy, matched_control) pair.
        path2 = f"{prefix}_policy_mappings.csv"
        with open(path2, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "app",
                "policy_id",
                "policy_name",
                "policy_category",
                "is_orphan",
                "matched_control_id",
                "match_count",
            ])
            for pm in report["policy_mappings"]:
                if pm["matched_controls"]:
                    for ctrl_id in pm["matched_controls"]:
                        writer.writerow([
                            app,
                            pm["policy_id"],
                            pm["policy_name"],
                            pm.get("policy_category", ""),
                            pm["is_orphan"],
                            ctrl_id,
                            pm["match_count"],
                        ])
                else:
                    writer.writerow([
                        app,
                        pm["policy_id"],
                        pm["policy_name"],
                        pm.get("policy_category", ""),
                        True,
                        "",
                        0,
                    ])
        print(f"📄  Saved: {path2}")

        # ── 3. Uncovered Controls ─────────────────────────────────────────────
        # Standards that have NO matching OOTB policy
        path3 = f"{prefix}_uncovered_controls.csv"
        with open(path3, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "app",
                "control_id",
                "control_text",
                "domain",
                "framework",
                "subdomain",
                "risk_level",
                "reason",
            ])
            for uc in report["uncovered_controls"]:
                writer.writerow([
                    app,
                    uc["control_id"],
                    uc["control_text"],
                    uc["domain"],
                    uc["framework"],
                    uc.get("subdomain", ""),
                    uc["risk_level"],
                    uc.get("reason", "No OOTB policy matches at or above threshold"),
                ])
        count_uc = len(report["uncovered_controls"])
        print(f"📄  Saved: {path3}  ({count_uc} uncovered controls)")

        # ── 4. Orphan Policies ────────────────────────────────────────────────
        # Policies that NO control maps to
        path4 = f"{prefix}_orphan_policies.csv"
        with open(path4, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "app",
                "policy_id",
                "policy_name",
                "policy_category",
                "reason",
            ])
            for op in report["orphan_policies"]:
                writer.writerow([
                    app,
                    op["policy_id"],
                    op["policy_name"],
                    op.get("policy_category", ""),
                    op.get("reason", "No org control maps to this OOTB policy"),
                ])
        count_op = len(report["orphan_policies"])
        print(f"📄  Saved: {path4}  ({count_op} orphan policies)")

        # ── 5. Domain Summary ─────────────────────────────────────────────────
        path5 = f"{prefix}_domain_summary.csv"
        with open(path5, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "app",
                "domain",
                "total_controls",
                "covered_controls",
                "uncovered_controls",
                "coverage_pct",
                "full_matches",
                "partial_matches",
                "indirect_matches",
                "coverage_status",
                "coverage_note",
                "high_risk_controls",
                "uncovered_control_ids",
            ])
            for d in report["domain_summary"]:
                writer.writerow([
                    app,
                    d["domain"],
                    d["total_controls"],
                    d["covered_controls"],
                    d["uncovered_controls"],
                    d["coverage_pct"],
                    d.get("full_matches", 0),
                    d.get("partial_matches", 0),
                    d.get("indirect_matches", 0),
                    d["coverage_status"],
                    d.get("coverage_note", ""),
                    d["high_risk_controls"],
                    ", ".join(d.get("uncovered_control_ids", [])),
                ])
        print(f"📄  Saved: {path5}")
        print(f"\n✅  All CSV outputs saved with prefix: '{prefix}'")


# ── Sample Data Generator ─────────────────────────────────────────────────────

def generate_sample_data():
    """Creates sample controls and policies files for testing."""

    # ── Controls (org standards input) ───────────────────────────────────────
    controls = [
        # Access Control domain
        ["CTR-001","All users must authenticate using MFA before accessing any SaaS application","Access Control","ISO 27001","A.9.4.2",""],
        ["CTR-002","Privileged accounts must use hardware MFA tokens","Access Control","ISO 27001","A.9.4.2","Admin and service accounts"],
        ["CTR-003","Legacy authentication protocols must be disabled organisation-wide","Access Control","ISO 27001","A.9.4.3",""],
        ["CTR-004","Access must be restricted based on user role and least privilege principle","Access Control","ISO 27001","A.9.2.3",""],
        ["CTR-005","All third-party application integrations must be reviewed and authorised","Access Control","ISO 27001","A.15.2.1",""],
        # Data Protection domain
        ["CTR-006","Sensitive PII and financial data must not be shared with external parties without approval","Data Protection","ISO 27001","A.8.2.3",""],
        ["CTR-007","All sensitive data must be encrypted at rest using AES-256 or equivalent","Data Protection","ISO 27001","A.10.1.1",""],
        ["CTR-008","Data Loss Prevention controls must be configured to detect sensitive data in transit","Data Protection","NIST CSF","PR.DS-5",""],
        # Logging & Monitoring domain
        ["CTR-009","All user authentication events must be logged and retained for minimum 12 months","Logging & Monitoring","ISO 27001","A.12.4.1",""],
        ["CTR-010","All privileged actions and admin configuration changes must be audited","Logging & Monitoring","ISO 27001","A.12.4.3",""],
        ["CTR-011","Security events must be forwarded to SIEM within 5 minutes","Logging & Monitoring","NIST CSF","DE.CM-1",""],
        # Identity Management domain
        ["CTR-012","User provisioning and deprovisioning must be automated via SCIM or equivalent","Identity Management","ISO 27001","A.9.2.1",""],
        ["CTR-013","Passwords must meet complexity requirements: min 12 chars, uppercase, numbers, symbols","Identity Management","ISO 27001","A.9.4.3",""],
        ["CTR-014","Session idle timeout must not exceed 15 minutes for privileged sessions","Identity Management","ISO 27001","A.9.4.2",""],
        # Incident Response domain
        ["CTR-015","Anomalous login behaviour must trigger automated alerts within 10 minutes","Incident Response","NIST CSF","DE.AE-2",""],
        ["CTR-016","Suspected account compromise must initiate automatic session termination","Incident Response","NIST CSF","RS.RP-1",""],
        # Compliance domain
        ["CTR-017","All SaaS platforms must provide audit reports for compliance reviews","Compliance","ISO 27001","A.18.2.3",""],
        ["CTR-018","Data residency requirements must be enforced — EU data must not leave EU region","Compliance","GDPR","Art.46",""],
    ]

    with open("sample_controls.csv","w",newline="",encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["control_id","control_text","domain","framework","subdomain","description"])
        w.writerows(controls)

    # ── Policies (OOTB for Microsoft 365) — NO framework references ──────────
    policies = [
        ["POL-001","Enable Multi-Factor Authentication for all users","Identity","Require MFA at every login for all Microsoft 365 accounts"],
        ["POL-002","Block legacy authentication protocols","Identity","Disable Basic Auth SMTP Auth IMAP POP3 across all services"],
        ["POL-003","Configure Conditional Access policies","Access Control","Enforce access policies based on user location device compliance and sign-in risk"],
        ["POL-004","Enable audit log search and retention","Logging","Enable unified audit log and retain for 90 days minimum"],
        ["POL-005","Disable anonymous sharing in SharePoint and OneDrive","Data Protection","Prevent unauthenticated external access to files and folders"],
        ["POL-006","Enable Safe Links and Safe Attachments","Threat Protection","Scan links and attachments for malware and phishing in real time"],
        ["POL-007","Enforce password complexity and expiration policy","Identity","Set minimum password length complexity and rotation requirements"],
        ["POL-008","Restrict mailbox auto-forwarding to external domains","Data Protection","Block rules that automatically forward emails outside the organisation"],
        ["POL-009","Enable Microsoft 365 DLP policies","Data Protection","Detect and block transmission of sensitive data types in email and files"],
        ["POL-010","Enable Microsoft Secure Score recommendations","Governance","Track and implement Microsoft security baseline recommendations"],
        ["POL-011","Enable Azure AD SCIM provisioning","Identity","Automate user lifecycle management via SCIM protocol"],
        ["POL-012","Configure session timeout for inactive sessions","Session","Automatically sign out users after period of inactivity"],
        ["POL-013","Enable Microsoft Sentinel log streaming","Logging","Forward security events from Microsoft 365 to SIEM in real time"],
        ["POL-014","Enable Identity Protection risk-based sign-in policies","Threat Detection","Automatically challenge or block risky sign-in attempts"],
        ["POL-015","Enable Microsoft Purview eDiscovery and retention","Compliance","Configure data retention labels and legal hold capabilities"],
        ["POL-016","Configure data residency settings","Compliance","Set tenant data location to specific geographic region"],
        ["POL-017","Enable Hardware FIDO2 security key authentication","Identity","Allow and enforce phishing-resistant hardware security keys for privileged users"],
        ["POL-018","Enable Privileged Identity Management (PIM)","Access Control","Just-in-time privileged access with approval workflows and time limits"],
        ["POL-019","Configure Microsoft Defender for Cloud Apps anomaly detection","Threat Detection","Alert on impossible travel unusual file downloads and suspicious admin actions"],
        ["POL-020","Restrict third-party OAuth app permissions","Access Control","Require admin consent for third-party apps requesting Microsoft 365 permissions"],
    ]

    # Add impact column to sample policies
    policies_with_impact = []
    impact_map = {
        "Identity":         "HIGH",
        "Access Control":   "HIGH",
        "Data Protection":  "HIGH",
        "Logging":          "MEDIUM",
        "Compliance":       "MEDIUM",
        "Session":          "MEDIUM",
        "Threat Detection": "HIGH",
        "Threat Protection":"HIGH",
        "Governance":       "LOW",
    }
    for p in policies:
        cat = p[2]
        impact = impact_map.get(cat, "MEDIUM")
        policies_with_impact.append(p + [impact])

    with open("sample_policies_m365.csv","w",newline="",encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["policy_id","policy_name","category","description","impact"])
        w.writerows(policies_with_impact)

    print("📄  Generated sample_controls.csv      (18 controls, 6 domains)")
    print("📄  Generated sample_policies_m365.csv (20 policies, Microsoft 365)\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    """
    Parse command line arguments.

    Usage:
      python sspm_mapper.py \
        --controls  your_controls.csv \
        --policies  your_policies.csv \
        --app       "Microsoft 365"   \
        --out       my_report         \
        --verbose

    All arguments are optional — defaults to sample data.
    """
    import argparse
    p = argparse.ArgumentParser(
        description="SSPM Policy Mapper — maps org security controls to OOTB policies",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--controls", "-c",
                   default=None,
                   help="Path to controls CSV/JSON file\n"
                        "Columns: control_id, control_text, domain, framework, subdomain")
    p.add_argument("--policies", "-p",
                   default=None,
                   help="Path to OOTB policies CSV/JSON file\n"
                        "Columns: policy_id, policy_name, category, description")
    p.add_argument("--app", "-a",
                   default=None,
                   help="SaaS application name (used as report title and output prefix)\n"
                        "Example: --app \"Microsoft 365\"")
    p.add_argument("--out", "-o",
                   default=None,
                   help="Output file prefix (default: derived from app name)\n"
                        "Example: --out salesforce  →  salesforce_report.xlsx")
    p.add_argument("--threshold", "-t",
                   type=float, default=0.40,
                   help="Minimum similarity score to include a match (default: 0.40)")
    p.add_argument("--topk", "-k",
                   type=int, default=5,
                   help="Max number of policy matches per control (default: 5)")
    p.add_argument("--verbose", "-v",
                   action="store_true",
                   help="Show all control→policy match details in console output")
    p.add_argument("--model", "-m",
                   default=None,
                   help="Path to local SecBERT model folder\n"
                        "Example: --model ./secbert_clean")
    p.add_argument("--clear-cache",
                   action="store_true",
                   help="Delete all cached policy embeddings before running\n"
                        "Use when switching policy files or SecBERT model")
    return p.parse_args()


def main():
    import sys
    args = parse_args()

    print("="*70)
    print("  🛡️  SSPM Policy Mapper v4 — Bidirectional Gap Analysis")
    print("="*70+"\n")

    # ── Resolve file paths ────────────────────────────────────────────────────
    # If no files passed → generate and use sample data
    controls_file = args.controls
    policies_file = args.policies

    if not controls_file or not policies_file:
        if not Path("sample_controls.csv").exists():
            generate_sample_data()
        controls_file = controls_file or "sample_controls.csv"
        policies_file = policies_file or "sample_policies_m365.csv"
        print(f"ℹ️   No files specified — using sample data.")
        print(f"     Controls : {controls_file}")
        print(f"     Policies : {policies_file}\n")
        print(f"     To use your own files:")
        print(f"     python sspm_mapper.py --controls your_controls.csv \\")
        print(f'                           --policies your_policies.csv \\')
        print(f'                           --app "Your App Name"\n')

    # ── Derive app name ───────────────────────────────────────────────────────
    # Priority: --app argument > filename stem > "Unknown App"
    if args.app:
        app_name = args.app
    else:
        # Derive from policy filename: "sample_policies_m365.csv" → "M365"
        stem = Path(policies_file).stem               # e.g. "sample_policies_m365"
        stem = stem.replace("sample_policies_", "")   # → "m365"
        stem = stem.replace("policies_", "")          # → "m365"
        stem = stem.replace("_policies", "")
        stem = stem.replace("_", " ").strip()
        app_name = stem.title() if stem else "Unknown App"
        print(f"ℹ️   No --app specified — using '{app_name}' derived from filename.")
        print(f"     Pass --app \"Your App Name\" for a proper title.\n")

    # ── Derive output prefix ──────────────────────────────────────────────────
    if args.out:
        out_prefix = args.out
    else:
        out_prefix = app_name.lower().replace(" ", "_").replace("/", "_")

    print(f"  App     : {app_name}")
    print(f"  Controls: {controls_file}")
    print(f"  Policies: {policies_file}")
    print(f"  Output  : {out_prefix}_report.xlsx\n")

    # ── Run mapper ────────────────────────────────────────────────────────────
    mapper = SSPMMapper(model_path=args.model)

    # Clear cache if requested or if a fresh start is needed
    if getattr(args, 'clear_cache', False):
        mapper.cache.clear()

    mapper.load_controls(controls_file)
    mapper.load_policies(policies_file, app=app_name)

    report = mapper.run(top_k=args.topk, threshold=args.threshold)
    mapper.print_report(report, verbose=args.verbose)

    # ── Save outputs ──────────────────────────────────────────────────────────
    mapper.save_report(report, f"{out_prefix}_report.json")

    try:
        mapper.save_csv(report, prefix=out_prefix)
    except Exception as e:
        print(f"⚠️  CSV export failed: {e}")

    try:
        import openpyxl
        mapper.save_xlsx(report, path=f"{out_prefix}_report.xlsx")
    except ImportError:
        print("⚠️  Excel export skipped — openpyxl not installed.")
        print("    Run:  pip install openpyxl")
    except Exception as e:
        print(f"⚠️  Excel export failed: {e}")

if __name__ == "__main__":
    main()
