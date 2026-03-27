import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter


# ──────────────────────────────────────────────────────────────────────────────
# Config loader
# ──────────────────────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(f"Config file not found: {cfg_path.resolve()}")
    with cfg_path.open("r", encoding="utf-8") as f:
        cfg = json.load(f)

    required = {
        "jira.url", "jira.email", "jira.token",
        "project.key", "project.output",
    }
    for key in required:
        section, field = key.split(".")
        if not cfg.get(section, {}).get(field):
            raise ValueError(f"Missing required config key: {key}")

    return cfg


# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

def setup_logging(cfg: dict) -> logging.Logger:
    log_cfg  = cfg.get("logging", {})
    level    = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
    log_file = log_cfg.get("file", "jira_extractor.log")

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )
    return logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Jira API client
# ──────────────────────────────────────────────────────────────────────────────

class JiraClient:
    def __init__(self, cfg: dict, logger: logging.Logger):
        jira_cfg    = cfg["jira"]
        fetch_cfg   = cfg.get("fetch", {})
        self.base   = jira_cfg["url"].rstrip("/")
        self.auth   = HTTPBasicAuth(jira_cfg["email"], jira_cfg["token"])
        self.max_results  = int(fetch_cfg.get("max_results", 100))
        self.timeout      = int(fetch_cfg.get("timeout_secs", 30))
        self.logger  = logger
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"Accept": "application/json"})
        session.auth = self.auth
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.mount("http://",  HTTPAdapter(max_retries=retry))
        return session

    def fetch_all(self, jql: str, fields: list[str]) -> list[dict]:
        """Paginate Jira search and return all matching issues."""
        issues, start = [], 0
        self.logger.debug("JQL: %s", jql)
        while True:
            resp = self.session.get(
                f"{self.base}/rest/api/3/search",
                params={
                    "jql":        jql,
                    "fields":     ",".join(fields),
                    "startAt":    start,
                    "maxResults": self.max_results,
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data  = resp.json()
            batch = data.get("issues", [])
            issues.extend(batch)
            start += len(batch)
            total  = data.get("total", 0)
            self.logger.debug("Fetched %d / %d", start, total)
            if start >= total or not batch:
                break
        return issues


# ──────────────────────────────────────────────────────────────────────────────
# Field helpers
# ──────────────────────────────────────────────────────────────────────────────

def gf(issue: dict, *keys, default=""):
    """Safely traverse nested issue fields."""
    val = issue.get("fields", {})
    for k in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(k)
    return val if val is not None else default


def first_value(issue: dict, field_ids: list[str], default=""):
    """Return the first non-null value among a list of custom field IDs."""
    for fid in field_ids:
        val = gf(issue, fid)
        if val not in (None, "", {}):
            return val
    return default


def fmt_date(raw) -> str:
    if not raw:
        return ""
    try:
        return datetime.fromisoformat(str(raw)[:10]).strftime("%d-%b-%Y")
    except ValueError:
        return str(raw)[:10]


def get_assignee(issue: dict) -> str:
    a = gf(issue, "assignee")
    return a.get("displayName", "") if isinstance(a, dict) else ""


def get_priority(issue: dict) -> str:
    p = gf(issue, "priority")
    return p.get("name", "") if isinstance(p, dict) else ""


def get_status(issue: dict) -> str:
    return gf(issue, "status", "name")


def get_labels(issue: dict) -> str:
    lb = gf(issue, "labels")
    return ", ".join(lb) if isinstance(lb, list) else ""


def get_story_points(issue: dict, field_ids: list[str]):
    val = first_value(issue, field_ids)
    return val if val != "" else ""


def get_start_date(issue: dict, field_ids: list[str]) -> str:
    return fmt_date(first_value(issue, field_ids))


def get_due_date(issue: dict, field_ids: list[str]) -> str:
    return fmt_date(first_value(issue, field_ids))


# ──────────────────────────────────────────────────────────────────────────────
# Style constants
# ──────────────────────────────────────────────────────────────────────────────

C_EPIC_BG  = "4A154B"
C_EPIC_FG  = "FFFFFF"
C_HDR_BG   = "172B4D"
C_HDR_FG   = "FFFFFF"
C_STORY_A  = "EFF6FF"
C_STORY_B  = "DBEAFE"
C_STORY_FG = "1E3A5F"
C_DONE     = "00875A"
C_INPROG   = "FF8B00"
C_TODO     = "6B778C"

STATUS_COLOURS = {
    "done":        C_DONE,
    "closed":      C_DONE,
    "resolved":    C_DONE,
    "in progress": C_INPROG,
    "in review":   C_INPROG,
}

COLS = [
    ("Epic",          22),
    ("Story Key",     12),
    ("Story Summary", 52),
    ("Status",        14),
    ("Assignee",      22),
    ("Priority",      12),
    ("Story Points",  13),
    ("Start Date",    14),
    ("Due Date",      14),
    ("Labels",        26),
]
NUM_COLS = len(COLS)


def mk_fill(hex_col: str) -> PatternFill:
    return PatternFill("solid", fgColor=hex_col)


def mk_border_bottom() -> Border:
    s = Side(style="thin", color="CCCCCC")
    n = Side(style=None)
    return Border(bottom=s, top=n, left=n, right=n)


def mk_border_all() -> Border:
    s = Side(style="thin", color="BBBBBB")
    return Border(top=s, bottom=s, left=s, right=s)


def status_colour(status: str) -> str:
    return STATUS_COLOURS.get(status.lower(), C_TODO)


# ──────────────────────────────────────────────────────────────────────────────
# Workbook builder
# ──────────────────────────────────────────────────────────────────────────────

def build_workbook(epics: list, story_map: dict,
                   project_key: str, fields_cfg: dict) -> Workbook:
    wb = Workbook()
    ws = wb.active
    ws.title = f"{project_key} Hierarchy"
    ws.freeze_panes = "B3"

    for i, (_, w) in enumerate(COLS, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.row_dimensions[1].height = 22
    ws.row_dimensions[2].height = 20

    # Title row
    ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=NUM_COLS)
    tc = ws.cell(row=1, column=1,
                 value=f"Jira Project: {project_key}  —  Issue Hierarchy")
    tc.font      = Font(name="Arial", bold=True, size=12, color=C_HDR_FG)
    tc.fill      = mk_fill(C_HDR_BG)
    tc.alignment = Alignment(horizontal="center", vertical="center")

    # Header row
    for ci, (hdr, _) in enumerate(COLS, 1):
        c = ws.cell(row=2, column=ci, value=hdr)
        c.font      = Font(name="Arial", bold=True, size=10, color=C_HDR_FG)
        c.fill      = mk_fill(C_HDR_BG)
        c.alignment = Alignment(horizontal="center", vertical="center")
        c.border    = mk_border_bottom()

    sp_fields    = fields_cfg.get("story_points", ["customfield_10016"])
    start_fields = fields_cfg.get("start_date",   ["customfield_10015"])
    due_fields   = fields_cfg.get("due_date",      ["duedate"])

    current_row = 3

    for epic in epics:
        epic_key   = epic["key"]
        epic_name  = gf(epic, "summary")
        stories    = story_map.get(epic_key, [])
        epic_span  = max(1, len(stories))
        epic_start = current_row

        # Epic cell — col A, merged across all story rows
        if epic_span > 1:
            ws.merge_cells(
                start_row=epic_start, start_column=1,
                end_row=epic_start + epic_span - 1, end_column=1,
            )
        ec = ws.cell(row=epic_start, column=1,
                     value=f"{epic_key}\n{epic_name}")
        ec.font      = Font(name="Arial", bold=True, size=10, color=C_EPIC_FG)
        ec.fill      = mk_fill(C_EPIC_BG)
        ec.alignment = Alignment(horizontal="center", vertical="center",
                                 wrap_text=True)
        ec.border    = mk_border_all()

        if not stories:
            for ci in range(2, NUM_COLS + 1):
                c = ws.cell(row=epic_start, column=ci)
                c.fill   = mk_fill(C_EPIC_BG)
                c.border = mk_border_bottom()
            ws.row_dimensions[epic_start].height = 30
            current_row += 1
            continue

        for s_idx, story in enumerate(stories):
            row    = epic_start + s_idx
            bg     = C_STORY_A if s_idx % 2 == 0 else C_STORY_B
            status = get_status(story)
            ws.row_dimensions[row].height = 18

            def sc(col, val="", bold=False, center=False):
                c = ws.cell(row=row, column=col, value=val)
                c.font      = Font(name="Arial", size=10,
                                   color=C_STORY_FG, bold=bold)
                c.fill      = mk_fill(bg)
                c.alignment = Alignment(
                    horizontal="center" if center else "left",
                    vertical="center", wrap_text=True,
                )
                c.border = mk_border_bottom()
                return c

            sc(2,  story["key"],                                    bold=True)
            sc(3,  gf(story, "summary"))
            # Status badge
            stc = ws.cell(row=row, column=4, value=status)
            stc.font      = Font(name="Arial", bold=True, size=9, color="FFFFFF")
            stc.fill      = mk_fill(status_colour(status))
            stc.alignment = Alignment(horizontal="center", vertical="center")
            stc.border    = mk_border_bottom()

            sc(5,  get_assignee(story))
            sc(6,  get_priority(story),                             center=True)
            sc(7,  get_story_points(story, sp_fields),              center=True)
            sc(8,  get_start_date(story, start_fields),             center=True)
            sc(9,  get_due_date(story, due_fields),                 center=True)
            sc(10, get_labels(story))

        current_row = epic_start + epic_span

    # Summary sheet
    ws2 = wb.create_sheet("Summary")
    ws2.column_dimensions["A"].width = 30
    ws2.column_dimensions["B"].width = 14

    total_stories = sum(len(v) for v in story_map.values())
    epics_no_story = sum(1 for e in epics if not story_map.get(e["key"]))

    summary_rows = [
        ("Metric",                "Count"),
        ("Total Epics",           len(epics)),
        ("Total Stories",         total_stories),
        ("Epics with no Stories", epics_no_story),
        ("Extracted on",          datetime.now().strftime("%d-%b-%Y %H:%M")),
    ]
    for ri, (lbl, val) in enumerate(summary_rows, 1):
        lc = ws2.cell(row=ri, column=1, value=lbl)
        vc = ws2.cell(row=ri, column=2, value=val)
        if ri == 1:
            lc.font = vc.font = Font(name="Arial", bold=True,
                                     color=C_HDR_FG, size=10)
            lc.fill = vc.fill = mk_fill(C_HDR_BG)
        else:
            lc.font = vc.font = Font(name="Arial", size=10)
            vc.alignment = Alignment(horizontal="center")
        lc.alignment = Alignment(horizontal="left")
        ws2.row_dimensions[ri].height = 18

    return wb


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────────────────────

def run(cfg: dict, logger: logging.Logger) -> None:
    client      = JiraClient(cfg, logger)
    project_key = cfg["project"]["key"]
    output      = cfg["project"]["output"]
    fields_cfg  = cfg.get("fields", {})

    base_fields = [
        "summary", "status", "assignee", "priority", "labels",
        *fields_cfg.get("story_points", ["customfield_10016", "customfield_10028"]),
        *fields_cfg.get("start_date",   ["customfield_10015", "startDate"]),
        *fields_cfg.get("due_date",     ["duedate", "customfield_10021"]),
    ]
    # De-duplicate
    base_fields = list(dict.fromkeys(base_fields))

    logger.info("Fetching Epics for project: %s", project_key)
    epics = client.fetch_all(
        f'project="{project_key}" AND issuetype=Epic ORDER BY key ASC',
        base_fields,
    )
    logger.info("Epics found: %d", len(epics))

    logger.info("Fetching Stories …")
    epic_link_fields = fields_cfg.get("epic_link", ["customfield_10014"])
    stories = client.fetch_all(
        f'project="{project_key}" AND issuetype=Story ORDER BY key ASC',
        base_fields + epic_link_fields + ["parent"],
    )
    logger.info("Stories found: %d", len(stories))

    # Map stories → epics
    story_map = {e["key"]: [] for e in epics}
    orphans   = []

    for story in stories:
        f = story.get("fields", {})
        epic_link = None
        for fid in epic_link_fields:
            epic_link = f.get(fid)
            if epic_link:
                break
        if not epic_link:
            epic_link = (f.get("parent") or {}).get("key")

        if epic_link and epic_link in story_map:
            story_map[epic_link].append(story)
        else:
            orphans.append(story)

    if orphans:
        logger.warning("%d stories have no linked Epic — grouped separately",
                       len(orphans))
        fake_epic = {
            "key": "NO-EPIC",
            "fields": {
                "summary":  "⚠ Stories without an Epic",
                "status":   {"name": "N/A"},
                "assignee": None,
                "priority": None,
                "labels":   [],
            },
        }
        epics.append(fake_epic)
        story_map["NO-EPIC"] = orphans

    logger.info("Building workbook …")
    wb = build_workbook(epics, story_map, project_key, fields_cfg)
    wb.save(output)
    logger.info("Saved → %s  (Epics: %d | Stories: %d)",
                output, len(epics), sum(len(v) for v in story_map.values()))


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract Jira Epics & Stories to a formatted Excel file."
    )
    parser.add_argument(
        "--config", "-c",
        default="config.json",
        help="Path to JSON config file (default: config.json)",
    )
    args = parser.parse_args()

    try:
        cfg    = load_config(args.config)
        logger = setup_logging(cfg)
        logger.info("Config loaded from: %s", args.config)
        run(cfg, logger)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"CONFIG ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        logging.error("Cannot connect to Jira. Check 'jira.url' in config.")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        logging.error("Jira API error: %s", e.response.text)
        sys.exit(1)
    except Exception as e:
        logging.exception("Unexpected error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
