#!/usr/bin/env python3
"""Build the RHEL 9 Konflux blockers dashboard (index.html + data/dashboard.json).

Data sources
------------
1. The tracking spreadsheet, either:
   - a local .xlsx file (``--xlsx PATH``), or
   - a live export from Google Drive using a service account
     (``GOOGLE_SERVICE_ACCOUNT_JSON`` + ``SPREADSHEET_ID``).
2. Jira REST API enrichment for every blocker key found in the spreadsheet
   (``JIRA_EMAIL`` + ``JIRA_API_TOKEN`` + optional ``JIRA_BASE``).

Both enrichment sources are optional so the script can still produce a
(less detailed) report when run locally without credentials.

Only ``openpyxl`` and ``requests`` are required -- the Google service-account
JWT is signed with a small pure-Python RSA/PKCS#1v1.5 implementation so we
don't need ``google-auth`` or ``cryptography``.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import openpyxl
import requests

DEFAULT_SPREADSHEET_ID = "1MJhmkOFgbSjuvuO9f8v5DDWiuxiMTGPOhVOHII67-5o"
DEFAULT_JIRA_BASE = "https://redhat.atlassian.net"
SPREADSHEET_URL_TMPL = "https://docs.google.com/spreadsheets/d/{id}"
EPIC_LINKS = [
    ("KFLUXMIG-1166", "https://redhat.atlassian.net/browse/KFLUXMIG-1166"),
    ("KFLUXMIG-937", "https://redhat.atlassian.net/browse/KFLUXMIG-937"),
]

SHEET_ACTIVE_RPMS = "Active RPMs"
SHEET_BLOCKERS = "RHEL9 Blockers"
SHEET_DATA_CHART = "RHEL 9 Data and Chart"

KEY_RE = re.compile(r"[A-Z][A-Z0-9]+-\d+")
DONE_STATUS_NAMES = {"done", "closed", "resolved", "release pending"}
JIRA_BATCH_SIZE = 40

JIRA_FIELDS = [
    "summary",
    "status",
    "assignee",
    "labels",
    "components",
    "priority",
    "issuetype",
    "updated",
    "project",
]


# --------------------------------------------------------------------------
# Pure-python RSA-SHA256 signing (avoids a google-auth / cryptography dep)
# --------------------------------------------------------------------------

def _der_read_tlv(data: bytes, offset: int):
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    value = data[offset:offset + length]
    return tag, value, offset + length


def _der_read_sequence(der: bytes):
    tag, value, _ = _der_read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("expected DER SEQUENCE")
    items = []
    offset = 0
    while offset < len(value):
        t, v, offset = _der_read_tlv(value, offset)
        items.append((t, v))
    return items


def _rsa_key_from_pem(pem_text: str):
    """Extract (modulus n, private exponent d) from a PKCS#8 or PKCS#1 PEM key."""
    body = "".join(
        line.strip()
        for line in pem_text.strip().splitlines()
        if line.strip() and not line.startswith("-----")
    )
    der = base64.b64decode(body)
    outer = _der_read_sequence(der)

    if len(outer) >= 3 and outer[0][0] == 0x02 and outer[2][0] == 0x04:
        # PKCS#8 PrivateKeyInfo: version INTEGER, algorithm SEQUENCE, privateKey OCTET STRING
        inner = _der_read_sequence(outer[2][1])
    else:
        # Already a bare PKCS#1 RSAPrivateKey
        inner = outer

    n = int.from_bytes(inner[1][1], "big")
    d = int.from_bytes(inner[3][1], "big")
    return n, d


_SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _rsa_sign_sha256(n: int, d: int, message: bytes) -> bytes:
    digest = hashlib.sha256(message).digest()
    t = _SHA256_DIGESTINFO_PREFIX + digest
    k = (n.bit_length() + 7) // 8
    ps_len = k - len(t) - 3
    if ps_len < 8:
        raise ValueError("RSA key too small for SHA-256 PKCS#1v1.5 signing")
    em = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
    m = int.from_bytes(em, "big")
    s = pow(m, d, n)
    return s.to_bytes(k, "big")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def get_google_access_token(sa_info: dict, scope: str = "https://www.googleapis.com/auth/drive.readonly") -> str:
    token_uri = sa_info.get("token_uri", "https://oauth2.googleapis.com/token")
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {
        "iss": sa_info["client_email"],
        "scope": scope,
        "aud": token_uri,
        "iat": now,
        "exp": now + 3600,
    }
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    n, d = _rsa_key_from_pem(sa_info["private_key"])
    signature = _rsa_sign_sha256(n, d, signing_input.encode("ascii"))
    assertion = signing_input + "." + _b64url(signature)

    resp = requests.post(
        token_uri,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def download_xlsx_via_drive(sa_info: dict, spreadsheet_id: str) -> bytes:
    token = get_google_access_token(sa_info)
    url = f"https://www.googleapis.com/drive/v3/files/{spreadsheet_id}/export"
    resp = requests.get(
        url,
        params={"mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        headers={"Authorization": f"Bearer {token}"},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.content


def _load_service_account(raw: str) -> dict:
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        path = Path(raw)
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        raise SystemExit(
            "GOOGLE_SERVICE_ACCOUNT_JSON is neither valid JSON nor an existing file path"
        )


# --------------------------------------------------------------------------
# Spreadsheet loading
# --------------------------------------------------------------------------

def load_workbook_source(args, spreadsheet_id: str):
    if args.xlsx:
        path = Path(args.xlsx)
        if not path.exists():
            raise SystemExit(f"--xlsx path not found: {path}")
        print(f"Loading spreadsheet from local file: {path}")
        wb = openpyxl.load_workbook(str(path), data_only=True)
        return wb, f"local file `{path.name}`"

    sa_raw = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON")
    if not sa_raw:
        raise SystemExit(
            "No spreadsheet source available: pass --xlsx PATH, or set "
            "GOOGLE_SERVICE_ACCOUNT_JSON (+ optionally SPREADSHEET_ID) to "
            "download the sheet from Google Drive."
        )
    sa_info = _load_service_account(sa_raw)
    print(f"Downloading spreadsheet {spreadsheet_id} from Google Drive...")
    content = download_xlsx_via_drive(sa_info, spreadsheet_id)
    wb = openpyxl.load_workbook(io.BytesIO(content), data_only=True)
    return wb, f"Google Drive export ({spreadsheet_id})"


def _num(value) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def load_active_rpms(wb) -> list:
    """Active RPMs columns: Status[0], Package Name[1], Assignee[2], SST Name[6], Blockers[8]."""
    ws = wb[SHEET_ACTIVE_RPMS]
    packages = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row or row[1] is None:
            continue
        status = row[0]
        name = row[1]
        assignee = row[2] if len(row) > 2 else None
        sst = row[6] if len(row) > 6 else None
        blockers_field = row[8] if len(row) > 8 else None

        keys = KEY_RE.findall(blockers_field) if isinstance(blockers_field, str) else []
        is_blocked_status = isinstance(status, str) and status.strip().lower() == "blocked"

        if is_blocked_status or keys:
            packages.append({
                "package": str(name).strip(),
                "status": status,
                "assignee": (assignee or "").strip() if isinstance(assignee, str) else assignee,
                "sst": (sst or "").strip() if isinstance(sst, str) else sst,
                "blocker_keys": list(dict.fromkeys(keys)),  # de-dup, keep order
                "blockers_raw": blockers_field,
            })
    return packages


def load_rhel9_blockers(wb) -> dict:
    """key, type, total, todo, in_progress, completed, url."""
    ws = wb[SHEET_BLOCKERS]
    out = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row or not row[0] or not isinstance(row[0], str):
            continue
        key = row[0].strip()
        out[key] = {
            "type": row[1] if len(row) > 1 else None,
            "total": _num(row[2] if len(row) > 2 else None),
            "todo": _num(row[3] if len(row) > 3 else None),
            "in_progress": _num(row[4] if len(row) > 4 else None),
            "completed": _num(row[5] if len(row) > 5 else None),
            "url": row[6] if len(row) > 6 else None,
        }
    return out


_DC_LABELS = {"Total RPMs", "Onboarded", "Ready to be onboarded", "Has blockers", "In Progress"}


def load_data_and_chart(wb) -> dict:
    """Read Total RPMs / Onboarded / Has blockers style summary counts."""
    ws = wb[SHEET_DATA_CHART]
    out = {}
    for row in ws.iter_rows(min_row=1, max_row=20, values_only=True):
        if not row or row[0] is None:
            continue
        label = str(row[0]).strip()
        if label not in _DC_LABELS:
            continue
        count = row[1] if len(row) > 1 else None
        pct = row[2] if len(row) > 2 and isinstance(row[2], (int, float)) else None
        out[label] = {"count": count, "pct": pct}
    return out


def _dc_count(dc: dict, label: str):
    entry = dc.get(label)
    return entry["count"] if entry else None


def _dc_pct(dc: dict, label: str):
    entry = dc.get(label)
    if not entry or entry.get("pct") is None:
        return None
    return round(entry["pct"] * 100, 1)


# --------------------------------------------------------------------------
# Jira enrichment
# --------------------------------------------------------------------------

def _jira_search(base: str, auth, jql: str, fields: list, max_results: int = 100) -> dict:
    body = {"jql": jql, "fields": fields, "maxResults": max_results}
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    resp = requests.post(f"{base}/rest/api/3/search/jql", auth=auth, headers=headers, json=body, timeout=30)
    if resp.status_code == 404:
        resp = requests.post(f"{base}/rest/api/3/search", auth=auth, headers=headers, json=body, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _jira_get_issue(base: str, auth, key: str, fields: list):
    headers = {"Accept": "application/json"}
    resp = requests.get(
        f"{base}/rest/api/3/issue/{key}",
        auth=auth,
        headers=headers,
        params={"fields": ",".join(fields)},
        timeout=30,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def _parse_issue(issue: dict) -> dict:
    key = issue.get("key")
    f = issue.get("fields") or {}
    status = f.get("status") or {}
    status_name = status.get("name") or "Unknown"
    status_category = ((status.get("statusCategory") or {}).get("key") or "").lower()
    assignee = f.get("assignee")
    assignee_name = assignee.get("displayName") if assignee else None
    labels = f.get("labels") or []
    components = [c.get("name") for c in (f.get("components") or []) if c.get("name")]
    project = (f.get("project") or {}).get("key")
    is_done = status_category == "done" or status_name.strip().lower() in DONE_STATUS_NAMES
    return {
        "key": key,
        "summary": f.get("summary") or "",
        "status": status_name,
        "status_category": status_category or "unknown",
        "assignee": assignee_name,
        "labels": labels,
        "components": components,
        "project": project,
        "updated": f.get("updated"),
        "issuetype": (f.get("issuetype") or {}).get("name"),
        "is_done": is_done,
    }


def fetch_jira_issues(keys: list, base: str, email: str, token: str):
    """Fetch Jira issues in batches of ~40 via JQL, falling back to per-key GET for misses."""
    keys = sorted(set(keys))
    auth = (email, token)
    result = {}
    missing = []

    for i in range(0, len(keys), JIRA_BATCH_SIZE):
        batch = keys[i:i + JIRA_BATCH_SIZE]
        jql = "key in (%s)" % ",".join(batch)
        found = set()
        try:
            data = _jira_search(base, auth, jql, JIRA_FIELDS)
            for issue in data.get("issues", []):
                parsed = _parse_issue(issue)
                result[parsed["key"]] = parsed
                found.add(parsed["key"])
        except requests.RequestException as exc:
            print(f"  warning: batch search failed ({exc}); will retry keys individually", file=sys.stderr)
        for k in batch:
            if k not in found and k not in result:
                missing.append(k)

    still_missing = []
    for k in missing:
        try:
            issue = _jira_get_issue(base, auth, k, JIRA_FIELDS)
        except requests.RequestException as exc:
            print(f"  warning: GET issue {k} failed ({exc})", file=sys.stderr)
            still_missing.append(k)
            continue
        if issue is None:
            still_missing.append(k)
            continue
        parsed = _parse_issue(issue)
        if parsed["key"] != k:
            parsed["moved_from"] = k
        result[k] = parsed

    return result, still_missing


def _age_days(updated_str):
    if not updated_str:
        return None
    try:
        s = updated_str
        if re.search(r"[+-]\d{4}$", s):
            s = s[:-2] + ":" + s[-2:]
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return max(0, (now - dt).days)
    except (ValueError, TypeError):
        return None


def _short_sst(sst):
    if not sst:
        return "(none)"
    return re.sub(r"^rhel-sst-", "", sst)


# --------------------------------------------------------------------------
# Dashboard assembly
# --------------------------------------------------------------------------

def build_dashboard(active_rpms, blockers_sheet, data_chart, jira_map, missing_keys,
                     jira_enabled, jira_base, spreadsheet_id, source_desc, snapshot_dt) -> dict:
    key_to_packages = defaultdict(list)
    for p in active_rpms:
        for k in p["blocker_keys"]:
            key_to_packages[k].append(p["package"])
    all_keys = sorted(key_to_packages.keys())

    def is_done(key: str) -> bool:
        j = jira_map.get(key)
        return bool(j and j["is_done"])

    packages_out = []
    ready_to_clear = []
    for p in active_rpms:
        keys = p["blocker_keys"]
        jira_entries = [jira_map[k] for k in keys if k in jira_map]
        all_resolved = bool(keys) and all(is_done(k) for k in keys)

        statuses = sorted({j["status"] for j in jira_entries}) if jira_entries else []
        j_assignees = sorted({j["assignee"] for j in jira_entries if j["assignee"]})
        comps = sorted({c for j in jira_entries for c in j["components"]})
        labels = sorted({l for j in jira_entries for l in j["labels"]})
        primary_category = jira_entries[0]["status_category"] if jira_entries else "unknown"

        row = {
            "package": p["package"],
            "sst": _short_sst(p["sst"]),
            "sst_full": p["sst"] or "(none)",
            "pkg_assignee": p["assignee"] or "Unassigned",
            "blocker_keys": keys,
            "blocker_state": "All resolved" if all_resolved else "Open",
            "jira_status": ", ".join(statuses) if statuses else ("Unknown" if keys else "—"),
            "jira_status_category": primary_category,
            "jira_assignee": ", ".join(j_assignees) if j_assignees else "Unassigned",
            "components": comps,
            "labels": labels,
        }
        packages_out.append(row)
        if all_resolved:
            ready_to_clear.append(p["package"])

    open_blockers = []
    stale_blockers = []
    assignee_counter = Counter()
    status_counter = Counter()

    for k in all_keys:
        j = jira_map.get(k)
        pkgs = key_to_packages.get(k, [])
        sheet_info = blockers_sheet.get(k)
        if j is None:
            entry = {
                "key": k,
                "summary": "(Jira data unavailable — spreadsheet-only)",
                "status": "Unknown",
                "status_category": "unknown",
                "assignee": "Unassigned",
                "components": [],
                "labels": [],
                "age_days": None,
                "package_count": len(pkgs),
                "packages": pkgs,
                "url": f"{jira_base}/browse/{k}",
                "sheet": sheet_info,
            }
        else:
            if j["is_done"]:
                continue
            entry = {
                "key": k,
                "summary": j["summary"],
                "status": j["status"],
                "status_category": j["status_category"],
                "assignee": j["assignee"] or "Unassigned",
                "components": j["components"],
                "labels": j["labels"],
                "age_days": _age_days(j["updated"]),
                "package_count": len(pkgs),
                "packages": pkgs,
                "url": f"{jira_base}/browse/{k}",
                "moved_from": j.get("moved_from"),
                "sheet": sheet_info,
            }
        open_blockers.append(entry)
        assignee_counter[entry["assignee"] or "Unassigned"] += 1
        status_counter[entry["status"]] += 1
        if entry["age_days"] is not None and entry["age_days"] >= 30:
            stale_blockers.append(entry)

    open_blockers.sort(key=lambda e: (-(e["package_count"] or 0), e["key"]))
    stale_blockers.sort(key=lambda e: -(e["age_days"] or 0))
    packages_out.sort(key=lambda r: r["package"].lower())

    sst_counter = Counter(_short_sst(p["sst"]) for p in active_rpms)
    label_counter = Counter()
    comp_counter = Counter()
    for e in open_blockers:
        for l in e["labels"]:
            label_counter[l] += 1
        if e["components"]:
            for c in e["components"]:
                comp_counter[c] += 1
        else:
            comp_counter["(none)"] += 1

    unassigned_open = sum(1 for e in open_blockers if (e["assignee"] or "Unassigned") == "Unassigned")
    blockers_field_rows = sum(1 for p in active_rpms if p["blocker_keys"])

    stats = {
        "total_rpms": _dc_count(data_chart, "Total RPMs"),
        "onboarded": _dc_count(data_chart, "Onboarded"),
        "onboarded_pct": _dc_pct(data_chart, "Onboarded"),
        "has_blockers_sheet": _dc_count(data_chart, "Has blockers"),
        "blocked_packages": len(active_rpms),
        "open_blockers": len(open_blockers),
        "ready_to_clear": len(ready_to_clear),
        "unassigned_open": unassigned_open,
        "stale_open": len(stale_blockers),
        "blockers_field_rows": blockers_field_rows,
        "unique_blocker_keys": len(all_keys),
        "jira_resolved_keys": len(jira_map),
        "jira_missing_keys": len(missing_keys),
    }

    findings = []
    if open_blockers:
        top = max(open_blockers, key=lambda e: e["package_count"])
        if top["package_count"] > 0:
            findings.append({
                "tag": "Largest blocker",
                "title": f"{top['key']} — {top['package_count']} package{'s' if top['package_count'] != 1 else ''}",
                "body": f"{top['summary']} Status {top['status']}, assignee {top['assignee']}.",
                "url": top["url"],
            })
    findings.append({
        "tag": "Spreadsheet hygiene",
        "title": f"{stats['ready_to_clear']} pkgs ready to clear",
        "body": (
            f"{stats['blocked_packages']} packages marked blocked; "
            f"{stats['blockers_field_rows']} rows carry a Blockers value. "
            "Clearing fully-resolved blockers will drop the blocked tally."
        ),
    })
    findings.append({
        "tag": "Needs attention",
        "title": f"{stats['unassigned_open']} unassigned · {stats['stale_open']} stale (≥30d)",
        "body": "Open blockers with no owner or no recent update — good candidates for triage or closure.",
    })

    dashboard = {
        "generated_at_iso": snapshot_dt.isoformat(),
        "snapshot_date_display": snapshot_dt.strftime("%d %b %Y"),
        "source_desc": source_desc,
        "spreadsheet_id": spreadsheet_id,
        "spreadsheet_url": SPREADSHEET_URL_TMPL.format(id=spreadsheet_id),
        "jira_base": jira_base,
        "jira_enabled": jira_enabled,
        "stats": stats,
        "open_blockers": open_blockers,
        "stale_blockers": stale_blockers,
        "packages": packages_out,
        "ready_to_clear": sorted(ready_to_clear, key=str.lower),
        "assignee_load": assignee_counter.most_common(20),
        "sst_breakdown": sst_counter.most_common(20),
        "status_breakdown": status_counter.most_common(20),
        "labels_freq": label_counter.most_common(30),
        "components_freq": comp_counter.most_common(30),
        "missing_keys": missing_keys,
        "findings": findings,
    }
    return dashboard


# --------------------------------------------------------------------------
# HTML rendering
# --------------------------------------------------------------------------

import html as _html


def esc(value) -> str:
    if value is None:
        return ""
    return _html.escape(str(value), quote=True)


CSS = """
:root {
  --bg: #f5f5f5;
  --surface: #ffffff;
  --ink: #1f1f1f;
  --muted: #6a6e73;
  --border: #d2d2d2;
  --accent: #ee0000;
  --accent-dark: #a30000;
  --info: #0066cc;
  --info-bg: #e7f1fa;
  --warn: #f0ab00;
  --warn-bg: #fdf7e7;
  --success: #3e8635;
  --success-bg: #f3faf2;
  --todo: #c58c00;
  --todo-bg: #fff8e6;
  --progress: #0066cc;
  --progress-bg: #e7f1fa;
  --done: #3e8635;
  --done-bg: #f3faf2;
  --other: #6a6e73;
  --other-bg: #f0f0f0;
  --callout: #f0f0f0;
  --nav-h: 56px;
  --max: 1200px;
  --bar: #c9190b;
  --bar-track: #e7e7e7;
  --card-border: #c8c8c8;
  --focus: #0066cc;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  font-family: "Red Hat Text", "Source Sans 3", "Segoe UI", system-ui, sans-serif;
  color: var(--ink);
  background: var(--bg);
  line-height: 1.45;
  font-size: 15px;
}
h1, h2, h3, .brand {
  font-family: "Red Hat Display", "Red Hat Text", "Source Sans 3", sans-serif;
  font-weight: 700;
  letter-spacing: -0.01em;
}
a { color: var(--info); text-decoration: none; }
a:hover { text-decoration: underline; }
.nav {
  position: sticky; top: 0; z-index: 100;
  height: var(--nav-h);
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 1rem; gap: 1rem;
}
.nav-left { display: flex; align-items: baseline; gap: .75rem; flex-wrap: wrap; min-width: 0; }
.nav .brand { font-size: 1rem; color: var(--ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.nav .meta { color: var(--muted); font-size: .85rem; white-space: nowrap; }
.nav-actions { display: flex; gap: .5rem; flex-shrink: 0; }
.btn {
  appearance: none; border: 1px solid var(--border); background: var(--surface);
  color: var(--ink); font: inherit; font-size: .875rem; font-weight: 500;
  padding: .4rem .75rem; border-radius: 4px; cursor: pointer;
}
.btn:hover { border-color: #989898; background: #fafafa; }
.btn-primary { background: var(--accent); color: #fff; border-color: var(--accent); }
.btn-primary:hover { background: var(--accent-dark); border-color: var(--accent-dark); }
.wrap { max-width: var(--max); margin: 0 auto; padding: 1.25rem 1rem 3rem; }
.hero {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1.5rem 1.5rem 1.25rem;
  margin-bottom: 1.25rem;
}
.hero h1 { margin: 0 0 .35rem; font-size: 1.75rem; }
.hero .sub { color: var(--muted); margin: 0 0 1rem; font-size: 1rem; }
.links { display: flex; flex-wrap: wrap; gap: .75rem 1.25rem; font-size: .95rem; }
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: .75rem;
  margin-bottom: 1.25rem;
}
.stat {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem 1.1rem;
}
.stat .n { font-family: "Red Hat Display", sans-serif; font-size: 2rem; font-weight: 700; line-height: 1.1; color: var(--ink); }
.stat .l { color: var(--muted); font-size: .85rem; margin-top: .25rem; }
.stat.warn .n { color: #8a6d00; }
.stat.danger .n { color: var(--accent-dark); }
.callout {
  background: var(--warn-bg);
  border: 1px solid #f0d78c;
  border-left: 4px solid var(--warn);
  border-radius: 4px;
  padding: 1rem 1.15rem;
  margin-bottom: 1.25rem;
}
.callout h2 { margin: 0 0 .5rem; font-size: 1.05rem; }
.callout p { margin: 0; color: var(--ink); }
.callout ul { margin: .5rem 0 0; padding-left: 1.2rem; }
.callout code { background: rgba(0,0,0,.06); padding: .05em .35em; border-radius: 3px; font-size: .9em; }
section {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1.25rem 1.35rem;
  margin-bottom: 1.25rem;
}
section h2 {
  margin: 0 0 .15rem;
  font-size: 1.2rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: .5rem;
}
.section-sub { color: var(--muted); font-size: .9rem; margin: .4rem 0 1rem; }
.charts {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin-bottom: 1.25rem;
}
.chart-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem 1.15rem;
}
.chart-card h3 { margin: 0 0 .75rem; font-size: 1rem; }
.bar-row {
  display: grid;
  grid-template-columns: minmax(100px, 38%) 1fr 2.5rem;
  gap: .5rem;
  align-items: center;
  margin-bottom: .4rem;
  font-size: .82rem;
}
.bar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink); }
.bar-track { background: var(--bar-track); height: 10px; border-radius: 2px; overflow: hidden; }
.bar-fill { background: var(--bar); height: 100%; border-radius: 2px; }
.bar-val { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); font-weight: 500; }
.findings {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: .75rem;
  margin-bottom: 1.25rem;
}
.finding {
  background: var(--surface);
  border: 1px solid var(--card-border);
  border-radius: 6px;
  padding: 1rem 1.1rem;
}
.finding h3 { margin: 0 0 .4rem; font-size: 1rem; }
.finding p { margin: 0; color: var(--muted); font-size: .9rem; }
.finding .tag {
  display: inline-block;
  font-size: .75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .04em;
  color: var(--accent-dark);
  margin-bottom: .35rem;
}
.toolbar {
  display: flex; flex-wrap: wrap; align-items: center; gap: .75rem;
  margin-bottom: .75rem;
}
.toolbar label { font-size: .85rem; color: var(--muted); }
.toolbar input {
  flex: 1; min-width: 180px; max-width: 360px;
  font: inherit; padding: .45rem .65rem;
  border: 1px solid var(--border); border-radius: 4px;
  background: #fff;
}
.toolbar input:focus { outline: 2px solid var(--focus); outline-offset: 1px; }
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 4px; }
table {
  width: 100%; border-collapse: collapse; font-size: .85rem;
}
th, td {
  text-align: left; padding: .5rem .6rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
th {
  background: #fafafa;
  font-weight: 600;
  white-space: nowrap;
  position: sticky; top: 0;
}
tr:last-child td { border-bottom: none; }
tbody tr:hover { background: #fafafa; }
.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.nowrap { white-space: nowrap; }
.small { font-size: .8rem; color: var(--muted); max-width: 160px; word-break: break-word; }
.muted { color: var(--muted); }
.tiny { font-size: .75rem; }
.age-stale { color: var(--accent-dark); font-weight: 600; }
.status {
  display: inline-block;
  font-size: .75rem;
  font-weight: 600;
  padding: .15rem .45rem;
  border-radius: 3px;
  white-space: nowrap;
}
.st-todo { background: var(--todo-bg); color: #8a6d00; }
.st-progress { background: var(--progress-bg); color: var(--progress); }
.st-done { background: var(--done-bg); color: var(--done); }
.st-other { background: var(--other-bg); color: var(--other); }
.pills { display: flex; flex-wrap: wrap; gap: .4rem; }
.pill {
  display: inline-flex; align-items: center; gap: .35rem;
  background: #f0f0f0; border: 1px solid var(--border);
  border-radius: 4px; padding: .25rem .55rem; font-size: .8rem;
}
.pill strong { font-variant-numeric: tabular-nums; }
.pill-muted { opacity: .85; }
.ready-list {
  display: flex; flex-wrap: wrap; gap: .4rem .55rem;
  line-height: 1.6;
}
.ready-list code {
  background: var(--success-bg);
  border: 1px solid #bde5b8;
  color: #1e4f18;
  padding: .15rem .4rem;
  border-radius: 3px;
  font-size: .85rem;
}
.appendix { font-size: .9rem; color: var(--muted); }
.appendix ul { margin: .4rem 0 0; padding-left: 1.2rem; }
.toc {
  display: flex; flex-wrap: wrap; gap: .5rem .9rem;
  margin-top: .85rem; font-size: .85rem;
}
.toc a { color: var(--muted); }
.toc a:hover { color: var(--info); }
.count-badge {
  display: inline-block;
  background: #f0f0f0;
  border-radius: 3px;
  padding: .1rem .4rem;
  font-size: .8rem;
  font-weight: 600;
  margin-left: .35rem;
  color: var(--muted);
}
.empty-note { color: var(--muted); font-size: .9rem; padding: .5rem 0; }
@media (max-width: 900px) {
  .findings, .charts { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 600px) {
  .findings, .charts { grid-template-columns: 1fr; }
  .nav .brand { font-size: .9rem; }
  .hero h1 { font-size: 1.35rem; }
  .bar-row { grid-template-columns: minmax(80px, 42%) 1fr 2rem; }
}
@media print {
  body { background: #fff; font-size: 11pt; }
  .nav-actions, .toolbar { display: none !important; }
  .nav { position: static; border: none; height: auto; padding: .5rem 0; }
  .wrap { max-width: none; padding: 0; }
  section, .hero, .stat, .chart-card, .finding, .callout {
    break-inside: avoid;
    box-shadow: none;
    border-color: #ccc;
  }
  .table-wrap { overflow: visible; border: none; }
  table { font-size: 9pt; }
  a { color: inherit; text-decoration: none; }
  a[href]::after { content: ""; }
}
"""

JS = """
(function () {
  function wireFilter(inputId, tableId, countId) {
    var input = document.getElementById(inputId);
    var table = document.getElementById(tableId);
    var countEl = document.getElementById(countId);
    if (!input || !table) return;
    var rows = Array.prototype.slice.call(table.querySelectorAll('tbody tr'));
    function update() {
      var q = (input.value || '').trim().toLowerCase();
      var shown = 0;
      rows.forEach(function (tr) {
        var hay = tr.getAttribute('data-search') || tr.textContent.toLowerCase();
        var ok = !q || hay.indexOf(q) !== -1;
        tr.style.display = ok ? '' : 'none';
        if (ok) shown++;
      });
      if (countEl) countEl.textContent = shown + ' / ' + rows.length + ' shown';
    }
    input.addEventListener('input', update);
    update();
  }
  wireFilter('filter-blockers', 'tbl-blockers', 'filter-blockers-count');
  wireFilter('filter-packages', 'tbl-packages', 'filter-packages-count');

  var printBtn = document.getElementById('btn-print');
  if (printBtn) printBtn.addEventListener('click', function () { window.print(); });

  var dlBtn = document.getElementById('btn-download');
  if (dlBtn) dlBtn.addEventListener('click', function () {
    var htmlOut = '<!DOCTYPE html>\\n' + document.documentElement.outerHTML;
    var blob = new Blob([htmlOut], { type: 'text/html;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'RHEL9-Konflux-Blockers-Report.html';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  });
})();
"""


def _status_class(category: str) -> str:
    category = (category or "").lower()
    if category == "done":
        return "st-done"
    if category in ("indeterminate", "in progress", "progress"):
        return "st-progress"
    if category in ("new", "todo", "to do"):
        return "st-todo"
    return "st-other"


def _status_badge(name: str, category: str) -> str:
    return f'<span class="status {_status_class(category)}">{esc(name)}</span>'


def _bars(rows, max_rows=12) -> str:
    rows = rows[:max_rows]
    if not rows:
        return '<p class="empty-note">No data.</p>'
    max_val = max(v for _, v in rows) or 1
    out = []
    for label, val in rows:
        width = round(val / max_val * 100, 1)
        out.append(
            '<div class="bar-row">'
            f'<div class="bar-label" title="{esc(label)}">{esc(label)}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{width}%"></div></div>'
            f'<div class="bar-val">{val}</div>'
            "</div>"
        )
    return "\n".join(out)


def _pills(rows, muted_label=None) -> str:
    if not rows:
        return '<p class="empty-note">None.</p>'
    out = []
    for label, val in rows:
        cls = "pill pill-muted" if label == muted_label else "pill"
        out.append(f'<span class="{cls}">{esc(label)} <strong>{val}</strong></span>')
    return "\n".join(out)


def _links_html(keys, urls_by_key) -> str:
    parts = [f'<a href="{esc(urls_by_key.get(k, "#"))}" target="_blank" rel="noopener">{esc(k)}</a>' for k in keys]
    return ", ".join(parts) if parts else "—"


def render_open_blockers_rows(open_blockers) -> str:
    out = []
    for e in open_blockers:
        age = e["age_days"]
        age_cell = f'{age}d' if age is not None else "—"
        age_cls = "num age-stale" if (age is not None and age >= 30) else "num"
        moved = f' <span class="muted tiny">(was {esc(e["moved_from"])})</span>' if e.get("moved_from") else ""
        search = " ".join([
            e["key"].lower(), (e.get("moved_from") or "").lower(), e["summary"].lower(),
            e["status"].lower(), e["assignee"].lower(),
            " ".join(e["components"]).lower(), " ".join(e["labels"]).lower(),
        ])
        out.append(
            f'<tr data-search="{esc(search)}">'
            f'<td class="nowrap"><a href="{esc(e["url"])}" target="_blank" rel="noopener">{esc(e["key"])}</a>{moved}</td>'
            f'<td>{esc(e["summary"])}</td>'
            f'<td class="num">{e["package_count"]}</td>'
            f'<td>{_status_badge(e["status"], e["status_category"])}</td>'
            f'<td>{esc(e["assignee"])}</td>'
            f'<td class="small">{esc(", ".join(e["components"]) or "—")}</td>'
            f'<td class="small">{esc(", ".join(e["labels"]) or "—")}</td>'
            f'<td class="{age_cls}">{age_cell}</td>'
            "</tr>"
        )
    return "\n".join(out)


def render_stale_rows(stale_blockers) -> str:
    out = []
    for e in stale_blockers:
        out.append(
            "<tr>"
            f'<td class="nowrap"><a href="{esc(e["url"])}" target="_blank" rel="noopener">{esc(e["key"])}</a></td>'
            f'<td>{esc(e["summary"])}</td>'
            f'<td class="num">{e["package_count"]}</td>'
            f'<td>{_status_badge(e["status"], e["status_category"])}</td>'
            f'<td>{esc(e["assignee"])}</td>'
            f'<td class="num age-stale">{e["age_days"]}d</td>'
            "</tr>"
        )
    return "\n".join(out)


def render_packages_rows(packages, jira_base) -> str:
    out = []
    for p in packages:
        blocker_urls = {k: f"{jira_base}/browse/{k}" for k in p["blocker_keys"]}
        state_cls = "st-done" if p["blocker_state"] == "All resolved" else "st-todo"
        search = " ".join([
            p["package"].lower(), p["sst"].lower(), p["pkg_assignee"].lower(),
            " ".join(p["blocker_keys"]).lower(), p["blocker_state"].lower(),
            p["jira_status"].lower(), p["jira_assignee"].lower(),
            " ".join(p["components"]).lower(), " ".join(p["labels"]).lower(),
        ])
        out.append(
            f'<tr data-search="{esc(search)}">'
            f'<td class="nowrap"><strong>{esc(p["package"])}</strong></td>'
            f'<td class="small" title="{esc(p["sst_full"])}">{esc(p["sst"])}</td>'
            f'<td>{esc(p["pkg_assignee"])}</td>'
            f'<td class="nowrap">{_links_html(p["blocker_keys"], blocker_urls)}</td>'
            f'<td><span class="status {state_cls}">{esc(p["blocker_state"])}</span></td>'
            f'<td>{_status_badge(p["jira_status"], p["jira_status_category"]) if p["blocker_keys"] else "—"}</td>'
            f'<td>{esc(p["jira_assignee"])}</td>'
            f'<td class="small">{esc(", ".join(p["components"]) or "—")}</td>'
            f'<td class="small">{esc(", ".join(p["labels"]) or "—")}</td>'
            "</tr>"
        )
    return "\n".join(out)


def render_html(d: dict) -> str:
    stats = d["stats"]
    stat_cards = []

    def stat(n, label, sub="", variant=""):
        cls = f"stat {variant}".strip()
        sub_html = f'<br/><span class="muted">{esc(sub)}</span>' if sub else ""
        stat_cards.append(f'<div class="{cls}"><div class="n">{n}</div><div class="l">{esc(label)}{sub_html}</div></div>')

    stat(stats["blocked_packages"], "Blocked packages", "status = blocked or has blocker keys", "danger")
    stat(stats["open_blockers"], "Open blockers", "live Jira issues" if d["jira_enabled"] else "Jira not queried")
    stat(stats["ready_to_clear"], "Resolved but still blocked", "pkgs ready to clear", "warn" if stats["ready_to_clear"] else "")
    unassigned_stale = f"{stats['unassigned_open']} unassigned + {stats['stale_open']} stale ≥30d"
    stat(stats["unassigned_open"] + stats["stale_open"], "Needs attention", unassigned_stale, "warn" if (stats["unassigned_open"] or stats["stale_open"]) else "")
    if stats["onboarded_pct"] is not None:
        stat(f'{stats["onboarded_pct"]}%', "Onboarded to Konflux", f'{stats["onboarded"]} / {stats["total_rpms"]} RPMs')

    jira_note = ""
    if not d["jira_enabled"]:
        jira_note = (
            '<p><strong>Note:</strong> Jira credentials were not provided for this build, so blocker '
            "status/assignee/labels below are shown as <code>Unknown</code> and derived only from the spreadsheet.</p>"
        )
    elif stats["jira_missing_keys"]:
        jira_note = (
            f'<p><strong>Note:</strong> {stats["jira_missing_keys"]} blocker key(s) could not be resolved via Jira '
            "(moved, deleted, or inaccessible) and are shown with status <code>Unknown</code>.</p>"
        )

    callout_html = (
        '<div class="callout" id="reconcile">'
        "<h2>Count reconciliation</h2>"
        "<p>"
        f'Spreadsheet summary cell shows <strong>{stats["has_blockers_sheet"]}</strong> blocked, '
        f'while packages with <code>status = blocked</code> or a Blockers value = <strong>{stats["blocked_packages"]}</strong>, '
        f'and rows with a Blockers field = <strong>{stats["blockers_field_rows"]}</strong>. '
        + (
            f'Onboarding progress: <strong>{stats["onboarded"]}</strong> / {stats["total_rpms"]} RPMs '
            f'(<strong>{stats["onboarded_pct"]}%</strong> onboarded).'
            if stats["onboarded_pct"] is not None else ""
        )
        + "</p>"
        "<ul>"
        f'<li>Open blockers: <strong>{stats["open_blockers"]}</strong> · Unassigned open: <strong>{stats["unassigned_open"]}</strong></li>'
        f'<li>Unique blocker keys: <strong>{stats["unique_blocker_keys"]}</strong> · Ready to clear: <strong>{stats["ready_to_clear"]}</strong></li>'
        f'<li>Stale open blockers (≥30 days since update): <strong>{stats["stale_open"]}</strong></li>'
        "</ul>"
        + jira_note
        + "</div>"
    )

    def _finding_title(f):
        if f.get("url"):
            return f'<a href="{esc(f["url"])}" target="_blank" rel="noopener">{esc(f["title"])}</a>'
        return esc(f["title"])

    findings_html = "\n".join(
        '<div class="finding">'
        f'<div class="tag">{esc(f["tag"])}</div>'
        f'<h3>{_finding_title(f)}</h3>'
        f'<p>{esc(f["body"])}</p>'
        "</div>"
        for f in d["findings"]
    )

    epic_links_html = " ".join(
        f'<a href="{esc(url)}" target="_blank" rel="noopener">{esc(key)}</a>' for key, url in EPIC_LINKS
    )

    open_rows = render_open_blockers_rows(d["open_blockers"])
    stale_rows = render_stale_rows(d["stale_blockers"])
    package_rows = render_packages_rows(d["packages"], d["jira_base"])
    ready_html = (
        ", ".join(f"<code>{esc(pkg)}</code>" for pkg in d["ready_to_clear"])
        if d["ready_to_clear"] else '<p class="empty-note">None — nothing to clear right now.</p>'
    )

    none_components = next((c for l, c in d["components_freq"] if l == "(none)"), 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>RHEL 9 Konflux Migration — Blockers Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Red+Hat+Display:wght@500;700&family=Red+Hat+Text:wght@400;500;700&family=Source+Sans+3:wght@400;600;700&display=swap" rel="stylesheet" />
<style>{CSS}</style>
</head>
<body>
<nav class="nav" aria-label="Report toolbar">
  <div class="nav-left">
    <span class="brand">RHEL 9 Konflux Blockers</span>
    <span class="meta">Snapshot · {esc(d["snapshot_date_display"])}</span>
  </div>
  <div class="nav-actions">
    <button type="button" class="btn" id="btn-print">Print</button>
    <button type="button" class="btn btn-primary" id="btn-download">Download HTML</button>
  </div>
</nav>

<div class="wrap">
  <header class="hero" id="top">
    <h1>RHEL 9 Konflux Migration — Blockers</h1>
    <p class="sub">Auto-refreshed snapshot of open blockers, blocked packages, and spreadsheet hygiene.</p>
    <div class="links">
      <a href="{esc(d["spreadsheet_url"])}" target="_blank" rel="noopener">Tracking spreadsheet</a>
      {epic_links_html}
    </div>
    <nav class="toc" aria-label="Sections">
      <a href="#stats">Stats</a>
      <a href="#reconcile">Counts</a>
      <a href="#charts">Charts</a>
      <a href="#findings">Findings</a>
      <a href="#open-blockers">Open blockers</a>
      <a href="#stale">Stale</a>
      <a href="#packages">Blocked packages</a>
      <a href="#ready">Ready to clear</a>
      <a href="#labels">Labels</a>
      <a href="#source">Source</a>
    </nav>
  </header>

  <div class="stats" id="stats">
    {"".join(stat_cards)}
  </div>

  {callout_html}

  <div class="charts" id="charts">
    <div class="chart-card">
      <h3>Open blocker status</h3>
      {_bars(d["status_breakdown"])}
    </div>
    <div class="chart-card">
      <h3>SST breakdown (blocked pkgs)</h3>
      {_bars(d["sst_breakdown"])}
    </div>
    <div class="chart-card">
      <h3>Assignee load (open blockers)</h3>
      {_bars(d["assignee_load"])}
    </div>
  </div>

  <div class="findings" id="findings">
    {findings_html}
  </div>

  <section id="open-blockers">
    <h2>Open blockers <span class="count-badge">{stats["open_blockers"]}</span></h2>
    <p class="section-sub">Live Jira issues currently blocking RHEL 9 Konflux packages. Keys link to Jira.</p>
    <div class="toolbar">
      <label for="filter-blockers">Filter</label>
      <input type="search" id="filter-blockers" placeholder="Search key, summary, assignee, label…" autocomplete="off" />
      <span class="muted tiny" id="filter-blockers-count"></span>
    </div>
    <div class="table-wrap">
      <table id="tbl-blockers">
        <thead>
          <tr>
            <th>Key</th>
            <th>Summary</th>
            <th class="num">Pkgs</th>
            <th>Status</th>
            <th>Assignee</th>
            <th>Components</th>
            <th>Labels</th>
            <th class="num">Age</th>
          </tr>
        </thead>
        <tbody>
{open_rows}
        </tbody>
      </table>
    </div>
  </section>

  <section id="stale">
    <h2>Stale open blockers (≥30 days) <span class="count-badge">{stats["stale_open"]}</span></h2>
    <p class="section-sub">Open issues with no recent update — candidates for triage, reassignment, or closure.</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Key</th>
            <th>Summary</th>
            <th class="num">Pkgs</th>
            <th>Status</th>
            <th>Assignee</th>
            <th class="num">Age</th>
          </tr>
        </thead>
        <tbody>
{stale_rows if stale_rows else '<tr><td colspan="6" class="empty-note">None.</td></tr>'}
        </tbody>
      </table>
    </div>
  </section>

  <section id="packages">
    <h2>All blocked packages <span class="count-badge">{stats["blocked_packages"]}</span></h2>
    <p class="section-sub">Packages currently marked blocked, with blocker keys and ownership.</p>
    <div class="toolbar">
      <label for="filter-packages">Filter</label>
      <input type="search" id="filter-packages" placeholder="Search package, SST, assignee, blocker…" autocomplete="off" />
      <span class="muted tiny" id="filter-packages-count"></span>
    </div>
    <div class="table-wrap">
      <table id="tbl-packages">
        <thead>
          <tr>
            <th>Package</th>
            <th>SST</th>
            <th>Pkg assignee</th>
            <th>Blockers</th>
            <th>Blocker state</th>
            <th>Jira status</th>
            <th>Jira assignee</th>
            <th>Components</th>
            <th>Labels</th>
          </tr>
        </thead>
        <tbody>
{package_rows}
        </tbody>
      </table>
    </div>
  </section>

  <section id="ready">
    <h2>Packages ready to clear <span class="count-badge">{stats["ready_to_clear"]}</span></h2>
    <p class="section-sub">Blockers appear fully resolved, but packages are still listed as blocked — clear spreadsheet status.</p>
    <div class="ready-list">{ready_html}</div>
  </section>

  <section id="labels">
    <h2>Labels &amp; components</h2>
    <p class="section-sub">Frequency across open blockers (components none = {none_components}).</p>
    <h3 style="font-size:.95rem;margin:0 0 .5rem">Labels</h3>
    <div class="pills" style="margin-bottom:1rem">{_pills(d["labels_freq"])}</div>
    <h3 style="font-size:.95rem;margin:0 0 .5rem">Components</h3>
    <div class="pills">{_pills(d["components_freq"], muted_label="(none)")}</div>
  </section>

  <section id="source" class="appendix">
    <h2>Source appendix</h2>
    <ul>
      <li>Snapshot date: <strong>{esc(d["snapshot_date_display"])}</strong></li>
      <li>Spreadsheet: <a href="{esc(d["spreadsheet_url"])}" target="_blank" rel="noopener">{esc(d["spreadsheet_url"])}</a> ({esc(d["source_desc"])})</li>
      <li>Epics / trackers: {epic_links_html}</li>
      <li>Jira base: <code>{esc(d["jira_base"])}</code> · Enrichment {"enabled" if d["jira_enabled"] else "disabled (no credentials)"}</li>
      <li>Data file: <code>data/dashboard.json</code></li>
      <li>Report is self-contained HTML (inline CSS/JS), generated by <code>scripts/build_report.py</code>. Google Fonts load when online; system fonts apply offline.</li>
    </ul>
  </section>
</div>

<script>{JS}</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Build the RHEL 9 Konflux blockers dashboard")
    parser.add_argument("--xlsx", help="Local path to the tracking spreadsheet (.xlsx)")
    parser.add_argument("--out", default="index.html", help="Output HTML path (default: ./index.html)")
    parser.add_argument("--data-out", default=None, help="Output dashboard JSON path (default: <out-dir>/data/dashboard.json)")
    parser.add_argument("--skip-jira", action="store_true", help="Skip Jira enrichment even if credentials are set")
    parser.add_argument("--jira-cache", help="Load pre-fetched Jira issue map JSON (key -> parsed fields)")
    return parser.parse_args()


def main():
    args = parse_args()

    jira_base = os.environ.get("JIRA_BASE", DEFAULT_JIRA_BASE).rstrip("/")
    jira_email = os.environ.get("JIRA_EMAIL")
    jira_token = os.environ.get("JIRA_API_TOKEN")
    spreadsheet_id = os.environ.get("SPREADSHEET_ID", DEFAULT_SPREADSHEET_ID)

    wb, source_desc = load_workbook_source(args, spreadsheet_id)

    active_rpms = load_active_rpms(wb)
    blockers_sheet = load_rhel9_blockers(wb)
    data_chart = load_data_and_chart(wb)
    print(f"Loaded {len(active_rpms)} blocked/flagged packages from `{SHEET_ACTIVE_RPMS}`.")

    all_keys = sorted({k for p in active_rpms for k in p["blocker_keys"]})
    jira_enabled = bool(jira_email and jira_token) and not args.skip_jira
    jira_map, missing_keys = {}, all_keys

    if args.jira_cache and not args.skip_jira:
        cache_path = Path(args.jira_cache)
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        jira_map = {k: v for k, v in cache.items() if k in all_keys or True}
        # also index by live key if present
        missing_keys = [k for k in all_keys if k not in jira_map]
        jira_enabled = True
        print(f"Loaded Jira cache {cache_path} with {len(jira_map)} issue(s); {len(missing_keys)} keys missing.")
    elif jira_enabled and all_keys:
        print(f"Fetching Jira data for {len(all_keys)} unique blocker key(s)...")
        jira_map, missing_keys = fetch_jira_issues(all_keys, jira_base, jira_email, jira_token)
        print(f"Resolved {len(jira_map)} / {len(all_keys)} keys via Jira ({len(missing_keys)} missing).")
    elif not all_keys:
        print("No blocker keys found in the spreadsheet.")
    else:
        print("Jira credentials not provided (or --skip-jira set) -- building with sheet-only data (status Unknown).")
        jira_enabled = False

    snapshot_dt = datetime.now(timezone.utc)
    dashboard = build_dashboard(
        active_rpms, blockers_sheet, data_chart, jira_map, missing_keys,
        jira_enabled, jira_base, spreadsheet_id, source_desc, snapshot_dt,
    )

    html_out = render_html(dashboard)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_out, encoding="utf-8")

    data_out = Path(args.data_out) if args.data_out else (out_path.parent / "data" / "dashboard.json")
    data_out.parent.mkdir(parents=True, exist_ok=True)
    data_out.write_text(json.dumps(dashboard, indent=2, default=str), encoding="utf-8")

    stats = dashboard["stats"]
    print(f"Wrote {out_path} and {data_out}")
    print(
        "Stats: "
        f"blocked_packages={stats['blocked_packages']} "
        f"open_blockers={stats['open_blockers']} "
        f"ready_to_clear={stats['ready_to_clear']} "
        f"has_blockers(sheet)={stats['has_blockers_sheet']}"
    )


if __name__ == "__main__":
    main()
