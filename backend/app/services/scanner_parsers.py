"""
Scanner-specific parsers — normalise proprietary export formats to VulnerabilityCreate.

Supported formats:
  - Tenable  (.csv export from Tenable.io / Tenable.sc)
  - Nessus   (.nessus XML from Nessus Professional / Tenable.sc)
  - Qualys   (.csv export from Qualys VMDR)
  - Rapid7   (.csv export from InsightVM / Nexpose)

Each parser returns the same list-of-tuples signature as parse_csv_bytes:
    list[tuple[row_number, VulnerabilityCreate | None, error_str | None]]

Findings without a usable CVE ID are skipped with an explanatory error message.
When a finding has multiple CVE IDs (common in Rapid7/Qualys exports), the first
valid CVE-format ID is used as the canonical identifier; the others are stored in
the notes field.

Severity normalisation:
  - Tenable  Risk: Critical → critical, High → high, Medium → medium, Low → low,
                   Info / None → informational
  - Nessus   severity attr: 4 → critical, 3 → high, 2 → medium, 1 → low, 0 → informational
  - Qualys   Severity: 5 → critical, 4 → high, 3 → medium, 2 → low, 1 → informational
  - Rapid7   Severity: Critical/High/Medium/Low/Info (same words as Tenable)
"""

from __future__ import annotations

import csv
import io
import re
import xml.etree.ElementTree as ET
from typing import Any

from app.core.sanitization import CSV_MAX_BYTES, check_upload_size
from app.schemas.vulnerability import VulnerabilityCreate

# ── Shared constants ──────────────────────────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_NESSUS_SEVERITY_MAP = {
    "4": "critical",
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "informational",
}

_QUALYS_SEVERITY_MAP = {
    "5": "critical",
    "4": "high",
    "3": "medium",
    "2": "low",
    "1": "informational",
}

_WORD_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
    "none": "informational",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_cves(text: str) -> list[str]:
    """Return all CVE IDs found in text, normalised to uppercase."""
    return [m.upper() for m in _CVE_RE.findall(text)]


def _normalise_word_severity(raw: str) -> str:
    return _WORD_SEVERITY_MAP.get(raw.strip().lower(), "informational")


def _safe_cvss(raw: str) -> float | None:
    try:
        v = float(raw.strip())
        return round(v, 1) if 0.0 <= v <= 10.0 else None
    except (ValueError, AttributeError):
        return None


def _truncate(s: str, n: int = 4000) -> str:
    return s[:n] if len(s) > n else s


def _row_to_create(
    cve_id: str,
    title: str,
    description: str,
    severity: str,
    cvss_score: float | None,
    affected_component: str | None,
    notes: str | None,
    source: str,
    source_id: str | None,
) -> VulnerabilityCreate:
    """Build a VulnerabilityCreate from normalised fields, running sanitizers."""
    payload: dict[str, Any] = {
        "cve_id": cve_id.upper().strip(),
        "title": title or cve_id,
        "description": description or title or cve_id,
        "severity": severity,
        "source": source,
    }
    if cvss_score is not None:
        payload["cvss_score"] = cvss_score
    if affected_component:
        payload["affected_component"] = affected_component[:255]
    if notes:
        payload["notes"] = _truncate(notes)
    if source_id:
        payload["source_id"] = source_id[:255]
    return VulnerabilityCreate(**payload)


# ── Tenable CSV parser ────────────────────────────────────────────────────────

# Key Tenable.io / .sc CSV export columns (case-insensitive):
#   Plugin ID, CVE, CVSS v3.0 Base Score, CVSS v2.0 Base Score, Risk,
#   Host, Port, Protocol, Name, Synopsis, Description, Solution
#
# CVE column may be empty (non-CVE plugin) → skip those rows.
# Risk values: Critical, High, Medium, Low, Info, None

def parse_tenable_csv(
    data: bytes,
) -> list[tuple[int, VulnerabilityCreate | None, str | None]]:
    """Parse a Tenable CSV export into VulnerabilityCreate objects."""
    check_upload_size(data, CSV_MAX_BYTES, "Tenable CSV")
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        return [(1, None, "File is empty or has no header row")]

    # Normalise header names for lookup
    headers = {h.strip().lower(): h for h in reader.fieldnames if h}

    def col(row: dict, *candidates: str) -> str:
        for c in candidates:
            orig = headers.get(c)
            if orig and row.get(orig, "").strip():
                return row[orig].strip()
        return ""

    results: list[tuple[int, VulnerabilityCreate | None, str | None]] = []

    for row_idx, raw in enumerate(reader, start=2):
        cve_raw = col(raw, "cve")
        cves = _extract_cves(cve_raw)

        if not cves:
            results.append((row_idx, None, f"No CVE ID found in row (Plugin: {col(raw, 'plugin id', 'pluginid')}) — skipped"))
            continue

        cve_id = cves[0]
        plugin_id = col(raw, "plugin id", "pluginid")
        host = col(raw, "host", "ip address")
        port = col(raw, "port")
        name = col(raw, "name", "plugin name")
        synopsis = col(raw, "synopsis")
        description = col(raw, "description", "plugin text")
        risk = col(raw, "risk", "risk factor")
        severity = _normalise_word_severity(risk) if risk else "informational"

        cvss = _safe_cvss(col(raw, "cvss v3.0 base score", "cvssv3", "cvss3_base_score"))
        if cvss is None:
            cvss = _safe_cvss(col(raw, "cvss v2.0 base score", "cvss v2 base score", "cvss_base_score"))

        affected = host
        if port and port not in ("0", ""):
            affected = f"{host}:{port}" if host else port

        extra_cves = ", ".join(cves[1:]) if len(cves) > 1 else None
        notes_parts = []
        if extra_cves:
            notes_parts.append(f"Additional CVEs: {extra_cves}")
        solution = col(raw, "solution")
        if solution:
            notes_parts.append(f"Solution: {solution}")

        source_id = f"tenable-{plugin_id}-{host}" if plugin_id else None

        try:
            obj = _row_to_create(
                cve_id=cve_id,
                title=name or synopsis or cve_id,
                description=description or synopsis or name or cve_id,
                severity=severity,
                cvss_score=cvss,
                affected_component=affected or None,
                notes="\n".join(notes_parts) or None,
                source="tenable",
                source_id=source_id,
            )
            results.append((row_idx, obj, None))
        except Exception as exc:
            results.append((row_idx, None, f"Row {row_idx}: {exc}"))

    return results


# ── Nessus XML parser ─────────────────────────────────────────────────────────

# .nessus file structure:
#   <NessusClientData_v2>
#     <Report name="...">
#       <ReportHost name="192.168.1.1">
#         <HostProperties>
#           <tag name="operating-system">...</tag>
#         </HostProperties>
#         <ReportItem port="443" protocol="tcp" severity="3"
#                     pluginID="12345" pluginName="SSL Certificate Expiry">
#           <cve>CVE-2021-44228</cve>
#           <cvss3_base_score>10.0</cvss3_base_score>
#           <cvss_base_score>10.0</cvss_base_score>
#           <description>...</description>
#           <synopsis>...</synopsis>
#           <risk_factor>Critical</risk_factor>
#           <solution>...</solution>
#         </ReportItem>
#       </ReportHost>
#     </Report>
#   </NessusClientData_v2>

def parse_nessus_xml(
    data: bytes,
) -> list[tuple[int, VulnerabilityCreate | None, str | None]]:
    """Parse a .nessus XML file into VulnerabilityCreate objects."""
    check_upload_size(data, CSV_MAX_BYTES, "Nessus XML")

    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        return [(1, None, f"Invalid XML: {exc}")]

    results: list[tuple[int, VulnerabilityCreate | None, str | None]] = []
    row_idx = 0

    for report_host in root.iter("ReportHost"):
        host_name = report_host.get("name", "")

        for item in report_host.findall("ReportItem"):
            row_idx += 1

            # Collect all CVE tags
            cves = [e.text.strip().upper() for e in item.findall("cve") if e.text]
            cves = [c for c in cves if _CVE_RE.match(c)]

            if not cves:
                plugin_id = item.get("pluginID", "")
                results.append((row_idx, None, f"Plugin {plugin_id} on {host_name}: no CVE ID — skipped"))
                continue

            cve_id = cves[0]
            plugin_id = item.get("pluginID", "")
            plugin_name = item.get("pluginName", "") or cve_id
            port = item.get("port", "")
            protocol = item.get("protocol", "")

            # Severity: prefer risk_factor text, fall back to numeric severity attr
            risk_text = (item.findtext("risk_factor") or "").strip()
            sev_attr = item.get("severity", "0")
            if risk_text:
                severity = _normalise_word_severity(risk_text)
            else:
                severity = _NESSUS_SEVERITY_MAP.get(sev_attr, "informational")

            cvss = _safe_cvss(item.findtext("cvss3_base_score") or "")
            if cvss is None:
                cvss = _safe_cvss(item.findtext("cvss_base_score") or "")

            description = (item.findtext("description") or "").strip()
            synopsis = (item.findtext("synopsis") or "").strip()
            solution = (item.findtext("solution") or "").strip()

            affected = host_name
            if port and port not in ("0", ""):
                suffix = f"/{protocol}" if protocol else ""
                affected = f"{host_name}:{port}{suffix}" if host_name else f"port {port}"

            notes_parts = []
            if len(cves) > 1:
                notes_parts.append(f"Additional CVEs: {', '.join(cves[1:])}")
            if solution:
                notes_parts.append(f"Solution: {solution}")

            source_id = f"nessus-{plugin_id}-{host_name}-{port}" if plugin_id else None

            try:
                obj = _row_to_create(
                    cve_id=cve_id,
                    title=plugin_name,
                    description=description or synopsis or plugin_name,
                    severity=severity,
                    cvss_score=cvss,
                    affected_component=affected or None,
                    notes="\n".join(notes_parts) or None,
                    source="nessus",
                    source_id=source_id,
                )
                results.append((row_idx, obj, None))
            except Exception as exc:
                results.append((row_idx, None, f"Plugin {plugin_id} on {host_name}: {exc}"))

    if not results:
        return [(1, None, "No ReportItem elements found — is this a valid .nessus file?")]

    return results


# ── Qualys VMDR CSV parser ────────────────────────────────────────────────────

# Qualys CSV export columns (VMDR vulnerability report):
#   QID, Title, Type, Severity, IP, DNS, OS, QDS, First Detected, Last Detected,
#   Times Detected, Last Fixed, First Reopened, Times Reopened, Last Reopened,
#   Asset Tags, Is Ignored, Is Disabled, Affect Running Kernel, Affect Running Service,
#   Affect Exploitable Config, Last Processed, Patch Available,
#   CVSS3 Base, CVSS3 Temporal, CVE ID, Vendor Reference, BugtraqID, CVSS Base,
#   Category, Port, Results, PCI Vuln, Category, Impact, Solution
#
# Severity: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
# CVE ID column may contain multiple CVEs comma/space-separated.

def parse_qualys_csv(
    data: bytes,
) -> list[tuple[int, VulnerabilityCreate | None, str | None]]:
    """Parse a Qualys VMDR CSV export into VulnerabilityCreate objects."""
    check_upload_size(data, CSV_MAX_BYTES, "Qualys CSV")
    text = data.decode("utf-8-sig", errors="replace")

    # Qualys CSVs sometimes start with metadata lines before the actual header.
    # Detect the actual header row by looking for 'QID' or 'Title'.
    lines = text.splitlines()
    header_line = 0
    for i, line in enumerate(lines):
        lower = line.lower()
        if "qid" in lower and "title" in lower:
            header_line = i
            break

    cleaned_text = "\n".join(lines[header_line:])
    reader = csv.DictReader(io.StringIO(cleaned_text))

    if reader.fieldnames is None:
        return [(1, None, "File is empty or has no header row")]

    headers = {h.strip().lower(): h for h in reader.fieldnames if h}

    def col(row: dict, *candidates: str) -> str:
        for c in candidates:
            orig = headers.get(c)
            if orig and row.get(orig, "").strip():
                return row[orig].strip()
        return ""

    results: list[tuple[int, VulnerabilityCreate | None, str | None]] = []

    for row_idx, raw in enumerate(reader, start=header_line + 2):
        cve_raw = col(raw, "cve id", "cve ids", "cve")
        cves = _extract_cves(cve_raw)

        if not cves:
            qid = col(raw, "qid")
            results.append((row_idx, None, f"QID {qid}: no CVE ID — skipped"))
            continue

        cve_id = cves[0]
        qid = col(raw, "qid")
        title = col(raw, "title")
        impact = col(raw, "impact", "description")
        solution = col(raw, "solution", "remediation")
        sev_raw = col(raw, "severity")
        severity = _QUALYS_SEVERITY_MAP.get(sev_raw, "informational")

        cvss = _safe_cvss(col(raw, "cvss3 base", "cvss3_base", "cvssv3 base", "cvssv3_base", "cvss base", "cvss_base"))
        ip = col(raw, "ip")
        dns = col(raw, "dns", "hostname")
        port = col(raw, "port")
        affected = dns or ip
        if port:
            affected = f"{affected}:{port}" if affected else port

        notes_parts = []
        if len(cves) > 1:
            notes_parts.append(f"Additional CVEs: {', '.join(cves[1:])}")
        if solution:
            notes_parts.append(f"Solution: {solution}")

        source_id = f"qualys-{qid}-{ip}" if qid else None

        try:
            obj = _row_to_create(
                cve_id=cve_id,
                title=title or cve_id,
                description=impact or title or cve_id,
                severity=severity,
                cvss_score=cvss,
                affected_component=affected or None,
                notes="\n".join(notes_parts) or None,
                source="qualys",
                source_id=source_id,
            )
            results.append((row_idx, obj, None))
        except Exception as exc:
            results.append((row_idx, None, f"QID {qid}: {exc}"))

    return results


# ── Rapid7 InsightVM CSV parser ───────────────────────────────────────────────

# Rapid7 InsightVM / Nexpose CSV export columns:
#   Asset IP Address, Asset Name, Asset MAC Address, Asset OS Name,
#   Asset OS Version, Vulnerability Title, Vulnerability ID, Severity,
#   CVE IDs, CVSSv3 Score, CVSSv2 Score, CVSS Score, Risk Score,
#   Vulnerability Published On, Asset Tags, Proof, First Seen, Last Seen, Status
#
# CVE IDs column may contain multiple IDs separated by comma or space.
# Severity values: Critical, High, Medium, Low, Informational

def parse_rapid7_csv(
    data: bytes,
) -> list[tuple[int, VulnerabilityCreate | None, str | None]]:
    """Parse a Rapid7 InsightVM CSV export into VulnerabilityCreate objects."""
    check_upload_size(data, CSV_MAX_BYTES, "Rapid7 CSV")
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        return [(1, None, "File is empty or has no header row")]

    headers = {h.strip().lower(): h for h in reader.fieldnames if h}

    def col(row: dict, *candidates: str) -> str:
        for c in candidates:
            orig = headers.get(c)
            if orig and row.get(orig, "").strip():
                return row[orig].strip()
        return ""

    results: list[tuple[int, VulnerabilityCreate | None, str | None]] = []

    for row_idx, raw in enumerate(reader, start=2):
        cve_raw = col(raw, "cve ids", "cve id", "cve")
        cves = _extract_cves(cve_raw)

        if not cves:
            vuln_id = col(raw, "vulnerability id")
            results.append((row_idx, None, f"Vulnerability ID '{vuln_id}': no CVE ID — skipped"))
            continue

        cve_id = cves[0]
        vuln_title = col(raw, "vulnerability title", "name")
        vuln_id = col(raw, "vulnerability id")
        proof = col(raw, "proof", "description")
        severity_raw = col(raw, "severity", "risk")
        severity = _normalise_word_severity(severity_raw) if severity_raw else "informational"

        cvss = _safe_cvss(col(raw, "cvssv3 score", "cvss3 score", "cvssv3_score"))
        if cvss is None:
            cvss = _safe_cvss(col(raw, "cvss score", "cvssv2 score", "cvss_score"))

        ip = col(raw, "asset ip address", "ip address", "ip")
        host = col(raw, "asset name", "hostname")
        affected = host or ip

        notes_parts = []
        if len(cves) > 1:
            notes_parts.append(f"Additional CVEs: {', '.join(cves[1:])}")
        os_name = col(raw, "asset os name", "os")
        if os_name:
            notes_parts.append(f"OS: {os_name}")

        source_id = f"rapid7-{vuln_id}-{ip}" if vuln_id else None

        try:
            obj = _row_to_create(
                cve_id=cve_id,
                title=vuln_title or cve_id,
                description=proof or vuln_title or cve_id,
                severity=severity,
                cvss_score=cvss,
                affected_component=affected or None,
                notes="\n".join(notes_parts) or None,
                source="rapid7",
                source_id=source_id,
            )
            results.append((row_idx, obj, None))
        except Exception as exc:
            results.append((row_idx, None, f"Vuln ID '{vuln_id}': {exc}"))

    return results
