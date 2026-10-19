"""
WinSentinel - National Vulnerability Database (NVD) API v2 Client.

Queries the NVD API v2 for CVEs associated with allowlisted software products.
Features:
  - 24-hour response caching in SQLite cve_cache table.
  - Strict rate limiting (~5 req/30s unauthenticated; ~50 req/30s with API key).
  - Offline mode and connection timeout handling without crashing scans.
  - NIST SP 800-30 Likelihood x Impact risk scoring derived from CVSS v3 base scores.
  - Transparent documentation of CPE mapping limitations.
"""

import re
import time
import requests
from typing import Iterable, List, Dict, Any, Optional, Tuple

from config import get_config
from db.database import get_cached_cves, insert_cached_cve
from db.models import SoftwareItem, Finding


# Cache marker meaning "NVD was queried and no CVE affects this product version"
NO_CVE_SENTINEL = "NONE"
# Bump when the matching logic changes so results cached by older logic are never reused
CACHE_KEY_SUFFIX = "#cpe2"


def map_cvss_to_impact(cvss_score: float) -> int:
    """
    Map CVSS base score to NIST SP 800-30 Impact rating (1-5).

    Rules:
      - 0.0 - 3.9 -> Impact 2 (Minor)
      - 4.0 - 6.9 -> Impact 3 (Moderate)
      - 7.0 - 8.9 -> Impact 4 (Significant)
      - 9.0 - 10.0 -> Impact 5 (Critical)

    Args:
        cvss_score: CVSS score between 0.0 and 10.0.

    Returns:
        int: Impact score between 2 and 5.
    """
    if cvss_score >= 9.0:
        return 5
    elif cvss_score >= 7.0:
        return 4
    elif cvss_score >= 4.0:
        return 3
    else:
        return 2


def map_product_to_likelihood(product_keyword: str) -> int:
    """
    Determine threat likelihood based on application exposure profile.

    Rules:
      - Web Browsers (Chrome, Firefox, Edge): Likelihood 4 (Directly exposed to untrusted web content)
      - File Handlers / Archive / Media (7-Zip, WinRAR, VLC, Adobe): Likelihood 3 (Processes untrusted files)
      - Interpreters / Dev Tools (Python, Java, Notepad++): Likelihood 2 (Local development runtime)

    Args:
        product_keyword: Normalized product name keyword.

    Returns:
        int: Likelihood score between 2 and 4.
    """
    kw = product_keyword.lower()
    if any(b in kw for b in ("chrome", "firefox", "edge")):
        return 4
    elif any(f in kw for f in ("7-zip", "winrar", "vlc", "adobe", "acrobat", "reader")):
        return 3
    else:
        return 2


def calculate_cve_severity(risk_score: int) -> str:
    """
    Map risk score (1-25) to NIST SP 800-30 severity band.

    Args:
        risk_score: Likelihood x Impact (1-25).

    Returns:
        str: Severity string ('Critical', 'High', 'Medium', 'Low').
    """
    if risk_score >= 16:
        return "Critical"
    elif risk_score >= 10:
        return "High"
    elif risk_score >= 5:
        return "Medium"
    else:
        return "Low"


def parse_version(ver: str) -> Tuple[int, ...]:
    """
    Convert a version string to a tuple of integers for comparison.

    Args:
        ver: Version text such as '120.0.6099.130' or '3.12.0 (64-bit)'.

    Returns:
        Tuple[int, ...]: Numeric components (empty tuple if no digits exist).
    """
    # Only the first dotted-number run counts, so "3.12.0 (64-bit)" is (3, 12, 0), not (3, 12, 0, 64)
    match = re.search(r"\d+(?:\.\d+)*", ver or "")
    return tuple(int(n) for n in match.group(0).split("."))[:6] if match else ()


def version_is_affected(cve_data: Dict[str, Any], products: Iterable[str], installed_version: str) -> Optional[bool]:
    """
    Decide whether an installed version falls inside a CVE's affected CPE ranges.

    Only vulnerable CPE matches whose CPE *product* is exactly one of `products` are considered
    (so "nautilus-python" never counts as "python"). A CPE version of "-" means "not applicable"
    and carries no version information, so it is ignored rather than treated as "all versions".

    Args:
        cve_data: The 'cve' object from the NVD API response.
        products: Exact CPE product names for the allowlisted application (e.g. {"7-zip"}).
        installed_version: Installed version string from the registry.

    Returns:
        True if affected, False if provably not affected, None if NVD gives no usable
        version data for this product.
    """
    installed = parse_version(installed_version)
    if not installed:
        return None
    wanted = {p.replace("\\", "").lower() for p in products}
    saw_relevant = False

    def walk(nodes: List[Dict[str, Any]]):
        for node in nodes:
            yield from node.get("cpeMatch", [])
            yield from walk(node.get("children", []))

    for config in cve_data.get("configurations", []):
        for match in walk(config.get("nodes", [])):
            if not match.get("vulnerable", False):
                continue
            parts = match.get("criteria", "").split(":")
            if len(parts) < 6:
                continue
            cpe_product, cpe_version = parts[4].replace("\\", "").lower(), parts[5]
            if cpe_product not in wanted or cpe_version == "-":
                continue
            saw_relevant = True

            if cpe_version != "*":
                if parse_version(cpe_version) == installed:
                    return True
                continue

            low_inc = match.get("versionStartIncluding")
            low_exc = match.get("versionStartExcluding")
            high_inc = match.get("versionEndIncluding")
            high_exc = match.get("versionEndExcluding")
            if not any((low_inc, low_exc, high_inc, high_exc)):
                return True  # product-wide match with no version bounds: every version affected
            if low_inc and installed < parse_version(low_inc):
                continue
            if low_exc and installed <= parse_version(low_exc):
                continue
            if high_inc and installed > parse_version(high_inc):
                continue
            if high_exc and installed >= parse_version(high_exc):
                continue
            return True
    return False if saw_relevant else None


class NvdClient:
    """National Vulnerability Database API client with rate limiting and local caching."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_ttl_hours: Optional[int] = None,
        delay_seconds: Optional[float] = None,
        timeout_seconds: Optional[int] = None,
    ):
        cfg = get_config()
        self.api_key = api_key if api_key is not None else cfg.NVD_API_KEY
        self.cache_ttl_hours = cache_ttl_hours or cfg.NVD_CACHE_TTL_HOURS
        self.delay_seconds = delay_seconds or cfg.NVD_REQUEST_DELAY_SECONDS
        self.timeout_seconds = timeout_seconds or cfg.NVD_TIMEOUT_SECONDS
        self.base_url = cfg.NVD_API_BASE_URL
        self.last_request_time: float = 0.0

    def _throttle(self) -> None:
        """Enforce NVD rate limiting delays between outbound requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.delay_seconds:
            time.sleep(self.delay_seconds - elapsed)
        self.last_request_time = time.time()

    def _fetch_page(self, vendor: str, cpe_product: str, start_index: int) -> Tuple[bool, Dict[str, Any], str]:
        """Fetch one page of CVEs for an exact CPE vendor:product. Returns (ok, json, error_message)."""
        headers = {
            "User-Agent": "WinSentinel-Vulnerability-Auditor/1.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        params = {
            "virtualMatchString": f"cpe:2.3:a:{vendor}:{cpe_product}",
            "resultsPerPage": 2000,
            "startIndex": start_index,
        }
        self._throttle()
        try:
            resp = requests.get(self.base_url, params=params, headers=headers, timeout=self.timeout_seconds * 4)
        except requests.exceptions.Timeout:
            return False, {}, "NVD API connection timed out. CVE lookup skipped (Offline Mode)."
        except requests.exceptions.ConnectionError:
            return False, {}, "NVD API unreachable / DNS resolution failed. CVE lookup skipped (Offline Mode)."
        except Exception as exc:
            return False, {}, f"CVE lookup error: {exc}"

        if resp.status_code == 403:
            return False, {}, "NVD API Access Forbidden (403). Check API Key or IP restrictions."
        if resp.status_code == 429:
            return False, {}, "NVD API Rate Limit Exceeded (429). Please wait before scanning again."
        if resp.status_code != 200:
            return False, {}, f"NVD API returned HTTP {resp.status_code}."
        try:
            return True, resp.json(), ""
        except ValueError:
            return False, {}, "NVD API returned invalid JSON."

    def query_cves(
        self,
        product: str,
        version: str = "Unknown",
        db_path: Optional[str] = None,
    ) -> Tuple[bool, List[Dict[str, Any]], str]:
        """
        Find CVEs affecting an installed product version, from the local cache or the live NVD API.

        The product keyword is mapped to its exact NVD CPE vendor:product (config.CPE_PRODUCTS),
        every CVE for that CPE product is downloaded, and each CVE's published version ranges are
        checked against the installed version. Results (including "no CVEs") are cached 24h.

        Args:
            product: Allowlisted product keyword (e.g. '7-zip').
            version: Installed version string.
            db_path: Optional path to the database.

        Returns:
            Tuple[bool, List[Dict[str, Any]], str]: (success, list_of_cves, message).
        """
        cfg = get_config()
        norm_product = product.lower().strip()
        norm_version = version.strip() if version else "Unknown"

        # 1. Local cache (a sentinel row records a fresh "zero CVEs" answer)
        cache_key = norm_product + CACHE_KEY_SUFFIX
        cached = get_cached_cves(
            product=cache_key,
            version=norm_version,
            max_age_hours=self.cache_ttl_hours,
            db_path=db_path,
        )
        if cached:
            records = [dict(c, product=norm_product) for c in cached if c["cve_id"] != NO_CVE_SENTINEL]
            return True, records, "Retrieved from local 24h cache"

        pairs = cfg.CPE_PRODUCTS.get(norm_product)
        if not pairs:
            return False, [], f"No exact NVD CPE mapping configured for '{product}'. CVE check skipped."
        if not parse_version(norm_version):
            return False, [], "Installed version is unknown, so affected-version matching is impossible. CVE check skipped."

        # 2. Live NVD query, then exact-product + version-range filtering
        wanted_products = {cpe_product for _, cpe_product in pairs}
        found: Dict[str, Dict[str, Any]] = {}

        for vendor, cpe_product in pairs:
            start_index = 0
            for _ in range(cfg.NVD_MAX_PAGES):
                ok, data, err = self._fetch_page(vendor, cpe_product, start_index)
                if not ok:
                    return False, [], err

                for item in data.get("vulnerabilities", []):
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "Unknown")
                    if cve_id in found:
                        continue
                    if version_is_affected(cve_data, wanted_products, norm_version) is not True:
                        continue

                    desc_text = "No description provided."
                    for d in cve_data.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc_text = d.get("value", desc_text)
                            break

                    metrics = cve_data.get("metrics", {})
                    cvss_score = 5.0  # Moderate fallback when NVD has not scored the CVE yet
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if metrics.get(key):
                            cvss_score = float(metrics[key][0]["cvssData"]["baseScore"])
                            break

                    found[cve_id] = {
                        "product": norm_product,
                        "version": norm_version,
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "description": desc_text[:500],
                    }

                start_index += data.get("resultsPerPage", 2000)
                if start_index >= data.get("totalResults", 0):
                    break

        records = sorted(found.values(), key=lambda c: c["cvss_score"], reverse=True)[:10]
        if records:
            for r in records:
                insert_cached_cve(cache_key, norm_version, r["cve_id"], r["cvss_score"], r["description"], db_path=db_path)
        else:
            insert_cached_cve(cache_key, norm_version, NO_CVE_SENTINEL, 0.0, "No CVEs affect this version", db_path=db_path)
        return True, records, "Successfully fetched from NVD API"


def audit_software_vulnerabilities(
    software_list: List[SoftwareItem],
    scan_id: Optional[int] = None,
    client: Optional[NvdClient] = None,
    db_path: Optional[str] = None,
    offline_mode: bool = False,
) -> Tuple[List[Finding], List[Dict[str, Any]]]:
    """
    Perform vulnerability auditing for allowlisted installed software against the NVD.

    Args:
        software_list: Installed software items discovered on the host.
        scan_id: Associated scan identifier.
        client: NvdClient instance (created if None).
        db_path: Optional database path.
        offline_mode: If True, skips network requests and relies only on cache/offline notice.

    Returns:
        Tuple[List[Finding], List[Dict[str, Any]]]:
            - List[Finding]: Findings generated for module='software'.
            - List[Dict[str, Any]]: Full list of discovered CVEs for dashboard view.
    """
    from collectors.software_inventory import match_allowed_software

    findings: List[Finding] = []
    all_cves: List[Dict[str, Any]] = []

    matched_items = match_allowed_software(software_list)
    if not matched_items:
        findings.append(Finding(
            scan_id=scan_id,
            module="software",
            title="Software Vulnerability Audit: No Allowlisted Applications Found",
            evidence="No applications matching the curated NVD allowlist were discovered in the Windows Registry.",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ))
        return findings, all_cves

    nvd = client or NvdClient()
    lookup_memo: Dict[Tuple[str, str], Tuple[bool, List[Dict[str, Any]], str]] = {}

    for item, kw in matched_items:
        if offline_mode:
            findings.append(Finding(
                scan_id=scan_id,
                module="software",
                title=f"CVE Check Skipped for {item.name} (Offline Mode)",
                evidence="CVE lookup skipped because offline mode is active or host has no internet connection.",
                status="error",
                likelihood=1,
                impact=1,
                risk_score=0,
                severity="Error",
                remediation="Connect host to internet or supply NVD_API_KEY in .env.",
            ))
            continue

        memo_key = (kw, item.version)
        if memo_key not in lookup_memo:  # e.g. several "Python 3.x" sub-packages share one lookup
            lookup_memo[memo_key] = nvd.query_cves(product=kw, version=item.version, db_path=db_path)
        success, cves, msg = lookup_memo[memo_key]

        if not success:
            findings.append(Finding(
                scan_id=scan_id,
                module="software",
                title=f"CVE Lookup Error for {item.name}",
                evidence=f"NVD query for '{kw}' failed: {msg}",
                status="error",
                likelihood=1,
                impact=1,
                risk_score=0,
                severity="Error",
                remediation="Verify internet connection and review NVD rate limits.",
            ))
            continue

        if not cves:
            findings.append(Finding(
                scan_id=scan_id,
                module="software",
                title=f"No Known Critical CVEs: {item.name} ({item.version})",
                evidence=f"Queried NVD for product '{kw}'. No known CVEs affecting this installed version were returned.",
                status="pass",
                likelihood=1,
                impact=1,
                risk_score=0,
                severity="Info",
                remediation="Continue maintaining routine application updates.",
            ))
        else:
            all_cves.extend(cves)
            # Find the highest CVSS score among results to generate a finding
            highest_cve = max(cves, key=lambda c: c.get("cvss_score", 0.0))
            cvss = highest_cve.get("cvss_score", 5.0)
            cve_id = highest_cve.get("cve_id", "Unknown")
            desc = highest_cve.get("description", "")

            impact = map_cvss_to_impact(cvss)
            likelihood = map_product_to_likelihood(kw)
            risk_score = likelihood * impact
            severity = calculate_cve_severity(risk_score)

            findings.append(Finding(
                scan_id=scan_id,
                module="software",
                title=f"Vulnerability Detected: {item.name} ({cve_id} - CVSS {cvss})",
                evidence=(
                    f"Product '{item.name}' (Version: {item.version}) matched known CVE {cve_id} with CVSS {cvss}. "
                    f"Description: {desc[:250]}... "
                    f"[Limitation Notice: Matched by product keyword '{kw}'. Confirm version applicability in vendor advisories.]"
                ),
                status="fail",
                likelihood=likelihood,
                impact=impact,
                risk_score=risk_score,
                severity=severity,
                remediation=f"Update {item.name} to the latest available vendor release to patch {cve_id}.",
            ))

    return findings, all_cves
