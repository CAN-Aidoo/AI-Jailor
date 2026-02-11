"""Immune CVE Feed — NVD API Poller.

Polls NVD for new CVEs, filters by CWE relevance, converts to attack patterns.
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from aijailer.immune.memory import AttackPattern, ThreatSeverity

logger = structlog.get_logger(__name__)

_RELEVANT_CWES = {
    "CWE-20", "CWE-22", "CWE-77", "CWE-78", "CWE-79", "CWE-89",
    "CWE-94", "CWE-116", "CWE-295", "CWE-327", "CWE-328", "CWE-384",
    "CWE-502", "CWE-613", "CWE-614", "CWE-862", "CWE-916", "CWE-918",
}


@dataclass(frozen=True)
class CVEFeedConfig:
    api_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: str | None = None
    poll_interval_seconds: int = 3600
    lookback_days: int = 7
    results_per_page: int = 50
    min_cvss_score: float = 4.0


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    cwes: list[str]
    cvss_score: float
    severity: ThreatSeverity
    published_date: str
    last_modified: str
    references: list[str] = field(default_factory=list)
    attack_vector: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


_CWE_CONSTRAINT_MAP: dict[str, str] = {
    "CWE-89": "no_string_concat_sql",
    "CWE-79": "require_output_encoding",
    "CWE-78": "no_shell_execution",
    "CWE-22": "require_path_validation",
    "CWE-918": "require_url_validation",
    "CWE-327": "require_approved_crypto",
    "CWE-916": "require_argon2id",
}

_CWE_COMPONENT_MAP: dict[str, str] = {
    "CWE-89": "safe_query_builder",
    "CWE-79": "output_encoder",
    "CWE-78": "safe_subprocess",
    "CWE-22": "safe_file_io",
    "CWE-918": "http_client",
    "CWE-327": "encryption",
    "CWE-916": "hashing",
}

_CWE_SIG_MAP: dict[str, str] = {
    "CWE-89": r"(?:execute|query)\s*\(\s*(?:f[\"']|[\"'].*%[sd])",
    "CWE-79": r"(?:innerHTML|document\.write|v-html|\|\s*safe)",
    "CWE-78": r"(?:os\.system|subprocess.*shell\s*=\s*True)",
    "CWE-22": r"(?:open|send_file)\s*\(.*(?:\+|join).*(?:request|user)",
    "CWE-918": r"(?:requests|httpx|urllib)\.\w+\s*\(.*(?:user|input)",
    "CWE-327": r"(?:hashlib\.(?:md5|sha1)|DES|RC4|ECB)",
    "CWE-916": r"(?:hashlib\.\w+\(.*password|md5.*pass)",
}


class CVEFeed:
    """Polls NVD API for CVEs relevant to code generation security."""

    def __init__(self, config: CVEFeedConfig | None = None) -> None:
        self._config = config or CVEFeedConfig()
        self._last_poll: float = 0
        self._processed: set[str] = set()
        self._cached: list[CVEEntry] = []

    async def poll(self) -> list[CVEEntry]:
        now = time.time()
        if now - self._last_poll < self._config.poll_interval_seconds:
            return []
        self._last_poll = now

        try:
            entries = await self._fetch_from_nvd()
        except Exception as e:
            logger.warning("cve_feed.fetch_failed", error=str(e))
            return []

        relevant = [
            e for e in entries
            if any(c in _RELEVANT_CWES for c in e.cwes)
            and e.cvss_score >= self._config.min_cvss_score
        ]

        new_entries: list[CVEEntry] = []
        for entry in relevant:
            if entry.cve_id not in self._processed:
                self._processed.add(entry.cve_id)
                new_entries.append(entry)

        self._cached.extend(new_entries)
        logger.info("cve_feed.poll_complete", total=len(entries), new=len(new_entries))
        return new_entries

    async def convert_to_patterns(self, entries: list[CVEEntry]) -> list[AttackPattern]:
        patterns: list[AttackPattern] = []
        for entry in entries:
            for cwe in entry.cwes:
                if cwe not in _RELEVANT_CWES:
                    continue
                patterns.append(AttackPattern(
                    pattern_id=f"cve-{entry.cve_id.lower()}-{cwe.lower()}",
                    cwe_id=cwe,
                    description=f"{entry.cve_id}: {entry.description[:200]}",
                    attack_vector=entry.attack_vector or entry.description[:500],
                    severity=entry.severity,
                    detection_signature=_CWE_SIG_MAP.get(cwe, f".*{cwe}.*"),
                    required_constraint=_CWE_CONSTRAINT_MAP.get(cwe),
                    required_component=_CWE_COMPONENT_MAP.get(cwe),
                    source="cve_feed",
                    metadata={"cve_id": entry.cve_id, "cvss": entry.cvss_score},
                ))
        return patterns

    async def get_recent(self, limit: int = 50) -> list[CVEEntry]:
        return self._cached[-limit:]

    async def _fetch_from_nvd(self) -> list[CVEEntry]:
        """MVP: returns sample entries. Production: calls NVD REST API."""
        return [
            CVEEntry(
                cve_id="CVE-2024-0001",
                description="SQL injection in ORM query builder",
                cwes=["CWE-89"], cvss_score=9.8,
                severity=ThreatSeverity.CRITICAL,
                published_date="2024-01-15", last_modified="2024-01-16",
                attack_vector="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
            ),
            CVEEntry(
                cve_id="CVE-2024-0002",
                description="XSS via unsanitized template variable",
                cwes=["CWE-79"], cvss_score=7.5,
                severity=ThreatSeverity.HIGH,
                published_date="2024-01-20", last_modified="2024-01-21",
                attack_vector="{{ user_input | safe }}",
            ),
            CVEEntry(
                cve_id="CVE-2024-0003",
                description="SSRF via unrestricted URL parameter",
                cwes=["CWE-918"], cvss_score=8.2,
                severity=ThreatSeverity.HIGH,
                published_date="2024-02-01", last_modified="2024-02-02",
                attack_vector="requests.get(user_provided_url)",
            ),
        ]
