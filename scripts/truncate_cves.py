"""Truncate a Trivy report to the first N vulnerabilities.

Lets the sweep vary CVE count while holding the repository — and therefore the
call-graph cost — fixed.
"""

import json
import sys


def main(source: str, target: str, limit: int) -> None:
    """Write `source` to `target` keeping at most `limit` vulnerabilities."""
    report = json.load(open(source))
    remaining = limit

    for result in report.get("Results") or []:
        vulns = result.get("Vulnerabilities") or []
        if remaining <= 0:
            result["Vulnerabilities"] = []
            continue
        result["Vulnerabilities"] = vulns[:remaining]
        remaining -= len(result["Vulnerabilities"])

    with open(target, "w") as handle:
        json.dump(report, handle)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
