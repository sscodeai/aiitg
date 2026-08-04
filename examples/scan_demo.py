"""Library-form usage demo: scan a file and print findings."""

from __future__ import annotations

import sys

from ai_input_trust_gateway import Severity, scan_file


def main(path: str) -> None:
    report = scan_file(path)
    print(f"file: {report.file} ({report.kind})")
    print(f"risk_score: {report.risk_score}")
    print(f"summary: {report.summary}")

    for ev in report.evidence:
        loc = ev.location
        where = (
            f"para {loc.paragraph}"
            if loc.paragraph is not None
            else f"{loc.sheet}:{loc.row}"
            if loc.sheet
            else f"page {loc.page}"
            if loc.page
            else loc.element or "?"
        )
        print(f"  [{ev.severity.value}] {ev.detector_id} {ev.title} @ {where}")

    high = report.filter(min_severity=Severity.HIGH)
    print(f"\nhigh+ findings: {len(high.evidence)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python examples/scan_demo.py <file>")
        sys.exit(2)
    main(sys.argv[1])
