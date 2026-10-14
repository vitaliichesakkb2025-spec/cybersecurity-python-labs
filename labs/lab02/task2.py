"""Email-header and phishing-indicator auditor for Laboratory 2, variant 12."""

from __future__ import annotations

import argparse
import csv
import logging
import re
from pathlib import Path
from typing import Any

LOG = logging.getLogger(__name__)
MESSAGE_SEPARATOR = re.compile(
    r"^\s*---\s*MESSAGE\s*---\s*$",
    re.IGNORECASE | re.MULTILINE,
)
HEADER_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$")
EMAIL_RE = re.compile(
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"([A-Z0-9.-]+\.[A-Z]{2,}|[A-Z0-9.-]+\.invalid)\b",
    re.IGNORECASE,
)

CSV_FIELDS = [
    "message_id",
    "from_address",
    "from_domain",
    "return_path",
    "return_domain",
    "reply_to",
    "reply_domain",
    "subject",
    "stopwords_found",
    "received_count",
    "risk_score",
    "risk_level",
    "from_return_mismatch",
    "from_reply_mismatch",
    "findings",
]


def _parse_message_block(block: str) -> dict[str, Any]:
    """Parse one RFC-822-like sample block, including folded header lines."""
    headers: dict[str, list[str]] = {}
    current_name: str | None = None
    for line in block.splitlines():
        if not line.strip():
            continue
        if line[:1].isspace() and current_name is not None:
            headers[current_name][-1] += " " + line.strip()
            continue
        match = HEADER_LINE.match(line)
        if not match:
            LOG.debug("Ignoring non-header line: %s", line)
            continue
        current_name = match.group(1).casefold()
        headers.setdefault(current_name, []).append(match.group(2).strip())

    def first(name: str) -> str:
        values = headers.get(name.casefold(), [])
        return values[0].strip() if values else ""

    return {
        "message_id": first("Message-ID").strip("<> "),
        "from": first("From"),
        "return_path": first("Return-Path"),
        "reply_to": first("Reply-To"),
        "subject": first("Subject"),
        "received": headers.get("received", []),
    }


def load_mail_messages(path: Path) -> list[dict[str, Any]]:
    """Read sample mail headers separated by MESSAGE markers."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ValueError(f"Cannot read mail log '{path}': {exc}") from exc
    if not text.strip():
        raise ValueError(f"Mail log '{path}' is empty")

    blocks = [
        part.strip() for part in MESSAGE_SEPARATOR.split(text) if part.strip()
    ]
    messages = [_parse_message_block(block) for block in blocks]
    messages = [message for message in messages if any(message.values())]
    if not messages:
        raise ValueError(f"No email headers found in '{path}'")
    LOG.info("Parsed %d email message(s) from %s", len(messages), path)
    return messages


def load_suspicious_keywords(path: Path) -> list[str]:
    """Load nonblank, noncomment keyword entries from a file."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise ValueError(f"Cannot read keyword file '{path}': {exc}") from exc
    keywords = [
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not keywords:
        raise ValueError(f"Keyword list '{path}' contains no keywords")
    return keywords


def extract_email(value: str) -> str:
    """Return an email address from a header value or an empty string."""
    match = EMAIL_RE.search(value or "")
    if not match:
        return ""
    # Keep the address rather than only the captured domain.
    address = re.search(
        r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+",
        match.group(0),
        re.IGNORECASE,
    )
    return address.group(0).rstrip(".") if address else ""


def extract_domain(value: str) -> str:
    """Extract a normalized email domain from a header value."""
    address = extract_email(value)
    if "@" not in address:
        return ""
    return address.rsplit("@", maxsplit=1)[1].casefold().rstrip(".")


def find_suspicious_keywords(subject: str, keywords: list[str]) -> list[str]:
    """Find configured phrases in a subject without regard to letter case."""
    normalized_subject = " ".join(subject.casefold().split())
    found: list[str] = []
    for keyword in keywords:
        normalized_keyword = " ".join(keyword.casefold().split())
        if not normalized_keyword:
            continue
        pattern = re.compile(
            r"(?<!\w)" + re.escape(normalized_keyword) + r"(?!\w)",
            re.IGNORECASE,
        )
        if pattern.search(normalized_subject) and keyword not in found:
            found.append(keyword)
    return found


def analyze_message(
    message: dict[str, Any], keywords: list[str]
) -> dict[str, Any]:
    """Score a message using transparent heuristic phishing indicators."""
    from_address = extract_email(str(message.get("from", "")))
    return_path = str(message.get("return_path", ""))
    reply_to = str(message.get("reply_to", ""))
    from_domain = extract_domain(from_address)
    return_domain = extract_domain(return_path)
    reply_domain = extract_domain(reply_to)
    subject = str(message.get("subject", ""))
    stopwords = find_suspicious_keywords(subject, keywords)
    received_count = len(message.get("received", []))

    from_return_mismatch = bool(
        from_domain and return_domain and from_domain != return_domain
    )
    from_reply_mismatch = bool(
        from_domain and reply_domain and from_domain != reply_domain
    )

    findings: list[str] = []
    score = 0
    if from_return_mismatch:
        score += 30
        findings.append(
            f"From/Return-Path domain mismatch: {from_domain} != "
            f"{return_domain}"
        )
    if from_reply_mismatch:
        score += 30
        findings.append(
            f"From/Reply-To domain mismatch: {from_domain} != {reply_domain}"
        )
    if stopwords:
        points = min(20, len(stopwords) * 10)
        score += points
        findings.append("Suspicious subject keywords: " + ", ".join(stopwords))
    if received_count >= 4:
        score += 20
        findings.append(
            f"Unusually long Received chain: {received_count} header(s)"
        )
    if not findings:
        findings.append("No configured phishing indicators found")

    score = min(score, 100)
    if score >= 75:
        risk_level = "CRITICAL"
    elif score >= 50:
        risk_level = "HIGH"
    elif score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    message_id = str(message.get("message_id") or "unknown")
    if (
        from_return_mismatch
        or from_reply_mismatch
        or stopwords
        or received_count >= 4
    ):
        LOG.warning(
            "%s: %s phishing indicator(s), risk %s/100",
            message_id,
            len(findings),
            score,
        )
    else:
        LOG.info(
            "%s: no configured indicators, risk %s/100",
            message_id,
            score,
        )

    return {
        "message_id": message_id,
        "from_address": from_address,
        "from_domain": from_domain,
        "return_path": return_path,
        "return_domain": return_domain,
        "reply_to": reply_to,
        "reply_domain": reply_domain,
        "subject": subject,
        "stopwords_found": "; ".join(stopwords),
        "received_count": received_count,
        "risk_score": score,
        "risk_level": risk_level,
        "from_return_mismatch": from_return_mismatch,
        "from_reply_mismatch": from_reply_mismatch,
        "findings": " | ".join(findings),
    }


def run_audit(
    mail_log: Path, keywords_file: Path, output_csv: Path
) -> list[dict[str, Any]]:
    """Analyze email messages and save the findings as UTF-8 CSV."""
    messages = load_mail_messages(mail_log)
    keywords = load_suspicious_keywords(keywords_file)
    results = [analyze_message(message, keywords) for message in messages]
    try:
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        with output_csv.open("w", encoding="utf-8-sig", newline="") as file:
            writer = csv.DictWriter(
                file, fieldnames=CSV_FIELDS, extrasaction="ignore"
            )
            writer.writeheader()
            writer.writerows(results)
    except OSError as exc:
        raise ValueError(
            f"Cannot write CSV report '{output_csv}': {exc}"
        ) from exc
    LOG.info("CSV report written: %s", output_csv)
    return results


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for audit options."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mail-log",
        type=Path,
        default=Path("labs/lab02/data/data_v12/mail_headers.log"),
    )
    parser.add_argument(
        "--suspicious-keywords",
        type=Path,
        default=Path("labs/lab02/data/data_v12/suspicious_keywords.txt"),
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=Path("labs/lab02/data/phishing_report.csv"),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="enable detailed diagnostic logging",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run a requested audit and return the CLI exit status."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )
    try:
        rows = run_audit(args.mail_log, args.suspicious_keywords, args.out_csv)
    except ValueError as exc:
        LOG.error("Audit failed: %s", exc)
        return 2

    print("\nEMAIL PHISHING AUDIT — VARIANT 12")
    print(f"Messages inspected: {len(rows)}")
    print(f"{'ID':18} {'RISK':10} {'SCORE':>7} {'RECEIVED':>8}  SUBJECT")
    print("-" * 95)
    for row in rows:
        print(
            f"{row['message_id'].split('@', maxsplit=1)[0]:18} "
            f"{row['risk_level']:10} "
            f"{row['risk_score']:>3}/100 {row['received_count']:>8}  "
            f"{row['subject'][:48]}"
        )
        if row["risk_level"] in {"HIGH", "CRITICAL"}:
            print(f"  Findings: {row['findings']}")
    print(f"\nCSV report: {args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
