import hashlib
import json
from datetime import datetime


def create_code_seal(code):
    """
    Creates a SHA-256 fingerprint of the developer's code.

    Raw code is NOT stored in the seal.
    """

    if not code:
        code = ""

    code_hash = hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()

    return {
        "algorithm": "SHA-256",
        "code_hash": code_hash,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }


def create_report_seal(report):
    """
    Creates a tamper-evident SHA-256 fingerprint
    of the security analysis report.
    """

    if not isinstance(report, dict):
        report = {
            "report": str(report)
        }

    # Convert report into deterministic JSON
    report_json = json.dumps(
        report,
        sort_keys=True,
        separators=(",", ":")
    )

    report_hash = hashlib.sha256(
        report_json.encode("utf-8")
    ).hexdigest()

    return {
        "algorithm": "SHA-256",
        "report_hash": report_hash,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }


def verify_report_seal(report, expected_hash):
    """
    Checks whether the current report matches
    the previously generated SHA-256 fingerprint.
    """

    current_seal = create_report_seal(report)

    return current_seal["report_hash"] == expected_hash


def create_security_passport(
    website_name,
    score,
    findings,
    files_scanned
):

    report = {
        "website": website_name,
        "security_score": score,
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "findings": findings
    }

    seal = create_report_seal(report)

    return {
        "passport_id": "CS-" + seal["report_hash"][:12].upper(),
        "website": website_name,
        "security_score": score,
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "hash_algorithm": "SHA-256",
        "report_hash": seal["report_hash"],
        "created_at": seal["created_at"]
    }