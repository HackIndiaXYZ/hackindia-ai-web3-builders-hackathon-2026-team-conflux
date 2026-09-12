import hashlib
import json
from datetime import datetime


def create_blockchain_proof(passport):
    """
    Creates a blockchain-ready proof from a Security Passport.

    Raw source code is never included.
    Only the cryptographic fingerprint is used.
    """

    report_hash = passport.get("report_hash", "")

    if not report_hash:
        raise ValueError("Report hash is required.")

    proof_payload = {
        "project": "AI CodeSecure",
        "passport_id": passport.get("passport_id"),
        "report_hash": report_hash,
        "hash_algorithm": "SHA-256",
        "network": "Polygon / Ethereum",
        "created_at": datetime.utcnow().isoformat() + "Z"
    }

    canonical_data = json.dumps(
        proof_payload,
        sort_keys=True,
        separators=(",", ":")
    )

    proof_hash = hashlib.sha256(
        canonical_data.encode("utf-8")
    ).hexdigest()

    proof_payload["proof_hash"] = proof_hash
    proof_payload["status"] = "READY_FOR_BLOCKCHAIN"

    return proof_payload


def verify_blockchain_proof(proof):

    original_hash = proof.get("proof_hash")

    if not original_hash:
        return False

    payload = {
        "project": proof.get("project"),
        "passport_id": proof.get("passport_id"),
        "report_hash": proof.get("report_hash"),
        "hash_algorithm": proof.get("hash_algorithm"),
        "network": proof.get("network"),
        "created_at": proof.get("created_at")
    }

    canonical_data = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":")
    )

    calculated_hash = hashlib.sha256(
        canonical_data.encode("utf-8")
    ).hexdigest()

    return calculated_hash == original_hash