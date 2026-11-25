"""
Cryptographic Blockchain Ledger for Healthcare Consent & Audit Logging.
Maintains an immutable, append-only chain of blocks recording every consent
state change (GRANT, REVOKE), data access event (READ, WRITE), and audit check.
Includes Merkle tree hashing and full chain integrity verification.
"""

import hashlib
import json
import time
from typing import List, Dict, Any, Optional
from healthcare_consent.core.models import AuditEvent, EventType


def sha256(data: str) -> str:
    """Computes SHA-256 hexadecimal digest of input string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def compute_merkle_root(tx_hashes: List[str]) -> str:
    """
    Computes Merkle root for a list of transaction hashes.
    Balanced binary tree recursive hashing.
    """
    if not tx_hashes:
        return sha256("EMPTY_TRANSACTIONS")
    if len(tx_hashes) == 1:
        return tx_hashes[0]

    current_level = list(tx_hashes)
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = sha256(left + right)
            next_level.append(combined)
        current_level = next_level

    return current_level[0]


class Block:
    """Represents a single block in the healthcare audit blockchain."""

    def __init__(
        self,
        index: int,
        timestamp: float,
        transactions: List[Dict[str, Any]],
        previous_hash: str,
        nonce: int = 0,
        block_hash: Optional[str] = None,
        merkle_root: Optional[str] = None
    ):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.merkle_root = merkle_root or self._calculate_merkle_root()
        self.hash = block_hash or self.calculate_hash()

    def _calculate_merkle_root(self) -> str:
        tx_hashes = []
        for tx in self.transactions:
            serialized = json.dumps(tx, sort_keys=True, separators=(',', ':'))
            tx_hashes.append(sha256(serialized))
        return compute_merkle_root(tx_hashes)

    def calculate_hash(self) -> str:
        header = {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce
        }
        serialized = json.dumps(header, sort_keys=True, separators=(',', ':'))
        return sha256(serialized)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "tx_count": len(self.transactions),
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "hash": self.hash
        }


class BlockchainLedger:
    """
    Append-only permissioned ledger holding audit events and consent transitions.
    Every event is cryptographically sealed into a block.
    """

    def __init__(self):
        self.chain: List[Block] = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis_tx = {
            "event_id": "GENESIS_000",
            "event_type": "GENESIS",
            "actor_id": "SYSTEM_CORE",
            "patient_id": "ALL_PATIENTS",
            "record_id": None,
            "record_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "timestamp": 1700000000.0,
            "details": {
                "message": "Healthcare Consent & Audit Log Genesis Ledger Initialized",
                "framework": "SHA-256 Merkle Audit Chain",
                "compliance": "HIPAA 45 CFR § 164.312(b) Audit Controls & GDPR Art. 7"
            },
            "status": "SUCCESS"
        }
        genesis_block = Block(
            index=0,
            timestamp=1700000000.0,
            transactions=[genesis_tx],
            previous_hash="0" * 64,
            nonce=101
        )
        self.chain.append(genesis_block)

    @property
    def latest_block(self) -> Block:
        return self.chain[-1]

    def record_audit_event(self, event: AuditEvent) -> Dict[str, Any]:
        """
        Appends an audit event into a newly minted block.
        Returns the transaction receipt including block index, tx_hash, and block hash.
        """
        event_dict = event.to_dict()
        tx_serialized = json.dumps(event_dict, sort_keys=True, separators=(',', ':'))
        tx_hash = sha256(tx_serialized)
        event_dict["tx_hash"] = tx_hash
        event.tx_hash = tx_hash

        new_index = len(self.chain)
        event_dict["block_index"] = new_index
        event.block_index = new_index

        new_block = Block(
            index=new_index,
            timestamp=event.timestamp or time.time(),
            transactions=[event_dict],
            previous_hash=self.latest_block.hash,
            nonce=new_index * 7
        )

        self.chain.append(new_block)

        return {
            "block_index": new_block.index,
            "block_hash": new_block.hash,
            "tx_hash": tx_hash,
            "merkle_root": new_block.merkle_root,
            "timestamp": new_block.timestamp
        }

    def verify_chain(self) -> Dict[str, Any]:
        """
        Performs a full cryptographic validation of the ledger:
        1. Validates hash links between consecutive blocks.
        2. Recalculates each block's SHA-256 header hash.
        3. Recalculates and matches Merkle root for transactions in each block.
        """
        errors = []
        for i in range(len(self.chain)):
            current = self.chain[i]

            # 1. Check Genesis block
            if i == 0:
                if current.previous_hash != "0" * 64:
                    errors.append(f"Block #0 Genesis previous hash corrupted: {current.previous_hash}")
                continue

            prev = self.chain[i - 1]

            # 2. Check previous hash pointer
            if current.previous_hash != prev.hash:
                errors.append(
                    f"Block #{i} previous_hash mismatch! Expected {prev.hash}, got {current.previous_hash}"
                )

            # 3. Check block header hash
            recalculated_hash = current.calculate_hash()
            if current.hash != recalculated_hash:
                errors.append(
                    f"Block #{i} header hash tampered! Recorded: {current.hash}, Recalculated: {recalculated_hash}"
                )

            # 4. Check Merkle root
            recalculated_merkle = current._calculate_merkle_root()
            if current.merkle_root != recalculated_merkle:
                errors.append(
                    f"Block #{i} Merkle root invalid! Recorded: {current.merkle_root}, Recalculated: {recalculated_merkle}"
                )

        return {
            "is_valid": len(errors) == 0,
            "height": len(self.chain),
            "total_blocks": len(self.chain),
            "errors": errors,
            "checked_at": time.time()
        }

    def get_audit_trail(
        self,
        patient_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Extracts all transactions from the blockchain in reverse chronological order
        with optional filtering by patient, actor, or event type.
        """
        audit_events = []
        for block in reversed(self.chain):
            for tx in reversed(block.transactions):
                # Filter by patient_id
                if patient_id and tx.get("patient_id") != patient_id and tx.get("patient_id") != "ALL_PATIENTS":
                    continue
                # Filter by actor_id
                if actor_id and tx.get("actor_id") != actor_id:
                    continue
                # Filter by event_type
                if event_type and tx.get("event_type") != event_type:
                    continue

                tx_copy = dict(tx)
                tx_copy["block_hash"] = block.hash
                tx_copy["block_index"] = block.index
                audit_events.append(tx_copy)

        return audit_events
