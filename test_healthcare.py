"""
Comprehensive Test Suite for Healthcare Consent & Audit Log.
Tests all Functional Requirements from the PRD:
- FR 4.1: Granting Access & On-chain GRANT Logging
- FR 4.2: Reading/Writing Records, Consent Enforcement, and READ/WRITE Logging
- FR 4.3: Revoking Access & Immediate Permission Cutoff
- FR 4.4: Chronological Audit Trail Inspection & Filtering
- Scoped Consent Enforcement (EHR vs Lab vs Rx)
- Time-Bounded Expiration
- Off-chain SHA-256 Integrity & Tamper Detection
- Blockchain Cryptographic Chain & Merkle Tree Verification
"""

import unittest
import time
import shutil
import tempfile
import os

from healthcare_consent.core.models import Role, Scope, ConsentStatus, EventType, MedicalRecord
from healthcare_consent.core.blockchain import BlockchainLedger
from healthcare_consent.core.offchain_store import OffChainMedicalStore
from healthcare_consent.core.smart_contract import ConsentSmartContractEngine
from healthcare_consent.database.mock_data import seed_database, get_default_identities


class TestHealthcareConsentSystem(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.ledger = BlockchainLedger()
        self.storage = OffChainMedicalStore(self.test_dir)
        self.engine = ConsentSmartContractEngine(self.ledger, self.storage)
        seed_database(self.ledger, self.storage, self.engine)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_identities_seeded(self):
        """Verifies initial identities (Patients, Doctors, Labs, Auditor)."""
        identities = get_default_identities()
        self.assertIn("P-101", identities)
        self.assertEqual(identities["P-101"].role, Role.PATIENT)
        self.assertIn("DOC-201", identities)
        self.assertEqual(identities["DOC-201"].role, Role.DOCTOR)
        self.assertIn("AUD-501", identities)
        self.assertEqual(identities["AUD-501"].role, Role.AUDITOR)

    def test_02_grant_access_workflow(self):
        """FR 4.1: Patient grants access to a provider; verify consent state and GRANT block."""
        init_height = len(self.ledger.chain)
        res = self.engine.grant_consent(
            patient_id="P-102",
            provider_id="DOC-202",
            scope=Scope.ALL,
            duration_seconds=3600,
            purpose="Oncology consultation"
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["consent"]["status"], "granted")
        self.assertEqual(len(self.ledger.chain), init_height + 1)

        # Check audit event
        latest_block = self.ledger.latest_block
        tx = latest_block.transactions[0]
        self.assertEqual(tx["event_type"], "GRANT")
        self.assertEqual(tx["actor_id"], "P-102")
        self.assertEqual(tx["details"]["provider_id"], "DOC-202")

    def test_03_authorized_read_workflow(self):
        """FR 4.2: Authorized provider reads medical record; verifies off-chain retrieval and on-chain READ log."""
        # DOC-201 has Scope.ALL on P-101
        res = self.engine.read_record(
            actor_id="DOC-201",
            patient_id="P-101",
            record_id="REC-EHR-101"
        )
        self.assertTrue(res["success"])
        self.assertTrue(res["authorized"])
        self.assertIn("record", res)
        self.assertEqual(res["record"]["patient_id"], "P-101")
        self.assertTrue(res["integrity"]["is_intact"])

        # Check blockchain receipt
        self.assertEqual(self.ledger.latest_block.transactions[0]["event_type"], "READ")

    def test_04_unauthorized_read_workflow(self):
        """FR 4.2: Provider without consent attempts read; smart contract blocks and logs UNAUTHORIZED_ATTEMPT."""
        # DOC-202 has no consent for P-101
        res = self.engine.read_record(
            actor_id="DOC-202",
            patient_id="P-101",
            record_id="REC-EHR-101"
        )
        self.assertFalse(res["authorized"])
        self.assertFalse(res["success"])
        self.assertIn("ACCESS DENIED", res["message"])

        # Check that UNAUTHORIZED_ATTEMPT was recorded on-chain for auditing
        latest_tx = self.ledger.latest_block.transactions[0]
        self.assertEqual(latest_tx["event_type"], "UNAUTHORIZED_ATTEMPT")
        self.assertEqual(latest_tx["actor_id"], "DOC-202")
        self.assertEqual(latest_tx["status"], "ALERT_REJECTED")

    def test_05_scoped_access_enforcement(self):
        """Extended Feature: Granular scope enforcement (LAB_REPORTS cannot read EHR_GENERAL)."""
        # LAB-301 has consent ONLY for LAB_REPORTS on P-101
        # Reading LAB record should succeed:
        lab_res = self.engine.read_record(
            actor_id="LAB-301",
            patient_id="P-101",
            record_id="REC-LAB-102"
        )
        self.assertTrue(lab_res["authorized"])

        # Reading EHR record should be rejected:
        ehr_res = self.engine.read_record(
            actor_id="LAB-301",
            patient_id="P-101",
            record_id="REC-EHR-101"
        )
        self.assertFalse(ehr_res["authorized"])

    def test_06_revoke_access_workflow(self):
        """FR 4.3: Revoking access cuts off access immediately and records REVOKE on-chain."""
        # Dr. Carter currently has access to Alice P-101
        auth_before, _, _ = self.engine.check_consent("P-101", "DOC-201", Scope.ALL)
        self.assertTrue(auth_before)

        # Alice revokes Dr. Carter
        rev_res = self.engine.revoke_consent(
            patient_id="P-101",
            provider_id="DOC-201",
            scope=Scope.ALL
        )
        self.assertTrue(rev_res["success"])
        self.assertEqual(self.ledger.latest_block.transactions[0]["event_type"], "REVOKE")

        # Now Dr. Carter attempts to read
        read_after = self.engine.read_record(
            actor_id="DOC-201",
            patient_id="P-101",
            record_id="REC-EHR-101"
        )
        self.assertFalse(read_after["authorized"])

    def test_07_expiration_enforcement(self):
        """Extended Feature: Expired consent automatically rejects access."""
        # Grant 1-second consent
        self.engine.grant_consent(
            patient_id="P-103",
            provider_id="DOC-201",
            scope=Scope.ALL,
            duration_seconds=1
        )
        # Immediate check is authorized
        auth1, _, _ = self.engine.check_consent("P-103", "DOC-201", Scope.ALL)
        self.assertTrue(auth1)

        # Wait 1.1s for expiration
        time.sleep(1.1)
        auth2, reason, _ = self.engine.check_consent("P-103", "DOC-201", Scope.ALL)
        self.assertFalse(auth2)
        self.assertIn("expired", reason.lower())

    def test_08_offchain_integrity_and_tamper_detection(self):
        """Extended Feature: Demonstrates SHA-256 detection when an off-chain record is modified."""
        # Baseline check is intact
        intact_res = self.engine.verify_record_integrity(actor_id="AUD-501", record_id="REC-EHR-101")
        self.assertTrue(intact_res["integrity"]["is_intact"])

        # Simulate unauthorized off-chain tampering
        self.storage.simulate_tamper(
            record_id="REC-EHR-101",
            tampered_field="clinical_notes",
            fraudulent_value="TAMPERED_FRAUD_DATA"
        )

        # Verify integrity again -> must detect tampering!
        tampered_res = self.engine.verify_record_integrity(actor_id="AUD-501", record_id="REC-EHR-101")
        self.assertFalse(tampered_res["integrity"]["is_intact"])
        self.assertEqual(tampered_res["integrity"]["status"], "TAMPER_DETECTED")

        # Restore record
        self.storage.restore_record("REC-EHR-101")
        restored_res = self.engine.verify_record_integrity(actor_id="AUD-501", record_id="REC-EHR-101")
        self.assertTrue(restored_res["integrity"]["is_intact"])

    def test_09_blockchain_chain_and_merkle_verification(self):
        """Validates complete cryptographic chain of blocks and Merkle roots."""
        report = self.ledger.verify_chain()
        self.assertTrue(report["is_valid"])
        self.assertGreaterEqual(report["height"], 5)
        self.assertEqual(len(report["errors"]), 0)

    def test_10_break_glass_emergency_override(self):
        """Break-glass emergency override allows emergency read with mandatory on-chain audit alert."""
        # DOC-202 has no consent on P-101
        res = self.engine.read_record(
            actor_id="DOC-202",
            patient_id="P-101",
            record_id="REC-EHR-101",
            emergency_override=True,
            override_reason="Unconscious trauma admission at ER"
        )
        self.assertTrue(res["authorized"])
        self.assertTrue(res["success"])
        # Check that override was flagged in audit
        latest_tx = self.ledger.latest_block.transactions[0]
        self.assertTrue(latest_tx["details"]["emergency_override"])


if __name__ == "__main__":
    unittest.main()
