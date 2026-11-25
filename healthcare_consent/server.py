"""
REST API & Web Application Server for Healthcare Consent & Audit Log.
Built on Python 3 Standard Library (ThreadingHTTPServer) with zero external
framework dependencies. Exposes complete REST endpoints for Patient, Provider,
and Compliance Auditor workflows.
"""

import os
import sys
import json
import time
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Dict, Any, Optional

from healthcare_consent.core.models import Role, Scope, EventType
from healthcare_consent.core.blockchain import BlockchainLedger
from healthcare_consent.core.offchain_store import OffChainMedicalStore
from healthcare_consent.core.smart_contract import ConsentSmartContractEngine
from healthcare_consent.database.mock_data import get_default_identities, seed_database


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP Server for concurrent requests."""
    daemon_threads = True
    allow_reuse_address = True


# Initialize Global Singletons
LEDGER = BlockchainLedger()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE = OffChainMedicalStore(os.path.join(BASE_DIR, "storage", "records"))
ENGINE = ConsentSmartContractEngine(LEDGER, STORAGE)
IDENTITIES = get_default_identities()
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Seed initial system
seed_database(LEDGER, STORAGE, ENGINE)


def reset_system():
    """Resets ledger and storage back to initial seeded state."""
    global LEDGER, STORAGE, ENGINE
    LEDGER = BlockchainLedger()
    # Clean storage dir
    for f in os.listdir(STORAGE.storage_dir):
        if f.endswith(".json"):
            try:
                os.remove(os.path.join(STORAGE.storage_dir, f))
            except Exception:
                pass
    STORAGE = OffChainMedicalStore(os.path.join(BASE_DIR, "storage", "records"))
    ENGINE = ConsentSmartContractEngine(LEDGER, STORAGE)
    seed_database(LEDGER, STORAGE, ENGINE)


class HealthcareRequestHandler(SimpleHTTPRequestHandler):
    """HTTP Request Handler routing REST API endpoints and static assets."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _read_body_json(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return {}
        body = self.rfile.read(content_length).decode("utf-8")
        try:
            return json.loads(body)
        except Exception:
            return {}

    def do_OPTIONS(self):
        """Handles CORS pre-flight requests."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Static assets
        if path == "/" or path == "/index.html":
            self.path = "/index.html"
            return super().do_GET()
        elif not path.startswith("/api/"):
            return super().do_GET()

        # REST API Routes
        try:
            if path == "/api/status":
                self._handle_get_status()
            elif path == "/api/identities":
                self._handle_get_identities()
            elif path == "/api/consents":
                self._handle_get_consents(query)
            elif path == "/api/records":
                self._handle_get_records(query)
            elif path == "/api/record":
                self._handle_get_single_record(query)
            elif path == "/api/audit-trail":
                self._handle_get_audit_trail(query)
            elif path == "/api/blockchain/blocks":
                self._handle_get_blocks()
            elif path == "/api/blockchain/verify":
                self._handle_verify_blockchain()
            else:
                self._send_json({"error": f"Endpoint {path} not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e), "path": path}, 500)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_body_json()

        try:
            if path == "/api/consent/grant":
                self._handle_grant_consent(body)
            elif path == "/api/consent/revoke":
                self._handle_revoke_consent(body)
            elif path == "/api/records/write":
                self._handle_write_record(body)
            elif path == "/api/records/verify-integrity":
                self._handle_verify_integrity(body)
            elif path == "/api/records/simulate-tamper":
                self._handle_simulate_tamper(body)
            elif path == "/api/records/restore":
                self._handle_restore_record(body)
            elif path == "/api/reset":
                reset_system()
                self._send_json({"success": True, "message": "System reset to clean initial seeded state."})
            else:
                self._send_json({"error": f"Endpoint {path} not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e), "path": path}, 500)

    # Handlers
    def _handle_get_status(self):
        verification = LEDGER.verify_chain()
        all_consents = ENGINE.get_all_consents()
        active_consents = [c for c in all_consents if c.get("is_active")]
        data = {
            "system_name": "Healthcare Consent & Audit Log",
            "version": "1.0.0",
            "compliance": "HIPAA 45 CFR § 164.312(b) & GDPR Art. 7",
            "blockchain": {
                "height": len(LEDGER.chain),
                "latest_block_hash": LEDGER.latest_block.hash,
                "chain_valid": verification["is_valid"],
                "total_events": len(LEDGER.get_audit_trail())
            },
            "offchain_storage": {
                "total_records": len(os.listdir(STORAGE.storage_dir)),
                "storage_mode": "Decoupled JSON/EHR File Store"
            },
            "consent_engine": {
                "total_consents_registered": len(all_consents),
                "active_consents": len(active_consents)
            },
            "timestamp": time.time()
        }
        self._send_json(data)

    def _handle_get_identities(self):
        result = {user_id: ident.to_dict() for user_id, ident in IDENTITIES.items()}
        self._send_json(result)

    def _handle_get_consents(self, query):
        patient_id = query.get("patient_id", [None])[0]
        provider_id = query.get("provider_id", [None])[0]
        consents = ENGINE.get_all_consents(patient_id=patient_id, provider_id=provider_id)
        self._send_json(consents)

    def _handle_get_records(self, query):
        patient_id = query.get("patient_id", [None])[0]
        actor_id = query.get("actor_id", [None])[0]
        category_str = query.get("category", [None])[0]

        if not patient_id:
            self._send_json({"error": "Missing patient_id parameter"}, 400)
            return

        scope = Scope(category_str) if category_str and category_str != "ALL" else None

        # If actor is provider (not the patient themselves or an auditor), enforce access check
        if actor_id and actor_id != patient_id and actor_id != "AUD-501":
            # Check consent for requested scope
            authorized, reason, consent = ENGINE.check_consent(patient_id, actor_id, scope or Scope.ALL)
            if not authorized:
                # Log unauthorized attempt
                evt = ENGINE.read_record(actor_id=actor_id, patient_id=patient_id, record_id="LIST_RECORDS_QUERY")
                self._send_json({
                    "authorized": False,
                    "reason": reason,
                    "records": [],
                    "message": "ACCESS DENIED: No active consent to list medical records for this patient."
                }, 403)
                return

        records = STORAGE.list_records_for_patient(patient_id, category=scope)
        # Attach anchored hashes and verification info
        output = []
        for r in records:
            r_dict = r.to_dict()
            anchored = ENGINE.record_anchors.get(r.record_id, r.calculate_hash())
            r_dict["anchored_hash"] = anchored
            r_dict["is_intact"] = (r.calculate_hash() == anchored)
            output.append(r_dict)

        self._send_json(output)

    def _handle_get_single_record(self, query):
        record_id = query.get("record_id", [None])[0]
        actor_id = query.get("actor_id", [None])[0]
        patient_id = query.get("patient_id", [None])[0]
        emergency = query.get("emergency", ["false"])[0].lower() == "true"
        override_reason = query.get("override_reason", [None])[0]

        if not record_id or not actor_id:
            self._send_json({"error": "Missing record_id or actor_id"}, 400)
            return

        # If patient_id not provided, resolve from storage
        rec = STORAGE.get_record(record_id)
        if not rec:
            self._send_json({"error": f"Record {record_id} not found"}, 404)
            return

        patient_id = patient_id or rec.patient_id
        result = ENGINE.read_record(
            actor_id=actor_id,
            patient_id=patient_id,
            record_id=record_id,
            emergency_override=emergency,
            override_reason=override_reason
        )

        status_code = 200 if result.get("authorized", False) else 403
        self._send_json(result, status_code)

    def _handle_get_audit_trail(self, query):
        patient_id = query.get("patient_id", [None])[0]
        actor_id = query.get("actor_id", [None])[0]
        event_type = query.get("event_type", [None])[0]

        trail = LEDGER.get_audit_trail(
            patient_id=patient_id,
            actor_id=actor_id,
            event_type=event_type
        )
        self._send_json(trail)

    def _handle_get_blocks(self):
        blocks_data = [b.to_dict() for b in LEDGER.chain]
        self._send_json(blocks_data)

    def _handle_verify_blockchain(self):
        res = LEDGER.verify_chain()
        self._send_json(res)

    def _handle_grant_consent(self, body):
        patient_id = body.get("patient_id")
        provider_id = body.get("provider_id")
        scope_str = body.get("scope", "ALL")
        duration = body.get("duration_seconds")
        purpose = body.get("purpose", "Medical diagnosis and care delivery")

        if not patient_id or not provider_id:
            self._send_json({"error": "patient_id and provider_id are required"}, 400)
            return

        try:
            scope = Scope(scope_str)
        except ValueError:
            scope = Scope.ALL

        res = ENGINE.grant_consent(
            patient_id=patient_id,
            provider_id=provider_id,
            scope=scope,
            duration_seconds=int(duration) if duration else None,
            purpose=purpose
        )
        self._send_json(res)

    def _handle_revoke_consent(self, body):
        patient_id = body.get("patient_id")
        provider_id = body.get("provider_id")
        scope_str = body.get("scope", "ALL")

        if not patient_id or not provider_id:
            self._send_json({"error": "patient_id and provider_id are required"}, 400)
            return

        try:
            scope = Scope(scope_str)
        except ValueError:
            scope = Scope.ALL

        res = ENGINE.revoke_consent(
            patient_id=patient_id,
            provider_id=provider_id,
            scope=scope
        )
        self._send_json(res)

    def _handle_write_record(self, body):
        actor_id = body.get("actor_id")
        patient_id = body.get("patient_id")
        category_str = body.get("category", "EHR_GENERAL")
        title = body.get("title", "Clinical Note")
        clinical_data = body.get("clinical_data", {})
        record_id = body.get("record_id")

        if not actor_id or not patient_id:
            self._send_json({"error": "actor_id and patient_id are required"}, 400)
            return

        try:
            category = Scope(category_str)
        except ValueError:
            category = Scope.EHR_GENERAL

        res = ENGINE.write_record(
            actor_id=actor_id,
            patient_id=patient_id,
            category=category,
            title=title,
            clinical_data=clinical_data,
            record_id=record_id
        )
        status_code = 200 if res.get("authorized", True) else 403
        self._send_json(res, status_code)

    def _handle_verify_integrity(self, body):
        actor_id = body.get("actor_id", "AUD-501")
        record_id = body.get("record_id")
        if not record_id:
            self._send_json({"error": "record_id is required"}, 400)
            return

        res = ENGINE.verify_record_integrity(actor_id=actor_id, record_id=record_id)
        self._send_json(res)

    def _handle_simulate_tamper(self, body):
        record_id = body.get("record_id")
        field = body.get("tampered_field", "clinical_notes")
        fake_val = body.get("fake_value", "FRAUDULENT_UNAUTHORIZED_MODIFICATION")

        if not record_id:
            self._send_json({"error": "record_id is required"}, 400)
            return

        res = STORAGE.simulate_tamper(record_id, field, fake_val)
        self._send_json(res)

    def _handle_restore_record(self, body):
        record_id = body.get("record_id")
        if not record_id:
            self._send_json({"error": "record_id is required"}, 400)
            return

        ok = STORAGE.restore_record(record_id)
        if ok:
            rec = STORAGE.get_record(record_id)
            ENGINE.record_anchors[record_id] = rec.calculate_hash()
            self._send_json({"success": True, "message": f"Record {record_id} restored to pristine clean state."})
        else:
            self._send_json({"success": False, "error": "No clean backup available"}, 404)


def run_server(port: int = 8085):
    """Starts the threaded HTTP server."""
    server_address = ("0.0.0.0", port)
    httpd = ThreadedHTTPServer(server_address, HealthcareRequestHandler)
    print(f"==================================================================")
    print(f" Healthcare Consent & Audit Log — Active Web & Ledger Server")
    print(f" Running at: http://localhost:{port}")
    print(f" Compliance: HIPAA 45 CFR § 164.312(b) & GDPR Art. 7")
    print(f"==================================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()


if __name__ == "__main__":
    p = 8085
    if len(sys.argv) > 1:
        try:
            p = int(sys.argv[1])
        except ValueError:
            pass
    run_server(p)
