"""
Realistic mock data initialization for Healthcare Consent & Audit Log.
Seeds Patients, Healthcare Providers (Doctors, Labs, Pharmacies), Compliance Auditors,
and initial Off-Chain EHR documents and on-chain consent states.
"""

import time
from typing import Dict, List
from healthcare_consent.core.models import Identity, Role, Scope, MedicalRecord
from healthcare_consent.core.smart_contract import ConsentSmartContractEngine
from healthcare_consent.core.offchain_store import OffChainMedicalStore
from healthcare_consent.core.blockchain import BlockchainLedger


def get_default_identities() -> Dict[str, Identity]:
    """Returns directory of standard simulated identities."""
    return {
        # Patients
        "P-101": Identity(
            id="P-101",
            name="Alice Smith",
            role=Role.PATIENT,
            organization="St. Jude Health Network",
            email="alice.smith@patient.org",
            avatar_color="#2563eb",
            specialty="Patient (DOB: 1989-05-14 | Blood: A+)"
        ),
        "P-102": Identity(
            id="P-102",
            name="Robert Chen",
            role=Role.PATIENT,
            organization="Metro Health System",
            email="robert.chen@patient.org",
            avatar_color="#7c3aed",
            specialty="Patient (DOB: 1978-11-22 | Blood: O-)"
        ),
        "P-103": Identity(
            id="P-103",
            name="Elena Rostova",
            role=Role.PATIENT,
            organization="Northside Medical",
            email="elena.rostova@patient.org",
            avatar_color="#059669",
            specialty="Patient (DOB: 1995-02-18 | Blood: B+)"
        ),

        # Healthcare Providers
        "DOC-201": Identity(
            id="DOC-201",
            name="Dr. Sarah Carter, MD",
            role=Role.DOCTOR,
            organization="St. Jude Cardiology Institute",
            email="s.carter@stjude-health.org",
            avatar_color="#0284c7",
            specialty="Cardiovascular Medicine & Internal Medicine"
        ),
        "DOC-202": Identity(
            id="DOC-202",
            name="Dr. Marcus Vance, MD",
            role=Role.DOCTOR,
            organization="Metro General Hospital",
            email="m.vance@metrohealth.org",
            avatar_color="#d97706",
            specialty="Oncology & Hematology"
        ),
        "LAB-301": Identity(
            id="LAB-301",
            name="BioCore Diagnostic Labs",
            role=Role.LAB,
            organization="BioCore Clinical Pathology Inc.",
            email="lab-dispatch@biocore-diagnostics.com",
            avatar_color="#10b981",
            specialty="Diagnostic Pathology & Molecular Panels"
        ),
        "RX-401": Identity(
            id="RX-401",
            name="Apex Clinical Pharmacy",
            role=Role.PHARMACY,
            organization="Apex Healthcare Pharmacy Group",
            email="dispensing@apexpharmacy.org",
            avatar_color="#8b5cf6",
            specialty="Clinical Pharmacology & Outpatient Dispensing"
        ),

        # Compliance & Auditor
        "AUD-501": Identity(
            id="AUD-501",
            name="Evelyn Reed",
            role=Role.AUDITOR,
            organization="Office for Civil Rights / HIPAA Compliance Inspector",
            email="evelyn.reed@hhs-audit.gov",
            avatar_color="#dc2626",
            specialty="Healthcare Regulatory Compliance & Security Audit"
        )
    }


def seed_database(
    ledger: BlockchainLedger,
    storage: OffChainMedicalStore,
    engine: ConsentSmartContractEngine
):
    """
    Populates off-chain store with realistic clinical records,
    establishes initial on-chain consent states, and records initial audit blocks.
    """
    now = time.time()
    t_minus_3d = now - (3 * 86400)
    t_minus_2d = now - (2 * 86400)
    t_minus_1d = now - (1 * 86400)

    # 1. Seed Off-Chain Medical Records for Alice Smith (P-101)
    rec1 = MedicalRecord(
        record_id="REC-EHR-101",
        patient_id="P-101",
        category=Scope.EHR_GENERAL,
        title="Comprehensive Health Assessment & Baseline",
        clinical_data={
            "vitals": {"blood_pressure": "118/76 mmHg", "heart_rate": "72 bpm", "bmi": 22.4, "temp": "98.6 F"},
            "allergies": ["Penicillin (Severe - Anaphylaxis)", "Sulfa antibiotics"],
            "chronic_conditions": ["Mild Seasonal Allergic Rhinitis"],
            "surgical_history": ["Appendectomy (2014)"],
            "clinical_notes": "Patient presents in excellent overall health. Cardiovascular, pulmonary, and neurological exams normal."
        },
        created_at=t_minus_3d,
        updated_at=t_minus_3d,
        version=1
    )
    storage.save_record(rec1)
    engine.record_anchors[rec1.record_id] = rec1.calculate_hash()

    rec2 = MedicalRecord(
        record_id="REC-LAB-102",
        patient_id="P-101",
        category=Scope.LAB_REPORTS,
        title="Complete Blood Count (CBC) & Lipid Panel",
        clinical_data={
            "laboratory": "BioCore Diagnostic Labs",
            "specimen_type": "Venous Whole Blood",
            "fasting_glucose": "92 mg/dL (Ref: 70-99)",
            "total_cholesterol": "184 mg/dL (Ref: <200)",
            "hdl": "58 mg/dL (Ref: >50)",
            "ldl": "108 mg/dL (Ref: <100)",
            "hemoglobin_a1c": "5.3% (Normal)",
            "wbc_count": "6.4 x10^3/uL",
            "pathologist_remark": "Normal lipid profile and glycemic indices."
        },
        created_at=t_minus_2d,
        updated_at=t_minus_2d,
        version=1
    )
    storage.save_record(rec2)
    engine.record_anchors[rec2.record_id] = rec2.calculate_hash()

    rec3 = MedicalRecord(
        record_id="REC-RX-103",
        patient_id="P-101",
        category=Scope.PRESCRIPTIONS,
        title="Outpatient Maintenance Pharmacotherapy",
        clinical_data={
            "pharmacy": "Apex Clinical Pharmacy",
            "prescriptions": [
                {
                    "drug_name": "Loratadine",
                    "strength": "10 mg",
                    "form": "Oral Tablet",
                    "directions": "Take 1 tablet daily by mouth as needed for seasonal allergies",
                    "refills_remaining": 3,
                    "prescribed_by": "DOC-201 (Dr. Sarah Carter)"
                }
            ]
        },
        created_at=t_minus_1d,
        updated_at=t_minus_1d,
        version=1
    )
    storage.save_record(rec3)
    engine.record_anchors[rec3.record_id] = rec3.calculate_hash()

    rec4 = MedicalRecord(
        record_id="REC-IMG-104",
        patient_id="P-101",
        category=Scope.IMAGING,
        title="Chest Radiograph (PA & Lateral Views)",
        clinical_data={
            "radiology_facility": "St. Jude Diagnostic Imaging Center",
            "technique": "Two-view upright posteroanterior and lateral chest radiography",
            "findings": "Cardiothoracic ratio within normal limits (<0.5). Lungs clear without focal consolidation, pneumothorax, or pleural effusion.",
            "radiologist_impression": "Unremarkable radiographic examination of the chest."
        },
        created_at=t_minus_1d,
        updated_at=t_minus_1d,
        version=1
    )
    storage.save_record(rec4)
    engine.record_anchors[rec4.record_id] = rec4.calculate_hash()

    # 2. Seed Records for Robert Chen (P-102)
    rec5 = MedicalRecord(
        record_id="REC-EHR-201",
        patient_id="P-102",
        category=Scope.EHR_GENERAL,
        title="Endocrine Metabolic Follow-up",
        clinical_data={
            "vitals": {"blood_pressure": "132/84 mmHg", "heart_rate": "78 bpm", "bmi": 27.2},
            "diagnosis": "Type 2 Diabetes Mellitus without complications",
            "plan": "Continue lifestyle modification and Metformin therapy."
        },
        created_at=t_minus_2d,
        updated_at=t_minus_2d,
        version=1
    )
    storage.save_record(rec5)
    engine.record_anchors[rec5.record_id] = rec5.calculate_hash()

    # 3. Seed Initial Blockchain Consent States & Historical Audit Events
    # Consent 1: Alice -> Dr. Sarah Carter (DOC-201) -> Scope: ALL (Active)
    engine.grant_consent(
        patient_id="P-101",
        provider_id="DOC-201",
        scope=Scope.ALL,
        duration_seconds=30 * 86400,  # 30 days
        purpose="Primary cardiology consultation and continuous care"
    )

    # Consent 2: Alice -> BioCore Labs (LAB-301) -> Scope: LAB_REPORTS (Active for 7 days)
    engine.grant_consent(
        patient_id="P-101",
        provider_id="LAB-301",
        scope=Scope.LAB_REPORTS,
        duration_seconds=7 * 86400,
        purpose="Diagnostic blood panel and metabolic testing analysis"
    )

    # Historical Action: Dr. Carter reads Alice's EHR
    engine.read_record(
        actor_id="DOC-201",
        patient_id="P-101",
        record_id="REC-EHR-101"
    )

    # Historical Action: BioCore writes Alice's lab report
    engine.write_record(
        actor_id="LAB-301",
        patient_id="P-101",
        category=Scope.LAB_REPORTS,
        title="Complete Blood Count (CBC) & Lipid Panel",
        clinical_data=rec2.clinical_data,
        record_id="REC-LAB-102"
    )

    # Consent 3: Alice previously granted and then REVOKED Apex Pharmacy (RX-401)
    engine.grant_consent(
        patient_id="P-101",
        provider_id="RX-401",
        scope=Scope.PRESCRIPTIONS,
        duration_seconds=14 * 86400,
        purpose="Temporary prescription refill verification"
    )
    engine.revoke_consent(
        patient_id="P-101",
        provider_id="RX-401",
        scope=Scope.PRESCRIPTIONS
    )

    # Historical Attempt: Dr. Marcus Vance (DOC-202) attempted to read Alice's EHR without consent
    # This automatically produces an UNAUTHORIZED_ATTEMPT on-chain log
    engine.read_record(
        actor_id="DOC-202",
        patient_id="P-101",
        record_id="REC-EHR-101"
    )
