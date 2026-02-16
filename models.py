"""
Models for Admin Portal
Reflects existing ArtPriv tables in Supabase (PostgreSQL with String UUIDs)
"""
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.sql import func
import uuid
import enum
from database import Base


def generate_uuid():
    """Generate UUID as string"""
    return str(uuid.uuid4())


# ========== Enums ==========
class DonorState(str, enum.Enum):
    VISITOR = "visitor"
    BANK_SELECTED = "bank_selected"
    LEAD_CREATED = "lead_created"
    ACCOUNT_CREATED = "account_created"
    COUNSELING_REQUESTED = "counseling_requested"
    CONSENT_PENDING = "consent_pending"
    CONSENT_VERIFIED = "consent_verified"
    TESTS_PENDING = "tests_pending"
    ELIGIBILITY_DECISION = "eligibility_decision"
    DONOR_ONBOARDED = "donor_onboarded"


class BankState(str, enum.Enum):
    UNREGISTERED = "unregistered"
    ACCOUNT_CREATED = "account_created"
    VERIFICATION_PENDING = "verification_pending"
    VERIFIED = "verified"
    SUBSCRIPTION_PENDING = "subscription_pending"
    SUBSCRIBED_ONBOARDED = "subscribed_onboarded"
    OPERATIONAL = "operational"


class EligibilityStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class AdminRole(str, enum.Enum):
    SUPER_ADMIN = "super_admin"
    SUPPORT = "support"
    VIEWER = "viewer"


class ConsentStatus(str, enum.Enum):
    PENDING = "pending"
    SIGNED = "signed"
    VERIFIED = "verified"
    REJECTED = "rejected"


class CounselingMethod(str, enum.Enum):
    CALL = "call"
    VIDEO = "video"
    IN_PERSON = "in_person"
    EMAIL = "email"


class CounselingStatus(str, enum.Enum):
    REQUESTED = "requested"
    SCHEDULED = "scheduled"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class TestReportSource(str, enum.Enum):
    BANK_CONDUCTED = "bank_conducted"


# ========== Models (reflect existing ArtPriv tables with native UUID) ==========
class Bank(Base):
    __tablename__ = "banks"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    name = Column(String, nullable=False)
    state = Column(String, default="account_created", nullable=False)
    
    address = Column(Text)
    phone = Column(String)
    website = Column(String)
    description = Column(Text)
    
    certification_documents = Column(JSON)
    
    is_verified = Column(Boolean, default=False)
    verified_at = Column(DateTime(timezone=True))
    verified_by = Column(String)
    
    is_subscribed = Column(Boolean, default=False)
    subscription_tier = Column(String)
    subscription_started_at = Column(DateTime(timezone=True))
    subscription_expires_at = Column(DateTime(timezone=True))
    billing_details = Column(JSON)
    
    counseling_config = Column(JSON)
    logo_url = Column(String)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class Donor(Base):
    __tablename__ = "donors"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    state = Column(String, default="visitor", nullable=False)
    
    first_name = Column(String)
    last_name = Column(String)
    phone = Column(String)
    date_of_birth = Column(DateTime(timezone=True))
    address = Column(Text)
    
    # Physical characteristics
    donor_type = Column(String)
    height_cm = Column(String)
    weight_kg = Column(String)
    hair_color = Column(String)
    skin_color = Column(String)
    eye_color = Column(String)
    blood_group = Column(String)
    
    medical_interest_info = Column(JSON)
    
    bank_id = Column(String, ForeignKey("banks.id"))
    selected_at = Column(DateTime(timezone=True))
    
    legal_documents = Column(JSON)
    
    # Status flags
    consent_pending = Column(Boolean, default=False)
    counseling_pending = Column(Boolean, default=False)
    tests_pending = Column(Boolean, default=False)
    
    # Module completion flags
    documents_uploaded = Column(Boolean, default=False)
    counseling_complete = Column(Boolean, default=False)
    consent_verified = Column(Boolean, default=False)
    tests_complete = Column(Boolean, default=False)
    
    # Eligibility
    eligibility_status = Column(String, default="pending")
    eligibility_notes = Column(Text)
    eligibility_decided_at = Column(DateTime(timezone=True))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class DonorDocument(Base):
    """Tracks individual donor legal documents with verification status"""
    __tablename__ = "donor_documents"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    donor_id = Column(String, ForeignKey("donors.id"), nullable=False)
    
    type = Column(String)  # e.g., 'government_id', 'address_proof', etc.
    status = Column(String, default="pending")  # pending, verified, rejected
    
    file_url = Column(String)
    file_name = Column(String)
    file_size = Column(String)
    
    rejection_reason = Column(Text)
    
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())
    verified_at = Column(DateTime(timezone=True))
    verified_by = Column(String)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class DonorStateHistory(Base):
    __tablename__ = "donor_state_history"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    donor_id = Column(String, ForeignKey("donors.id"), nullable=False)
    
    from_state = Column(String)
    to_state = Column(String, nullable=False)
    
    changed_by = Column(String)
    changed_by_role = Column(String)
    reason = Column(Text)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class BankStateHistory(Base):
    __tablename__ = "bank_state_history"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    bank_id = Column(String, ForeignKey("banks.id"), nullable=False)
    
    from_state = Column(String)
    to_state = Column(String, nullable=False)
    
    changed_by = Column(String)
    reason = Column(Text)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ========== Admin-specific models ==========
class Admin(Base):
    __tablename__ = "admins"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    name = Column(String, nullable=False)
    role = Column(String, default="viewer", nullable=False)
    
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime(timezone=True))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class ActivityLog(Base):
    __tablename__ = "activity_logs"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    admin_id = Column(String, ForeignKey("admins.id"), nullable=False)
    
    action = Column(String, nullable=False)
    entity_type = Column(String, nullable=False)
    entity_id = Column(String)  # Keep as string since it can reference different tables
    
    details = Column(JSON)
    ip_address = Column(String)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ConsentTemplate(Base):
    __tablename__ = "consent_templates"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    bank_id = Column(String, ForeignKey("banks.id"), nullable=False)
    
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    version = Column(String, default="1.0")
    order = Column(String, default="1")
    
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class DonorConsent(Base):
    __tablename__ = "donor_consents"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    donor_id = Column(String, ForeignKey("donors.id"), nullable=False)
    template_id = Column(String, ForeignKey("consent_templates.id"), nullable=False)
    
    status = Column(String, default="pending", nullable=False)
    
    signed_at = Column(DateTime(timezone=True))
    signature_data = Column(JSON)
    
    verified_at = Column(DateTime(timezone=True))
    verified_by = Column(String)
    verification_notes = Column(Text)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class CounselingSession(Base):
    __tablename__ = "counseling_sessions"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    donor_id = Column(String, ForeignKey("donors.id"), nullable=False)
    bank_id = Column(String, ForeignKey("banks.id"), nullable=False)
    
    status = Column(String, default="requested", nullable=False)
    method = Column(String)
    
    requested_at = Column(DateTime(timezone=True), server_default=func.now())
    scheduled_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    meeting_link = Column(String)
    location = Column(String)
    notes = Column(Text)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class TestReport(Base):
    __tablename__ = "test_reports"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    donor_id = Column(String, ForeignKey("donors.id"), nullable=False)
    bank_id = Column(String, ForeignKey("banks.id"), nullable=False)
    
    source = Column(String, nullable=False)
    
    test_type = Column(String, nullable=False)
    test_name = Column(String, nullable=False)
    file_url = Column(String, nullable=False)
    file_name = Column(String)
    
    uploaded_by = Column(String)
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())
    
    test_date = Column(DateTime(timezone=True))
    lab_name = Column(String)
    notes = Column(Text)
    
    # Status tracking
    status = Column(String, default="pending")  # pending, approved, rejected
    reviewed_at = Column(DateTime(timezone=True))
    reviewed_by = Column(String)
    review_notes = Column(Text)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class SubscriptionPlan(Base):
    __tablename__ = "subscription_plans"
    
    id = Column(String, primary_key=True)  # e.g., "basic", "professional", "enterprise"
    name = Column(String, nullable=False)
    price = Column(String, nullable=False)  # Store as string to handle decimal precision
    max_donors = Column(String)  # "null" for unlimited, or a number as string
    description = Column(Text)
    features = Column(JSON)  # List of feature strings
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
