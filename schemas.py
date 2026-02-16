"""Admin-specific Pydantic schemas"""
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime


# ========== Admin Auth Schemas ==========
class AdminLogin(BaseModel):
    email: EmailStr
    password: str


class AdminTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    admin_id: str
    role: str
    name: str


class AdminCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str = Field(..., min_length=2)
    role: str = "viewer"


class AdminResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    email: EmailStr
    name: str
    role: str
    is_active: bool
    last_login: Optional[datetime] = None
    created_at: datetime


# ========== Dashboard Schemas ==========
class DashboardStats(BaseModel):
    total_banks: int
    verified_banks: int
    subscribed_banks: int
    operational_banks: int
    total_donors: int
    onboarded_donors: int
    pending_verifications: int
    expiring_subscriptions: int
    expired_subscriptions: int
    recent_signups: int


class SubscriptionSummary(BaseModel):
    tier: str
    count: int
    revenue_estimate: float


class ActivityLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    admin_id: str
    admin_name: Optional[str] = None
    action: str
    entity_type: str
    entity_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    created_at: datetime


class DashboardResponse(BaseModel):
    stats: DashboardStats
    subscription_breakdown: List[SubscriptionSummary]
    recent_activity: List[ActivityLogResponse]


# ========== Bank Management Schemas ==========
class BankAdminView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    email: str
    name: str
    state: str
    phone: Optional[str] = None
    address: Optional[str] = None
    website: Optional[str] = None
    is_verified: bool
    verified_at: Optional[datetime] = None
    is_subscribed: bool
    subscription_tier: Optional[str] = None
    subscription_started_at: Optional[datetime] = None
    subscription_expires_at: Optional[datetime] = None
    donor_count: int = 0
    created_at: datetime


class BankListResponse(BaseModel):
    items: List[BankAdminView]
    total: int
    page: int
    page_size: int
    total_pages: int


class BankVerifyRequest(BaseModel):
    verified_by: str
    notes: Optional[str] = None


class SubscriptionUpdateRequest(BaseModel):
    subscription_tier: str
    subscription_started_at: datetime
    subscription_expires_at: datetime
    notes: Optional[str] = None


# ========== Donor Management Schemas ==========
class DonorAdminView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    state: str
    bank_id: Optional[str] = None
    bank_name: Optional[str] = None
    eligibility_status: str
    created_at: datetime


class DonorListResponse(BaseModel):
    items: List[DonorAdminView]
    total: int
    page: int
    page_size: int
    total_pages: int


class StateHistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    from_state: Optional[str] = None
    to_state: str
    changed_by: Optional[str] = None
    changed_by_role: Optional[str] = None
    reason: Optional[str] = None
    created_at: datetime


class DonorDetailAdminView(DonorAdminView):
    address: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    medical_interest_info: Optional[Dict[str, Any]] = None
    eligibility_notes: Optional[str] = None
    selected_at: Optional[datetime] = None
    consent_pending: bool = False
    counseling_pending: bool = False
    tests_pending: bool = False
    state_history: List[StateHistoryItem] = []


# ========== Activity Log Schemas ==========
class ActivityLogListResponse(BaseModel):
    items: List[ActivityLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# ========== Subscription Analytics ==========
class MonthlySubscriptionTrend(BaseModel):
    month: str
    new_subscriptions: int
    renewals: int
    churned: int


class SubscriptionAnalytics(BaseModel):
    active_subscriptions: int
    expiring_soon: int
    expired: int
    never_subscribed: int
    total_revenue_estimate: float
    tier_breakdown: List[SubscriptionSummary]
    monthly_trend: List[MonthlySubscriptionTrend]


# ========== Document & File Schemas ==========
class DocumentMetadata(BaseModel):
    file_name: str
    file_url: str
    uploaded_at: Optional[datetime] = None
    file_type: Optional[str] = None


class CertificationDocument(BaseModel):
    documents: List[DocumentMetadata]


# ========== Consent Form Schemas ==========
class ConsentTemplateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    bank_id: str
    title: str
    content: str
    version: str
    order: str
    is_active: bool
    created_at: datetime


class DonorConsentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    donor_id: str
    template_id: str
    template_title: Optional[str] = None
    status: str
    signed_at: Optional[datetime] = None
    signature_data: Optional[Dict[str, Any]] = None
    verified_at: Optional[datetime] = None
    verified_by: Optional[str] = None
    verification_notes: Optional[str] = None
    created_at: datetime


# ========== Counseling Schemas ==========
class CounselingSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    donor_id: str
    bank_id: str
    donor_name: Optional[str] = None
    bank_name: Optional[str] = None
    status: str
    method: Optional[str] = None
    requested_at: datetime
    scheduled_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    meeting_link: Optional[str] = None
    location: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime


# ========== Test Report Schemas ==========
class TestReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    donor_id: str
    bank_id: str
    donor_name: Optional[str] = None
    bank_name: Optional[str] = None
    source: str
    test_type: str
    test_name: str
    file_url: str
    file_name: Optional[str] = None
    uploaded_by: Optional[str] = None
    uploaded_at: datetime
    test_date: Optional[datetime] = None
    lab_name: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = "pending"  # pending, approved, rejected
    reviewed_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None
    review_notes: Optional[str] = None
    created_at: datetime


# ========== Enhanced Bank Schemas ==========
class BankDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    email: str
    name: str
    state: str
    phone: Optional[str] = None
    address: Optional[str] = None
    website: Optional[str] = None
    description: Optional[str] = None
    certification_documents: Optional[Any] = None  # Can be list or dict
    is_verified: bool
    verified_at: Optional[datetime] = None
    verified_by: Optional[str] = None
    is_subscribed: bool
    subscription_tier: Optional[str] = None
    subscription_started_at: Optional[datetime] = None
    subscription_expires_at: Optional[datetime] = None
    billing_details: Optional[Dict[str, Any]] = None
    counseling_config: Optional[Dict[str, Any]] = None
    logo_url: Optional[str] = None
    donor_count: int = 0
    consent_template_count: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None


class BankUpdateRequest(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    website: Optional[str] = None
    description: Optional[str] = None
    logo_url: Optional[str] = None


class BankStateChangeRequest(BaseModel):
    to_state: str
    reason: Optional[str] = None


# ========== Enhanced Donor Schemas ==========
class DonorDetailFullResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    state: str
    date_of_birth: Optional[datetime] = None
    address: Optional[str] = None
    medical_interest_info: Optional[Dict[str, Any]] = None
    legal_documents: Optional[List[Dict[str, Any]]] = None
    bank_id: Optional[str] = None
    bank_name: Optional[str] = None
    selected_at: Optional[datetime] = None
    consent_pending: bool = False
    counseling_pending: bool = False
    tests_pending: bool = False
    eligibility_status: str
    eligibility_notes: Optional[str] = None
    eligibility_decided_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    # Related data
    state_history: List[StateHistoryItem] = []
    consent_documents: List[DonorConsentResponse] = []
    test_reports: List[TestReportResponse] = []
    consents: List[DonorConsentResponse] = []
    counseling_sessions: List[CounselingSessionResponse] = []
    test_reports: List[TestReportResponse] = []


class DonorUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    address: Optional[str] = None
    date_of_birth: Optional[datetime] = None


class DonorEligibilityUpdateRequest(BaseModel):
    eligibility_status: str
    eligibility_notes: Optional[str] = None


# ========== Subscription Management Schemas ==========
class SubscriptionCreateRequest(BaseModel):
    subscription_tier: str
    subscription_started_at: datetime
    subscription_expires_at: datetime
    billing_details: Optional[Dict[str, Any]] = None


class SubscriptionDetailResponse(BaseModel):
    bank_id: str
    bank_name: str
    bank_email: str
    subscription_tier: Optional[str] = None
    subscription_started_at: Optional[datetime] = None
    subscription_expires_at: Optional[datetime] = None
    billing_details: Optional[Dict[str, Any]] = None
    is_subscribed: bool
    is_verified: bool
    donor_count: int
    created_at: datetime


# ========== Subscription Plan Schemas ==========
class SubscriptionPlanCreate(BaseModel):
    id: str  # e.g., "basic", "professional", "enterprise"
    name: str
    price: float
    max_donors: Optional[int] = None  # None for unlimited
    description: Optional[str] = None
    features: Optional[List[str]] = []


class SubscriptionPlanUpdate(BaseModel):
    name: Optional[str] = None
    price: Optional[float] = None
    max_donors: Optional[int] = None
    description: Optional[str] = None
    features: Optional[List[str]] = None


class SubscriptionPlanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    name: str
    price: str  # Returned as string for precision
    max_donors: Optional[str] = None  # "null" or number as string
    description: Optional[str] = None
    features: Optional[List[str]] = []
    is_active: bool
    active_subscriptions: int = 0  # Count of banks using this plan
    created_at: datetime
    updated_at: Optional[datetime] = None


# ========== Document Verification Schemas ==========
class DocumentVerifyRequest(BaseModel):
    document_url: str
    notes: Optional[str] = None


class DocumentRejectRequest(BaseModel):
    document_url: str
    reason: str


class ConsentApproveRequest(BaseModel):
    notes: Optional[str] = None


class ConsentRejectRequest(BaseModel):
    reason: str


class TestReportApproveRequest(BaseModel):
    notes: Optional[str] = None


class TestReportRejectRequest(BaseModel):
    reason: str


# ========== Counseling Schedule Schema ==========
class CounselingSessionSchedule(BaseModel):
    session_id: str
    scheduled_at: datetime
    meeting_link: Optional[str] = None
    location: Optional[str] = None
