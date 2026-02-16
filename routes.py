"""Admin API routes"""
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy import func, and_, or_
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from database import get_db
from models import Bank, Donor, Admin, ActivityLog, DonorStateHistory, BankStateHistory, DonorDocument
from models import ConsentTemplate, DonorConsent, CounselingSession, TestReport, SubscriptionPlan
from schemas import (
    AdminLogin, AdminTokenResponse, AdminCreate, AdminResponse,
    DashboardStats, DashboardResponse, SubscriptionSummary,
    BankAdminView, BankListResponse, BankVerifyRequest, SubscriptionUpdateRequest,
    DonorAdminView, DonorListResponse, DonorDetailAdminView, StateHistoryItem,
    ActivityLogResponse, ActivityLogListResponse,
    SubscriptionAnalytics, MonthlySubscriptionTrend,
    BankDetailResponse, BankUpdateRequest, BankStateChangeRequest,
    DonorDetailFullResponse, DonorUpdateRequest, DonorEligibilityUpdateRequest,
    ConsentTemplateResponse, DonorConsentResponse,
    CounselingSessionResponse, TestReportResponse,
    SubscriptionCreateRequest, SubscriptionDetailResponse,
    SubscriptionPlanCreate, SubscriptionPlanUpdate, SubscriptionPlanResponse,
    DocumentVerifyRequest, DocumentRejectRequest, 
    ConsentApproveRequest, ConsentRejectRequest,
    TestReportApproveRequest, TestReportRejectRequest
)
from auth import hash_password, verify_password, create_access_token
from config import settings
from storage_utils import (
    get_bank_certification_documents,
    get_donor_legal_documents,
    get_all_donor_documents,
    get_signed_url
)

router = APIRouter()


# ========== Auth Helpers ==========
def get_current_admin(request: Request, db: Session = Depends(get_db)) -> Admin:
    """Get the current authenticated admin from JWT token"""
    from jose import jwt, JWTError
    
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header"
        )
    
    token = auth_header.split(" ")[1]
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        admin_id = payload.get("sub")
        user_type = payload.get("type")
        
        if user_type != "admin" or not admin_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    admin = db.query(Admin).filter(Admin.id == admin_id).first()
    if not admin or not admin.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin not found or inactive"
        )
    
    return admin


def require_role(required_roles: List[str]):
    """Dependency to require specific admin roles"""
    def check_role(admin: Admin = Depends(get_current_admin)):
        if admin.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {required_roles}"
            )
        return admin
    return check_role


def log_activity(db: Session, admin: Admin, action: str, entity_type: str, 
                 entity_id: str = None, details: dict = None, ip_address: str = None):
    """Helper to create activity log entries"""
    log = ActivityLog(
        admin_id=admin.id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details,
        ip_address=ip_address
    )
    db.add(log)
    db.commit()


# ========== Authentication ==========
@router.post("/login", response_model=AdminTokenResponse)
async def admin_login(credentials: AdminLogin, db: Session = Depends(get_db)):
    """Authenticate admin and return JWT token"""
    admin = db.query(Admin).filter(Admin.email == credentials.email).first()
    
    # Development only: Auto-create admin with default credentials
    # This behavior mirrors the main backend
    import os
    is_production = os.getenv("ENVIRONMENT", "development").lower() == "production"
    
    if not admin and not is_production:
        if credentials.email == "admin@artconnect.com" and credentials.password == "Admin@2025":
            print("DEV MODE: Auto-creating default admin in admin portal.")
            admin = Admin(
                email="admin@artconnect.com",
                hashed_password=hash_password("Admin@2025"),
                name="System Admin",
                role="super_admin"
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)

    if not admin or not verify_password(credentials.password, admin.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    if not admin.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin account is inactive"
        )
    
    # Update last login
    admin.last_login = datetime.utcnow()
    db.commit()
    
    # Create access token
    access_token = create_access_token(
        data={"sub": str(admin.id), "type": "admin", "role": admin.role}
    )
    
    return AdminTokenResponse(
        access_token=access_token,
        admin_id=str(admin.id),
        role=admin.role,
        name=admin.name
    )


@router.post("/register", response_model=AdminResponse, status_code=status.HTTP_201_CREATED)
async def create_admin(
    admin_data: AdminCreate,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin"]))
):
    """Create a new admin (super_admin only)"""
    existing = db.query(Admin).filter(Admin.email == admin_data.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    admin = Admin(
        email=admin_data.email,
        hashed_password=hash_password(admin_data.password),
        name=admin_data.name,
        role=admin_data.role
    )
    
    db.add(admin)
    db.commit()
    db.refresh(admin)
    
    log_activity(db, current_admin, "admin_created", "admin", admin.id, 
                 {"name": admin.name, "role": admin.role})
    
    return admin


@router.get("/me", response_model=AdminResponse)
async def get_current_admin_profile(current_admin: Admin = Depends(get_current_admin)):
    """Get current admin's profile"""
    return current_admin


# ========== Dashboard ==========
@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard(
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get dashboard statistics"""
    now = datetime.utcnow()
    thirty_days_ago = now - timedelta(days=30)
    seven_days_ago = now - timedelta(days=7)
    thirty_days_future = now + timedelta(days=30)
    
    # Bank statistics
    total_banks = db.query(func.count(Bank.id)).scalar()
    verified_banks = db.query(func.count(Bank.id)).filter(Bank.is_verified == True).scalar()
    subscribed_banks = db.query(func.count(Bank.id)).filter(Bank.is_subscribed == True).scalar()
    operational_banks = db.query(func.count(Bank.id)).filter(Bank.state == "operational").scalar()
    pending_verifications = db.query(func.count(Bank.id)).filter(
        Bank.state == "verification_pending"
    ).scalar()
    
    # Subscription statistics
    expiring_subscriptions = db.query(func.count(Bank.id)).filter(
        and_(
            Bank.is_subscribed == True,
            Bank.subscription_expires_at <= thirty_days_future,
            Bank.subscription_expires_at > now
        )
    ).scalar()
    
    expired_subscriptions = db.query(func.count(Bank.id)).filter(
        and_(
            Bank.subscription_expires_at != None,
            Bank.subscription_expires_at < now
        )
    ).scalar()
    
    # Recent signups
    recent_signups = db.query(func.count(Bank.id)).filter(
        Bank.created_at >= seven_days_ago
    ).scalar()
    
    # Donor statistics
    total_donors = db.query(func.count(Donor.id)).scalar()
    onboarded_donors = db.query(func.count(Donor.id)).filter(
        Donor.state == "donor onboarded"
    ).scalar()
    
    stats = DashboardStats(
        total_banks=total_banks or 0,
        verified_banks=verified_banks or 0,
        subscribed_banks=subscribed_banks or 0,
        operational_banks=operational_banks or 0,
        total_donors=total_donors or 0,
        onboarded_donors=onboarded_donors or 0,
        pending_verifications=pending_verifications or 0,
        expiring_subscriptions=expiring_subscriptions or 0,
        expired_subscriptions=expired_subscriptions or 0,
        recent_signups=recent_signups or 0
    )
    
    # Subscription tier breakdown
    tier_counts = db.query(
        Bank.subscription_tier,
        func.count(Bank.id)
    ).filter(Bank.is_subscribed == True).group_by(Bank.subscription_tier).all()
    
    tier_prices = {"Starter": 999, "Professional": 2499, "Enterprise": 4999}
    subscription_breakdown = [
        SubscriptionSummary(
            tier=tier or "Unknown",
            count=count,
            revenue_estimate=count * tier_prices.get(tier, 0)
        )
        for tier, count in tier_counts
    ]
    
    # Recent activity
    recent_logs = db.query(ActivityLog).order_by(
        ActivityLog.created_at.desc()
    ).limit(10).all()
    
    recent_activity = []
    for log in recent_logs:
        admin = db.query(Admin).filter(Admin.id == log.admin_id).first()
        recent_activity.append(ActivityLogResponse(
            id=str(log.id),
            admin_id=str(log.admin_id),
            admin_name=admin.name if admin else None,
            action=log.action,
            entity_type=log.entity_type,
            entity_id=log.entity_id,
            details=log.details,
            ip_address=log.ip_address,
            created_at=log.created_at
        ))
    
    return DashboardResponse(
        stats=stats,
        subscription_breakdown=subscription_breakdown,
        recent_activity=recent_activity
    )


# ========== Bank Management ==========
@router.get("/banks", response_model=BankListResponse)
async def list_banks(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    state: Optional[str] = None,
    is_verified: Optional[bool] = None,
    is_subscribed: Optional[bool] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """List all banks with filters and pagination"""
    query = db.query(Bank)
    
    if state:
        query = query.filter(Bank.state == state)
    if is_verified is not None:
        query = query.filter(Bank.is_verified == is_verified)
    if is_subscribed is not None:
        query = query.filter(Bank.is_subscribed == is_subscribed)
    if search:
        query = query.filter(
            or_(
                Bank.name.ilike(f"%{search}%"),
                Bank.email.ilike(f"%{search}%")
            )
        )
    
    total = query.count()
    offset = (page - 1) * page_size
    banks = query.order_by(Bank.created_at.desc()).offset(offset).limit(page_size).all()
    
    items = []
    for bank in banks:
        donor_count = db.query(func.count(Donor.id)).filter(Donor.bank_id == bank.id).scalar()
        items.append(BankAdminView(
            id=str(bank.id),
            email=bank.email,
            name=bank.name,
            state=bank.state,
            phone=bank.phone,
            address=bank.address,
            website=bank.website,
            is_verified=bank.is_verified,
            verified_at=bank.verified_at,
            is_subscribed=bank.is_subscribed,
            subscription_tier=bank.subscription_tier,
            subscription_started_at=bank.subscription_started_at,
            subscription_expires_at=bank.subscription_expires_at,
            donor_count=donor_count or 0,
            created_at=bank.created_at
        ))
    
    return BankListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size
    )


@router.get("/banks/{bank_id}", response_model=BankAdminView)
async def get_bank_details(
    bank_id: str,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get bank details"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    donor_count = db.query(func.count(Donor.id)).filter(Donor.bank_id == bank.id).scalar()
    
    return BankAdminView(
        id=str(bank.id),
        email=bank.email,
        name=bank.name,
        state=bank.state,
        phone=bank.phone,
        address=bank.address,
        website=bank.website,
        is_verified=bank.is_verified,
        verified_at=bank.verified_at,
        is_subscribed=bank.is_subscribed,
        subscription_tier=bank.subscription_tier,
        subscription_started_at=bank.subscription_started_at,
        subscription_expires_at=bank.subscription_expires_at,
        donor_count=donor_count or 0,
        created_at=bank.created_at
    )


@router.put("/banks/{bank_id}/verify", response_model=BankAdminView)
async def verify_bank(
    bank_id: str,
    verify_data: BankVerifyRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Verify a bank"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    if bank.is_verified:
        raise HTTPException(status_code=400, detail="Bank is already verified")
    
    bank.is_verified = True
    bank.verified_at = datetime.utcnow()
    bank.verified_by = verify_data.verified_by
    
    if bank.state == "verification_pending":
        bank.state = "verified"
    
    db.commit()
    db.refresh(bank)
    
    log_activity(
        db, current_admin, "bank_verified", "bank", bank.id,
        {"bank_name": bank.name, "notes": verify_data.notes},
        request.client.host if request.client else None
    )
    
    donor_count = db.query(func.count(Donor.id)).filter(Donor.bank_id == bank.id).scalar()
    
    return BankAdminView(
        id=str(bank.id),
        email=bank.email,
        name=bank.name,
        state=bank.state,
        phone=bank.phone,
        address=bank.address,
        website=bank.website,
        is_verified=bank.is_verified,
        verified_at=bank.verified_at,
        is_subscribed=bank.is_subscribed,
        subscription_tier=bank.subscription_tier,
        subscription_started_at=bank.subscription_started_at,
        subscription_expires_at=bank.subscription_expires_at,
        donor_count=donor_count or 0,
        created_at=bank.created_at
    )


@router.put("/banks/{bank_id}/subscription", response_model=BankAdminView)
async def update_bank_subscription(
    bank_id: str,
    subscription_data: SubscriptionUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Update bank subscription"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    if not bank.is_verified:
        raise HTTPException(status_code=400, detail="Bank must be verified first")
    
    old_tier = bank.subscription_tier
    bank.is_subscribed = True
    bank.subscription_tier = subscription_data.subscription_tier
    bank.subscription_started_at = subscription_data.subscription_started_at
    bank.subscription_expires_at = subscription_data.subscription_expires_at
    
    if bank.state in ["verified", "subscription_pending"]:
        bank.state = "subscribed_onboarded"
    
    db.commit()
    db.refresh(bank)
    
    log_activity(
        db, current_admin, "subscription_updated", "bank", bank.id,
        {
            "bank_name": bank.name,
            "old_tier": old_tier,
            "new_tier": subscription_data.subscription_tier,
            "expires_at": subscription_data.subscription_expires_at.isoformat(),
            "notes": subscription_data.notes
        },
        request.client.host if request.client else None
    )
    
    donor_count = db.query(func.count(Donor.id)).filter(Donor.bank_id == bank.id).scalar()
    
    return BankAdminView(
        id=str(bank.id),
        email=bank.email,
        name=bank.name,
        state=bank.state,
        phone=bank.phone,
        address=bank.address,
        website=bank.website,
        is_verified=bank.is_verified,
        verified_at=bank.verified_at,
        is_subscribed=bank.is_subscribed,
        subscription_tier=bank.subscription_tier,
        subscription_started_at=bank.subscription_started_at,
        subscription_expires_at=bank.subscription_expires_at,
        donor_count=donor_count or 0,
        created_at=bank.created_at
    )


# ========== Donor Management ==========
@router.get("/donors", response_model=DonorListResponse)
async def list_donors(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    state: Optional[str] = None,
    bank_id: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """List all donors with filters"""
    query = db.query(Donor)
    
    if state:
        query = query.filter(Donor.state == state)
    if bank_id:
        query = query.filter(Donor.bank_id == bank_id)
    if search:
        query = query.filter(
            or_(
                Donor.first_name.ilike(f"%{search}%"),
                Donor.last_name.ilike(f"%{search}%"),
                Donor.email.ilike(f"%{search}%")
            )
        )
    
    total = query.count()
    offset = (page - 1) * page_size
    donors = query.order_by(Donor.created_at.desc()).offset(offset).limit(page_size).all()
    
    items = []
    for donor in donors:
        bank_name = None
        if donor.bank_id:
            bank = db.query(Bank).filter(Bank.id == donor.bank_id).first()
            bank_name = bank.name if bank else None
        
        items.append(DonorAdminView(
            id=str(donor.id),
            email=donor.email,
            first_name=donor.first_name,
            last_name=donor.last_name,
            phone=donor.phone,
            state=donor.state,
            bank_id=str(donor.bank_id) if donor.bank_id else None,
            bank_name=bank_name,
            eligibility_status=donor.eligibility_status or "pending",
            created_at=donor.created_at
        ))
    
    return DonorListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size
    )


@router.get("/donors/{donor_id}", response_model=DonorDetailAdminView)
async def get_donor_details(
    donor_id: str,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get donor details with state history"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    bank_name = None
    if donor.bank_id:
        bank = db.query(Bank).filter(Bank.id == donor.bank_id).first()
        bank_name = bank.name if bank else None
    
    history = db.query(DonorStateHistory).filter(
        DonorStateHistory.donor_id == donor_id
    ).order_by(DonorStateHistory.created_at.desc()).all()
    
    state_history = [
        StateHistoryItem(
            id=str(h.id),
            from_state=h.from_state,
            to_state=h.to_state,
            changed_by=h.changed_by,
            changed_by_role=h.changed_by_role,
            reason=h.reason,
            created_at=h.created_at
        )
        for h in history
    ]
    
    return DonorDetailAdminView(
        id=str(donor.id),
        email=donor.email,
        first_name=donor.first_name,
        last_name=donor.last_name,
        phone=donor.phone,
        state=donor.state,
        bank_id=str(donor.bank_id) if donor.bank_id else None,
        bank_name=bank_name,
        eligibility_status=donor.eligibility_status or "pending",
        created_at=donor.created_at,
        address=donor.address,
        date_of_birth=donor.date_of_birth,
        medical_interest_info=donor.medical_interest_info,
        eligibility_notes=donor.eligibility_notes,
        selected_at=donor.selected_at,
        consent_pending=donor.consent_pending or False,
        counseling_pending=donor.counseling_pending or False,
        tests_pending=donor.tests_pending or False,
        state_history=state_history
    )


@router.get("/donors/{donor_id}/full", response_model=DonorDetailFullResponse)
async def get_donor_full_details(
    donor_id: str,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get full donor details with test reports and consent documents"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    # Get bank name
    bank_name = None
    if donor.bank_id:
        bank = db.query(Bank).filter(Bank.id == donor.bank_id).first()
        bank_name = bank.name if bank else None
    
    # Get state history
    history = db.query(DonorStateHistory).filter(
        DonorStateHistory.donor_id == donor_id
    ).order_by(DonorStateHistory.created_at.desc()).all()
    
    state_history = [
        StateHistoryItem(
            id=str(h.id),
            from_state=h.from_state,
            to_state=h.to_state,
            changed_by=h.changed_by,
            changed_by_role=h.changed_by_role,
            reason=h.reason,
            created_at=h.created_at
        )
        for h in history
    ]
    
    # Get consent documents
    consents = db.query(DonorConsent).filter(DonorConsent.donor_id == donor_id).all()
    consent_documents = []
    for consent in consents:
        template = db.query(ConsentTemplate).filter(ConsentTemplate.id == consent.template_id).first()
        consent_documents.append(DonorConsentResponse(
            id=str(consent.id),
            donor_id=str(consent.donor_id),
            template_id=str(consent.template_id),
            template_title=template.title if template else "Unknown",
            status=consent.status,
            signed_at=consent.signed_at,
            signature_data=consent.signature_data,
            verified_at=consent.verified_at,
            verified_by=consent.verified_by,
            verification_notes=consent.verification_notes,
            created_at=consent.created_at,
            updated_at=consent.updated_at
        ))
    
    # Get test reports
    reports = db.query(TestReport).filter(TestReport.donor_id == donor_id).all()
    test_reports = [
        TestReportResponse(
            id=str(report.id),
            donor_id=str(report.donor_id),
            bank_id=str(report.bank_id),
            source=report.source,
            test_type=report.test_type,
            test_name=report.test_name,
            file_url=report.file_url,
            file_name=report.file_name,
            uploaded_by=report.uploaded_by,
            uploaded_at=report.uploaded_at,
            test_date=report.test_date,
            lab_name=report.lab_name,
            notes=report.notes,
            status=report.status or "pending",
            reviewed_at=report.reviewed_at,
            reviewed_by=report.reviewed_by,
            review_notes=report.review_notes,
            created_at=report.created_at
        )
        for report in reports
    ]
    
    # Get documents from donor_documents table and merge with legal_documents JSON
    donor_docs_from_table = db.query(DonorDocument).filter(DonorDocument.donor_id == donor_id).all()
    
    # Build combined documents list - prioritize donor_documents table as source of truth
    combined_legal_documents = []
    seen_urls = set()
    
    # First add documents from the donor_documents table
    for doc in donor_docs_from_table:
        doc_entry = {
            "url": doc.file_url,
            "name": doc.file_name,
            "type": doc.type,
            "status": doc.status,
            "uploaded_at": doc.uploaded_at.isoformat() if doc.uploaded_at else None,
            "verified_at": doc.verified_at.isoformat() if doc.verified_at else None,
            "verified_by": doc.verified_by,
            "rejection_reason": doc.rejection_reason
        }
        combined_legal_documents.append(doc_entry)
        seen_urls.add(doc.file_url)
    
    # Then add any documents from legal_documents JSON that aren't in the table
    if donor.legal_documents:
        docs_from_json = []
        if isinstance(donor.legal_documents, list):
            docs_from_json = donor.legal_documents
        elif isinstance(donor.legal_documents, dict) and "documents" in donor.legal_documents:
            docs_from_json = donor.legal_documents["documents"]
        
        for doc in docs_from_json:
            doc_url = doc.get("url", "")
            if doc_url and doc_url not in seen_urls:
                combined_legal_documents.append(doc)
                seen_urls.add(doc_url)
    
    return DonorDetailFullResponse(
        id=str(donor.id),
        email=donor.email,
        first_name=donor.first_name,
        last_name=donor.last_name,
        phone=donor.phone,
        state=donor.state,
        date_of_birth=donor.date_of_birth,
        address=donor.address,
        medical_interest_info=donor.medical_interest_info,
        legal_documents=combined_legal_documents if combined_legal_documents else None,
        bank_id=str(donor.bank_id) if donor.bank_id else None,
        bank_name=bank_name,
        selected_at=donor.selected_at,
        consent_pending=donor.consent_pending or False,
        counseling_pending=donor.counseling_pending or False,
        tests_pending=donor.tests_pending or False,
        eligibility_status=donor.eligibility_status or "pending",
        eligibility_notes=donor.eligibility_notes,
        eligibility_decided_at=donor.eligibility_decided_at,
        created_at=donor.created_at,
        updated_at=donor.updated_at,
        state_history=state_history,
        consent_documents=consent_documents,
        test_reports=test_reports
    )


# ========== Activity Logs ==========
@router.get("/activity-logs", response_model=ActivityLogListResponse)
async def list_activity_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    entity_type: Optional[str] = None,
    admin_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """List activity logs"""
    query = db.query(ActivityLog)
    
    if entity_type:
        query = query.filter(ActivityLog.entity_type == entity_type)
    if admin_id:
        query = query.filter(ActivityLog.admin_id == admin_id)
    
    total = query.count()
    offset = (page - 1) * page_size
    logs = query.order_by(ActivityLog.created_at.desc()).offset(offset).limit(page_size).all()
    
    items = []
    for log in logs:
        admin = db.query(Admin).filter(Admin.id == log.admin_id).first()
        items.append(ActivityLogResponse(
            id=str(log.id),
            admin_id=str(log.admin_id),
            admin_name=admin.name if admin else None,
            action=log.action,
            entity_type=log.entity_type,
            entity_id=log.entity_id,
            details=log.details,
            ip_address=log.ip_address,
            created_at=log.created_at
        ))
    
    return ActivityLogListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size
    )


# ========== Subscription Analytics ==========
@router.get("/subscriptions/analytics", response_model=SubscriptionAnalytics)
async def get_subscription_analytics(
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get subscription analytics"""
    now = datetime.utcnow()
    thirty_days_future = now + timedelta(days=30)
    
    active_subscriptions = db.query(func.count(Bank.id)).filter(
        and_(
            Bank.is_subscribed == True,
            or_(
                Bank.subscription_expires_at == None,
                Bank.subscription_expires_at > now
            )
        )
    ).scalar()
    
    expiring_soon = db.query(func.count(Bank.id)).filter(
        and_(
            Bank.is_subscribed == True,
            Bank.subscription_expires_at <= thirty_days_future,
            Bank.subscription_expires_at > now
        )
    ).scalar()
    
    expired = db.query(func.count(Bank.id)).filter(
        and_(
            Bank.subscription_expires_at != None,
            Bank.subscription_expires_at < now
        )
    ).scalar()
    
    never_subscribed = db.query(func.count(Bank.id)).filter(
        Bank.subscription_started_at == None
    ).scalar()
    
    tier_prices = {"Starter": 999, "Professional": 2499, "Enterprise": 4999}
    tier_counts = db.query(
        Bank.subscription_tier,
        func.count(Bank.id)
    ).filter(Bank.is_subscribed == True).group_by(Bank.subscription_tier).all()
    
    tier_breakdown = []
    total_revenue = 0
    for tier, count in tier_counts:
        price = tier_prices.get(tier, 0)
        revenue = count * price
        total_revenue += revenue
        tier_breakdown.append(SubscriptionSummary(
            tier=tier or "Unknown",
            count=count,
            revenue_estimate=revenue
        ))
    
    monthly_trend = []
    for i in range(5, -1, -1):
        month_start = (now.replace(day=1) - timedelta(days=30*i)).replace(day=1)
        month_end = (month_start + timedelta(days=32)).replace(day=1)
        
        new_subs = db.query(func.count(Bank.id)).filter(
            and_(
                Bank.subscription_started_at >= month_start,
                Bank.subscription_started_at < month_end
            )
        ).scalar()
        
        monthly_trend.append(MonthlySubscriptionTrend(
            month=month_start.strftime("%Y-%m"),
            new_subscriptions=new_subs or 0,
            renewals=0,
            churned=0
        ))
    
    return SubscriptionAnalytics(
        active_subscriptions=active_subscriptions or 0,
        expiring_soon=expiring_soon or 0,
        expired=expired or 0,
        never_subscribed=never_subscribed or 0,
        total_revenue_estimate=total_revenue,
        tier_breakdown=tier_breakdown,
        monthly_trend=monthly_trend
    )


# ========== Enhanced Bank Management ==========
@router.get("/banks/{bank_id}/full", response_model=BankDetailResponse)
async def get_bank_full_details(
    bank_id: str,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get comprehensive bank details including all related data"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    donor_count = db.query(func.count(Donor.id)).filter(Donor.bank_id == bank.id).scalar()
    consent_template_count = db.query(func.count(ConsentTemplate.id)).filter(
        ConsentTemplate.bank_id == bank.id
    ).scalar()
    
    return BankDetailResponse(
        id=str(bank.id),
        email=bank.email,
        name=bank.name,
        state=bank.state,
        phone=bank.phone,
        address=bank.address,
        website=bank.website,
        description=bank.description,
        certification_documents=bank.certification_documents,
        is_verified=bank.is_verified,
        verified_at=bank.verified_at,
        verified_by=bank.verified_by,
        is_subscribed=bank.is_subscribed,
        subscription_tier=bank.subscription_tier,
        subscription_started_at=bank.subscription_started_at,
        subscription_expires_at=bank.subscription_expires_at,
        billing_details=bank.billing_details,
        counseling_config=bank.counseling_config,
        logo_url=bank.logo_url,
        donor_count=donor_count or 0,
        consent_template_count=consent_template_count or 0,
        created_at=bank.created_at,
        updated_at=bank.updated_at
    )


@router.put("/banks/{bank_id}", response_model=BankDetailResponse)
async def update_bank(
    bank_id: str,
    bank_data: BankUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Update bank information"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    update_data = bank_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(bank, field, value)
    
    db.commit()
    db.refresh(bank)
    
    log_activity(
        db, current_admin, "bank_updated", "bank", bank.id,
        {"bank_name": bank.name, "updated_fields": list(update_data.keys())},
        request.client.host if request.client else None
    )
    
    donor_count = db.query(func.count(Donor.id)).filter(Donor.bank_id == bank.id).scalar()
    consent_template_count = db.query(func.count(ConsentTemplate.id)).filter(
        ConsentTemplate.bank_id == bank.id
    ).scalar()
    
    return BankDetailResponse(
        id=str(bank.id),
        email=bank.email,
        name=bank.name,
        state=bank.state,
        phone=bank.phone,
        address=bank.address,
        website=bank.website,
        description=bank.description,
        certification_documents=bank.certification_documents,
        is_verified=bank.is_verified,
        verified_at=bank.verified_at,
        verified_by=bank.verified_by,
        is_subscribed=bank.is_subscribed,
        subscription_tier=bank.subscription_tier,
        subscription_started_at=bank.subscription_started_at,
        subscription_expires_at=bank.subscription_expires_at,
        billing_details=bank.billing_details,
        counseling_config=bank.counseling_config,
        logo_url=bank.logo_url,
        donor_count=donor_count or 0,
        consent_template_count=consent_template_count or 0,
        created_at=bank.created_at,
        updated_at=bank.updated_at
    )


@router.put("/banks/{bank_id}/state", response_model=BankDetailResponse)
async def change_bank_state(
    bank_id: str,
    state_data: BankStateChangeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin"]))
):
    """Change bank state (super admin only)"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    old_state = bank.state
    bank.state = state_data.to_state
    
    # Record state transition in history
    state_history = BankStateHistory(
        bank_id=bank.id,
        from_state=old_state,
        to_state=state_data.to_state,
        changed_by=str(current_admin.id),
        reason=state_data.reason
    )
    db.add(state_history)
    
    db.commit()
    db.refresh(bank)
    
    log_activity(
        db, current_admin, "bank_state_changed", "bank", bank.id,
        {"bank_name": bank.name, "from_state": old_state, "to_state": state_data.to_state, "reason": state_data.reason},
        request.client.host if request.client else None
    )
    
    donor_count = db.query(func.count(Donor.id)).filter(Donor.bank_id == bank.id).scalar()
    consent_template_count = db.query(func.count(ConsentTemplate.id)).filter(
        ConsentTemplate.bank_id == bank.id
    ).scalar()
    


    # Process documents to generate signed URLs
    documents = []
    if bank.certification_documents:
        # Use existing documents structure but refresh URLs
        for doc in bank.certification_documents:
            doc_copy = doc.copy()
            # If we have a path stored or can derive it, sign the URL
            # Assuming path is stored or can be derived from filename
            # The storage structure seems to be banks/bank_{id}/{filename} based on storage_utils
            if "filename" in doc_copy:
                # Ideally we should store the path, but let's try to reconstruct if missing
                # or use the path if available in the doc object
                path = doc_copy.get("path")
                if not path:
                    # Fallback to standard path pattern
                    path = f"banks/bank_{bank.id}/{doc_copy['filename']}"
                
                try:
                    # Refresh the URL with a signed one
                    doc_copy["url"] = get_signed_url("certification-documents", path)
                except Exception:
                    # Keep original URL or leave as is if signing fails
                    pass
            documents.append(doc_copy)
            
    return BankDetailResponse(
        id=str(bank.id),
        email=bank.email,
        name=bank.name,
        state=bank.state,
        phone=bank.phone,
        address=bank.address,
        website=bank.website,
        description=bank.description,
        certification_documents=documents,
        is_verified=bank.is_verified,
        verified_at=bank.verified_at,
        verified_by=bank.verified_by,
        is_subscribed=bank.is_subscribed,
        subscription_tier=bank.subscription_tier,
        subscription_started_at=bank.subscription_started_at,
        subscription_expires_at=bank.subscription_expires_at,
        billing_details=bank.billing_details,
        counseling_config=bank.counseling_config,
        logo_url=bank.logo_url,
        donor_count=donor_count or 0,
        consent_template_count=consent_template_count or 0,
        created_at=bank.created_at,
        updated_at=bank.updated_at
    )


# ========== Enhanced Donor Management ==========
@router.get("/donors/{donor_id}/full", response_model=DonorDetailFullResponse)
async def get_donor_full_details(
    donor_id: str,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get comprehensive donor details with all relations"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    bank_name = None
    if donor.bank_id:
        bank = db.query(Bank).filter(Bank.id == donor.bank_id).first()
        bank_name = bank.name if bank else None
    
    # State history
    history = db.query(DonorStateHistory).filter(
        DonorStateHistory.donor_id == donor_id
    ).order_by(DonorStateHistory.created_at.desc()).all()
    
    state_history = [
        StateHistoryItem(
            id=str(h.id),
            from_state=h.from_state,
            to_state=h.to_state,
            changed_by=h.changed_by,
            changed_by_role=h.changed_by_role,
            reason=h.reason,
            created_at=h.created_at
        )
        for h in history
    ]
    
    # Consents
    consents = db.query(DonorConsent).filter(DonorConsent.donor_id == donor_id).all()
    consent_list = []
    for consent in consents:
        template = db.query(ConsentTemplate).filter(ConsentTemplate.id == consent.template_id).first()
        consent_list.append(DonorConsentResponse(
            id=str(consent.id),
            donor_id=str(consent.donor_id),
            template_id=str(consent.template_id),
            template_title=template.title if template else None,
            status=consent.status,
            signed_at=consent.signed_at,
            signature_data=consent.signature_data,
            verified_at=consent.verified_at,
            verified_by=consent.verified_by,
            verification_notes=consent.verification_notes,
            created_at=consent.created_at
        ))
    
    # Counseling sessions
    sessions = db.query(CounselingSession).filter(CounselingSession.donor_id == donor_id).all()
    session_list = [
        CounselingSessionResponse(
            id=str(s.id),
            donor_id=str(s.donor_id),
            bank_id=str(s.bank_id),
            donor_name=f"{donor.first_name} {donor.last_name}" if donor.first_name and donor.last_name else None,
            bank_name=bank_name,
            status=s.status,
            method=s.method,
            requested_at=s.requested_at,
            scheduled_at=s.scheduled_at,
            completed_at=s.completed_at,
            meeting_link=s.meeting_link,
            location=s.location,
            notes=s.notes,
            created_at=s.created_at
        )
        for s in sessions
    ]
    
    # Test reports - ADMIN SHOULD NOT SEE THESE
    # reports = db.query(TestReport).filter(TestReport.donor_id == donor_id).all()
    report_list = [] 
    # [
    #     TestReportResponse(
    #         id=str(r.id),
    #         donor_id=str(r.donor_id),
    #         bank_id=str(r.bank_id),
    #         donor_name=f"{donor.first_name} {donor.last_name}" if donor.first_name and donor.last_name else None,
    #         bank_name=bank_name,
    #         source=r.source,
    #         test_type=r.test_type,
    #         test_name=r.test_name,
    #         file_url=r.file_url,
    #         file_name=r.file_name,
    #         uploaded_by=r.uploaded_by,
    #         uploaded_at=r.uploaded_at,
    #         test_date=r.test_date,
    #         lab_name=r.lab_name,
    #         notes=r.notes,
    #         created_at=r.created_at
    #     )
    #     for r in reports
    # ]
    
    return DonorDetailFullResponse(
        id=str(donor.id),
        email=donor.email,
        first_name=donor.first_name,
        last_name=donor.last_name,
        phone=donor.phone,
        state=donor.state,
        date_of_birth=donor.date_of_birth,
        address=donor.address,
        medical_interest_info=donor.medical_interest_info,
        legal_documents=donor.legal_documents.get("documents", []) if isinstance(donor.legal_documents, dict) else (donor.legal_documents if isinstance(donor.legal_documents, list) else []),
        bank_id=str(donor.bank_id) if donor.bank_id else None,
        bank_name=bank_name,
        selected_at=donor.selected_at,
        consent_pending=donor.consent_pending or False,
        counseling_pending=donor.counseling_pending or False,
        tests_pending=donor.tests_pending or False,
        eligibility_status=donor.eligibility_status or "pending",
        eligibility_notes=donor.eligibility_notes,
        eligibility_decided_at=donor.eligibility_decided_at,
        created_at=donor.created_at,
        updated_at=donor.updated_at,
        state_history=state_history,
        consents=consent_list,
        counseling_sessions=session_list,
        test_reports=report_list
    )


@router.put("/donors/{donor_id}", response_model=DonorDetailFullResponse)
async def update_donor(
    donor_id: str,
    donor_data: DonorUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Update donor information"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    update_data = donor_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(donor, field, value)
    
    db.commit()
    db.refresh(donor)
    
    log_activity(
        db, current_admin, "donor_updated", "donor", donor.id,
        {"donor_name": f"{donor.first_name} {donor.last_name}", "updated_fields": list(update_data.keys())},
        request.client.host if request.client else None
    )
    
    # Return full details
    return await get_donor_full_details(donor_id, db, current_admin)


    return await get_donor_full_details(donor_id, db, current_admin)


# ========== Document Verification Endpoints ==========
@router.get("/donors/{donor_id}/documents", response_model=List[Dict[str, Any]])
async def get_donor_documents(
    donor_id: str, 
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "admin", "verification_staff"]))
):
    """Get donor legal documents with status"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
        
    if isinstance(donor.legal_documents, dict) and "documents" in donor.legal_documents:
        return donor.legal_documents["documents"]
    elif isinstance(donor.legal_documents, list):
        return donor.legal_documents
    return []


@router.post("/donors/{donor_id}/documents/verify")
async def verify_donor_document(
    donor_id: str,
    verify_data: DocumentVerifyRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "admin", "verification_staff"]))
):
    """Verify a specific donor document"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    document_found = False
    
    # Primary: Update the donor_documents table
    donor_doc = db.query(DonorDocument).filter(
        DonorDocument.donor_id == donor_id,
        or_(
            DonorDocument.file_url == verify_data.document_url,
            DonorDocument.file_name == verify_data.document_url,
            DonorDocument.file_url.contains(verify_data.document_url.split('/')[-1]) if verify_data.document_url else False
        )
    ).first()
    
    if donor_doc:
        donor_doc.status = "verified"
        donor_doc.verified_at = datetime.utcnow()
        donor_doc.verified_by = str(current_admin.id)
        document_found = True
    
    # Secondary: Also update legal_documents JSON if it exists
    docs = []
    if isinstance(donor.legal_documents, dict) and "documents" in donor.legal_documents:
        docs = donor.legal_documents["documents"]
    elif isinstance(donor.legal_documents, list):
        docs = donor.legal_documents
    
    for doc in docs:
        doc_url = doc.get("url") or ""
        doc_name = doc.get("name") or doc.get("filename") or ""
        if (doc_url == verify_data.document_url or 
            doc_name == verify_data.document_url or 
            (verify_data.document_url and verify_data.document_url.split('/')[-1] in doc_url)):
            doc["status"] = "verified"
            doc["verified_at"] = datetime.utcnow().isoformat()
            doc["verified_by"] = str(current_admin.id)
            doc["verification_notes"] = verify_data.notes
            document_found = True
            break
    
    if not document_found:
        raise HTTPException(status_code=404, detail="Document not found in donor_documents table or legal_documents JSON")
    
    # Save back legal_documents if it was modified
    if docs:
        if isinstance(donor.legal_documents, dict):
            donor.legal_documents["documents"] = docs
        else:
            donor.legal_documents = docs
        flag_modified(donor, "legal_documents")
    
    # Check if ALL documents are verified (from donor_documents table)
    all_donor_docs = db.query(DonorDocument).filter(DonorDocument.donor_id == donor_id).all()
    all_verified = len(all_donor_docs) > 0 and all(d.status == "verified" for d in all_donor_docs)
    
    # Also check legal_documents JSON if it exists
    if docs and not all_verified:
        all_verified = all(d.get("status") == "verified" for d in docs)
    
    if all_verified:
        donor.documents_uploaded = True
        
        # Transition donor state to 'legal document verification verified'
        old_state = donor.state
        if old_state in ["medical information submitted", "legal document verification pending", "legal document verification rejected"]:
            donor.state = "legal document verification verified"
            
            # Create history entry for state change
            history = DonorStateHistory(
                donor_id=donor.id,
                from_state=old_state,
                to_state="legal document verification verified",
                changed_by=current_admin.name,
                changed_by_role=current_admin.role,
                reason=f"All legal documents verified by {current_admin.name}"
            )
            db.add(history)

    db.commit()
    
    log_activity(
        db, current_admin, "document_verified", "donor_document", donor.id,
        {"document_url": verify_data.document_url},
        request.client.host if request.client else None
    )
    
    return {"message": "Document verified successfully", "all_verified": all_verified}


@router.post("/donors/{donor_id}/documents/reject")
async def reject_donor_document(
    donor_id: str,
    reject_data: DocumentRejectRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "admin", "verification_staff"]))
):
    """Reject a specific donor document"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    document_found = False
    
    # Primary: Update the donor_documents table
    donor_doc = db.query(DonorDocument).filter(
        DonorDocument.donor_id == donor_id,
        or_(
            DonorDocument.file_url == reject_data.document_url,
            DonorDocument.file_name == reject_data.document_url,
            DonorDocument.file_url.contains(reject_data.document_url.split('/')[-1]) if reject_data.document_url else False
        )
    ).first()
    
    if donor_doc:
        donor_doc.status = "rejected"
        donor_doc.rejection_reason = reject_data.reason
        donor_doc.updated_at = datetime.utcnow()
        document_found = True
    
    # Secondary: Also update legal_documents JSON if it exists
    docs = []
    if isinstance(donor.legal_documents, dict) and "documents" in donor.legal_documents:
        docs = donor.legal_documents["documents"]
    elif isinstance(donor.legal_documents, list):
        docs = donor.legal_documents
    
    for doc in docs:
        doc_url = doc.get("url") or ""
        doc_name = doc.get("name") or doc.get("filename") or ""
        if (doc_url == reject_data.document_url or 
            doc_name == reject_data.document_url or 
            (reject_data.document_url and reject_data.document_url.split('/')[-1] in doc_url)):
            doc["status"] = "rejected"
            doc["rejected_at"] = datetime.utcnow().isoformat()
            doc["rejected_by"] = str(current_admin.id)
            doc["rejection_reason"] = reject_data.reason
            document_found = True
            break
    
    if not document_found:
        raise HTTPException(status_code=404, detail="Document not found in donor_documents table or legal_documents JSON")
    
    # Reset verified flag
    donor.documents_uploaded = False
    
    # Save back legal_documents if it was modified
    if docs:
        if isinstance(donor.legal_documents, dict):
            donor.legal_documents["documents"] = docs
        else:
            donor.legal_documents = docs
        flag_modified(donor, "legal_documents")
    
    # Transition donor state to 'legal document verification rejected' if in document verification states
    old_state = donor.state
    if old_state in ["legal document verification pending", "legal document verification verified", "medical information submitted"]:
        donor.state = "legal document verification rejected"
        
        # Create history entry for state change
        history = DonorStateHistory(
            donor_id=donor.id,
            from_state=old_state,
            to_state="legal document verification rejected",
            changed_by=current_admin.name,
            changed_by_role=current_admin.role,
            reason=f"Document rejected: {reject_data.reason}"
        )
        db.add(history)
    
    db.commit()
    
    log_activity(
        db, current_admin, "document_rejected", "donor_document", donor.id,
        {"document_url": reject_data.document_url, "reason": reject_data.reason},
        request.client.host if request.client else None
    )
    
    return {"message": "Document rejected"}


@router.put("/donors/{donor_id}/eligibility", response_model=DonorDetailFullResponse)
async def update_donor_eligibility(
    donor_id: str,
    eligibility_data: DonorEligibilityUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Update donor eligibility status"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    old_status = donor.eligibility_status
    donor.eligibility_status = eligibility_data.eligibility_status
    donor.eligibility_notes = eligibility_data.eligibility_notes
    donor.eligibility_decided_at = datetime.utcnow()
    
    db.commit()
    db.refresh(donor)
    
    log_activity(
        db, current_admin, "donor_eligibility_updated", "donor", donor.id,
        {
            "donor_name": f"{donor.first_name} {donor.last_name}",
            "from_status": old_status,
            "to_status": eligibility_data.eligibility_status,
            "notes": eligibility_data.eligibility_notes
        },
        request.client.host if request.client else None
    )
    
    return await get_donor_full_details(donor_id, db, current_admin)


# ========== Subscription Management ==========
@router.get("/subscriptions", response_model=List[SubscriptionDetailResponse])
async def list_all_subscriptions(
    active_only: bool = Query(False),
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """List all subscriptions with details"""
    query = db.query(Bank)
    
    if active_only:
        now = datetime.utcnow()
        query = query.filter(
            and_(
                Bank.is_subscribed == True,
                or_(
                    Bank.subscription_expires_at == None,
                    Bank.subscription_expires_at > now
                )
            )
        )
    
    banks = query.all()
    
    result = []
    for bank in banks:
        donor_count = db.query(func.count(Donor.id)).filter(Donor.bank_id == bank.id).scalar()
        result.append(SubscriptionDetailResponse(
            bank_id=str(bank.id),
            bank_name=bank.name,
            bank_email=bank.email,
            subscription_tier=bank.subscription_tier,
            subscription_started_at=bank.subscription_started_at,
            subscription_expires_at=bank.subscription_expires_at,
            billing_details=bank.billing_details,
            is_subscribed=bank.is_subscribed,
            is_verified=bank.is_verified,
            donor_count=donor_count or 0,
            created_at=bank.created_at
        ))
    
    return result


@router.post("/subscriptions/{bank_id}", response_model=SubscriptionDetailResponse)
async def create_update_subscription(
    bank_id: str,
    subscription_data: SubscriptionCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Create or update a bank subscription"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    if not bank.is_verified:
        raise HTTPException(status_code=400, detail="Bank must be verified before subscribing")
    
    old_tier = bank.subscription_tier
    bank.is_subscribed = True
    bank.subscription_tier = subscription_data.subscription_tier
    bank.subscription_started_at = subscription_data.subscription_started_at
    bank.subscription_expires_at = subscription_data.subscription_expires_at
    
    if subscription_data.billing_details:
        bank.billing_details = subscription_data.billing_details
    
    if bank.state in ["verified", "subscription_pending"]:
        bank.state = "subscribed_onboarded"
    
    db.commit()
    db.refresh(bank)
    
    log_activity(
        db, current_admin, "subscription_created_updated", "bank", bank.id,
        {
            "bank_name": bank.name,
            "old_tier": old_tier,
            "new_tier": subscription_data.subscription_tier,
            "started_at": subscription_data.subscription_started_at.isoformat(),
            "expires_at": subscription_data.subscription_expires_at.isoformat()
        },
        request.client.host if request.client else None
    )
    
    donor_count = db.query(func.count(Donor.id)).filter(Donor.bank_id == bank.id).scalar()
    
    return SubscriptionDetailResponse(
        bank_id=str(bank.id),
        bank_name=bank.name,
        bank_email=bank.email,
        subscription_tier=bank.subscription_tier,
        subscription_started_at=bank.subscription_started_at,
        subscription_expires_at=bank.subscription_expires_at,
        billing_details=bank.billing_details,
        is_subscribed=bank.is_subscribed,
        is_verified=bank.is_verified,
        donor_count=donor_count or 0,
        created_at=bank.created_at
    )


@router.delete("/subscriptions/{bank_id}")
async def cancel_subscription(
    bank_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin"]))
):
    """Cancel a bank subscription"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    if not bank.is_subscribed:
        raise HTTPException(status_code=400, detail="Bank does not have an active subscription")
    
    bank.is_subscribed = False
    bank.subscription_expires_at = datetime.utcnow()
    
    db.commit()
    
    log_activity(
        db, current_admin, "subscription_cancelled", "bank", bank.id,
        {"bank_name": bank.name, "cancelled_at": datetime.utcnow().isoformat()},
        request.client.host if request.client else None
    )
    
    return {"message": "Subscription cancelled successfully", "bank_id": str(bank.id)}


# ========== Subscription Plan Management ==========
@router.get("/subscription-plans", response_model=List[SubscriptionPlanResponse])
async def list_subscription_plans(
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """List all subscription plans with active subscription counts"""
    plans = db.query(SubscriptionPlan).filter(SubscriptionPlan.is_active == True).all()
    
    result = []
    for plan in plans:
        # Count banks using this plan
        active_count = db.query(func.count(Bank.id)).filter(
            and_(
                Bank.subscription_tier == plan.id,
                Bank.is_subscribed == True
            )
        ).scalar()
        
        # Parse features from JSON
        features = plan.features if plan.features else []
        
        result.append(SubscriptionPlanResponse(
            id=plan.id,
            name=plan.name,
            price=plan.price,
            max_donors=plan.max_donors,
            description=plan.description,
            features=features,
            is_active=plan.is_active,
            active_subscriptions=active_count or 0,
            created_at=plan.created_at,
            updated_at=plan.updated_at
        ))
    
    return result


@router.post("/subscription-plans", response_model=SubscriptionPlanResponse)
async def create_subscription_plan(
    plan_data: SubscriptionPlanCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin"]))
):
    """Create a new subscription plan"""
    # Check if plan ID already exists
    existing = db.query(SubscriptionPlan).filter(SubscriptionPlan.id == plan_data.id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Plan with this ID already exists")
    
    plan = SubscriptionPlan(
        id=plan_data.id,
        name=plan_data.name,
        price=str(plan_data.price),
        max_donors=str(plan_data.max_donors) if plan_data.max_donors is not None else "null",
        description=plan_data.description,
        features=plan_data.features or [],
        is_active=True
    )
    
    db.add(plan)
    db.commit()
    db.refresh(plan)
    
    log_activity(
        db, current_admin, "subscription_plan_created", "subscription_plan", plan.id,
        {"plan_name": plan.name, "price": plan.price},
        request.client.host if request.client else None
    )
    
    return SubscriptionPlanResponse(
        id=plan.id,
        name=plan.name,
        price=plan.price,
        max_donors=plan.max_donors,
        description=plan.description,
        features=plan.features or [],
        is_active=plan.is_active,
        active_subscriptions=0,
        created_at=plan.created_at,
        updated_at=plan.updated_at
    )


@router.put("/subscription-plans/{plan_id}", response_model=SubscriptionPlanResponse)
async def update_subscription_plan(
    plan_id: str,
    plan_data: SubscriptionPlanUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin"]))
):
    """Update a subscription plan - changes will apply to all banks using this plan"""
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    
    # Update fields
    if plan_data.name is not None:
        plan.name = plan_data.name
    if plan_data.price is not None:
        plan.price = str(plan_data.price)
    if plan_data.max_donors is not None:
        plan.max_donors = str(plan_data.max_donors) if plan_data.max_donors else "null"
    if plan_data.description is not None:
        plan.description = plan_data.description
    if plan_data.features is not None:
        plan.features = plan_data.features
    
    db.commit()
    db.refresh(plan)
    
    # Count active subscriptions
    active_count = db.query(func.count(Bank.id)).filter(
        and_(
            Bank.subscription_tier == plan.id,
            Bank.is_subscribed == True
        )
    ).scalar()
    
    log_activity(
        db, current_admin, "subscription_plan_updated", "subscription_plan", plan.id,
        {"plan_name": plan.name, "price": plan.price, "affected_banks": active_count or 0},
        request.client.host if request.client else None
    )
    
    return SubscriptionPlanResponse(
        id=plan.id,
        name=plan.name,
        price=plan.price,
        max_donors=plan.max_donors,
        description=plan.description,
        features=plan.features or [],
        is_active=plan.is_active,
        active_subscriptions=active_count or 0,
        created_at=plan.created_at,
        updated_at=plan.updated_at
    )


@router.delete("/subscription-plans/{plan_id}")
async def delete_subscription_plan(
    plan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin"]))
):
    """Delete (deactivate) a subscription plan"""
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    
    # Check if any banks are using this plan
    active_count = db.query(func.count(Bank.id)).filter(
        and_(
            Bank.subscription_tier == plan.id,
            Bank.is_subscribed == True
        )
    ).scalar()
    
    if active_count and active_count > 0:
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot delete plan with {active_count} active subscriptions. Please migrate banks to another plan first."
        )
    
    # Soft delete by marking as inactive
    plan.is_active = False
    db.commit()
    
    log_activity(
        db, current_admin, "subscription_plan_deleted", "subscription_plan", plan.id,
        {"plan_name": plan.name},
        request.client.host if request.client else None
    )
    
    return {"message": "Subscription plan deleted successfully", "plan_id": plan_id}


# ========== Document Verification ==========
@router.put("/banks/{bank_id}/documents/{document_index}/verify")
async def verify_bank_document(
    bank_id: str,
    document_index: int,
    verify_data: DocumentVerifyRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Verify a specific bank document"""
    from models import BankState
    
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    if not bank.certification_documents or document_index >= len(bank.certification_documents):
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Update document status
    docs = bank.certification_documents.copy()
    docs[document_index]["status"] = "verified"
    docs[document_index]["verified_at"] = datetime.utcnow().isoformat()
    docs[document_index]["verified_by"] = current_admin.name
    if verify_data.notes:
        docs[document_index]["verification_notes"] = verify_data.notes
    
    bank.certification_documents = docs
    flag_modified(bank, "certification_documents")  # Ensure SQLAlchemy detects JSON change
    
    # Check if all documents are verified
    all_verified = all(doc.get("status") == "verified" for doc in docs)
    
    # Transition state if all documents verified and bank is in verification_pending
    if all_verified and bank.state == "verification_pending":
        old_state = bank.state
        bank.is_verified = True
        bank.verified_at = datetime.utcnow()
        bank.verified_by = current_admin.name
        bank.state = "verified"
        
        # Create history record
        history = BankStateHistory(
            bank_id=bank.id,
            from_state=old_state,
            to_state="verified",
            changed_by=current_admin.name,
            reason=f"All certification documents verified by {current_admin.name}"
        )
        db.add(history)
    
    db.commit()
    
    log_activity(
        db, current_admin, "bank_document_verified", "bank", bank.id,
        {"bank_name": bank.name, "document_index": document_index, "notes": verify_data.notes, "all_verified": all_verified},
        request.client.host if request.client else None
    )
    
    return {"message": "Document verified successfully", "document": docs[document_index], "all_verified": all_verified, "state_transitioned": all_verified and bank.state == "verified"}


@router.put("/banks/{bank_id}/documents/{document_index}/reject")
async def reject_bank_document(
    bank_id: str,
    document_index: int,
    reject_data: DocumentRejectRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Reject a specific bank document - bank must re-upload"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    if not bank.certification_documents or document_index >= len(bank.certification_documents):
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Update document status
    docs = bank.certification_documents.copy()
    docs[document_index]["status"] = "rejected"
    docs[document_index]["reviewed_at"] = datetime.utcnow().isoformat()
    docs[document_index]["reviewed_by"] = current_admin.name
    docs[document_index]["rejection_reason"] = reject_data.reason
    
    bank.certification_documents = docs
    flag_modified(bank, "certification_documents")  # Ensure SQLAlchemy detects JSON change
    
    # Mark bank verification as incomplete
    bank.is_verified = False
    bank.verified_at = None
    
    db.commit()
    
    log_activity(
        db, current_admin, "bank_document_rejected", "bank", bank.id,
        {"bank_name": bank.name, "document_index": document_index, "reason": reject_data.reason},
        request.client.host if request.client else None
    )
    
    return {"message": "Document rejected - bank must re-upload", "document": docs[document_index]}


@router.put("/donors/{donor_id}/documents/{document_index}/verify")
async def verify_donor_document(
    donor_id: str,
    document_index: int,
    verify_data: DocumentVerifyRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Verify a specific donor legal document"""
    from models import DonorState
    
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    if not donor.legal_documents or document_index >= len(donor.legal_documents):
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Update document status
    docs = donor.legal_documents.copy()
    docs[document_index]["status"] = "verified"
    docs[document_index]["verified_at"] = datetime.utcnow().isoformat()
    docs[document_index]["verified_by"] = current_admin.name
    if verify_data.notes:
        docs[document_index]["verification_notes"] = verify_data.notes
    
    donor.legal_documents = docs
    flag_modified(donor, "legal_documents")  # Ensure SQLAlchemy detects JSON change
    
    # Also update the donor_documents table if corresponding record exists
    doc_url = docs[document_index].get("url")
    doc_name = docs[document_index].get("name") or docs[document_index].get("filename")
    
    if doc_url or doc_name:
        query_conditions = [DonorDocument.donor_id == donor_id]
        if doc_url and doc_name:
            query_conditions.append(or_(DonorDocument.file_url == doc_url, DonorDocument.file_name == doc_name))
        elif doc_url:
            query_conditions.append(DonorDocument.file_url == doc_url)
        elif doc_name:
            query_conditions.append(DonorDocument.file_name == doc_name)
        
        donor_doc = db.query(DonorDocument).filter(and_(*query_conditions)).first()
        
        if donor_doc:
            donor_doc.status = "verified"
            donor_doc.verified_at = datetime.utcnow()
            donor_doc.verified_by = current_admin.name
    
    # Check if all legal documents are verified
    all_verified = all(doc.get("status") == "verified" for doc in docs)
    
    if all_verified:
        # Set documents_uploaded flag when all documents are verified
        donor.documents_uploaded = True
        
        # Transition donor state to 'legal document verification verified'
        old_state = donor.state
        if old_state in ["medical information submitted", "legal document verification pending", "legal document verification rejected"]:
            donor.state = "legal document verification verified"
            
            # Create history entry for state change
            history = DonorStateHistory(
                donor_id=donor.id,
                from_state=old_state,
                to_state="legal document verification verified",
                changed_by=current_admin.name,
                changed_by_role=current_admin.role,
                reason=f"All legal documents verified by {current_admin.name}"
            )
            db.add(history)
    
    db.commit()
    
    log_activity(
        db, current_admin, "donor_document_verified", "donor", donor.id,
        {"donor_name": f"{donor.first_name} {donor.last_name}", "document_index": document_index, "all_verified": all_verified},
        request.client.host if request.client else None
    )
    
    return {"message": "Document verified successfully - donor can now proceed in onboarding", "document": docs[document_index], "all_verified": all_verified}


@router.put("/donors/{donor_id}/documents/{document_index}/reject")
async def reject_donor_document(
    donor_id: str,
    document_index: int,
    reject_data: DocumentRejectRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Reject a specific donor document - donor must re-upload"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    if not donor.legal_documents or document_index >= len(donor.legal_documents):
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Update document status
    docs = donor.legal_documents.copy()
    docs[document_index]["status"] = "rejected"
    docs[document_index]["reviewed_at"] = datetime.utcnow().isoformat()
    docs[document_index]["reviewed_by"] = current_admin.name
    docs[document_index]["rejection_reason"] = reject_data.reason
    
    donor.legal_documents = docs
    flag_modified(donor, "legal_documents")  # Ensure SQLAlchemy detects JSON change
    
    # Reset documents_uploaded flag since a document was rejected
    donor.documents_uploaded = False
    
    # Also update the donor_documents table if corresponding record exists
    doc_url = docs[document_index].get("url")
    doc_name = docs[document_index].get("name") or docs[document_index].get("filename")
    
    if doc_url or doc_name:
        query_conditions = [DonorDocument.donor_id == donor_id]
        if doc_url and doc_name:
            query_conditions.append(or_(DonorDocument.file_url == doc_url, DonorDocument.file_name == doc_name))
        elif doc_url:
            query_conditions.append(DonorDocument.file_url == doc_url)
        elif doc_name:
            query_conditions.append(DonorDocument.file_name == doc_name)
        
        donor_doc = db.query(DonorDocument).filter(and_(*query_conditions)).first()
        
        if donor_doc:
            donor_doc.status = "rejected"
            donor_doc.rejection_reason = reject_data.reason
            donor_doc.updated_at = datetime.utcnow()
    
    # Transition donor state to 'legal document verification rejected' if in document verification states
    old_state = donor.state
    if old_state in ["legal document verification pending", "legal document verification verified"]:
        donor.state = "legal document verification rejected"
        
        # Create history entry for state change
        history = DonorStateHistory(
            donor_id=donor.id,
            from_state=old_state,
            to_state="legal document verification rejected",
            changed_by=current_admin.name,
            changed_by_role=current_admin.role,
            reason=f"Document rejected: {reject_data.reason}"
        )
        db.add(history)
    
    db.commit()
    
    log_activity(
        db, current_admin, "donor_document_rejected", "donor", donor.id,
        {"donor_name": f"{donor.first_name} {donor.last_name}", "document_index": document_index, "reason": reject_data.reason},
        request.client.host if request.client else None
    )
    
    return {"message": "Document rejected - donor must re-upload", "document": docs[document_index]}


# ========== Donor Consent & Test Approval ==========
@router.put("/donors/{donor_id}/consent/approve")
async def approve_donor_consent(
    donor_id: str,
    approve_data: ConsentApproveRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Approve all donor consent documents"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    # Update consent status in all DonorConsent records
    consents = db.query(DonorConsent).filter(DonorConsent.donor_id == donor_id).all()
    for consent in consents:
        consent.status = "verified"
        consent.verified_at = datetime.utcnow()
        consent.verified_by = current_admin.id
        if approve_data.notes:
            consent.verification_notes = approve_data.notes
    
    donor.consent_pending = False
    donor.consent_verified = True
    
    # State transition: consent forms uploaded -> consent forms verified
    if donor.state in ['consent forms uploaded', 'consent forms rejected']:
        old_state = donor.state
        donor.state = 'consent forms verified'
        donor.updated_at = datetime.utcnow()
        
        # Log state history
        state_history = DonorStateHistory(
            donor_id=donor.id,
            from_state=old_state,
            to_state='consent forms verified',
            changed_by=str(current_admin.id),
            changed_by_role='admin',
            reason=f"Consent forms verified by admin: {approve_data.notes or 'No notes'}"
        )
        db.add(state_history)
    
    db.commit()
    
    log_activity(
        db, current_admin, "donor_consent_approved", "donor", donor.id,
        {"donor_name": f"{donor.first_name} {donor.last_name}", "notes": approve_data.notes},
        request.client.host if request.client else None
    )
    
    return {"message": "Consent approved successfully"}


@router.put("/donors/{donor_id}/consent/reject")
async def reject_donor_consent(
    donor_id: str,
    reject_data: ConsentRejectRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Reject donor consent documents"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    # Update consent status
    consents = db.query(DonorConsent).filter(DonorConsent.donor_id == donor_id).all()
    for consent in consents:
        consent.status = "rejected"
        consent.verified_at = datetime.utcnow()
        consent.verified_by = current_admin.id
        consent.verification_notes = reject_data.reason
    
    donor.consent_pending = True
    donor.consent_verified = False
    
    # State transition: consent forms uploaded -> consent forms rejected
    if donor.state in ['consent forms uploaded', 'consent forms verified']:
        old_state = donor.state
        donor.state = 'consent forms rejected'
        donor.updated_at = datetime.utcnow()
        
        # Log state history
        state_history = DonorStateHistory(
            donor_id=donor.id,
            from_state=old_state,
            to_state='consent forms rejected',
            changed_by=str(current_admin.id),
            changed_by_role='admin',
            reason=f"Consent forms rejected: {reject_data.reason}"
        )
        db.add(state_history)
    
    db.commit()
    
    log_activity(
        db, current_admin, "donor_consent_rejected", "donor", donor.id,
        {"donor_name": f"{donor.first_name} {donor.last_name}", "reason": reject_data.reason},
        request.client.host if request.client else None
    )
    
    return {"message": "Consent rejected successfully"}


@router.put("/donors/{donor_id}/tests/approve")
async def approve_donor_tests(
    donor_id: str,
    approve_data: ConsentApproveRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Approve donor test results"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    donor.tests_pending = False
    db.commit()
    
    log_activity(
        db, current_admin, "donor_tests_approved", "donor", donor.id,
        {"donor_name": f"{donor.first_name} {donor.last_name}", "notes": approve_data.notes},
        request.client.host if request.client else None
    )
    
    return {"message": "Test results approved successfully"}


@router.put("/donors/{donor_id}/tests/reject")
async def reject_donor_tests(
    donor_id: str,
    reject_data: ConsentRejectRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Reject donor test results"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    # Keep tests_pending true so they can resubmit
    log_activity(
        db, current_admin, "donor_tests_rejected", "donor", donor.id,
        {"donor_name": f"{donor.first_name} {donor.last_name}", "reason": reject_data.reason},
        request.client.host if request.client else None
    )
    
    return {"message": "Test results rejected successfully"}


# ========== Individual Test Report Approval/Rejection ==========
@router.put("/donors/{donor_id}/tests/{report_id}/approve")
async def approve_individual_test_report(
    donor_id: str,
    report_id: str,
    approve_data: TestReportApproveRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Approve an individual test report"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    report = db.query(TestReport).filter(
        TestReport.id == report_id,
        TestReport.donor_id == donor_id
    ).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Test report not found")
    
    # Update report status
    report.status = "approved"
    report.reviewed_at = datetime.utcnow()
    report.reviewed_by = current_admin.name
    if approve_data.notes:
        report.review_notes = approve_data.notes
    
    # Check if all test reports are approved
    all_reports = db.query(TestReport).filter(TestReport.donor_id == donor_id).all()
    all_approved = all(r.status == "approved" for r in all_reports)
    
    if all_approved:
        donor.tests_pending = False
    
    db.commit()
    
    log_activity(
        db, current_admin, "test_report_approved", "test_report", report_id,
        {
            "donor_id": str(donor_id),
            "donor_name": f"{donor.first_name} {donor.last_name}",
            "test_type": report.test_type,
            "notes": approve_data.notes,
            "all_approved": all_approved
        },
        request.client.host if request.client else None
    )
    
    return {
        "message": "Test report approved successfully",
        "all_approved": all_approved,
        "report_id": str(report_id)
    }


@router.put("/donors/{donor_id}/tests/{report_id}/reject")
async def reject_individual_test_report(
    donor_id: str,
    report_id: str,
    reject_data: TestReportRejectRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Reject an individual test report"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    report = db.query(TestReport).filter(
        TestReport.id == report_id,
        TestReport.donor_id == donor_id
    ).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Test report not found")
    
    # Update report status
    report.status = "rejected"
    report.reviewed_at = datetime.utcnow()
    report.reviewed_by = current_admin.name
    report.review_notes = reject_data.reason
    
    db.commit()
    
    log_activity(
        db, current_admin, "test_report_rejected", "test_report", report_id,
        {
            "donor_id": str(donor_id),
            "donor_name": f"{donor.first_name} {donor.last_name}",
            "test_type": report.test_type,
            "reason": reject_data.reason
        },
        request.client.host if request.client else None
    )
    
    return {
        "message": "Test report rejected successfully - donor may need to resubmit",
        "report_id": str(report_id)
    }


# ========== Donor CRUD Operations ==========
@router.post("/donors", status_code=status.HTTP_201_CREATED)
async def create_donor(
    donor_data: DonorUpdateRequest,
    bank_id: Optional[str] = None,
    request: Request = None,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Create a new donor from admin portal"""
    from auth import hash_password
    import uuid
    
    # Check if email already exists
    if donor_data.email:
        existing = db.query(Donor).filter(Donor.email == donor_data.email).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already exists")
    
    # Verify bank if provided
    if bank_id:
        bank = db.query(Bank).filter(Bank.id == bank_id).first()
        if not bank:
            raise HTTPException(status_code=404, detail="Bank not found")
    
    # Create donor with temporary password
    temp_password = f"temp_{uuid.uuid4().hex[:8]}"
    
    new_donor = Donor(
        email=donor_data.email,
        hashed_password=hash_password(temp_password) if donor_data.email else None,
        first_name=donor_data.first_name,
        last_name=donor_data.last_name,
        phone=donor_data.phone,
        address=donor_data.address,
        date_of_birth=donor_data.date_of_birth,
        bank_id=bank_id,
        state="visitor",
        eligibility_status="pending"
    )
    
    db.add(new_donor)
    db.commit()
    db.refresh(new_donor)
    
    log_activity(
        db, current_admin, "donor_created", "donor", new_donor.id,
        {"donor_name": f"{donor_data.first_name} {donor_data.last_name}", "email": donor_data.email},
        request.client.host if request.client else None
    )
    
    return {
        "message": "Donor created successfully",
        "donor_id": str(new_donor.id),
        "temp_password": temp_password if donor_data.email else None
    }


@router.put("/donors/{donor_id}/update")
async def update_donor_info(
    donor_id: str,
    donor_data: DonorUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin", "support"]))
):
    """Update donor information"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    update_data = donor_data.model_dump(exclude_unset=True)
    
    # Check email uniqueness if updating email
    if 'email' in update_data and update_data['email'] != donor.email:
        existing = db.query(Donor).filter(Donor.email == update_data['email']).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already exists")
    
    for field, value in update_data.items():
        setattr(donor, field, value)
    
    db.commit()
    db.refresh(donor)
    
    log_activity(
        db, current_admin, "donor_updated", "donor", donor.id,
        {"donor_name": f"{donor.first_name} {donor.last_name}", "updated_fields": list(update_data.keys())},
        request.client.host if request.client else None
    )
    
    return {"message": "Donor updated successfully", "donor_id": str(donor.id)}


@router.delete("/donors/{donor_id}")
async def delete_donor(
    donor_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin"]))
):
    """Delete a donor (super admin only)"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    donor_name = f"{donor.first_name} {donor.last_name}"
    
    # Delete related records first
    db.query(DonorConsent).filter(DonorConsent.donor_id == donor_id).delete()
    db.query(CounselingSession).filter(CounselingSession.donor_id == donor_id).delete()
    db.query(TestReport).filter(TestReport.donor_id == donor_id).delete()
    db.query(TestSchedulingRequest).filter(TestSchedulingRequest.donor_id == donor_id).delete()
    
    db.delete(donor)
    db.commit()
    
    log_activity(
        db, current_admin, "donor_deleted", "donor", donor_id,
        {"donor_name": donor_name},
        request.client.host if request.client else None
    )
    
    return {"message": "Donor deleted successfully", "donor_id": donor_id}


# ========== Bank CRUD Operations ==========
@router.delete("/banks/{bank_id}")
async def delete_bank(
    bank_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(require_role(["super_admin"]))
):
    """Delete a bank (super admin only)"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    bank_name = bank.name
    
    # Check if bank has associated donors
    donor_count = db.query(func.count(Donor.id)).filter(Donor.bank_id == bank_id).scalar()
    if donor_count > 0:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete bank with {donor_count} associated donors. Please reassign or delete donors first."
        )
    
    # Delete related records
    db.query(ConsentTemplate).filter(ConsentTemplate.bank_id == bank_id).delete()
    db.query(CounselingSession).filter(CounselingSession.bank_id == bank_id).delete()
    db.query(TestReport).filter(TestReport.bank_id == bank_id).delete()
    db.query(TestSchedulingRequest).filter(TestSchedulingRequest.bank_id == bank_id).delete()
    
    db.delete(bank)
    db.commit()
    
    log_activity(
        db, current_admin, "bank_deleted", "bank", bank_id,
        {"bank_name": bank_name},
        request.client.host if request.client else None
    )
    
    return {"message": "Bank deleted successfully", "bank_id": bank_id}


# ========== Document Management ==========
@router.get("/documents/pending")
async def get_pending_documents(
    doc_type: Optional[str] = Query(None, description="Filter by document type: certification, consent, test_report"),
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get all pending documents for verification"""
    pending_docs = []
    
    # Bank certifications
    if not doc_type or doc_type == "certification":
        banks_with_pending = db.query(Bank).filter(
            Bank.certification_documents != None
        ).all()
        
        for bank in banks_with_pending:
            if bank.certification_documents:
                for idx, doc in enumerate(bank.certification_documents):
                    if doc.get("status") == "pending":
                        pending_docs.append({
                            "type": "certification",
                            "entity_type": "bank",
                            "entity_id": str(bank.id),
                            "entity_name": bank.name,
                            "document_index": idx,
                            "document": doc,
                            "uploaded_at": doc.get("uploaded_at")
                        })
    
    # Donor consents
    if not doc_type or doc_type == "consent":
        pending_consents = db.query(DonorConsent).filter(
            DonorConsent.status == "pending"
        ).all()
        
        for consent in pending_consents:
            donor = db.query(Donor).filter(Donor.id == consent.donor_id).first()
            pending_docs.append({
                "type": "consent",
                "entity_type": "donor",
                "entity_id": str(consent.donor_id),
                "entity_name": f"{donor.first_name} {donor.last_name}" if donor else "Unknown",
                "consent_id": str(consent.id),
                "signed_at": consent.signed_at,
                "template_id": str(consent.template_id)
            })
    
    # Test reports (if they have pending status)
    if not doc_type or doc_type == "test_report":
        # Get all test reports with pending status
        pending_reports = db.query(TestReport).filter(
            or_(TestReport.status == "pending", TestReport.status == None)
        ).all()
        
        for report in pending_reports:
            donor = db.query(Donor).filter(Donor.id == report.donor_id).first()
            if donor:
                pending_docs.append({
                    "type": "test_report",
                    "entity_type": "donor",
                    "entity_id": str(donor.id),
                    "entity_name": f"{donor.first_name} {donor.last_name}",
                    "report_id": str(report.id),
                    "uploaded_at": report.uploaded_at,
                    "test_type": report.test_type,
                    "test_name": report.test_name,
                    "file_url": report.file_url,
                    "status": report.status or "pending"
                })
    
    return {
        "pending_documents": pending_docs,
        "total": len(pending_docs)
    }


# ========== Storage Document Retrieval ==========
@router.get("/banks/{bank_id}/storage-documents")
async def get_bank_storage_documents(
    bank_id: str,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get all certification documents from storage for a bank"""
    bank = db.query(Bank).filter(Bank.id == bank_id).first()
    if not bank:
        raise HTTPException(status_code=404, detail="Bank not found")
    
    documents = get_bank_certification_documents(bank_id)
    
    # Merge with database metadata if exists
    if bank.certification_documents and isinstance(bank.certification_documents, list):
        db_docs = {doc.get('filename'): doc for doc in bank.certification_documents}
        
        for doc in documents:
            filename = doc['filename']
            if filename in db_docs:
                doc['status'] = db_docs[filename].get('status', 'pending')
                doc['verified_at'] = db_docs[filename].get('verified_at')
                doc['verified_by'] = db_docs[filename].get('verified_by')
                doc['verification_notes'] = db_docs[filename].get('verification_notes')
                doc['rejection_reason'] = db_docs[filename].get('rejection_reason')
            else:
                doc['status'] = 'pending'
    
    return {
        "bank_id": str(bank_id),
        "bank_name": bank.name,
        "documents": documents,
        "total": len(documents)
    }


@router.get("/donors/{donor_id}/storage-documents")
async def get_donor_storage_documents(
    donor_id: str,
    db: Session = Depends(get_db),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get all documents from storage for a donor"""
    donor = db.query(Donor).filter(Donor.id == donor_id).first()
    if not donor:
        raise HTTPException(status_code=404, detail="Donor not found")
    
    bank_id = donor.bank_id if donor.bank_id else "unknown"
    all_docs = get_all_donor_documents(bank_id, donor_id)
    
    # Merge legal documents with database metadata
    if donor.legal_documents and isinstance(donor.legal_documents, list):
        db_docs = {doc.get('filename'): doc for doc in donor.legal_documents}
        
        for doc in all_docs['legal_documents']:
            filename = doc['filename']
            if filename in db_docs:
                doc['status'] = db_docs[filename].get('status', 'pending')
                doc['verified_at'] = db_docs[filename].get('verified_at')
                doc['verified_by'] = db_docs[filename].get('verified_by')
                doc['verification_notes'] = db_docs[filename].get('verification_notes')
                doc['rejection_reason'] = db_docs[filename].get('rejection_reason')
            else:
                doc['status'] = 'pending'
    
    return {
        "donor_id": str(donor_id),
        "donor_name": f"{donor.first_name} {donor.last_name}" if donor.first_name else "Unknown",
        "bank_id": str(bank_id),
        "documents": all_docs,
        "total": sum(len(docs) for docs in all_docs.values())
    }


@router.get("/documents/signed-url")
async def get_document_signed_url(
    bucket: str = Query(..., description="Storage bucket name"),
    path: str = Query(..., description="File path within bucket"),
    current_admin: Admin = Depends(get_current_admin)
):
    """Get a signed URL for a document in Supabase Storage"""
    try:
        signed_url = get_signed_url(bucket, path)
        return {"url": signed_url, "bucket": bucket, "path": path}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
