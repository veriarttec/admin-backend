"""
Supabase Storage utilities for Admin Portal
"""
from supabase import create_client, Client
from config import settings
from typing import List, Dict, Optional
from fastapi import HTTPException

# Lazy initialization of Supabase client
_supabase_client: Optional[Client] = None


def get_supabase_client() -> Client:
    """Get or create Supabase client instance"""
    global _supabase_client
    if _supabase_client is None:
        _supabase_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)
    return _supabase_client


def get_signed_url(bucket: str, file_path: str, expires_in: int = 3600) -> str:
    """
    Get a signed URL for a file in Supabase Storage
    
    Args:
        bucket: Bucket name
        file_path: Path to file within bucket
        expires_in: URL expiration time in seconds (default 1 hour)
    
    Returns:
        Signed URL
    """
    supabase = get_supabase_client()
    try:
        response = supabase.storage.from_(bucket).create_signed_url(file_path, expires_in)
        if response and 'signedURL' in response:
            return response['signedURL']
        # Fallback to public URL
        return supabase.storage.from_(bucket).get_public_url(file_path)
    except Exception as e:
        # If signed URL fails, try public URL
        try:
            return supabase.storage.from_(bucket).get_public_url(file_path)
        except:
            raise HTTPException(status_code=404, detail=f"File not found: {str(e)}")


def list_files_in_folder(bucket: str, folder_path: str) -> List[Dict]:
    """
    List all files in a folder within a bucket
    
    Args:
        bucket: Bucket name
        folder_path: Folder path within bucket
    
    Returns:
        List of file objects with metadata
    """
    supabase = get_supabase_client()
    try:
        response = supabase.storage.from_(bucket).list(folder_path)
        return response if response else []
    except Exception as e:
        return []


def get_bank_certification_documents(bank_id: str) -> List[Dict]:
    """
    Get all certification documents for a bank
    
    Args:
        bank_id: Bank ID
    
    Returns:
        List of documents with signed URLs
    """
    supabase = get_supabase_client()
    folder_path = f"banks/bank_{bank_id}"
    files = list_files_in_folder("certification-documents", folder_path)
    
    documents = []
    for file in files:
        if file.get('name') and not file.get('name').startswith('.'):
            file_path = f"{folder_path}/{file['name']}"
            try:
                signed_url = get_signed_url("certification-documents", file_path)
                documents.append({
                    "filename": file['name'],
                    "url": signed_url,
                    "size": file.get('metadata', {}).get('size'),
                    "uploaded_at": file.get('created_at') or file.get('updated_at'),
                    "path": file_path
                })
            except:
                pass
    
    return documents


def get_donor_legal_documents(donor_id: str) -> List[Dict]:
    """
    Get all legal documents for a donor
    
    Args:
        donor_id: Donor ID
    
    Returns:
        List of documents with signed URLs
    """
    supabase = get_supabase_client()
    folder_path = f"donors/donor_{donor_id}"
    files = list_files_in_folder("certification-documents", folder_path)
    
    documents = []
    for file in files:
        if file.get('name') and not file.get('name').startswith('.'):
            file_path = f"{folder_path}/{file['name']}"
            try:
                signed_url = get_signed_url("certification-documents", file_path)
                documents.append({
                    "filename": file['name'],
                    "url": signed_url,
                    "size": file.get('metadata', {}).get('size'),
                    "uploaded_at": file.get('created_at') or file.get('updated_at'),
                    "path": file_path
                })
            except:
                pass
    
    return documents


def get_donor_consent_forms(bank_id: str, donor_id: str) -> List[Dict]:
    """
    Get all consent forms for a donor
    
    Args:
        bank_id: Bank ID
        donor_id: Donor ID
    
    Returns:
        List of consent forms with signed URLs
    """
    supabase = get_supabase_client()
    folder_path = f"bank_{bank_id}/donor_{donor_id}"
    files = list_files_in_folder("consent-forms", folder_path)
    
    documents = []
    for file in files:
        if file.get('name') and not file.get('name').startswith('.'):
            file_path = f"{folder_path}/{file['name']}"
            try:
                signed_url = get_signed_url("consent-forms", file_path)
                documents.append({
                    "filename": file['name'],
                    "url": signed_url,
                    "size": file.get('metadata', {}).get('size'),
                    "uploaded_at": file.get('created_at') or file.get('updated_at'),
                    "path": file_path
                })
            except:
                pass
    
    return documents


def get_donor_test_reports(bank_id: str, donor_id: str) -> List[Dict]:
    """
    Get all test reports for a donor
    
    Args:
        bank_id: Bank ID
        donor_id: Donor ID
    
    Returns:
        List of test reports with signed URLs
    """
    supabase = get_supabase_client()
    folder_path = f"bank_{bank_id}/donor_{donor_id}"
    files = list_files_in_folder("test-reports", folder_path)
    
    documents = []
    for file in files:
        if file.get('name') and not file.get('name').startswith('.'):
            file_path = f"{folder_path}/{file['name']}"
            try:
                signed_url = get_signed_url("test-reports", file_path)
                documents.append({
                    "filename": file['name'],
                    "url": signed_url,
                    "size": file.get('metadata', {}).get('size'),
                    "uploaded_at": file.get('created_at') or file.get('updated_at'),
                    "path": file_path
                })
            except:
                pass
    
    return documents


def get_donor_counseling_reports(bank_id: str, donor_id: str) -> List[Dict]:
    """
    Get all counseling reports for a donor
    
    Args:
        bank_id: Bank ID
        donor_id: Donor ID
    
    Returns:
        List of counseling reports with signed URLs
    """
    supabase = get_supabase_client()
    folder_path = f"bank_{bank_id}/donor_{donor_id}"
    files = list_files_in_folder("counseling-reports", folder_path)
    
    documents = []
    for file in files:
        if file.get('name') and not file.get('name').startswith('.'):
            file_path = f"{folder_path}/{file['name']}"
            try:
                signed_url = get_signed_url("counseling-reports", file_path)
                documents.append({
                    "filename": file['name'],
                    "url": signed_url,
                    "size": file.get('metadata', {}).get('size'),
                    "uploaded_at": file.get('created_at') or file.get('updated_at'),
                    "path": file_path
                })
            except:
                pass
    
    return documents


def get_all_donor_documents(bank_id: str, donor_id: str) -> Dict[str, List[Dict]]:
    """
    Get all documents for a donor across all buckets
    
    Args:
        bank_id: Bank ID
        donor_id: Donor ID
    
    Returns:
        Dictionary with document types as keys and lists of documents as values
    """
    return {
        "legal_documents": get_donor_legal_documents(donor_id),
        "consent_forms": get_donor_consent_forms(bank_id, donor_id),
        "test_reports": get_donor_test_reports(bank_id, donor_id),
        "counseling_reports": get_donor_counseling_reports(bank_id, donor_id)
    }
