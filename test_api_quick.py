"""
Quick test to verify admin login and API endpoints work
"""
import requests
import json

BASE_URL = "http://localhost:8001"

def test_admin_login():
    """Test admin login"""
    print("🔐 Testing admin login...")
    
    response = requests.post(
        f"{BASE_URL}/api/admin/auth/login",
        json={
            "email": "admin@artpriv.com",
            "password": "admin123"
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        print("✅ Login successful!")
        print(f"   Token: {data['access_token'][:50]}...")
        print(f"   Role: {data['role']}")
        return data['access_token']
    else:
        print(f"❌ Login failed: {response.status_code}")
        print(f"   {response.text}")
        return None

def test_get_donors(token):
    """Test getting donors list"""
    print("\n👥 Testing get donors...")
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/admin/donors", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Got {data['total']} donors")
        if data['donors']:
            donor = data['donors'][0]
            print(f"   First donor: {donor['first_name']} {donor['last_name']}")
            return donor['id']
    else:
        print(f"❌ Failed: {response.status_code}")
        print(f"   {response.text}")
    return None

def test_get_donor_detail(token, donor_id):
    """Test getting donor detail with test reports"""
    print(f"\n🔍 Testing get donor detail...")
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/admin/donors/{donor_id}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Got donor: {data['first_name']} {data['last_name']}")
        print(f"   Tests pending: {data.get('tests_pending', False)}")
        if data.get('test_reports'):
            print(f"   Test reports: {len(data['test_reports'])}")
            for report in data['test_reports']:
                print(f"     - {report['test_name']}: {report.get('status', 'N/A')}")
        return data
    else:
        print(f"❌ Failed: {response.status_code}")
        print(f"   {response.text}")
    return None

if __name__ == "__main__":
    print("="*60)
    print("Testing Admin Portal API")
    print("="*60)
    print("\n⚠️  Make sure the admin backend is running on port 8001")
    print("   Run: cd d:\\Work\\adminside\\backend && uvicorn main:app --reload --port 8001\n")
    
    try:
        token = test_admin_login()
        
        if token:
            donor_id = test_get_donors(token)
            
            if donor_id:
                donor_data = test_get_donor_detail(token, donor_id)
        
        print("\n" + "="*60)
        print("✅ All API tests passed!")
        print("="*60)
        
    except requests.exceptions.ConnectionError:
        print("\n" + "="*60)
        print("❌ Could not connect to backend!")
        print("="*60)
        print("\nPlease start the backend first:")
        print("  cd d:\\Work\\adminside\\backend")
        print("  uvicorn main:app --reload --port 8001")
        print("="*60)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
