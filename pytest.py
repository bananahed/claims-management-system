import pytest
from main import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_get_policyholders_info(client):
    response = client.get('/policyholders')
    assert response.status_code == 200

def test_get_policies(client):
    response = client.get('/policies')
    assert response.status_code == 200

def test_get_claims(client):
    response = client.get('/get-claims')
    assert response.status_code == 200

def test_get_pending_claims(client):
    response = client.get('/get-pending-claims')
    assert response.status_code == 200

def test_create_policy(client):
    data = {
        "policy_name": "Health Insurance",
        "description": "Comprehensive health insurance",
        "type": "Health",
        "max_claim_amt": 100000,
        "premium": 5000,
        "tenure": 1
    }
    response = client.post('/create-policy', json=data)
    assert response.status_code == 200

def test_create_policyholder(client):
    data = {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "phone": "9876543210",
        "dob": "1990-01-01"
    }
    response = client.post('/create-policyholder', json=data)
    assert response.status_code == 200

def test_assign_policy(client):
    data = {
        "policyholder_id": 1,
        "policy_id": "001_001"
    }
    response = client.post('/assign-policy', json=data)
    assert response.status_code == 200

def test_file_claim(client):
    data = {
        "policyholder_id": 1,
        "policy_id": "001_001",
        "claim_amt": 5000
    }
    response = client.post('/file-claim', json=data)
    assert response.status_code == 200

def test_update_policyholder(client):
    data = {
        "policyholder_id": 1,
        "name": "John Doe",
        "email": "john.doe@example.com",
        "phone": "9876543210",
        "dob": "1990-01-01"
    }
    response = client.put('/update-policyholder', json=data)
    assert response.status_code == 200

def test_update_policy(client):
    data = {
        "policy_id": "001_001",
        "policy_name": "Health Insurance",
        "description": "Updated description",
        "type": "Health"
    }
    response = client.put('/update-policy', json=data)
    assert response.status_code == 200

def test_update_claim_amt(client):
    data = {
        "claim_id": "000001",
        "claim_amt": 6000
    }
    response = client.put('/update-claim-amount', json=data)
    assert response.status_code == 200

def test_update_claim_status(client):
    data = {
        "claim_id": "000001",
        "claim_status": "Accepted"
    }
    response = client.put('/update-claim-status', json=data)
    assert response.status_code == 200

def test_delete_policyholder(client):
    data = {
        "policyholder_id": 1
    }
    response = client.delete('/delete-policyholder', json=data)
    assert response.status_code == 200

def test_delete_policy(client):
    data = {
        "policy_id": "001_001"
    }
    response = client.delete('/delete-policy', json=data)
    assert response.status_code == 200

def test_delete_claim(client):
    data = {
        "claim_id": "000001"
    }
    response = client.delete('/delete-claim', json=data)
    assert response.status_code == 200