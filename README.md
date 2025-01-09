# Stateless API Documentation

## Overview
This project is a Flask-based API for managing insurance policies, policyholders, and claims. It provides endpoints for creating, updating, retrieving, and deleting policies, policyholders, and claims.

## Endpoints

### Policyholders

- **Get Policyholders Info**
    - **URL:** `/policyholders`
    - **Method:** `GET`
    - **Description:** Retrieves information about all policyholders.

- **Create Policyholder**
    - **URL:** `/create-policyholder`
    - **Method:** `POST`
    - **Description:** Creates a new policyholder.
    - **Request Body:**
        ```json
        {
            "name": "John Doe",
            "email": "john.doe@example.com",
            "phone": "9876543210",
            "dob": "1990-01-01"
        }
        ```

- **Update Policyholder**
    - **URL:** `/update-policyholder`
    - **Method:** `PUT`
    - **Description:** Updates an existing policyholder's information.
    - **Request Body:**
        ```json
        {
            "policyholder_id": 1,
            "name": "John Doe",
            "email": "john.doe@example.com",
            "phone": "9876543210",
            "dob": "1990-01-01"
        }
        ```

- **Delete Policyholder**
    - **URL:** `/delete-policyholder`
    - **Method:** `DELETE`
    - **Description:** Deletes a policyholder.
    - **Request Body:**
        ```json
        {
            "policyholder_id": 1
        }
        ```

### Policies

- **Get Policies**
    - **URL:** `/policies`
    - **Method:** `GET`
    - **Description:** Retrieves information about all policies.

- **Create Policy**
    - **URL:** `/create-policy`
    - **Method:** `POST`
    - **Description:** Creates a new policy.
    - **Request Body:**
        ```json
        {
            "policy_name": "Health Insurance",
            "description": "Comprehensive health insurance",
            "type": "Health",
            "max_claim_amt": 100000,
            "premium": 5000,
            "tenure": 1
        }
        ```

- **Update Policy**
    - **URL:** `/update-policy`
    - **Method:** `PUT`
    - **Description:** Updates an existing policy.
    - **Request Body:**
        ```json
        {
            "policy_id": "001_001",
            "policy_name": "Health Insurance",
            "description": "Updated description",
            "type": "Health"
        }
        ```

- **Delete Policy**
    - **URL:** `/delete-policy`
    - **Method:** `DELETE`
    - **Description:** Deletes a policy.
    - **Request Body:**
        ```json
        {
            "policy_id": "001_001"
        }
        ```

### Claims

- **Get Claims**
    - **URL:** `/get-claims`
    - **Method:** `GET`
    - **Description:** Retrieves information about all claims.

- **Get Pending Claims**
    - **URL:** `/get-pending-claims`
    - **Method:** `GET`
    - **Description:** Retrieves information about all pending claims.

- **File Claim**
    - **URL:** `/file-claim`
    - **Method:** `POST`
    - **Description:** Files a new claim.
    - **Request Body:**
        ```json
        {
            "policyholder_id": 1,
            "policy_id": "001_001",
            "claim_amt": 5000
        }
        ```

- **Update Claim Amount**
    - **URL:** `/update-claim-amount`
    - **Method:** `PUT`
    - **Description:** Updates the amount of an existing claim.
    - **Request Body:**
        ```json
        {
            "claim_id": "000001",
            "claim_amt": 6000
        }
        ```

- **Update Claim Status**
    - **URL:** `/update-claim-status`
    - **Method:** `PUT`
    - **Description:** Updates the status of an existing claim.
    - **Request Body:**
        ```json
        {
            "claim_id": "000001",
            "claim_status": "Accepted"
        }
        ```

- **Delete Claim**
    - **URL:** `/delete-claim`
    - **Method:** `DELETE`
    - **Description:** Deletes a claim.
    - **Request Body:**
        ```json
        {
            "claim_id": "000001"
        }
        ```

## Helper Functions

The `helper.py` file contains various utility functions used by the API:

- **ID Generators:**
    - `generate_policyid(type)`: Generates a unique policy ID based on the policy type.
    - `generate_policyholderid()`: Generates a unique policyholder ID.
    - `generate_claim_id()`: Generates a unique claim ID.

- **Sanitization:**
    - `sanitize_inputs(data)`: Sanitizes input data to prevent SQL injection and XSS attacks.

- **Validations:**
    - `validate_policyid(policy_id)`: Validates if a policy ID exists.
    - `validate_policy_name(param)`: Validates if a policy name already exists.
    - `validate_policyholderid(policyholder_id)`: Validates if a policyholder ID exists.
    - `validate_email(email)`: Validates an email address.
    - `validate_phone(phone)`: Validates a phone number.
    - `validate_claim_id(claim_id)`: Validates if a claim ID exists.
    - `validate_claim_status(claim_id, policyholder_id)`: Validates if a claim status is pending.
    - `validate_claim_amt(policyholder_id, claim_amt, policy_id)`: Validates if a claim amount is within the policy limit.
    - `validate_policy_inputs(premium, max_claim_amt)`: Validates the premium and maximum claim amount.
    - `validate_user_policy(policyholder_id, policy_id)`: Validates if a policyholder has a specific policy.

## Running the API

To run the API, execute the following command:

```bash
python stateless-api.py
```

The API will be available at `http://127.0.0.7:50`.
