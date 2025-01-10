# CMS Backend API Documentation

## Overview
This project is a Flask-based API for managing insurance policies, policyholders, and claims. It provides endpoints for creating, updating, retrieving, and deleting policies, policyholders, and claims. The API also includes user authentication and role-based access control.

## Setup

1. Clone the repository:
    ```bash
    git clone <repository-url>
    ```

2. Create a virtual environment and activate it:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Create a `.env` file in the project root and add the following environment variables:
    ```plaintext
    MONGO_URI=<your-mongo-uri>
    DB_NAME=<your-database-name>
    SECRET_KEY=<your-secret-key>
    ```

5. Run the application:
    ```bash
    python app_cms.py
    ```

## Endpoints

### Authentication

- **Register**
    - **URL:** `/register`
    - **Method:** `POST`
    - **Description:** Registers a new user.
    - **Request Body:**
        ```json
        {
            "username": "string",
            "password": "string"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "User registered successfully"
        }
        ```

- **Login**
    - **URL:** `/login`
    - **Method:** `POST`
    - **Description:** Logs in a user.
    - **Request Body:**
        ```json
        {
            "username": "string",
            "password": "string"
        }
        ```
    - **Response:**
        ```json
        {
            "token": "string"
        }
        ```

- **Logout**
    - **URL:** `/logout`
    - **Method:** `POST`
    - **Description:** Logs out a user.
    - **Response:**
        ```json
        {
            "message": "Logged out successfully"
        }
        ```

### Policies

- **Get Policies**
    - **URL:** `/get-policies`
    - **Method:** `GET`
    - **Description:** Retrieves information about all policies.
    - **Response:**
        ```json
        [
            {
                "_id": "string",
                "policy_name": "string",
                "type": "string"
            }
        ]
        ```

- **Create Policy**
    - **URL:** `/create-policy`
    - **Method:** `POST`
    - **Description:** Creates a new policy.
    - **Request Body:**
        ```json
        {
            "policy_name": "string",
            "description": "string",
            "type": "string",
            "max_claim_amt": "number",
            "premium": "number",
            "tenure": "number"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "Policy created successfully"
        }
        ```

- **Update Policy**
    - **URL:** `/update-policy`
    - **Method:** `PUT`
    - **Description:** Updates an existing policy.
    - **Request Body:**
        ```json
        {
            "policy_id": "string",
            "policy_name": "string",
            "description": "string",
            "type": "string"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "Policy updated successfully"
        }
        ```

- **Delete Policy**
    - **URL:** `/delete-policy`
    - **Method:** `DELETE`
    - **Description:** Deletes a policy.
    - **Request Body:**
        ```json
        {
            "policy_id": "string"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "Policy deleted successfully"
        }
        ```

### Policyholders

- **Get Policyholders**
    - **URL:** `/get-policyholders`
    - **Method:** `GET`
    - **Description:** Retrieves information about all policyholders.
    - **Response:**
        ```json
        [
            {
                "_id": "string",
                "name": "string",
                "email": "string",
                "phone": "string"
            }
        ]
        ```

- **Create Policyholder**
    - **URL:** `/create-policyholder`
    - **Method:** `POST`
    - **Description:** Creates a new policyholder.
    - **Request Body:**
        ```json
        {
            "name": "string",
            "email": "string",
            "phone": "string",
            "dob": "string"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "Policyholder created successfully"
        }
        ```

- **Update Policyholder**
    - **URL:** `/update-policyholder`
    - **Method:** `PUT`
    - **Description:** Updates an existing policyholder.
    - **Request Body:**
        ```json
        {
            "policyholder_id": "string",
            "name": "string",
            "email": "string",
            "phone": "string",
            "dob": "string"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "Policyholder updated successfully"
        }
        ```

- **Delete Policyholder**
    - **URL:** `/delete-policyholder`
    - **Method:** `DELETE`
    - **Description:** Deletes a policyholder.
    - **Request Body:**
        ```json
        {
            "policyholder_id": "string"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "Policyholder deleted successfully"
        }
        ```

### Claims

- **Get Claims**
    - **URL:** `/get-claims`
    - **Method:** `GET`
    - **Description:** Retrieves information about all claims.
    - **Response:**
        ```json
        {
            "claim_id": {
                "policyholder_id": "string",
                "policy_id": "string",
                "claim_amt": "number",
                "claim_status": "string",
                "claim_date": "string"
            }
        }
        ```

- **Get Pending Claims**
    - **URL:** `/get-pending-claims`
    - **Method:** `GET`
    - **Description:** Retrieves information about all pending claims.
    - **Response:**
        ```json
        {
            "claim_id": {
                "policyholder_id": "string",
                "policy_id": "string",
                "claim_amt": "number",
                "claim_status": "string",
                "claim_date": "string"
            }
        }
        ```

- **File Claim**
    - **URL:** `/file-claim`
    - **Method:** `POST`
    - **Description:** Files a new claim.
    - **Request Body:**
        ```json
        {
            "policyholder_id": "string",
            "policy_id": "string",
            "claim_amt": "number"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "Claim filed successfully"
        }
        ```

- **Update Claim Amount**
    - **URL:** `/update-claim-amount`
    - **Method:** `PUT`
    - **Description:** Updates the amount of an existing claim.
    - **Request Body:**
        ```json
        {
            "claim_id": "string",
            "claim_amt": "number"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "Claim amount updated successfully"
        }
        ```

- **Update Claim Status**
    - **URL:** `/update-claim-status`
    - **Method:** `PUT`
    - **Description:** Updates the status of an existing claim.
    - **Request Body:**
        ```json
        {
            "claim_id": "string",
            "claim_status": "string"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "Claim status updated successfully"
        }
        ```

- **Delete Claim**
    - **URL:** `/delete-claim`
    - **Method:** `DELETE`
    - **Description:** Deletes a claim.
    - **Request Body:**
        ```json
        {
            "claim_id": "string"
        }
        ```
    - **Response:**
        ```json
        {
            "message": "Claim deleted successfully"
        }
        ```

## Running the API

To run the API, execute the following command:

```bash
python app_cms.py
```

The API will be available at `http://127.0.0.1:5000`.

## Swagger Documentation

The API documentation is available at `http://127.0.0.1:5000/swagger`.

## Helper Functions

The `helper.py` file contains various utility functions used by the API:

- **ID Generators:**
    - `generate_policyid(type)`: Generates a unique policy ID based on the policy type.
    - `generate_policyholderid()`: Generates a unique policyholder ID.
    - `generate_claimid()`: Generates a unique claim ID.

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