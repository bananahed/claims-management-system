from flask import Flask
from flask_swagger_ui import get_swaggerui_blueprint

app = Flask(__name__)

SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "CMS API"
    }
)

app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

@app.route('/static/swagger.json')
def swagger_json():
    return {
        "swagger": "2.0",
        "info": {
            "description": "This is the API documentation for the CMS application.",
            "version": "1.0.0",
            "title": "CMS API"
        },
        "host": "localhost:5000",
        "basePath": "/",
        "tags": [
            {
                "name": "auth",
                "description": "Authentication related endpoints"
            },
            {
                "name": "policies",
                "description": "Policy related endpoints"
            },
            {
                "name": "policyholders",
                "description": "Policyholder related endpoints"
            },
            {
                "name": "claims",
                "description": "Claim related endpoints"
            }
        ],
        "paths": {
            "/register": {
                "post": {
                    "tags": ["auth"],
                    "summary": "Register a new user",
                    "description": "",
                    "operationId": "registerUser",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "User object that needs to be added",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/User"
                            }
                        }
                    ],
                    "responses": {
                        "201": {
                            "description": "User registered successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/login": {
                "post": {
                    "tags": ["auth"],
                    "summary": "Login a user",
                    "description": "",
                    "operationId": "loginUser",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "User login object",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/Login"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User logged in successfully"
                        },
                        "401": {
                            "description": "Invalid username or password"
                        }
                    }
                }
            },
            "/get-policies": {
                "get": {
                    "tags": ["policies"],
                    "summary": "Get all policies",
                    "description": "",
                    "operationId": "getPolicies",
                    "produces": ["application/json"],
                    "responses": {
                        "200": {
                            "description": "Successful operation"
                        }
                    }
                }
            },
            "/create-policy": {
                "post": {
                    "tags": ["policies"],
                    "summary": "Create a new policy",
                    "description": "",
                    "operationId": "createPolicy",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Policy object that needs to be added",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/Policy"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Policy created successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/get-policyholders": {
                "get": {
                    "tags": ["policyholders"],
                    "summary": "Get all policyholders",
                    "description": "",
                    "operationId": "getPolicyholders",
                    "produces": ["application/json"],
                    "responses": {
                        "200": {
                            "description": "Successful operation"
                        }
                    }
                }
            },
            "/create-policyholder": {
                "post": {
                    "tags": ["policyholders"],
                    "summary": "Create a new policyholder",
                    "description": "",
                    "operationId": "createPolicyholder",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Policyholder object that needs to be added",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/Policyholder"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Policyholder created successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/get-claims": {
                "get": {
                    "tags": ["claims"],
                    "summary": "Get all claims",
                    "description": "",
                    "operationId": "getClaims",
                    "produces": ["application/json"],
                    "responses": {
                        "200": {
                            "description": "Successful operation"
                        }
                    }
                }
            },
            "/file-claim": {
                "post": {
                    "tags": ["claims"],
                    "summary": "File a new claim",
                    "description": "",
                    "operationId": "fileClaim",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Claim object that needs to be added",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/Claim"
                            }
                        }
                    ],
                    "responses": {
                        "201": {
                            "description": "Claim filed successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/assign-policy": {
                "post": {
                    "tags": ["policies"],
                    "summary": "Assign a policy to a policyholder",
                    "description": "",
                    "operationId": "assignPolicy",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Policy assignment object",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/AssignPolicy"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Policy assigned successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/update-role": {
                "put": {
                    "tags": ["auth"],
                    "summary": "Update user role",
                    "description": "",
                    "operationId": "updateRole",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Role update object",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/UpdateRole"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User role updated successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/logout": {
                "post": {
                    "tags": ["auth"],
                    "summary": "Logout a user",
                    "description": "",
                    "operationId": "logoutUser",
                    "produces": ["application/json"],
                    "responses": {
                        "200": {
                            "description": "Logged out successfully"
                        },
                        "401": {
                            "description": "Invalid token"
                        }
                    }
                }
            },
            "/update-policy": {
                "put": {
                    "tags": ["policies"],
                    "summary": "Update a policy",
                    "description": "",
                    "operationId": "updatePolicy",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Policy update object",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/UpdatePolicy"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Policy updated successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/update-policyholder": {
                "put": {
                    "tags": ["policyholders"],
                    "summary": "Update a policyholder",
                    "description": "",
                    "operationId": "updatePolicyholder",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Policyholder update object",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/UpdatePolicyholder"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Policyholder updated successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/update-claim-status": {
                "put": {
                    "tags": ["claims"],
                    "summary": "Update claim status",
                    "description": "",
                    "operationId": "updateClaimStatus",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Claim status update object",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/UpdateClaimStatus"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Claim status updated successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/update-claim-amount": {
                "put": {
                    "tags": ["claims"],
                    "summary": "Update claim amount",
                    "description": "",
                    "operationId": "updateClaimAmount",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Claim amount update object",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/UpdateClaimAmount"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Claim amount updated successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/delete-policy": {
                "delete": {
                    "tags": ["policies"],
                    "summary": "Delete a policy",
                    "description": "",
                    "operationId": "deletePolicy",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Policy delete object",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/DeletePolicy"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Policy deleted successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/delete-policyholder": {
                "delete": {
                    "tags": ["policyholders"],
                    "summary": "Delete a policyholder",
                    "description": "",
                    "operationId": "deletePolicyholder",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Policyholder delete object",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/DeletePolicyholder"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Policyholder deleted successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/delete-claim": {
                "delete": {
                    "tags": ["claims"],
                    "summary": "Delete a claim",
                    "description": "",
                    "operationId": "deleteClaim",
                    "consumes": ["application/json"],
                    "produces": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "description": "Claim delete object",
                            "required": True,
                            "schema": {
                                "$ref": "#/definitions/DeleteClaim"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Claim deleted successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            }
        },
        "definitions": {
            "User": {
                "type": "object",
                "required": ["username", "password"],
                "properties": {
                    "username": {
                        "type": "string"
                    },
                    "password": {
                        "type": "string"
                    }
                }
            },
            "Login": {
                "type": "object",
                "required": ["username", "password"],
                "properties": {
                    "username": {
                        "type": "string"
                    },
                    "password": {
                        "type": "string"
                    }
                }
            },
            "Policy": {
                "type": "object",
                "required": ["policy_name", "description", "type", "max_claim_amt", "premium", "tenure"],
                "properties": {
                    "policy_name": {
                        "type": "string"
                    },
                    "description": {
                        "type": "string"
                    },
                    "type": {
                        "type": "string"
                    },
                    "max_claim_amt": {
                        "type": "number"
                    },
                    "premium": {
                        "type": "number"
                    },
                    "tenure": {
                        "type": "number"
                    }
                }
            },
            "Policyholder": {
                "type": "object",
                "required": ["name", "email", "phone", "dob"],
                "properties": {
                    "name": {
                        "type": "string"
                    },
                    "email": {
                        "type": "string"
                    },
                    "phone": {
                        "type": "string"
                    },
                    "dob": {
                        "type": "string",
                        "format": "date"
                    }
                }
            },
            "Claim": {
                "type": "object",
                "required": ["policyholder_id", "policy_id", "claim_amt"],
                "properties": {
                    "policyholder_id": {
                        "type": "string"
                    },
                    "policy_id": {
                        "type": "string"
                    },
                    "claim_amt": {
                        "type": "number"
                    }
                }
            },
            "AssignPolicy": {
                "type": "object",
                "required": ["policyholder_id", "policy_id"],
                "properties": {
                    "policyholder_id": {
                        "type": "string"
                    },
                    "policy_id": {
                        "type": "string"
                    }
                }
            },
            "UpdateRole": {
                "type": "object",
                "required": ["username", "role"],
                "properties": {
                    "username": {
                        "type": "string"
                    },
                    "role": {
                        "type": "string"
                    }
                }
            },
            "UpdatePolicy": {
                "type": "object",
                "required": ["policy_id", "policy_name", "description", "type"],
                "properties": {
                    "policy_id": {
                        "type": "string"
                    },
                    "policy_name": {
                        "type": "string"
                    },
                    "description": {
                        "type": "string"
                    },
                    "type": {
                        "type": "string"
                    }
                }
            },
            "UpdatePolicyholder": {
                "type": "object",
                "required": ["policyholder_id", "name", "email", "phone", "dob"],
                "properties": {
                    "policyholder_id": {
                        "type": "string"
                    },
                    "name": {
                        "type": "string"
                    },
                    "email": {
                        "type": "string"
                    },
                    "phone": {
                        "type": "string"
                    },
                    "dob": {
                        "type": "string",
                        "format": "date"
                    }
                }
            },
            "UpdateClaimStatus": {
                "type": "object",
                "required": ["claim_id", "claim_status"],
                "properties": {
                    "claim_id": {
                        "type": "string"
                    },
                    "claim_status": {
                        "type": "string"
                    }
                }
            },
            "UpdateClaimAmount": {
                "type": "object",
                "required": ["claim_id", "claim_amt"],
                "properties": {
                    "claim_id": {
                        "type": "string"
                    },
                    "claim_amt": {
                        "type": "number"
                    }
                }
            },
            "DeletePolicy": {
                "type": "object",
                "required": ["policy_id"],
                "properties": {
                    "policy_id": {
                        "type": "string"
                    }
                }
            },
            "DeletePolicyholder": {
                "type": "object",
                "required": ["policyholder_id"],
                "properties": {
                    "policyholder_id": {
                        "type": "string"
                    }
                }
            },
            "DeleteClaim": {
                "type": "object",
                "required": ["claim_id"],
                "properties": {
                    "claim_id": {
                        "type": "string"
                    }
                }
            }
        }
    }

if __name__ == '__main__':
    app.run(debug=True)