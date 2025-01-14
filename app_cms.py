from flask import Flask, request, jsonify
import datetime
import jwt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from helper import (validate_user_policy, validate_claim_amt, validate_email, validate_phone, validate_policy_name, validate_policyholderid, validate_policyid, sanitize_inputs, generate_claimid, generate_policyholderid, generate_policyid, validate_username)
from config import db,SECRET_KEY,JWT_ALGORITHM
import json
app = Flask(__name__)
CORS(app)

# User registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = sanitize_inputs(data['username'])
    response = validate_username(username,'register')
    if response:
        return response
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    user = {
        'username': username,
        'password': hashed_password,
        'role': 'Agent',  # default role
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    db.users.insert_one(user)
    return jsonify({'message': 'User registered successfully'}), 201

# SECRET_KEY = os.getenv('SECRET_KEY')
if not isinstance(SECRET_KEY, str):
    raise ValueError("Invalid secret key")

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = sanitize_inputs(data['username'])
    user = validate_username(username,'login')
    if isinstance(user,tuple):
        return user
    if not check_password_hash(user['password'], data['password']):
        return jsonify({'error': 'Incorrect password'}), 401

    token = jwt.encode({
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)},
            SECRET_KEY,
            algorithm=JWT_ALGORITHM
    )
    return jsonify({'token': token})


# token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            print("Token is missing")
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = db.users.find_one({'username': data['username']})
            blacklisted = db.blacklisted_tokens.find_one({'token':token})
            if blacklisted:
                return jsonify({"message":"Token has been blacklisted. Please log in again"}),403 
        except jwt.ExpiredSignatureError:
            print("expired")
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            print("invalid")
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user['role'] != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Role-based access control decorators
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(current_user, *args, **kwargs):
            if current_user['role'] not in roles:
                return jsonify({'message': 'Access denied'}), 403
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator

# Admin: Update user role
@app.route('/update-role', methods=['PUT'])
@token_required
@admin_required
def update_role(current_user):
    data = request.json
    db.users.update_one({'username': data['username']}, {'$set': {'role': data['role']}})
    return jsonify({'message': 'User role updated successfully'})

# Logout (invalidate token)
@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    # Token invalidation handled using token expiration
    token = request.headers['Authorization'].split(" ")[1]
    try:
        # decode token for data
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options={"verify_exp": False})
        # set token expiry to a second ago
        data['exp'] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        # re -encode token
        invalidated_token = jwt.encode(data, SECRET_KEY, algorithm='HS256')
        if token: 
            db.blacklisted_tokens.insert_one({ 
                'token': token, 
                'expire_at': datetime.datetime.now(datetime.timezone.utc),})
        return jsonify({'message': 'Logged out successfully', 'invalidated_token': invalidated_token})
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Token is invalid'}), 401


#post 
@app.route('/create-policy', methods=["POST"])
@token_required
@role_required('admin','policy-admin')
def create_policy(current_user):
    raw_data = request.json
    data = sanitize_inputs(raw_data)

    #check if policy with same name exists
    if validate_policy_name(data['policy_name']):
        return jsonify({'error':f"Policy with name: {data['policy_name']} already exists."}), 409

    try:
        policy_id = generate_policyid(data['type'])
    except (ValueError,TypeError) as e:
        return e
    
    db.policies.insert_one({
        '_id' : policy_id,
        'policy_name' : data['policy_name'],
        'description' : data['description'],
        'type' : data['type'],
        'max_claim_amt' : data['max_claim_amt'],
        'premium' : data['premium'],
        'tenure' : data['tenure'],
        'launch_date' : f"{datetime.datetime.now().date()}"
    })
    return jsonify({'message' : "Policy created successfully."}) , 200

@app.route('/create-policyholder', methods=['POST'])
@token_required
@role_required('admin','policyholder-admin','Agent')
def create_policyholder(current_user):
    raw_data = request.json
    data = sanitize_inputs(raw_data)
    #validations
    #email
    if not validate_email(data['email']):
        return jsonify({'error':f"Please enter a valid email: {data['email']}."}),400
    #phone
    if not validate_phone(data['phone']):
        return jsonify({'error': f"Invalid phone number: {data['phone']} or phone number already in use."})
    policyholder_id = generate_policyholderid()

    db.policyholders.insert_one({
        '_id': policyholder_id,
        'name' : data['name'],
        'email' : data['email'],
        'phone' : data['phone'],
        'dob' : f"{datetime.datetime.strptime(data['dob'],'%Y-%m-%d').date()}",
        'user_policies' : {},
        'claims' : {},
        'registration_date' : f"{datetime.datetime.now().date()}"
    })
    return jsonify({'message':'Policyholder created successfully.'}),200


# #assign policy to user
@app.route('/assign-policy', methods=["POST"])
@token_required
@role_required('Agent', 'admin','policyholder-admin')
def assign_policy(current_user):
    raw_data = request.json
    data = sanitize_inputs(raw_data)
    #validations
    #check if policyholder exists
    if validate_policyholderid(data['policyholder_id']):
        return jsonify({'error':f"Policyholder with id: {data['policyholder_id']} does not exist."}),404
    #check if policy exists
    if validate_policyid(data['policy_id']):
        return jsonify({'error':f"Policy with id: {data['policy_id']} does not exist."}),404
    #check if user already has the policy assigned
    if validate_user_policy(data['policyholder_id'],data['policy_id']):
        return jsonify({'error':f"Policy: {data['policy_id']} already registered for policyholder: {data['policyholder_id']}."}) , 409
    
    policy = db.policies.find_one({'_id':data['policy_id']})
    if not policy:
        return jsonify({'error': f"Policy with id: {data['policy_id']} does not exist."})
    default = {
            'max_limit': policy['max_claim_amt'],
            'available_limit' : policy['max_claim_amt'],
            'start_date' : f"{datetime.datetime.now().date()}"
        }

    db.policyholders.update_one({'_id': data['policyholder_id']},{'$set' : {f"user_policies.{data['policy_id']}" : default }})
    default.clear()
    return jsonify({'message': "Policy assigned successfully."}),201

#file claims    
@app.route('/file-claim', methods=["POST"])
@token_required
@role_required('Agent', 'claim-admin','admin')
def file_claim(current_user):
    raw_data = request.json
    data = sanitize_inputs(raw_data)
    #validations
    #check if policyholder exists
    if validate_policyid(data['policy_id']):
        return jsonify({'error':f"Policy with id: {data['policy_id']} does not exist."}),404
    #check if policy id exists
    if validate_policyholderid(data['policyholder_id']):
        return jsonify({'error':f"Policyholder with id: {data['policyholder_id']} does not exist."}),404
    #check if user-policy exists
    if not validate_user_policy(data['policyholder_id'],data['policy_id']):
        return jsonify({'error':f"Policy: {data['policy_id']} is not assigned to policyholder: {data['policyholder_id']}."}) , 400
    
    #validate claim_amt
    if not validate_claim_amt(data['policyholder_id'],data['policy_id'],data['claim_amt']):
        return jsonify({'error':f"Invalid claim amount:{data['claim_amt']} ."}) , 400
    claim_id = generate_claimid()

    default = {
        'policy_id' : data['policy_id'],
        'claim_amt' : data['claim_amt'],
        'claim_status' : "Pending",
        'date_filed' : f"{datetime.datetime.now().date()}"
    }

    result = db.policyholders.update_one(
        {'_id':data['policyholder_id']},
        {'$set': { f"claims.{claim_id}" : default}}
        )
    default.clear()
    if result.modified_count == 1:
        return jsonify({'message': "Claim filed successfully."}), 201
    else:
        return jsonify({'error': "Error filing claim."}), 500


#get
#list policies
@app.route('/get-policies',methods=["GET"])
@token_required
def get_policies(current_user):
    policy_id = request.args.get('policy_id')
    if policy_id:
        policy = db.policies.find_one({'_id':policy_id})
        if policy:
            return jsonify(policy)
        else:
            return jsonify({'error': f"Policy with id: {policy_id} does not exists."}),404
    else:
        policies = list(db.policies.find({}, {'_id': 1, 'policy_name': 1, 'type': 1}))
        return jsonify(policies),200

#list policyholders
@app.route('/get-policyholders',methods=["GET"])
@token_required
def get_policyholders(current_user):
    policyholder_id = request.args.get('policyholder_id')
    # search_name = request.args.get('name') removed because the ui filters users using useState
    if policyholder_id:
        policyholder = db.policyholders.find_one({'_id':policyholder_id})
        if policyholder:
            return jsonify(policyholder),200
        else:
            return jsonify({'error': f"Policyholder with id: {policyholder_id} does not exists."}),404
    # elif search_name:
    #     policyholders = list(db.policyholders.find({'name':{'$regex': search_name, '$options' : 'i'}},{'_id':1,'name':1,'email':1,'phone':1}))
    #     if not policyholders:
    #         return jsonify({'error':f"No policyholder found with name : {search_name}."}),404
    #     return jsonify(policyholders),200
    else:
        policyholders = list(db.policyholders.find({},{'_id':1,'name':1,'email':1,'phone':1}))
        return jsonify(policyholders),200

# list claims
@app.route('/get-claims', methods=["GET"])
@token_required
def get_claims(current_user): 
    claim_id = request.args.get('claim_id') 
    if claim_id: 
        # Find policyholder containing the specific claim_id 
        policyholder = db.policyholders.find_one({'claims.' + claim_id: {'$exists': True}}, {'claims.' + claim_id: 1, '_id': 1}) 
        if policyholder: 
            claim = policyholder['claims'][claim_id] 
            claim['policyholder_id'] = policyholder['_id'] 
            return jsonify(claim) 
        else: 
            return jsonify({'error': f"Claim with id: {claim_id} does not exist."}), 404 
    else: 
        # Get all claims with their policyholder_id 
        policyholders = db.policyholders.find() 
        all_claims = {} 
        for policyholder in policyholders: 
            claims = policyholder.get('claims', {}) 
            for claim_id, claim in claims.items():
                claim['policyholder_id'] = policyholder['_id'] 
                all_claims[claim_id] = claim 
        return jsonify(all_claims),200
    

#list pending claims

@app.route('/get-pending-claims', methods=['GET'])
@token_required
# @role_required()
def get_pending_claims(current_user):
    claim_id = request.args.get('claim_id')
    if claim_id:
        policyholder = db.policyholders.find_one({'claims.' + claim_id: {'$exists': True}}, {'claims.' + claim_id: 1})
        if policyholder:
            claim = policyholder['claims'][claim_id]
            if claim['claim_status'] == 'Pending':
                return jsonify(claim)
            else:
                return jsonify({'error': f"Claim with id: {claim_id} is not pending."}), 404
        else:
            return jsonify({'error': f"Claim with id: {claim_id} does not exist."}), 404
    else:
        policyholders = list(db.policyholders.find())
        pending_claims = {}
        for policyholder in policyholders:
            claims = policyholder.get('claims')
            for claim_id, claim in claims.items():
                if claim['claim_status'] == 'Pending':
                    pending_claims[claim_id] = claim
        return jsonify(pending_claims),200


#put
#update policy
@app.route('/update-policy', methods=['PUT'])
@token_required
@role_required('admin', 'policy-admin')
def update_policy(current_user):
    raw_data = request.json
    data = sanitize_inputs(raw_data)
    #validation
    #check if valid policy_id
    if validate_policyid(data['policy_id']):
        return jsonify({'error':f"Policy with id: {data['policy_id']} does not exist."}) , 404
    
    if validate_policy_name(data['policy_name'],data['policy_id']):
        return jsonify({'error':f"Policy with name: {data['policy_name']} already exists."}),409
    
    db.policies.find_one_and_update({'_id' : data['policy_id']} , 
     {'$set' : 
      {
        'policy_name': data['policy_name'],
        'description' : data['description'],
        'type' : data['type'],
        'update_timestamp' : f"{datetime.datetime.now()}"
      }
    })
    return jsonify({'message':'Policy updated successfully.'}),200

#update policyholder
@app.route('/update-policyholder', methods=["PUT"])
@token_required
@role_required('admin','policyholder-admin')
def update_policyholder(current_user):
    raw_data = request.json
    data = sanitize_inputs(raw_data)
    #validation
    if validate_policyholderid(data['policyholder_id']):
        return jsonify({'error':f"Policyholder with id: {data['policyholder_id']} does not exist."}),404
    #check if phone number is unique
    if validate_phone(data['phone'],data['policyholder_id']):
        return jsonify({'error':f"Phone number is already taken: {data['phone']}."}),409
    #check if valid phone
    if not validate_email(data['email']):
        return jsonify({'error':f"Invalid email: {data['email']}"}),400
    #check if valid email
    if not validate_phone(data['phone']):
        return jsonify({'error':f"Invalid phone number: {data['phone']}"}), 400
    db.policyholders.find_one_and_update(
        {'_id':data['policyholder_id']},
        {
            '$set': 
                {
            'name' : data['name'],
            'email' : data['email'],
            'phone' : data['phone'],
            'dob' : f"{datetime.datetime.strptime(data['dob'],'%Y-%m-%d').date()}",
            'update_timestamp' : f"{datetime.datetime.now()}",
            }
        }
    )
    return jsonify({'message': 'Policyholder updated successfully.'}), 200

#update claim status
@app.route('/update-claim-status', methods=["PUT"])
@token_required
@role_required('claim-admin','admin')
def update_claim_status(current_user):
    raw_data = request.json
    data = sanitize_inputs(raw_data)
    #validation
    #check if status pending or not 
    if 'claim_id' not in data or 'claim_status' not in data:
        return jsonify({'error': 'Claim ID and Claim Status are required'}), 400
    
    if data['claim_status'] not in ["Approved","Rejected"]:
        return jsonify({'error':f"Invalid claim status entered: {data['claim_status']}. Claim status can be Approved or Rejected."})
    
    policyholder = db.policyholders.find_one({'claims.' + data['claim_id'] : {'$exists' : True}})
    if not policyholder:
        return jsonify({'error':f"Invalid claim id: {data['claim_id']}."}), 400

    claim = policyholder['claims'][data['claim_id']]
    policy_id = claim['policy_id']
    #check if status pending or not
    if claim['claim_status'] != "Pending":
        return jsonify({'error':f"Claim already processed for id: {data['claim_id']} "}), 400

    policy_id = claim['policy_id']

    #if approved
    if claim['claim_status'] == "Pending":
        if data['claim_status'] == "Approved":
            #set limit to new limit
            claim_amt = int(claim['claim_amt'])
            user_policy = policyholder['user_policies'][policy_id]
            new_limit = int(user_policy['available_limit']) - claim_amt

            result = db.policyholders.update_one(
                {'_id': policyholder['_id'], 'user_policies.' + policy_id: {'$exists' : True}},
                {'$set': {'user_policies.' + policy_id + '.available_limit': new_limit}}
            )
            if result.modified_count != 1:
                return jsonify({'error': 'Error while processing the claim.'}), 500
            #set the status
            result = db.policyholders.update_one( 
                {'_id': policyholder['_id'], 'claims.' + data['claim_id']: {'$exists': True}}, 
                {'$set': {'claims.' + data['claim_id'] + '.claim_status': data['claim_status']}} 
                )
            if result.modified_count != 1:
                return jsonify({'error': 'Error while processing the claim.'}), 500
            
        elif data['claim_status'] == "Rejected":
            result = db.policyholder.update_one(
                {'_id': policyholder['_id'], 'user-policies.' + policy_id: {'$exists' : True}},
                {'$set': {'user_policies.' + policy_id + '.available_limit': new_limit}}
            )

        return jsonify({'message':'Claim processed successfully.'}),200
        

#update claim amount
@app.route('/update-claim-amount', methods=["PUT"])
@token_required
@role_required('claim-admin', 'admin')
def update_claim_amount(current_user):
    raw_data = request.json
    data = {}
    data['claim_id'] = sanitize_inputs(raw_data['claim_id'])
    data['claim_amt'] = int(raw_data['claim_amt'])
    
    # Validation
    if 'claim_id' not in data or 'claim_amt' not in data:
        return jsonify({'error': 'Claim ID and Claim Amount are required'}), 400
    
    # Check if claim exists
    policyholder = db.policyholders.find_one({'claims.' + data['claim_id']: {'$exists': True}})
    if not policyholder:
        return jsonify({'error': f"Claim with id: {data['claim_id']} does not exist."}), 404
    
    # Parse claim data if it is in string format
    claim = policyholder['claims'][data['claim_id']]
    if isinstance(claim, str):
        try:
            claim = json.loads(claim.replace("'", "\""))
        except json.JSONDecodeError:
            return jsonify({'error': 'Claim data is not in the expected format'}), 500

    # Check if claim amount is valid
    claim_status = claim['claim_status']
    policy_id = claim['policy_id']
    available_policy_limit = int(policyholder['user_policies'][policy_id]['available_limit'])
    
    if data['claim_amt'] > available_policy_limit or data['claim_amt'] < 0:
        return jsonify({'error': f"Invalid claim amount: {data['claim_amt']}. Claim amount must be lower than {available_policy_limit} and greater than zero"}), 400

    # Check if claim status is pending
    if claim_status != "Pending":
        return jsonify({'error': f"Invalid claim id: {data['claim_id']} or claim already processed."}), 400
    
    # Update claim amount
    claim['claim_amt'] = data['claim_amt']
    policyholder['claims'][data['claim_id']] = claim

    result = db.policyholders.update_one(
        {'_id': policyholder['_id']},
        {'$set': {'claims.' + data['claim_id']: claim}}
    )
    if result.modified_count == 1:
        return jsonify({'message': 'Claim amount changed successfully.'})
    else:
        return jsonify({'error': f"Error updating claim amount for claim id: {data['claim_id']}"}), 500
    
    # Update claim amount
    db.policyholders.update_one(
        {'_id': policyholder['_id']},
        {'$set': {
            'claims.' + data['claim_id'] + '.claim_amt': data['claim_amt']
        }}
    )
    return jsonify({'message': 'Claim amount changed successfully.'})


#delete
#delete policy
@app.route('/delete-policy', methods=['DELETE'])
@token_required
@role_required('policy-admin','admin')
def delete_policy(current_user):
    raw_data = request.json
    data = sanitize_inputs(raw_data) 
    #validations
    if 'policy_id' not in data:
        return jsonify({'error':'Policy ID is required'}),400
    
    if validate_policyid(data['policy_id']):
        return jsonify({'error':f"Policy with id: {data['policy_id']} does not exist."}),404
    #delete from policy table
    result = db.policies.delete_one({'_id':data['policy_id']})
    #deleting records if policies were assigned to policyholders
    if result.deleted_count != 1:
        return jsonify({'error': f"Error deleting policy : {data['policy_id']}"}),500
    
    policyholders = db.policyholders.find({'$or':[
        {'user_policies.'+ data['policy_id'] : {'$exists' : True}},
        {'claims.' : {'$elemMatch': {'policy_id' : data['policy_id']}}}
        ]})
    for policyholder in policyholders:
        result = db.policyholders.update_one({'_id':policyholder['_id']},{'$unset':{f"user_policies.{data['policy_id']}" : "" }})
        if result.modified_count != 1:
            return jsonify({'error': f"Error deleting policy: {data['policy_id']}"}), 500
        
        claims_to_remove = {claim_id for claim_id,claim in policyholder['claims'].items() if claim['policy_id'] == data['policy_id']}
        for claim_id in claims_to_remove:
            result = db.policyholders.update_one({'claim_id': claim_id},{'$unset:' :{f"claims.{claim_id}" : ""}})
            return jsonify({'error': f"Error deleting policy: {data['policy_id']}"}), 500
    return jsonify({'message': 'Policy deleted successfully.'}), 200

    

#delete policyholder
@app.route('/delete-policyholder', methods=["DELETE"])
@token_required
@role_required('policyholder-admin','admin')
def delete_policyholder(current_user):
    raw_data = request.json
    data = sanitize_inputs(raw_data)
    #validations
    if validate_policyholderid(data['policyholder_id']): #check if policyholder exists
        return jsonify({'error':f"Policyholder with id: {data['policyholder_id']} does not exist."}),404
    
    result = db.policyholders.delete_one({
        '_id' : data['policyholder_id']
    })
    if result.deleted_count == 1:
        return f"Policyholder with id: {data['policyholder_id']} deleted successfully."
    else:
        return jsonify({'error':f"Error deleting policyholder: {data['policyholder_id']}"}),500

#delete claim
@app.route('/delete-claim', methods=["DELETE"])
@token_required
@role_required('claim-admin','admin')
def delete_claim(current_user):
    raw_data = request.json
    data = sanitize_inputs(raw_data)
    #validations
    policyholder = db.policyholders.find_one({'claims.' + data['claim_id'] : {'$exists' : True}})
    claims = policyholder['claims']
    if data['claim_id'] not in claims.keys():
        return jsonify({'error':f"Invalid claim id: {data['claim_id']}"}), 404
    if claims[data['claim_id']]['claim_status'] != "Pending":
        return jsonify({'error':f"Invalid claim id: {data['claim_id']} or claim already processed."}), 400
    
    result = db.policyholders.update_one(
        {'_id':policyholder['_id']},
        {'$unset':
         {
             f"claims.{data['claim_id']}" : ""
         }}
    )
    if result.modified_count == 1:
        return f"Claim with id: {data['claim_id']} deleted successfully."
    else:
        return jsonify({'error':f"Error deleting claim: {data['claim_id']}"}),500

    

if __name__ =='__main__':
    app.run(threaded=True)