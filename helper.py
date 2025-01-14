import re
import html
from config import db
from flask import jsonify
#regex 
email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-z0-9-.]+\.[a-zA-Z]{2,}$'
phone_pattern = r'^[9876][0-9]{9}$'

#email validation
def validate_email(email):
    try:
        if not re.match(email_pattern,email):
            return False
        return True
    except(TypeError,ValueError):
        return False

#validate phone number
def validate_phone(phone):
    try:
        if not re.match(phone_pattern,phone):
            return False
        return db.policyholders.find_one({'phone': phone}) is None
    except (ValueError,TypeError):
        return False

#type dictionary
type_codes = {
        'Health': '001', 'Vehicle': '002', 'Home': '003', 'Life': '004', 'Travel': '005'
         }
#generate ids

#generate policyid
def generate_policyid(policy_type):
    if policy_type not in type_codes:
        return f"Invalid policy type: {policy_type}"
    
    type_code = type_codes[policy_type]

    counter = db.counters.find_one_and_update(
        {'_id': policy_type},
        {'$inc': {'count' : 1}},
        upsert = True,
        return_document=True
    )
    count = counter['count']

    policy_id = f"{type_code}_{count:03d}"

    return policy_id

#generate policyholder id
def generate_policyholderid():
    counter = db.counters.find_one_and_update(
        {'_id':'policyholders'},
        {'$inc': {'count':1}},
        upsert = True,
        return_document=True
    )
    count = counter['count']
    policyholder_id = f"PH{count:09d}"

    return policyholder_id

#generate claim id
def generate_claimid():
    counter = db.counters.find_one_and_update(
        {'_id' : 'claims'},
        {'$inc' : {'count':1}},
        upsert=True,
        return_document=True
    )
    count = counter['count']
    claim_id = f"CLAIM{count:09d}"
    return claim_id

#sanitize data
def sanitize_inputs(data):
    def sanitize_value(value):
        if isinstance(value,str):
            value = html.escape(value)

            value = re.sub(r"('|\"|;|--|\/\*|\*\/|\\)", "", value)

            value = re.sub(r"<script.*?>.*?</script>", "", value, flags=re.I|re.S)
            return value
    def convert_to_int(value):
        try:
            return int(value)
        except (ValueError, TypeError):
            return value
    if isinstance(data, dict):
        sanitized_data = {key: sanitize_value(value) for key, value in data.items()}
        if 'max_claim_amt' in sanitized_data:
            sanitized_data['max_claim_amt'] = convert_to_int(sanitized_data['max_claim_amt'])
        if 'claim_amt' in sanitized_data:
            sanitized_data['claim_amt'] = convert_to_int(sanitized_data['claim_amt'])
        return sanitized_data
    elif isinstance(data, str):
        return sanitize_value(data)
    else:
        return data

#validation checks

#check for whether the user exists || can be used to verify when registering and logging in both
def validate_username(username,context):
    user = db.users.find_one({'username':username})
    if context == "register":
        if user:
            return jsonify({'error':f"User with username: {username} exists"}), 400
    elif context == "login":
       if not user:
           return jsonify({'error':'User does not exist'}), 404
    return user
   

#check for policy name already in db
def validate_policy_name(policy_name,policy_id=None):
    query = {'policy_name':policy_name}
    if policy_id:
        query['_id'] = {'$ne': policy_id}
    return db.policies.find_one(query) is not None

#check for valid inputs for premium and max_claim_amt
# def validate_policy_inputs(premium,max_claim_amt):
#     return 0 < premium < max_claim_amt

def validate_phone(phone,policyholder_id=None):
    query = {'phone':phone}
    if policyholder_id:
        query['_id'] = {'$ne': policyholder_id}
    return db.policyholders.find_one(query) is not None

#check whether policy with policy_id exists
def validate_policyid(policy_id):
    return db.policies.find_one({'_id' : policy_id}) is None

#check whether policyholder with policyholder_id exist or not
def validate_policyholderid(policyholder_id):
    return db.policyholders.find_one({'_id':policyholder_id}) is None

#check whether policy exists for the policyholder
def validate_user_policy(policyholder_id,policy_id):
    policyholder  = db.policyholders.find_one({'_id':policyholder_id})
    return policy_id in policyholder['user_policies']

#validate the claim_amt
def validate_claim_amt(policyholder_id,policy_id,claim_amt):
    policyholder = db.policyholders.find_one({'_id':policyholder_id })
    user_policy = policyholder['user_policies'].get(policy_id)
    return claim_amt < user_policy['available_limit']

#validate claim status is pending before updating
# def validate_claim_status(claim_id):
#     result = db.policyholders.find_one({'claims.' + claim_id : {'$exists':True}}, {'claims.' +claim_id :1})
#     return result['claim_status'] == "Pending"
