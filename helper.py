import re
import html
policies = {}
policyholders = {}


#type codes and id counter
type_codes = {
        'Health': '001', 'Vehicle': '002', 'Home': '003', 'Life': '004', 'Travel': '005'
         }
type_count = {code : 0 for code in type_codes.values()}

claim_count = 0

#regex 
email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-z0-9-.]+\.[a-zA-Z]{2,}$'
phone_pattern = r'^[9876][0-9]{9}$'

#generate policy id 
def generate_policyid(type):
    try:
        type_code = type_codes[type]
    except ValueError:
        return f"Invalid type entered: {type}"
    type_count[type_code] +=1
    return f"{type_code}_{type_count[type_code]:03d}"


def generate_policyholderid():
    return max(policyholders.keys(),default=0) + 1

def generate_claim_id():
    global claim_count
    claim_count +=1
    return f"{claim_count:06d}"

# sanitize inputs
def sanitize_inputs(data):
    def sanitize_value(value):
        if isinstance(value, str):
            value = html.escape(value)
            value = re.sub(r"('|\"|;|--|\/\*|\*\/|\\)", "", value)
            value = re.sub(r"<script.*?>.*?</script>", "", value, flags=re.I | re.S)
        return value

    if isinstance(data, dict):
        sanitized_data = {key: sanitize_value(value) for key, value in data.items()}
        return sanitized_data
    elif isinstance(data, str):
        return sanitize_value(data)
    else:
        return data

#validations

#check if policy id is valid
def validate_policyid(policy_id):
    return policy_id in policies

#check if policy name exists
def validate_policy_name(param): 
    for policy in policies.values():
        if param == policy['policy_name']:
            return True
    return False

#check if policyholder id is valid
def validate_policyholderid(policyholder_id):
    return policyholder_id in policyholders

#validate email
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
        for policyholder in policyholders.values():
            if phone == policyholder.get('phone'):
                return False
        return True
    except (ValueError,TypeError):
        return False

#check if claim id is valid
def validate_claim_id(claim_id):
    for policyholder_info in policyholders.values():
        if claim_id in policyholder_info['claims']:
            return True
    return False

def validate_claim_status(claim_id,policyholder_id):    
    return policyholders[policyholder_id]['claims'][claim_id]['claim_status'] == "Pending"

#check if claim_amt is valid without using policyholder_id or policy_id
def get_ids(claim_id):
    for policyholder_key,policyholder_info in policyholders.items():
        if claim_id in policyholder_info['claims']:
            policy_id = policyholder_info['claims'][claim_id]['policy_id']
            return policyholder_key, policy_id
    return None, None

#validate claim_amt
def validate_claim_amt(policyholder_id, claim_amt, policy_id):
    return claim_amt < policyholders[policyholder_id]['user_policies'][policy_id]['available_limit']

#validate premium and max_claim_amt
def validate_policy_inputs(premium,max_claim_amt):
    try: 
        premium = float(premium)
        max_claim_amt = float(max_claim_amt)
        if premium < 1 or max_claim_amt < 1 or premium > max_claim_amt:
            return False
        return True
    except (ValueError,TypeError):
        return False
    

#validate user-policy before filing claim
#validate if user has the policy before assigning (check for duplicates)
#using the same check for both 
def validate_user_policy(policyholder_id,policy_id):
    return policy_id in policyholders[policyholder_id]['user_policies']

