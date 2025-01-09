from flask import Flask, jsonify, request
import datetime
from helper import (
    validate_claim_amt, validate_claim_id, validate_claim_status, validate_email,
    validate_phone, validate_policy_inputs, validate_policy_name, validate_policyholderid,
    validate_policyid, validate_user_policy, generate_claim_id, generate_policyholderid, generate_policyid,
    get_ids,policies,policyholders,sanitize_inputs
)

app = Flask(__name__)

#dictionaries
default = {}

#get

#get policyholder_info
@app.route('/policyholders',methods=['GET'])
def get_policyholders_info():
    return jsonify(policyholders),200

#get policy_info
@app.route('/policies',methods=["GET"])
def get_policies():
    return jsonify(policies),200

#get claims
@app.route('/get-claims',methods=["GET"])
def get_claims():
    claim_dict = {}
    for policyholder_id, policyholder_info in policyholders.items():
        for claim_id, claim_info in policyholder_info['claims'].items():
            claim_dict[claim_id] = {
                'policyholder_id' : policyholder_id,
                'policy_id' : claim_info['policy_id'],
                'claim_amt' : claim_info['claim_amt'],
                'claim_status' : claim_info['claim_status'],
                'claim_date' : claim_info['claim_date']
            }
    return jsonify(claim_dict),200
               
#get pending claims
@app.route('/get-pending-claims',methods=["GET"])
def get_pending_claims():
    claim_dict = {}
    for policyholder_id, policyholder_info in policyholders.items():
        for claim_id, claim_info in policyholder_info['claims'].items():
            if claim_info['claim_status'] == "Pending":   
                claim_dict[claim_id] = {
                    'policyholder_id' : policyholder_id,
                    'policy_id' : claim_info['policy_id'],
                    'claim_amt' : claim_info['claim_amt'],
                    'claim_status' : claim_info['claim_status'],
                    'claim_date' : claim_info['claim_date']
                }
    return jsonify(claim_dict),200



#post

#create policy
@app.route('/create-policy',methods=["POST"])
def create_policy():
    data = sanitize_inputs(request.json)

    #check policy name exists
    if validate_policy_name(data['policy_name']):
        return jsonify({'error':f"Policy with name :{data['plicy_name']} exists already."}), 409

    #check if premium and max_claim_amt are valid
    if not validate_policy_inputs(data['premium'],data['max_claim_amt']):
        return jsonify({'error':f"Invalid inputs for premium: {data['premium']} and max_claim_amt: {data['max_claim_amt']}."}) , 400

    policy_id = generate_policyid(data['type'])
    policies[policy_id] = {
        'policy_name': data['policy_name'],
        'description' : data['description'],
        'type' : data['type'],
        'max_claim_amt' : data['max_claim_amt'],
        'premium' : data['premium'],
        'tenure' : data['tenure'],
        'launch_date' : f"{datetime.datetime.now().date()}"
    }
    return "Policy created successfully."


#create policyholder
@app.route('/create-policyholder',methods = ["POST"])
def create_policyholder():
    data = sanitize_inputs(request.json)

    #check phone number
    if not validate_phone(data['phone']):
        return jsonify({'error':f"Invalid phone number: {data['phone']} or phone number already exists."}),400
    #check email
    if not validate_email(data['email']):
        return jsonify({'error':f"Invalid email: {data['email']}."}), 400
    
    policyholder_id = generate_policyholderid()

    policyholders[policyholder_id] = {
        'name' : data['name'],
        'email' : data['email'],
        'phone' : data['phone'],
        'dob':f"{datetime.datetime.strptime(data['dob'],'%Y-%m-%d').date()}",
        'user_policies' : {},
        'claims' : {},
        'registration_date' : f"{datetime.datetime.now().date()}"
    }
    return "Policyholder created successfully."

#assign policy
@app.route('/assign-policy',methods=["POST"])
def assign_policy():
    data = sanitize_inputs(request.json)

    #check if policyholder exists
    if not validate_policyholderid(data['policyholder_id']):
        return jsonify({'error':f"Policyholder: {data['policyholder_id']} deos not exist."}),404
    #check if policy exists 
    if not validate_policyid(data['policy_id']):
        return jsonify({'error':f"Policy id: {data['policy_id']} does not exist."}),404
    #check if user has the policy already
    if validate_user_policy(data['policyholder_id'],data['policy_id']):
        return jsonify({'error':f"Policy: {data['policy_id']} already exists for policyholder: {data['policyholder_id']}"}), 409
    
    default = {
        'max_limit': policies[data['policy_id']]['max_claim_amt'],
        'available_limit' : policies[data['policy_id']]['max_claim_amt'],
        'start_date' : f"{datetime.datetime.now().date()}"
    }

    policyholders[data['policyholder_id']]['user_policies'][data['policy_id']] = default
    return "Policy assigned successfully."

#file claim
@app.route('/file-claim',methods=["POST"])
def file_claim():
    data = sanitize_inputs(request.json)

    #check if policyholder is valid
    if not validate_policyholderid(data['policyholder_id']):
        return jsonify({'error':f"Policyholder: {data['policyholder_id']} does not exist."})
    #check if policy id is valid
    if not validate_policyid(data['policy_id']):
        return jsonify({'error':f"Policy: {data['policy_id']} does not exist."})
    #check if policy exist for policyholder
    if not validate_user_policy(data['policyholder_id'],data['policy_id']):
        return jsonify({'error':f"Policy: {data['policy_id']} does not exist for {data['policyholder_id']}."})
    #validate claim amount
    if not validate_claim_amt(data['policyholder_id'],data['claim_amt'],data['policy_id']):
        return jsonify({'error':f"Claim amount: {data['claim_amt']} cannot exceed {policyholders[data['policyholder_id']]['user_policies'][data['policy_id']]['available_limit']} ."})
    
    claim_id = generate_claim_id()
    
    default = {
        claim_id : {
            'policy_id' : data['policy_id'],
            'claim_amt' : data['claim_amt'],
            'claim_status' : 'Pending',
            'claim_date' : f"{datetime.datetime.now().date()}"
        }
    }
    policyholders[data['policyholder_id']]['claims'][claim_id] = default
    return "Claim filed successfully."


#put

#update policyholder
@app.route('/update-policyholder',methods=["PUT"])
def update_policyholder():
    data = sanitize_inputs(request.json)

    #check if policyholder exist
    if not validate_policyholderid(data['policyholder_id']):
        return jsonify({'error':f"Policyholder with id: {data['policyholder_id']} does not exist."}) , 404
    policyholders[data['policyholder_id']].update({
        'name' : data['name'],
        'email' : data['email'],
        'phone' : data['phone'],
        'dob':f"{datetime.datetime.strptime(data['dob'],'%Y-%m-%d').date()}",
        'update_timestamp' : f"{datetime.datetime.now()}"
    })
    return "Record updated successfully."

#update policy
@app.route('/update-policy',methods=["PUT"])
def update_policy():
    data = sanitize_inputs(request.json)

    #check
    if not validate_policyid(data['policy_id']):
        return jsonify({'error':f"Policy with id: {data['policy_id']} does not exist."}) , 404
    policies[data['policy_id']].update({
        'policy_name': data['policy_name'],
        'description' : data['description'],
        'type' : data['type'],
        'update_timestamp' : f"{datetime.datetime.now()}"
    })
    return "Policy updated successfully."

#update claim_amt
@app.route('/update-claim-amount',methods=["PUT"])
def update_claim_amt():
    data = sanitize_inputs(request.json)
    
    #check if claim id exists
    if not validate_claim_id(data['claim_id']):
        return jsonify({'error':f"Claim with id: {data['claim_id']} does not exist."}) , 404
    #get ids
    policyholder_id,policy_id = get_ids(data['claim_id'])
    #validate claim_amt
    if not validate_claim_amt(policyholder_id,data['claim_amt'],policy_id):
        return jsonify({'error':f"Invalid claim_amt for: {data['claim_id']}, amount cannot exceed: {policyholders[policyholder_id]['user_policies'][policy_id]['available_limit']}"}),400
    
    policyholders[policyholder_id]['claims'][data['claim_id']]['claim_amt'] = data['claim_amt']
    return "Claim amount updated successfully"

#update claim status
@app.route('/update-claim-status',methods=["PUT"])
def update_claim_status():
    data = sanitize_inputs(request.json)
    
    #check if claim id exists
    if not validate_claim_id(data['claim_id']):
        return jsonify({'error':f"Claim with id: {data['claim_id']} does not exist."}) , 404
    #get ids
    policyholder_id,policy_id = get_ids(data['claim_id'])
    #check if claim status is pending
    if not validate_claim_status(data['claim_id'],policyholder_id):
        return jsonify({'error':f"Claim already processed."}),400
    
    #update available limit if claim passed 
    if data['claim_status'] == "Accepted":
        policyholders[policyholder_id]['user-policies'][policy_id]['available_limit'] -= policyholders[policyholder_id]['claims'][data['claim_id']]['claim_amt']

    #update status 
    policyholders[policyholder_id]['claims'][data['claim_id']]['claim_status'] = data['claim_status']
    
    return "Claim processed successfully."




#delete

#delete policyholder
@app.route('/delete-policyholder', methods=["DELETE"])
def delete_policyholder():
    data = sanitize_inputs(request.json)

    #check if policyholder exists
    if not validate_policyholderid(data['policyholder_id']):
        return jsonify({'error':f"Policyholder with id: {data['policyholder_id']} does not exist."}) , 404
    
    policyholders.pop(data['policyholder_id'])
    return "Policyholder deleted successfully."

#delete policy
@app.route('/delete-policy',methods=["DELETE"])
def delete_policy():
    data = sanitize_inputs(request.json)

    #check if policy exists
    if not validate_policyid(data['policy_id']):
        return jsonify({'error':f"Policy with id: {data['policy_id']} does not exist."}) , 404

    #removing the policy from policy table
    policies.pop(data['policy_id'])

    #removing the policy from policyholders['user_policies']
    for policyholder_key , policyholder_value in policyholders.items():
        if data['policy_id'] in policyholder_value['user_policies']:
            policyholders[policyholder_key]['user_policies'].pop(data['policy_id'])
    #removing the claims made for the policy
    for policyholder_key, policyholder_value in policyholders.items():
        claims_to_delete = [claim_id for claim_id, claim_info in policyholder_value['claims'].items() if claim_info['policy_id'] == data['policy_id']]

        for claim_id in claims_to_delete:
            policyholders[policyholder_key]['claims'].pop(claim_id)
    
    return "Policy data deleted successfully."

#delete claim
@app.route('/delete-claim',methods=["DELETE"])
def delete_claim():
    data = sanitize_inputs(request.json)

    #check if claim is valid
    if not validate_claim_id(data['claim_id']):
        return jsonify({'error':f"Claim id: {data['claim_id']} does not exist."}),404
    #check if claim is pending
    if not validate_claim_status(data['claim_id'], get_ids(data['claim_id'])[0]):
        return jsonify({'error':f"Claim with id: {data['claim_id']} has been processed."}), 400

    policyholder_key,_ = get_ids(data['claim_id'])

    policyholders[policyholder_key]['claims'].pop(data['claim_id'])

    return "Claim deleted successfully."



if __name__ == "__main__":
    app.run(host='127.0.0.7',port=50)