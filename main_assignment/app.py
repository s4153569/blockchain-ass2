from flask import Flask, render_template, request
import hashlib
import json
import os

app = Flask(__name__)

# RSA key values from the assignment key list
inventory_keys = {
    "Inventory A": {
        "p": 1210613765735147311106936311866593978079938707,
        "q": 1247842850282035753615951347964437248190231863,
        "e": 815459040813953176289801
    },
    "Inventory B": {
        "p": 787435686772982288169641922308628444877260947,
        "q": 1325305233886096053310340418467385397239375379,
        "e": 692450682143089563609787
    },
    "Inventory C": {
        "p": 1014247300991039444864201518275018240361205111,
        "q": 904030450302158058469475048755214591704639633,
        "e": 1158749422015035388438057
    },
    "Inventory D": {
        "p": 1287737200891425621338551020762858710281638317,
        "q": 1330909125725073469794953234151525201084537607,
        "e": 33981230465225879849295979
    }
}

# RSA helper functions

def generate_rsa_components(node_name):
    # Calculate the RSA values used for signing and verifying
    p = inventory_keys[node_name]["p"]
    q = inventory_keys[node_name]["q"]
    e = inventory_keys[node_name]["e"]

    n = p * q
    phi = (p - 1) * (q - 1)

    # d is the private exponent
    d = pow(e, -1, phi)

    return {
        "p": p,
        "q": q,
        "e": e,
        "n": n,
        "phi": phi,
        "d": d
    }


def hash_record(record):
    """
    Converts the inventory record into a SHA-256 hash integer.
    """
    hash_hex = hashlib.sha256(record.encode()).hexdigest()
    hash_int = int(hash_hex, 16)
    return hash_hex, hash_int


def sign_record(record, origin_node):
    # Sign the record hash using the selected inventory node
    rsa = generate_rsa_components(origin_node)
    hash_hex, hash_int = hash_record(record)

    signature = pow(hash_int, rsa["d"], rsa["n"])

    return signature, hash_hex, hash_int


def verify_signature(record, signature, origin_node):
    """
    Verifies the signature using the public key of the origin node.
    recovered_hash = signature^e mod n
    """
    rsa = generate_rsa_components(origin_node)
    hash_hex, hash_int = hash_record(record)

    recovered_hash = pow(signature, rsa["e"], rsa["n"])

    return recovered_hash == hash_int, recovered_hash

# Checks the basic record fields before consensus
def validate_record_format(item_id, quantity, price, location):
    """
    Checks whether the submitted inventory record has a valid format.
    """
    if not item_id.isdigit():
        return False

    if not quantity.isdigit():
        return False

    if not price.isdigit():
        return False

    if location not in ["A", "B", "C", "D"]:
        return False

    return True


# Runs a simple 3-out-of-4 majority vote
def run_consensus(record, signature, origin_node, item_id, quantity, price, location):
    """
    Simplified permissioned majority consensus.
    Each node votes ACCEPT if:
    1. The record format is valid
    2. The RSA signature is valid

    The record is accepted if at least 3 out of 4 nodes vote ACCEPT.
    """
    votes = {}
    accept_count = 0

    for node in inventory_keys.keys():
        format_valid = validate_record_format(item_id, quantity, price, location)
        signature_valid, recovered_hash = verify_signature(record, signature, origin_node)

        if format_valid and signature_valid:
            votes[node] = "ACCEPT"
            accept_count += 1
        else:
            votes[node] = "REJECT"

    consensus_result = accept_count >= 3

    return votes, accept_count, consensus_result


# Local JSON storage
def initialise_storage():
    """
    Creates a JSON file to simulate local storage for each inventory node.
    """
    if not os.path.exists("inventory_storage.json"):
        initial_data = {
            "Inventory A": [],
            "Inventory B": [],
            "Inventory C": [],
            "Inventory D": []
        }

        with open("inventory_storage.json", "w") as file:
            json.dump(initial_data, file, indent=4)


def store_record_in_all_nodes(record):
    """
    Stores the accepted record in each inventory node's local storage.
    Duplicate records are not added again.
    """
    initialise_storage()

    with open("inventory_storage.json", "r") as file:
        data = json.load(file)

    for node in data:
        if record not in data[node]:
            data[node].append(record)

    with open("inventory_storage.json", "w") as file:
        json.dump(data, file, indent=4)

    return data

# Task 3 query section - Harn-style multisignature + RSA encryption

pkg_key = {
    "p": 1004162036461488639338597000466705179253226703,
    "q": 950133741151267522116252385927940618264103623,
    "e": 973028207197278907211
}

procurement_officer_key = {
    "p": 1080954735722463992988394149602856332100628417,
    "q": 1158106283320086444890911863299879973542293243,
    "e": 106506253943651610547613
}

inventory_identity_values = {
    "Inventory A": 126,
    "Inventory B": 127,
    "Inventory C": 128,
    "Inventory D": 129
}

inventory_random_values = {
    "Inventory A": 621,
    "Inventory B": 721,
    "Inventory C": 821,
    "Inventory D": 921
}


def setup_key_components(key):
    p = key["p"]
    q = key["q"]
    e = key["e"]

    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    return {
        "p": p,
        "q": q,
        "e": e,
        "n": n,
        "phi": phi,
        "d": d
    }


pkg_components = setup_key_components(pkg_key)
procurement_components = setup_key_components(procurement_officer_key)


def query_record(item_id):
    initialise_storage()

    with open("inventory_storage.json", "r") as file:
        data = json.load(file)

    for node in data:
        for record in data[node]:
            parts = record.split("|")

            if parts[0] == item_id:
                return record

    return None


def hash_message_for_multisig(message, combined_commitment):
    data = message + str(combined_commitment)
    hash_hex = hashlib.sha256(data.encode()).hexdigest()
    return int(hash_hex, 16) % pkg_components["n"]


def create_multisignature(record):
    """
    Harn-style identity-based multi-signature process.
    Each inventory node creates a partial signature.
    Partial signatures are then aggregated into one combined signature.
    """

    commitments = {}
    combined_commitment = 1

    for node in inventory_identity_values:
        random_value = inventory_random_values[node]

        commitment = pow(
            random_value,
            pkg_components["e"],
            pkg_components["n"]
        )

        commitments[node] = commitment
        combined_commitment = (
            combined_commitment * commitment
        ) % pkg_components["n"]

    challenge = hash_message_for_multisig(record, combined_commitment)

    partial_signatures = {}
    combined_signature = 1

    for node in inventory_identity_values:
        identity = inventory_identity_values[node]
        random_value = inventory_random_values[node]

        identity_private_key = pow(
            identity,
            pkg_components["d"],
            pkg_components["n"]
        )

        partial_signature = (
            identity_private_key *
            pow(random_value, challenge, pkg_components["n"])
        ) % pkg_components["n"]

        partial_signatures[node] = partial_signature

        combined_signature = (
            combined_signature * partial_signature
        ) % pkg_components["n"]

    return {
        "partial_signatures": partial_signatures,
        "combined_signature": combined_signature,
        "combined_commitment": combined_commitment,
        "challenge": challenge,
        "commitments": commitments
    }


def verify_multisignature(record, multisig_data):
    """
    Verifies the aggregated Harn-style multi-signature.
    """

    combined_signature = multisig_data["combined_signature"]
    combined_commitment = multisig_data["combined_commitment"]
    challenge = multisig_data["challenge"]

    left_side = pow(
        combined_signature,
        pkg_components["e"],
        pkg_components["n"]
    )

    product_of_identities = 1

    for node in inventory_identity_values:
        product_of_identities = (
            product_of_identities * inventory_identity_values[node]
        ) % pkg_components["n"]

    right_side = (
        product_of_identities *
        pow(combined_commitment, challenge, pkg_components["n"])
    ) % pkg_components["n"]

    valid = left_side == right_side

    verification_results = {}

    for node in inventory_identity_values:
        verification_results[node] = {
            "valid": valid,
            "left_side": left_side,
            "right_side": right_side
        }

    return verification_results


def encrypt_response(response):
    """
    RSA encryption using Procurement Officer public key.
    The response is split into blocks so it can be safely encrypted.
    """

    n = procurement_components["n"]
    e = procurement_components["e"]

    block_size = (n.bit_length() // 8) - 1
    response_bytes = response.encode()

    encrypted_blocks = []

    for i in range(0, len(response_bytes), block_size):
        block = response_bytes[i:i + block_size]
        message_int = int.from_bytes(block, byteorder="big")

        cipher_int = pow(message_int, e, n)
        encrypted_blocks.append(cipher_int)

    return encrypted_blocks


def decrypt_response(encrypted_response):
    """
    RSA decryption using Procurement Officer private key.
    """

    n = procurement_components["n"]
    d = procurement_components["d"]

    decrypted_bytes = b""

    for cipher_int in encrypted_response:
        message_int = pow(cipher_int, d, n)

        block_length = (message_int.bit_length() + 7) // 8
        block = message_int.to_bytes(block_length, byteorder="big")

        decrypted_bytes += block

    return decrypted_bytes.decode()

# Web routes
@app.route("/", methods=["GET", "POST"])
def index():
    output = None

    if request.method == "POST":
        item_id = request.form["item_id"]
        quantity = request.form["quantity"]
        price = request.form["price"]
        location = request.form["location"]
        origin_node = request.form["origin_node"]

        record = f"{item_id}|{quantity}|{price}|{location}"

        signature, hash_hex, hash_int = sign_record(record, origin_node)

        verification_results = {}

        for node in inventory_keys.keys():
            valid, recovered_hash = verify_signature(record, signature, origin_node)
            verification_results[node] = {
                "valid": valid,
                "recovered_hash": recovered_hash
            }

        votes, accept_count, consensus_result = run_consensus(
            record,
            signature,
            origin_node,
            item_id,
            quantity,
            price,
            location
        )

        storage_data = None

        if consensus_result:
            storage_data = store_record_in_all_nodes(record)

        rsa_components = generate_rsa_components(origin_node)

        output = {
            "record": record,
            "origin_node": origin_node,
            "hash_hex": hash_hex,
            "hash_int": hash_int,
            "signature": signature,
            "rsa_components": rsa_components,
            "verification_results": verification_results,
            "votes": votes,
            "accept_count": accept_count,
            "consensus_result": consensus_result,
            "storage_data": storage_data
        }

    return render_template("index.html", output=output)

@app.route("/query", methods=["GET", "POST"])
def query():

    query_output = None

    if request.method == "POST":

        item_id = request.form["query_item_id"]

        record = query_record(item_id)

        if record is None:

            query_output = {
                "found": False,
                "message": "Record not found."
            }

        else:

            signatures = create_multisignature(record)

            verification_results = verify_multisignature(
                record,
                signatures
            )

            encrypted_response = encrypt_response(record)

            decrypted_response = decrypt_response(
                encrypted_response
            )

            query_output = {
                "found": True,
                "record": record,
                "signatures": signatures,
                "verification_results": verification_results,
                "encrypted_response": encrypted_response,
                "decrypted_response": decrypted_response
            }

    return render_template(
        "query.html",
        query_output=query_output
    )

if __name__ == "__main__":
    initialise_storage()
    app.run(debug=True)

