from flask import Flask, render_template, request
import hashlib
import json
import os

app = Flask(__name__)

# ============================================================
# RSA KEY PARAMETERS FROM LIST OF KEYS
# ============================================================

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


# ============================================================
# RSA KEY GENERATION FUNCTIONS
# ============================================================

def generate_rsa_components(node_name):
    """
    Generates n, phi, and d from p, q, and e.
    These values are required for RSA digital signatures.
    """
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
    """
    Signs the record using the private key of the origin node.
    signature = hash^d mod n
    """
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


# ============================================================
# SIMPLE RECORD VALIDATION
# ============================================================

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


# ============================================================
# CONSENSUS MECHANISM
# ============================================================

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


# ============================================================
# LOCAL STORAGE
# ============================================================

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


# ============================================================
# WEB ROUTE
# ============================================================

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


if __name__ == "__main__":
    initialise_storage()
    app.run(debug=True)