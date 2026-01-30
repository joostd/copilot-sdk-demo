#!/usr/bin/env python3

"""
Register a resident FIDO credential, using USB
Insert a FIDO2 security key in a USB port, and run with:
	ykman script register.py
"""

from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from fido2.ctap import CtapError
from fido2.utils import sha256, hmac_sha256
from getpass import getpass
from secrets import token_bytes
from argparse import ArgumentParser
import json

# configurartion constants
rpID = 'fido-gh-authz'
rpName = "GitHub Authorization Assistant"

parser = ArgumentParser(description='register a FIDO credential')
parser.add_argument('--username', dest='username', required=True, help='username for the user to register ')
args = parser.parse_args()
user_name = args.username

try:
    with open('credentials.json', 'r') as f:
        credentials = json.load(f)
except FileNotFoundError:
    print("credentials.json not found. Creating empty credentials file.")
    credentials = {}
    with open('credentials.json', 'w') as f:
        json.dump(credentials, f)

devices = list(CtapHidDevice.list_devices())
if not devices:
    print("No devices found")
    exit()

print("Enrolling new credential for user:", user_name)
# assume a single SK connected to USB
ctap = Ctap2(devices[0])
client_data_hash = sha256(token_bytes(32))

pin = getpass("Enter your security key PIN: ")
client_pin = ClientPin(ctap)
try:
    pin_token = client_pin.get_pin_token(pin)
except CtapError as e:
    if e.code == 0x31:  # PIN_INVALID
        print("Error: Incorrect PIN.")
        exit(1)
    elif e.code == 0x32:  # PIN_BLOCKED
        print("Error: PIN blocked. Too many incorrect attempts.")
        exit(1)
    elif e.code == 0x34:  # PIN_AUTH_BLOCKED
        print("Error: PIN authentication blocked. Remove and reinsert the security key.")
        exit(1)
    else:
        print(f"Error: CTAP error {e.code:#x} - {e}")
        exit(1)
pin_auth = hmac_sha256(pin_token, client_data_hash)
if user_name in credentials:
    user_id = bytes.fromhex(credentials[user_name]["user_id"])
else:
    user_id = token_bytes(16)

print("Please touch your security key to complete enrollment...")
attestation_object = ctap.make_credential(
    client_data_hash,
    rp = { "id": rpID, "name": rpName },
    user = { "id": user_id, "name": user_name, "displayName": user_name },
    key_params = [{"type": "public-key", "alg": -7}],
    pin_uv_param=pin_auth,
    pin_uv_protocol=2,
    options = {"rk": True}
)
# skip: validate attestation_object

credentials[user_name] = {
    'user_id': bytes.hex(user_id),
    'credential_id': bytes.hex(attestation_object.auth_data.credential_data.credential_id),
    'public_key': {
	'x': bytes.hex(attestation_object.auth_data.credential_data.public_key[-2]),
	'y': bytes.hex(attestation_object.auth_data.credential_data.public_key[-3])
    }
}

# sync credentials to file
with open('credentials.json', 'w') as f:
    json.dump(credentials, f)


print("Credential registered successfully for user:", user_name)
