#!/usr/bin/env python3
import asyncio
import sys
from copilot import CopilotClient
from copilot.tools import define_tool
from copilot.generated.session_events import SessionEventType
from pydantic import BaseModel, Field

from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from fido2.ctap import CtapError
from fido2.utils import sha256, hmac_sha256
from secrets import token_bytes
import json
import yaml
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# configuration constants
rpID = 'fido-gh-authz'

try:
    with open('credentials.json', 'r') as f:
        credentials = json.load(f)
except FileNotFoundError:
    print("credentials.json not found. Creating empty credentials file.")
    credentials = {}
    with open('credentials.json', 'w') as f:
        json.dump(credentials, f)

def getDevice():
    devices = list(CtapHidDevice.list_devices())
    if len(devices) < 1:
        raise "no devices found"
    return devices[0]

def sign(ctap: CtapHidDevice, datatobesigned: bytes ):
    client_data_hash = sha256(datatobesigned)
    assertion_object = ctap.get_assertion(rpID, client_data_hash)
    return assertion_object


class ghToolParams(BaseModel):
    repo: str = Field(default="local", description="The name of the repository to operate on (defaults to local repository)")
    branch: str = Field(description="The name of the branch to operate on")


@define_tool(description="Delete GitHub repository branches")
async def delete_branch(params: ghToolParams) -> dict:
    nonce = token_bytes(32)
    datatobesigned = json.dumps({
        "tool": "delete_branch",
        "repo": params.repo,
        "branch": params.branch,
        "nonce": nonce.hex()
    }).encode('utf-8')
    record = { "transaction": {
        "data": datatobesigned.decode('utf-8'),
        "client_data_hash": sha256(datatobesigned).hex(),
        "rp_id": rpID,
        "verified": False,
    }}
    try:
        device = getDevice()
        print("Data to be signed:")
        print(datatobesigned.decode('utf-8'))
        print(f"To authorize this operation, please touch your device ({device.product_name}) ")
        ctap = Ctap2(device)
        assertion = sign(ctap, datatobesigned)
        record["transaction"]["signature"] = bytes.hex(assertion.signature)
        record["transaction"]["credential_id"] = bytes.hex(assertion.credential['id'])
        record["transaction"]["user_id"] = bytes.hex(assertion.user['id'])
        # Find the credential in our store
        credential_found = False
        for cred in credentials:
            if bytes.fromhex(credentials[cred]["user_id"]) == assertion.user['id'] and bytes.fromhex(credentials[cred]["credential_id"]) == assertion.credential['id']:
                credential_found = True
                # Verify ECDSA signature
                try:
                    x = int(credentials[cred]["public_key"]["x"], 16)
                    y = int(credentials[cred]["public_key"]["y"], 16)
                    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
                    public_key = public_numbers.public_key(default_backend())
                    
                    # Verify signature over auth_data + client_data_hash
                    signed_data = assertion.auth_data + sha256(datatobesigned)
                    public_key.verify(
                        assertion.signature,
                        signed_data,
                        ec.ECDSA(hashes.SHA256())
                    )
                    record["transaction"]["verified"] = True
                    record["transaction"]["credential_name"] = cred
                except Exception as verify_error:
                    record["transaction"]["verified"] = False
                    record["transaction"]["verification_error"] = str(verify_error)
        print("\033[96m" + yaml.dump(record, default_flow_style=False) + "\033[0m")
        if not credential_found:
            print("No matching credential found in credential store.")
            return {"result": "fail", "reason": "credential not found"}
        if record["transaction"]["verified"] == False:
            print("Signature verification failed. Aborting operation.")
            return {"result": "fail", "reason": "signature verification failed"}
        # Here you would add the actual GitHub API call to delete the branch
        print(f"Deleting branch '{params.branch}' in repository '{params.repo}'....")
    except CtapError as e:
        if e.code == 0x2E:  # NO_CREDENTIALS
            print("No credentials found on security key for this RP ID.")
            return {"result": "fail", "reason": "no credentials on device"}
        else:
            print(f"CTAP error occurred: {e.code:#x} - {e}")
            return {"result": "fail", "reason": f"CTAP error {e.code:#x}"}
    except Exception as e:
        print(f"Error occurred: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return {"result": "fail"}
    return {"result": "ok"}


async def main():
    client = CopilotClient()
    await client.start()

    session = await client.create_session({
        "model": "gpt-4.1",
        "streaming": True,
        "tools": [delete_branch],
        # "mcpServers": {
        #     "github": {
        #         "type": "http",
        #         "url": "https://api.githubcopilot.com/mcp/",
        #     }
        # }
    })

    def handle_event(event):
        if event.type == SessionEventType.ASSISTANT_MESSAGE_DELTA:
            sys.stdout.write(event.data.delta_content)
            sys.stdout.flush()

    session.on(handle_event)

    print("×  GitHub Assistant (type 'exit' to quit)")
    print("   Try: 'Delete the branch with name \"test\"' or 'remove branch \"patch-1\"'\n")

    while True:
        try:
            user_input = input("You: ")
        except EOFError:
            break

        if user_input.lower() == "exit":
            break

        sys.stdout.write("Assistant: ")
        await session.send_and_wait({"prompt": user_input})
        print("\n")

    await client.stop()

asyncio.run(main())
