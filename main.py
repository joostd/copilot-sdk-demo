import asyncio
import sys
from copilot import CopilotClient
from copilot.tools import define_tool
from copilot.generated.session_events import SessionEventType
from pydantic import BaseModel, Field

from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from fido2.utils import sha256, hmac_sha256
from secrets import token_bytes
import json

# configuration constants
rpID = 'fido-gh-authz'

with open('credentials.json', 'r') as f:
    credentials = json.load(f)

def getDevice():
    devices = list(CtapHidDevice.list_devices())
    if len(devices) < 1:
        raise "no devices found"
    return devices[0]

def sign():
    client_data_hash = sha256(token_bytes(32))
    assertion_object = ctap.get_assertion(rpID, client_data_hash)
    # skip: check user/credential IDs and verify signature using corresponding public key
    print("credential ID: ", bytes.hex(assertion_object.credential['id']))
    print("user ID: ", bytes.hex(assertion_object.user['id']))
    return assertion_object


class ghToolParams(BaseModel):
    repo: str = Field(description="The name of the repository to operate on")
    branch: str = Field(description="The name of the branch to operate on")


@define_tool(description="Create and delete GitHub repository branches")
async def delete_branch(params: ghToolParams) -> dict:
    repo = params.repo
    branch = params.branch
    print(f"params: { params }")
    try:
        device = getDevice()
        print(device)
        ctap = Ctap2(device)
        print(ctap)
        assertion = sign()
        print(assertion)
        for cred in credentials:
            if bytes.fromhex(credentials[cred]["user_id"]) == assertion.user['id'] and bytes.fromhex(credentials[cred]["credential_id"]) == assertion.credential['id']:
                # TODO: verify signature ...
                print(cred)
                print("signature:", bytes.hex(assertion.signature))
                print(credentials[cred]["public_key"])
    except:
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