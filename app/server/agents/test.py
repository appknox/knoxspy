import frida
import sys
import time
import json

# Change this to your target app's package name
PACKAGE_NAME = "com.appknox.mfva"
PACKAGE_NAME = "MFVA"

# Get the USB device (usually Android)
device = frida.get_usb_device()

print("[*] Spawning app...")
# pid = device.spawn([PACKAGE_NAME])
processes = device.enumerate_processes()
pid = None
for process in processes:
    print(f"[*] Found process {process.name} with PID {process.pid}")
    if process.name == PACKAGE_NAME:
        print(f"[*] Matched process {PACKAGE_NAME} with PID {process.pid}")
        pid = process.pid
        break

print(f"[*] Attaching to process {PACKAGE_NAME} with PID {pid}")
# Attach to the app using package name
session = device.attach(pid)

# Load the agent script
with open("android_makeAPIRequest.js") as f:
    script = session.create_script(f.read())

# Callback for messages from the agent
def on_message(message, data):
    if message['type'] == 'send':
        # This is a message sent using send({...}) in agent.js
        print("[*] Message from agent:", message['payload'])
        print(json.loads(message['payload'])['request_headers'])
        print(json.loads(message['payload'])['response_headers'])
    elif message['type'] == 'error':
        # If there is a script error
        print("[!] Error:", message['stack'])
    elif message['type'] == 'log':
        # This will capture console.log output
        print("[LOG]", message['payload'])
    else:
        print("[?] Other message:", message)


script.on("message", on_message)

# Load the script into the app
script.load()

# device.resume(pid)   

# Send a payload to the agent
sample_requests = [
    {
        "method": "GET",
        "endpoint": "/get?param=value",
        "request_headers": {
            "Accept": "application/json"
        },
        "request_body": None,
        "id": "req-001",
        "protocol": "https",
        "host": "httpbin.org",
        "status_code": 200,
        "response_body": "",
        "response_headers": {},
        "session_id": "session-001"
    },
    {
        "method": "POST",
        "endpoint": "/post",
        "request_headers": {
            "Content-Type": "application/json"
        },
        "request_body": '{"key": "value"}',
        "id": "req-002",
        "protocol": "https",
        "host": "httpbin.org",
        "status_code": 200,
        "response_body": "",
        "response_headers": {},
        "session_id": "session-002"
    },
    {
        "method": "PUT",
        "endpoint": "/put",
        "request_headers": {
            "Content-Type": "application/json"
        },
        "request_body": '{"update": "info"}',
        "id": "req-003",
        "protocol": "https",
        "host": "httpbin.org",
        "status_code": 200,
        "response_body": "",
        "response_headers": {},
        "session_id": "session-003"
    },
    {
        "method": "DELETE",
        "endpoint": "/delete",
        "request_headers": {
            "Authorization": "Bearer sometoken"
        },
        "request_body": None,
        "id": "req-004",
        "protocol": "https",
        "host": "httpbin.org",
        "status_code": 200,
        "response_body": "",
        "response_headers": {},
        "session_id": "session-004"
    },
    {
        "method": "HEAD",
        "endpoint": "/get",  # httpbin treats HEAD same as GET but without body
        "request_headers": {
            "Accept": "*/*"
        },
        "request_body": None,
        "id": "req-005",
        "protocol": "https",
        "host": "httpbin.org",
        "status_code": 200,
        "response_body": "",
        "response_headers": {},
        "session_id": "session-005"
    },
    {
        "method": "OPTIONS",
        "endpoint": "/anything",
        "request_headers": {
            "Access-Control-Request-Method": "POST",
            "Origin": "https://example.com"
        },
        "request_body": None,
        "id": "req-006",
        "protocol": "https",
        "host": "httpbin.org",
        "status_code": 200,
        "response_body": "",
        "response_headers": {},
        "session_id": "session-006"
    },
    {
        "method": "PATCH",
        "endpoint": "/patch",
        "request_headers": {
            "Content-Type": "application/json"
        },
        "request_body": '{"patch": "data"}',
        "id": "req-007",
        "protocol": "https",
        "host": "httpbin.org",
        "status_code": 200,
        "response_body": "",
        "response_headers": {},
        "session_id": "session-007"
    },
    {
        "method": "TRACE",
        "endpoint": "/anything",  # httpbin doesn't support /trace, but /anything echoes
        "request_headers": {
            "Content-Type": "message/http"
        },
        "request_body": None,
        "id": "req-008",
        "protocol": "https",
        "host": "httpbin.org",
        "status_code": 200,
        "response_body": "",
        "response_headers": {},
        "session_id": "session-008"
    }
]

tmp_payload = {
    "id": 8,
    "protocol": 'http',
    "host": 'vapi.appknox.io',
    "status_code": '',
    "response_body": '',
    "response_headers": '',
    "session_id": 5,
    "method": 'GET',
    "endpoint": '/uptime',
    "request_headers": '["Host: vapi.appknox.io","X-Auth-Token: 700a502d0762cb23733f4cf8ecb384e3"]',
    "request_body": ' '
}

script.post({
    "type": "data",
    "payload": tmp_payload
})
# # Keep running so the script stays alive
sys.stdin.read()
