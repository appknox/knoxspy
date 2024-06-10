import frida, time, json
from queue import Queue

def on_message(message, data):
    print(message)
    print(data)
    if message['type'] == 'send':
        print("[*] Response from Frida script: {0}".format(message['payload']))
    elif message['type'] == 'error':
        print("[!] {0}".format(message['stack']))

device = frida.get_usb_device()
pid = device.spawn(["com.appknox.Ecommerce"])
# pid = device.spawn(["com.example.okhttp"])
device.resume(pid)
session = device.attach(pid)

with open("iOS_makeAPIRequest.js") as f:
# with open("okhttp_repeater.js") as f:
    script_code = f.read()


script = session.create_script(script_code)
script.on('message', on_message)
try:
    script.load()
    print("Script loaded successfully.")
except Exception as e:
    print("An error occurred:", e)


print("Script loaded")
def send_data(data):
    print("Sending the data")
    script.post({'type': 'data', 'payload': data})

# payload = {
#   "method": 'POST',
#   "endpoint": '/api/v1/auth/login/223',
#   "request_headers": '["Content-Type: application/json"]',
#   "request_body": '{"password":"password","email":"user1@test.comffftff"}',
#   "id": 4,
#   "host": '192.168.29.200',
#   "status_code": 200,
#   "response_body": '{"userId": 1,"id": 1,"title": "delectus aut autem","completed": false}',
#   "response_headers": '["HTTP/2 200","Date: Wed, 15 May 2024 02:49:07 GMT","Content-Type: application/json","Content-Length: 83"]',
#   "session_id": 1
# }

payload = {
  "request_body": '{  "password": "password",  "email": "user1@test.comtest"}',
  "request_headers": '["Content-Type: application/json"]',
  "method": 'POST',
  "host": '192.168.29.200',
  "endpoint": '/api/v1/auth/login/',
  "status_code": '200',
  "response_headers": '["Date: Wed, 05 Jun 2024 08:48:59 GMT","Content-Type: application/json","Connection: keep-alive","Content-Length: 43","Server: nginx/1.18.0"]',
  "response_body": '{"message":"Username or Password Invalid"}\n',
  "id": 36
}


queue = Queue()
responses_received = 0


def send_next_batch():
    global responses_received
    responses_received = 0
    for _ in range(10):
        if not queue.empty():
            send_data(queue.get())

# Populate the queue with 100 requests
for _ in range(100):
    queue.put(payload)

# Send the first batch of requests
send_next_batch()

# Keep the script running
input("Press Enter to exit...\n")
# send_data(payload)