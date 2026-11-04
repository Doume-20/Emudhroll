import argparse
import asyncio
import logging

from pathlib import Path

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from dmbackend import device_management_backend_pb2 as proto

parser = argparse.ArgumentParser()
parser.add_argument("-e", "--enroll", action="store_true", help="temporarily re enroll the device with the saved dmtoken")
parser.add_argument("-b", "--backup", action="store_true", help="backup the dmtoken to a file")
parser.add_argument("-v", "--verbose", action="store_true", help="enable mitmproxy verbose logging")
args = parser.parse_args()

class DMProxy:
    def __init__(self, master: DumpMaster, enroll: bool = False, backup: bool = False) -> None:
        self.master = master
        self.enroll = enroll
        self.backup = backup
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

        if self.backup:
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
            response = proto.DeviceManagementResponse()
            response.device_state_retrieval_response.restore_mode = 4 if self.enroll else 0

            flow.response = http.Response.make(
                200, response.SerializeToString(),
                {"Content-Type": "application/x-protobuffer"},
            )

            print("[proxy] sent crafted device state retrieval response")
            return

        if self.enroll and req_type == "certificate_based_register":
            data = proto.DeviceManagementResponse()
            data.register_response.device_management_token = self.dmtoken
            data.register_response.enrollment_type = proto.DeviceRegisterResponse.ENTERPRISE

            flow.response = http.Response.make(
                200, data.SerializeToString(),
                {"Content-Type": "application/x-protobuffer"},
            )

            print("[proxy] spoofed device registration response with saved dmtoken")
            return

        if self.enroll:
            flow.request.query["deviceid"] = self.deviceid

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.backup:
            return
        if "/devicemanagement/" not in flow.request.path:
            return
        if flow.request.query.get("request") != "certificate_based_register":
            return
        if flow.response.status_code != 200:
            return

        data = proto.DeviceManagementResponse()
        data.ParseFromString(flow.response.content)

        deviceid = flow.request.query.get("deviceid")
        dmtoken = data.register_response.device_management_token

        dmtoken_file = Path("dmtoken.txt")
        dmtoken_file.write_text(f"{deviceid}:{dmtoken}")

        print(f"[proxy] got dmtoken: {dmtoken}, wrote dmtoken file out to {dmtoken_file.resolve()}")
        self.master.shutdown()

async def main():
    opts = Options(allow_hosts=["m.google.com", "edgedl.me.gvt1.com"])
    master = DumpMaster(opts, with_termlog=args.verbose, with_dumper=args.verbose)
    master.addons.add(DMProxy(master, enroll=args.enroll, backup=args.backup))

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    opts.update(emudhra=True)

    print("[proxy] listening at *:8080")
    await master.run()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
