import argparse
from pathlib import Path

from pen15 import db, exposure, nmap


def main() -> None:
    parser = argparse.ArgumentParser(prog="pen15")
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser(
        "ingest", help="record an internal nmap XML scan and report unexpected exposure"
    )
    ingest.add_argument("path", type=Path)
    args = parser.parse_args()

    scan = nmap.read(args.path)
    with db.connect().begin() as conn:
        opened = exposure.ingest(conn, scan, vantage="internal")
    for finding in opened:
        print(f"unexpected {finding.asset_id} {finding.port}/{finding.protocol} ({finding.vantage})")
