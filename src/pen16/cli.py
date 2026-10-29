import argparse
import logging
from importlib.resources import files
from pathlib import Path

import uvicorn
from alembic import command
from alembic.config import Config as AlembicConfig

from pen16 import backups, db, exposure, nmap, runner, stig, tokens, worker


def main() -> None:
    parser = argparse.ArgumentParser(prog="pen16")
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser(
        "ingest", help="record an internal nmap XML scan and report unexpected exposure"
    )
    ingest.add_argument("path", type=Path)
    commands.add_parser("migrate", help="bring the database schema up to date")
    commands.add_parser("worker", help="run schedules, job deadlines, and notification delivery")
    commands.add_parser("runner", help="claim scan jobs from the listener and run them")
    for name, about, port in (
        ("web", "serve the owner dashboard", 8080),
        ("listener", "serve the runner listener", 8443),
        ("intake", "serve the compliance intake hosts push results to", 8444),
    ):
        serve = commands.add_parser(name, help=about)
        serve.add_argument("--host", default="127.0.0.1")
        serve.add_argument("--port", type=int, default=port)
    token = commands.add_parser("token", help="create a token and print it once")
    token.add_argument("name", help="the runner, or for a compliance token the host's asset ID")
    token.add_argument("--kind", choices=["runner", "compliance"], default="runner")
    stig_import = commands.add_parser(
        "stig-import", help="import a DISA STIG's manual XCCDF, the rules a checklist lists"
    )
    stig_import.add_argument("path", type=Path)
    backed_up = commands.add_parser(
        "backed-up", help="record a verified backup (deploy/pen16-backup runs this)"
    )
    backed_up.add_argument("name")
    backed_up.add_argument("size_bytes", type=int)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.command == "ingest":
        scan = nmap.read(args.path)
        with db.connect().begin() as conn:
            opened = exposure.ingest(conn, scan, vantage="internal")
        for finding in opened:
            print(f"unexpected {finding.asset_id} {finding.port}/{finding.protocol} ({finding.vantage})")
    elif args.command == "migrate":
        alembic = AlembicConfig()
        alembic.set_main_option("script_location", str(files("pen16") / "migrations"))
        command.upgrade(alembic, "head")
    elif args.command == "worker":
        worker.run_forever()
    elif args.command == "runner":
        runner.run_forever()
    elif args.command in ("web", "listener", "intake"):
        uvicorn.run(
            f"pen16.{args.command}:app", factory=True, host=args.host, port=args.port, proxy_headers=False
        )
    elif args.command == "token":
        if args.kind == "compliance" and not exposure.ASSET_ID.fullmatch(args.name):
            parser.error(
                "a compliance token's name is the host's asset ID: lowercase letters, digits, and dashes"
            )
        with db.connect().begin() as conn:
            print(tokens.create(conn, args.kind, args.name))
    elif args.command == "stig-import":
        imported = stig.parse(args.path.read_bytes())
        with db.connect().begin() as conn:
            stig.load(conn, imported)
        print(f"{imported.id} {imported.release}: {len(imported.rules)} rules")
    elif args.command == "backed-up":
        with db.connect().begin() as conn:
            backups.record(conn, args.name, args.size_bytes)
