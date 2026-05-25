"""
Argus — CLI Entrypoint
Enterprise-grade AI security evaluation framework.

Usage:
  argus scan --target ./my-agent-config/
  argus scan --target https://github.com/org/repo
  argus scan --target ./config/ --profile banking_agent
"""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus — AI Security Evaluation Framework"
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run a security evaluation")
    scan_parser.add_argument("--target", required=True, help="Local path or Git URL")
    scan_parser.add_argument("--profile", default="default", help="Config profile name")
    scan_parser.add_argument("--output", default="./reports", help="Report output directory")

    args = parser.parse_args()

    if args.command == "scan":
        print(f"[Argus] Scanning target: {args.target}")
        print(f"[Argus] Profile: {args.profile}")
        print("[Argus] Engine not yet implemented — scaffold only.")
        sys.exit(0)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
