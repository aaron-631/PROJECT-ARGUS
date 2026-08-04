"""Run the Argus V2 runtime monitoring and blocking gateway."""

from __future__ import annotations

import argparse

from aiohttp import web

from src.runtime.config import RuntimeConfigurationError, load_runtime_config
from src.runtime.gateway import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Argus runtime policy gateway")
    parser.add_argument("--config", default=None, help="Runtime YAML configuration")
    parser.add_argument("--host", default=None, help="Override the listening host")
    parser.add_argument("--port", type=int, default=None, help="Override the listening port")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_runtime_config(args.config)
    except RuntimeConfigurationError as exc:
        print(f"[Argus Runtime] Error: {exc}")
        return 1
    if args.host is not None:
        config = config.model_copy(update={"listen_host": args.host})
    if args.port is not None:
        config = config.model_copy(update={"listen_port": args.port})
    web.run_app(create_app(config), host=config.listen_host, port=config.listen_port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
