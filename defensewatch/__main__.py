"""CLI entry point for DefenseWatch: python -m defensewatch [--validate]"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="DefenseWatch HIDS")
    parser.add_argument("--validate", action="store_true",
                        help="Validate configuration and environment, then exit")
    parser.add_argument("--config", default="config.yaml",
                        help="Path to config.yaml (default: config.yaml)")
    args = parser.parse_args()

    if args.validate:
        from defensewatch.validate import run_validate_cli
        sys.exit(run_validate_cli(args.config))

    # Normal startup via uvicorn
    import uvicorn
    from defensewatch.config import load_config

    config = load_config(args.config)
    uvicorn.run(
        "defensewatch.main:app",
        host=config.server.host,
        port=config.server.port,
    )


if __name__ == "__main__":
    main()
