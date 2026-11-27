"""
CLI entry point for the DevOps AI Agent.

Usage:
    devops-agent serve              # start webhook API server
    devops-agent serve --port 8080  # custom port
    devops-agent version            # print version
"""
import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    # Load .env before reading HOST/PORT/UVICORN_WORKERS: the load_dotenv() in
    # api/server.py runs too late, as uvicorn imports "api.server:app" by
    # string only after these values are read. Real environment variables
    # still win (load_dotenv does not override), and the CLI flags win over
    # both via the `args.x or os.getenv(...)` fallbacks below.
    # The path is explicit: a bare load_dotenv() anchors its upward search at
    # this module, so after installation it would find site-packages' parents
    # and never the user's .env in the invocation directory.
    load_dotenv(Path.cwd() / ".env")

    # Local default binds loopback; set HOST=0.0.0.0 for Docker/K8s ingress.
    host = args.host or os.getenv("HOST", "127.0.0.1")
    port = args.port or int(os.getenv("PORT", "8000"))
    workers = args.workers or int(os.getenv("WEB_CONCURRENCY") or os.getenv("UVICORN_WORKERS") or "1")
    reload = args.reload

    if reload and workers > 1:
        workers = 1
    if workers > 1 and os.getenv("STORAGE_PROVIDER", "memory").lower().strip() in ("memory", "local", ""):
        # Each worker would keep its own private queue, approvals and config (#224).
        print(
            "error: --workers > 1 needs shared storage. With STORAGE_PROVIDER=memory each worker "
            "keeps its own queue and approvals, so incidents and Slack approvals would be lost. "
            "Use one worker, or set STORAGE_PROVIDER=s3|gcs|azure|minio.",
            file=sys.stderr,
        )
        return 2

    uvicorn.run(
        "api.server:app",
        host=host,
        port=port,
        workers=workers if not reload else 1,
        reload=reload,
    )
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    from devops_mcp.server import run_mcp

    run_mcp(transport=args.transport, host=args.host, port=args.port)
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    from devops_agent import __version__

    print(f"devops-ai-agent {__version__}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="devops-agent",
        description="DevOps AI Agent — autonomous incident diagnosis and remediation",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Start the webhook API server")
    serve.add_argument("--host", default=None, help="Bind host (default: 127.0.0.1, or HOST env)")
    serve.add_argument("--port", type=int, default=None, help="Bind port (default: 8000)")
    serve.add_argument("--workers", type=int, default=None, help="Uvicorn workers (default: 1; >1 needs shared storage)")
    serve.add_argument("--reload", action="store_true", help="Dev mode: auto-reload on code changes")
    serve.set_defaults(func=cmd_serve)

    mcp = sub.add_parser("mcp", help="Start MCP server (stdio by default — for Cursor, Claude Desktop, etc.)")
    mcp.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    mcp.add_argument(
        "--host",
        default=None,
        help="Bind host for HTTP transports (default: 127.0.0.1, or FASTMCP_HOST env)",
    )
    mcp.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port for HTTP transports (default: 8090, or FASTMCP_PORT env)",
    )
    mcp.set_defaults(func=cmd_mcp)

    ver = sub.add_parser("version", help="Print package version")
    ver.set_defaults(func=cmd_version)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
