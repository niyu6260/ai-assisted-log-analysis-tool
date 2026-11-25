from __future__ import annotations

import argparse
import signal
import time

from charger_log_cloud.service import AnalysisService


def run_worker(*, once: bool = False) -> int:
    service = AnalysisService.create()
    stop = False

    def request_stop(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_stop)

    while not stop:
        job = service.process_next_job()
        if job:
            print(f"{job['id']}: {job['status']}", flush=True)
        if once:
            return 0
        if not job:
            time.sleep(service.settings.worker_poll_seconds)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Charger diagnosis worker")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process at most one queued job and exit",
    )
    args = parser.parse_args()
    return run_worker(once=args.once)


if __name__ == "__main__":
    raise SystemExit(main())
