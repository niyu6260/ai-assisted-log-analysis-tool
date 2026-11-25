from __future__ import annotations

from charger_log_cloud.service import AnalysisService


def main() -> int:
    deleted = AnalysisService.create().cleanup_expired()
    print(f"Deleted {deleted} expired analysis job(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
