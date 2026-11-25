from __future__ import annotations

import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path


INTERESTING_SUFFIXES = (".log", ".txt", ".json")
INTERESTING_NAMES = (
    "operationocppmessage",
    "vccu_ethernet",
    "pcu_",
)
MAX_NESTED_ZIP_DEPTH = 3


@dataclass
class LogArtifact:
    path: Path
    relative_path: str
    size_bytes: int
    detected_parser: str | None = None
    detected_domain: str = "unknown"
    detection_confidence: float = 0.0
    parse_status: str = "pending"
    event_count: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "relative_path": self.relative_path,
            "size_bytes": self.size_bytes,
            "detected_parser": self.detected_parser,
            "detected_domain": self.detected_domain,
            "detection_confidence": round(self.detection_confidence, 3),
            "parse_status": self.parse_status,
            "event_count": self.event_count,
            "error": self.error,
        }


def _safe_extract(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "r") as zf:
        base = destination.resolve()
        for member in zf.infolist():
            target = (destination / member.filename).resolve()
            if target != base and base not in target.parents:
                raise ValueError(f"Unsafe zip member path: {member.filename}")
        zf.extractall(destination)


def _extract_nested_zips(root: Path) -> None:
    current = [path for path in root.rglob("*.zip") if path.is_file()]
    for _ in range(MAX_NESTED_ZIP_DEPTH):
        if not current:
            return
        next_level: list[Path] = []
        for archive in current:
            destination = archive.with_suffix("")
            _safe_extract(archive, destination)
            next_level.extend(
                path
                for path in destination.rglob("*.zip")
                if path.is_file()
            )
        current = next_level
    if current:
        raise ValueError(
            f"Nested ZIP depth exceeds {MAX_NESTED_ZIP_DEPTH}: {current[0]}"
        )


def prepare_workspace(input_path: Path, work_root: Path) -> Path:
    """Return a directory containing extracted / copied logs."""
    input_path = input_path.resolve()
    work_root.mkdir(parents=True, exist_ok=True)

    if input_path.is_file() and input_path.suffix.lower() == ".zip":
        extract_dir = work_root / "extracted"
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir(parents=True)
        _safe_extract(input_path, extract_dir)
        _extract_nested_zips(extract_dir)
        return extract_dir

    if input_path.is_dir():
        return input_path

    raise FileNotFoundError(f"Input not found or unsupported: {input_path}")


def iter_log_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        name = p.name.lower()
        if not name.endswith(INTERESTING_SUFFIXES):
            continue
        if any(key in name for key in INTERESTING_NAMES) or name.endswith(".log"):
            files.append(p)
    return sorted(files)


def discover_log_artifacts(root: Path) -> list[LogArtifact]:
    artifacts: list[LogArtifact] = []
    for path in iter_log_files(root):
        artifacts.append(
            LogArtifact(
                path=path,
                relative_path=str(path.relative_to(root)),
                size_bytes=path.stat().st_size,
            )
        )
    return artifacts


def classify_log(path: Path) -> str:
    name = path.name.lower()
    if "operationocppmessage" in name or name.startswith("ocpp"):
        return "ocpp"
    if "vccu_ethernet" in name or "vccu" in name:
        return "vccu"
    if name.startswith("pcu_") or "/pcu/" in str(path).replace("\\", "/").lower():
        return "pcu"
    return "other"
