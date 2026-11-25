from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    create_engine,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


metadata = MetaData()

jobs = Table(
    "analysis_jobs",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("created_by", String(255), nullable=False),
    Column("status", String(32), nullable=False, index=True),
    Column("original_name", String(512), nullable=False),
    Column("input_uri", Text, nullable=False),
    Column("request_json", Text, nullable=False),
    Column("result_json", Text),
    Column("error", Text),
)

feedback = Table(
    "analysis_feedback",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("job_id", String(36), nullable=False, index=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("created_by", String(255), nullable=False),
    Column("verdict", String(32), nullable=False),
    Column("review_status", String(32), nullable=False),
    Column("payload_json", Text, nullable=False),
)

audit_events = Table(
    "audit_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("created_at", DateTime(timezone=True), nullable=False, index=True),
    Column("user_id", String(255), nullable=False),
    Column("role", String(32), nullable=False),
    Column("action", String(128), nullable=False),
    Column("resource", String(512), nullable=False),
    Column("details_json", Text, nullable=False),
)


def _decode_job(row: Any) -> dict[str, Any] | None:
    if row is None:
        return None
    item = dict(row._mapping)
    item["request"] = json.loads(item.pop("request_json") or "{}")
    item["result"] = json.loads(item.pop("result_json") or "{}")
    return item


class CloudRepository:
    def __init__(self, database_url: str):
        connect_args = (
            {"check_same_thread": False}
            if database_url.startswith("sqlite")
            else {}
        )
        self.engine: Engine = create_engine(
            database_url,
            future=True,
            pool_pre_ping=True,
            connect_args=connect_args,
        )

    def initialize(self) -> None:
        metadata.create_all(self.engine)

    def create_job(
        self,
        *,
        job_id: str,
        user_id: str,
        original_name: str,
        input_uri: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        now = utc_now()
        with self.engine.begin() as connection:
            connection.execute(
                insert(jobs).values(
                    id=job_id,
                    created_at=now,
                    updated_at=now,
                    created_by=user_id,
                    status="queued",
                    original_name=original_name,
                    input_uri=input_uri,
                    request_json=json.dumps(request, ensure_ascii=False),
                )
            )
        return self.get_job(job_id) or {}

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(jobs).where(jobs.c.id == job_id)
            ).first()
        return _decode_job(row)

    def list_jobs(
        self,
        *,
        user_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        statement = select(jobs).order_by(jobs.c.created_at.desc()).limit(limit)
        if user_id:
            statement = statement.where(jobs.c.created_by == user_id)
        with self.engine.connect() as connection:
            rows = connection.execute(statement).all()
        return [_decode_job(row) or {} for row in rows]

    def claim_next_job(self) -> dict[str, Any] | None:
        with self.engine.begin() as connection:
            statement = (
                select(jobs)
                .where(jobs.c.status == "queued")
                .order_by(jobs.c.created_at)
                .limit(1)
            )
            if self.engine.dialect.name == "postgresql":
                statement = statement.with_for_update(skip_locked=True)
            row = connection.execute(statement).first()
            if row is None:
                return None
            job_id = row._mapping["id"]
            updated = connection.execute(
                update(jobs)
                .where(
                    and_(
                        jobs.c.id == job_id,
                        jobs.c.status == "queued",
                    )
                )
                .values(status="running", updated_at=utc_now())
            )
            if updated.rowcount != 1:
                return None
        return self.get_job(job_id)

    def complete_job(self, job_id: str, result: dict[str, Any]) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                update(jobs)
                .where(jobs.c.id == job_id)
                .values(
                    status="succeeded",
                    updated_at=utc_now(),
                    result_json=json.dumps(result, ensure_ascii=False),
                    error=None,
                )
            )

    def fail_job(self, job_id: str, error: str) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                update(jobs)
                .where(jobs.c.id == job_id)
                .values(
                    status="failed",
                    updated_at=utc_now(),
                    error=error[:8000],
                )
            )

    def add_feedback(
        self,
        *,
        feedback_id: str,
        job_id: str,
        user_id: str,
        verdict: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        now = utc_now()
        with self.engine.begin() as connection:
            connection.execute(
                insert(feedback).values(
                    id=feedback_id,
                    job_id=job_id,
                    created_at=now,
                    created_by=user_id,
                    verdict=verdict,
                    review_status="pending_review",
                    payload_json=json.dumps(payload, ensure_ascii=False),
                )
            )
        return {
            "id": feedback_id,
            "job_id": job_id,
            "created_at": now,
            "created_by": user_id,
            "verdict": verdict,
            "review_status": "pending_review",
            "payload": payload,
        }

    def list_feedback(self, job_id: str) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(feedback)
                .where(feedback.c.job_id == job_id)
                .order_by(feedback.c.created_at)
            ).all()
        return [
            {
                **dict(row._mapping),
                "payload": json.loads(row._mapping["payload_json"]),
            }
            for row in rows
        ]

    def audit(
        self,
        *,
        user_id: str,
        role: str,
        action: str,
        resource: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                insert(audit_events).values(
                    created_at=utc_now(),
                    user_id=user_id,
                    role=role,
                    action=action,
                    resource=resource,
                    details_json=json.dumps(details or {}, ensure_ascii=False),
                )
            )

    def list_audit(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(audit_events)
                .order_by(audit_events.c.created_at.desc())
                .limit(limit)
            ).all()
        return [
            {
                **dict(row._mapping),
                "details": json.loads(row._mapping["details_json"]),
            }
            for row in rows
        ]

    def expired_jobs(self, retention_days: int) -> list[dict[str, Any]]:
        cutoff = utc_now() - timedelta(days=retention_days)
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(jobs).where(jobs.c.created_at < cutoff)
            ).all()
        return [_decode_job(row) or {} for row in rows]

    def delete_job(self, job_id: str) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                delete(feedback).where(feedback.c.job_id == job_id)
            )
            connection.execute(delete(jobs).where(jobs.c.id == job_id))
