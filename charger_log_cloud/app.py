from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from charger_log_cloud import __version__
from charger_log_cloud.auth import UserContext, current_user, require_roles
from charger_log_cloud.schemas import (
    FeedbackRequest,
    FeedbackResponse,
    HealthResponse,
    JobResponse,
)
from charger_log_cloud.service import AnalysisService


WORKBENCH_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Charger Log Diagnosis</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 20px}
    form,pre{border:1px solid #8885;border-radius:8px;padding:18px}
    label{display:block;margin:10px 0 4px}button{margin-top:14px;padding:8px 16px}
    input,textarea{width:100%;box-sizing:border-box;padding:8px}
  </style>
</head>
<body>
  <h1>整桩日志诊断工作台</h1>
  <p>上传ZIP后由Worker异步分析。生产环境身份由内网SSO代理注入。</p>
  <form id="upload">
    <label>日志ZIP</label><input name="file" type="file" required>
    <label>现场症状</label><textarea id="symptom"></textarea>
    <button>提交分析</button>
  </form>
  <pre id="result">等待提交</pre>
  <script>
    document.querySelector("#upload").onsubmit=async(e)=>{
      e.preventDefault();
      const body=new FormData(e.target);
      body.set("request_json",JSON.stringify({customer_symptom:
        document.querySelector("#symptom").value}));
      const r=await fetch("/api/v1/jobs",{method:"POST",body,
        headers:{"X-User-Id":"local-ui","X-User-Role":"user"}});
      document.querySelector("#result").textContent=
        JSON.stringify(await r.json(),null,2);
    };
  </script>
</body></html>"""


def create_app(service: AnalysisService | None = None) -> FastAPI:
    app = FastAPI(
        title="Charger Log Diagnosis Cloud",
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.state.service = service or AnalysisService.create()

    def visible_job(job_id: str, user: UserContext) -> dict[str, Any]:
        job = app.state.service.repository.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if user.role == "user" and job["created_by"] != user.user_id:
            raise HTTPException(status_code=404, detail="Job not found")
        return job

    @app.get("/", response_class=HTMLResponse)
    def workbench() -> str:
        return WORKBENCH_HTML

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok", version=__version__)

    @app.post(
        "/api/v1/jobs",
        response_model=JobResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def submit_job(
        file: UploadFile = File(...),
        request_json: str = Form(default="{}"),
        user: UserContext = Depends(current_user),
    ) -> dict[str, Any]:
        if not file.filename or not file.filename.casefold().endswith(".zip"):
            raise HTTPException(
                status_code=400,
                detail="Only ZIP uploads are accepted",
            )
        try:
            request = json.loads(request_json)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid request_json: {exc.msg}",
            ) from exc
        if not isinstance(request, dict):
            raise HTTPException(status_code=400, detail="request_json must be an object")

        upload_root = app.state.service.settings.work_root / "incoming"
        upload_root.mkdir(parents=True, exist_ok=True)
        temporary = Path(
            tempfile.mkdtemp(prefix="upload-", dir=upload_root)
        ) / "payload.zip"
        size = 0
        try:
            with temporary.open("wb") as output:
                while chunk := await file.read(1024 * 1024):
                    size += len(chunk)
                    if size > app.state.service.settings.max_upload_bytes:
                        raise HTTPException(
                            status_code=413,
                            detail="Upload exceeds configured size limit",
                        )
                    output.write(chunk)
            job = app.state.service.submit(
                temporary,
                original_name=file.filename,
                user_id=user.user_id,
                request=request,
            )
            app.state.service.repository.audit(
                user_id=user.user_id,
                role=user.role,
                action="job.submit",
                resource=f"job:{job['id']}",
                details={"filename": job["original_name"], "bytes": size},
            )
            return job
        finally:
            shutil.rmtree(temporary.parent, ignore_errors=True)

    @app.get("/api/v1/jobs", response_model=list[JobResponse])
    def list_jobs(
        user: UserContext = Depends(current_user),
    ) -> list[dict[str, Any]]:
        return app.state.service.repository.list_jobs(
            user_id=user.user_id if user.role == "user" else None
        )

    @app.get("/api/v1/jobs/{job_id}", response_model=JobResponse)
    def get_job(
        job_id: str,
        user: UserContext = Depends(current_user),
    ) -> dict[str, Any]:
        return visible_job(job_id, user)

    @app.get("/api/v1/jobs/{job_id}/report", response_class=PlainTextResponse)
    def get_report(
        job_id: str,
        user: UserContext = Depends(current_user),
    ) -> bytes:
        job = visible_job(job_id, user)
        if job["status"] != "succeeded":
            raise HTTPException(status_code=409, detail="Job is not complete")
        return app.state.service.read_result(job, "report.md")

    @app.get("/api/v1/jobs/{job_id}/findings")
    def get_findings(
        job_id: str,
        user: UserContext = Depends(current_user),
    ) -> JSONResponse:
        job = visible_job(job_id, user)
        if job["status"] != "succeeded":
            raise HTTPException(status_code=409, detail="Job is not complete")
        return JSONResponse(
            app.state.service.result_json(job, "findings.json")
        )

    @app.get("/api/v1/jobs/{job_id}/triage")
    def get_triage(
        job_id: str,
        user: UserContext = Depends(current_user),
    ) -> JSONResponse:
        job = visible_job(job_id, user)
        if job["status"] != "succeeded":
            raise HTTPException(status_code=409, detail="Job is not complete")
        return JSONResponse(app.state.service.result_json(job, "triage.json"))

    @app.post(
        "/api/v1/jobs/{job_id}/feedback",
        response_model=FeedbackResponse,
    )
    def submit_feedback(
        job_id: str,
        payload: FeedbackRequest,
        user: UserContext = Depends(require_roles("expert", "admin")),
    ) -> dict[str, Any]:
        job = visible_job(job_id, user)
        item = app.state.service.repository.add_feedback(
            feedback_id=str(uuid.uuid4()),
            job_id=job["id"],
            user_id=user.user_id,
            verdict=payload.verdict,
            payload=payload.model_dump(),
        )
        app.state.service.repository.audit(
            user_id=user.user_id,
            role=user.role,
            action="feedback.submit",
            resource=f"job:{job_id}",
            details={"feedback_id": item["id"], "verdict": payload.verdict},
        )
        return item

    @app.get("/api/v1/audit")
    def list_audit(
        user: UserContext = Depends(require_roles("admin")),
    ) -> list[dict[str, Any]]:
        return app.state.service.repository.list_audit()

    return app


app = create_app()
