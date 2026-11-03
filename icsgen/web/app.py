"""FastAPI 应用：JSON API 与页面路由。

路由层只做参数解析、结果呈现与错误映射，业务逻辑在 service.py。
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..paths import DATASETS_DIR
from ..spec.loader import ScenarioError
from .models import ConfigPayload, GenerationPayload
from .service import (
    AlreadyGenerated,
    GenerationService,
    NotFound,
    WebError,
    artifact_detail,
    generation_detail,
    list_operations,
    list_protocols,
    save_config,
)
from .store import WebStore

#: 模板与静态资源目录
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"

#: 生成 id 的合法形态：单段路径，只含字母数字下划线连字符。
#: 存储层生成的 id 形如 gen_1a2b3c4d5e6f —— 单段、无分隔符。
_GENERATION_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def default_root() -> Path:
    """账本与生成目录的默认位置。"""
    return DATASETS_DIR / "web"


def _generation_base(store: WebStore, generation_id: str) -> Path:
    """取生成目录；id 越界或形态不对一律 404（spec §12：路径越界 → 404）。

    generation_id 来自 URL，能带 `..` 或斜杠 —— 必须确认解析后的目录
    仍在账本的 generations 目录里，否则就能读到目录外的文件
    （比如账本 events.jsonl 本身）。
    """
    if not _GENERATION_ID.match(generation_id):
        raise HTTPException(status_code=404, detail="生成记录不存在")
    root = (store.root / "generations").resolve()
    base = (root / generation_id).resolve()
    if not base.is_relative_to(root):
        raise HTTPException(status_code=404, detail="生成记录不存在")
    return base


def create_app(root: Path | None = None) -> FastAPI:
    """构造 Web 应用。root 是账本与生成目录的存放位置。"""
    store = WebStore(Path(root) if root is not None else default_root())
    service = GenerationService(store)
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    app = FastAPI(title="icsgen Web 交互界面", version="0.1.0")
    app.state.store = store
    app.state.service = service
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _fail(exc: Exception) -> HTTPException:
        """把服务层异常映射成 HTTP 状态码。"""
        if isinstance(exc, NotFound):
            return HTTPException(status_code=404, detail=str(exc))
        if isinstance(exc, AlreadyGenerated):
            return HTTPException(status_code=409, detail=str(exc))
        if isinstance(exc, (WebError, ScenarioError)):
            return HTTPException(status_code=422, detail=str(exc))
        return HTTPException(status_code=500, detail=str(exc))

    # ---- JSON API ----
    @app.get("/api/protocols")
    def api_protocols() -> list[dict[str, Any]]:
        return list_protocols()

    @app.get("/api/protocols/{protocol}/operations")
    def api_operations(protocol: str) -> list[dict[str, Any]]:
        try:
            return list_operations(protocol)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/configs")
    def api_configs() -> list[dict[str, Any]]:
        return store.list_configs()

    @app.post("/api/configs", status_code=201)
    def api_save_config(payload: ConfigPayload) -> dict[str, Any]:
        try:
            return save_config(store, payload)
        except (WebError, ScenarioError) as exc:
            raise _fail(exc) from exc

    @app.get("/api/generations")
    def api_generations() -> list[dict[str, Any]]:
        return store.list_generations()

    @app.post("/api/generations", status_code=201)
    def api_start_generation(payload: GenerationPayload) -> dict[str, Any]:
        try:
            return service.start(payload.config_id)
        except WebError as exc:
            raise _fail(exc) from exc

    @app.get("/api/generations/{generation_id}")
    def api_generation(generation_id: str) -> dict[str, Any]:
        try:
            return generation_detail(store, service, generation_id)
        except WebError as exc:
            raise _fail(exc) from exc

    @app.get("/api/generations/{generation_id}/artifacts/{artifact_id}")
    def api_artifact(generation_id: str, artifact_id: str) -> dict[str, Any]:
        try:
            return artifact_detail(store, generation_id, artifact_id)
        except WebError as exc:
            raise _fail(exc) from exc

    @app.get("/api/generations/{generation_id}/download/{file_path:path}")
    def api_download(generation_id: str, file_path: str) -> FileResponse:
        base = _generation_base(store, generation_id)
        target = (base / file_path).resolve()
        if not target.is_relative_to(base) or not target.is_file():
            raise HTTPException(status_code=404, detail="文件不存在")
        return FileResponse(target, filename=target.name)

    @app.get("/api/generations/{generation_id}/archive.zip")
    def api_archive(generation_id: str) -> FileResponse:
        base = _generation_base(store, generation_id)
        if not (base / "manifest.json").exists():
            raise HTTPException(status_code=404, detail="数据集不存在")
        archive = base.parent / f"{generation_id}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path in sorted(base.rglob("*")):
                # 符号链接不打包：zipfile.write 会跟随它，把生成目录之外的文件
                # 内容读进归档 —— 而同目录的下载路由（app.py:137 的
                # is_relative_to 校验）会拒绝这种文件。两条同类路由的防护
                # 强度必须一致。
                if path.is_symlink() or not path.is_file():
                    continue
                bundle.write(path, Path(generation_id) / path.relative_to(base))
        return FileResponse(archive, filename=f"{generation_id}.zip")

    # ---- 页面 ----
    @app.get("/")
    def page_index(request: Request):
        return templates.TemplateResponse(
            request, "index.html", {"protocols": list_protocols()}
        )

    @app.get("/records")
    def page_records(request: Request):
        generations = store.list_generations()
        by_config = store.generations_by_config()
        configs = [
            {**config, "generation_id": by_config.get(config.get("id"))}
            for config in store.list_configs()
        ]
        return templates.TemplateResponse(
            request, "records.html", {"configs": configs, "generations": generations}
        )

    @app.get("/generations/{generation_id}")
    def page_generation(request: Request, generation_id: str):
        try:
            detail = generation_detail(store, service, generation_id)
        except WebError as exc:
            raise _fail(exc) from exc
        return templates.TemplateResponse(
            request, "generation.html", {"generation": detail}
        )

    return app
