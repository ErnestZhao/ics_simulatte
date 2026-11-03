"""icsgen 命令行界面。

所有命令都是薄封装，核心逻辑在 icsgen 的库接口中，命令行仅负责参数
解析与结果呈现。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from .emit.dataset import Artifact, DatasetBuilder
from .generator import build_dataset
from .mutate.engine import mutate
from .protocols.modbus.adapter import CATALOG_PATH, load_modbus_adapter
from .spec.catalog import Catalog, load_catalog
from .spec.loader import ScenarioError, load_scenario

app = typer.Typer(help="ICS 工控协议流量生成器")
ops_app = typer.Typer(help="操作类型目录")
app.add_typer(ops_app, name="ops")


def _catalog_for(protocol: str) -> Catalog:
    if protocol != "modbus":
        raise typer.BadParameter(f"暂不支持协议 {protocol!r}，当前仅支持 modbus")
    return load_catalog(CATALOG_PATH)


@ops_app.command("list")
def ops_list(
    protocol: str = typer.Option("modbus", "--protocol", help="协议名"),
    variant: str = typer.Option(None, "--variant", help="只列出支持该变体的操作"),
    as_json: bool = typer.Option(False, "--json", help="以 JSON 输出"),
) -> None:
    """列出操作类型。"""
    catalog = _catalog_for(protocol)
    items: list[dict[str, Any]] = []
    for name, entry in catalog.operations.items():
        if variant is not None and variant not in entry.variants:
            continue
        items.append(
            {
                "name": name,
                "summary": entry.summary,
                "layout": entry.layout,
                "variants": entry.variants,
                "func_code": entry.func_code,
            }
        )
    if as_json:
        typer.echo(json.dumps(items, ensure_ascii=False, indent=2))
        return
    for item in items:
        typer.echo(f"{item['name']:<52} {item['summary']}")


@ops_app.command("show")
def ops_show(name: str = typer.Argument(..., help="操作名")) -> None:
    """显示单个操作类型的详情。"""
    catalog = _catalog_for("modbus")
    entry = catalog.get(name)
    typer.echo(f"名称: {entry.name}")
    typer.echo(f"说明: {entry.summary}")
    typer.echo(f"布局: {entry.layout}")
    typer.echo(f"功能码: {entry.func_code}")
    typer.echo(f"可用变体: {', '.join(entry.variants)}")
    if entry.params:
        typer.echo("参数:")
        for param, spec in entry.params.items():
            typer.echo(f"  {param}: {json.dumps(spec, ensure_ascii=False)}")


@app.command("validate")
def validate(scenario: Path = typer.Argument(..., help="场景 YAML 路径")) -> None:
    """校验场景文件。"""
    catalog = _catalog_for("modbus")
    try:
        loaded = load_scenario(scenario, catalog)
    except ScenarioError as exc:
        typer.echo(f"校验失败: {exc}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"校验通过: {loaded.name}，共 {len(loaded.operations)} 条操作")


@app.command("generate")
def generate(
    scenario: Path = typer.Argument(..., help="场景 YAML 路径"),
    output: Path = typer.Option(..., "-o", "--output", help="数据集输出目录"),
) -> None:
    """按场景生成分层数据集。"""
    catalog = _catalog_for("modbus")
    try:
        loaded = load_scenario(scenario, catalog)
    except ScenarioError as exc:
        typer.echo(f"场景不合法: {exc}", err=True)
        raise typer.Exit(code=1)
    adapter = load_modbus_adapter()
    root = build_dataset(loaded, adapter, output, name=loaded.name)
    typer.echo(f"已生成数据集: {root}")


@app.command("mutate")
def mutate_cmd(
    dataset: Path = typer.Argument(..., help="源数据集目录"),
    output: Path = typer.Option(..., "-o", "--output", help="变异数据集输出目录"),
    rules: str = typer.Option("all", "--rules", help="逗号分隔的规则名，all 表示全部"),
    seed: int = typer.Option(0, "--seed", help="随机种子"),
) -> None:
    """对数据集做变异，产出 mutated 层。"""
    manifest_path = dataset / "manifest.json"
    if not manifest_path.exists():
        typer.echo(f"找不到 {manifest_path}", err=True)
        raise typer.Exit(code=1)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    builder = DatasetBuilder(manifest.get("dataset", dataset.name), output)
    rule_names = [r.strip() for r in rules.split(",") if r.strip()]

    for entry in manifest["artifacts"]:
        source = dataset / entry["tier"] / f"{entry['protocol']}_{entry['transport']}" / "frames" / f"{entry['id']}.bin"
        if not source.exists():
            continue
        payload = source.read_bytes()
        try:
            mutated_frames = mutate(payload, rule_names, seed)
        except KeyError as exc:
            typer.echo(f"变异规则名非法: {exc}", err=True)
            raise typer.Exit(code=1)
        for mutated in mutated_frames:
            builder.add(
                Artifact(
                    id=f"{entry['id']}~{mutated.rule}",
                    protocol=entry["protocol"],
                    transport=entry["transport"],
                    op=entry["op"],
                    variant=entry["variant"],
                    tier="mutated",
                    payload=mutated.payload,
                    metadata=entry.get("meta", {}),
                    parent_id=entry["id"],
                    mutation={
                        "rule": mutated.rule,
                        "seed": mutated.seed,
                        "offset": mutated.offset,
                        "original_sha256": mutated.original_sha256,
                    },
                )
            )
    root = builder.write()
    typer.echo(f"已生成变异数据集: {root}")


@app.command("catalog")
def catalog_cmd(
    protocol: str = typer.Option("modbus", "--protocol", help="协议名"),
    count: bool = typer.Option(False, "--count", help="只输出覆盖条目数"),
) -> None:
    """查看操作目录统计。"""
    catalog = _catalog_for(protocol)
    if count:
        typer.echo(str(catalog.coverage_count()))
        return
    typer.echo(
        f"协议 {catalog.protocol}，操作类型 {catalog.count()} 个，"
        f"传输 {'/'.join(catalog.transports)}，覆盖条目 {catalog.coverage_count()} 个"
    )


@app.command("serve")
def serve(
    protocol: str = typer.Option("modbus", "--protocol", help="协议名"),
    transport: str = typer.Option("tcp", "--transport", help="tcp 或 serial"),
    host: str = typer.Option("127.0.0.1", "--host", help="监听地址"),
    port: int = typer.Option(5020, "--port", help="监听端口"),
    role: str = typer.Option("plc", "--role", help="plc 被动应答 / client 主动请求"),
) -> None:
    """启动 PLC 服务端模拟。"""
    from .server.modbus_server import run_modbus_server

    run_modbus_server(transport=transport, host=host, port=port, role=role)
