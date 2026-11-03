"""Modbus 协议适配器。

按 catalog 声明的布局与变体语义把一次操作变成协议帧：
TCP 用 MBAP 组帧，RTU 用地址 + PDU + CRC 组帧。
一次操作产出请求与响应两帧，响应由服务端发往客户端。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...codec.encoder import encode
from ...codec.fields import Layout
from ...spec.catalog import Catalog, OperationEntry, load_catalog
from ...spec.model import Operation, Variant
from ..base import BuildContext, OperationSpec, ProtocolFrame
from . import framing
from .layouts import get_layout
from .variants import DEFAULT_EXCEPTION_CODE, VariantPlan, plan_variant

#: catalog 文件位置
CATALOG_PATH = Path(__file__).resolve().parent / "catalog.yaml"


class ModbusAdapter:
    """Modbus 协议适配器。"""

    name = "modbus"

    def __init__(self, catalog: Catalog) -> None:
        self.catalog = catalog
        self.operations = {
            name: OperationSpec(
                name=name,
                summary=entry.summary,
                layout=entry.layout,
                variants=tuple(entry.variants),
                params_schema=entry.params,
            )
            for name, entry in catalog.operations.items()
        }

    def build(self, op: Operation, ctx: BuildContext) -> ProtocolFrame:
        """把一次操作构建成请求帧。"""
        layout, plan = self._plan(op)
        request_pdu = framing.build_pdu(
            plan.func_code,
            encode(layout.request, plan.request_values),
        )
        metadata: dict[str, Any] = {
            "fc": plan.func_code,
            "unit_id": ctx.unit_id,
            "transport": ctx.transport,
            "is_exception": plan.is_exception,
        }
        metadata.update(plan.metadata)

        return ProtocolFrame(payload=self._frame(request_pdu, ctx), metadata=metadata)

    def build_response(self, op: Operation, ctx: BuildContext) -> ProtocolFrame | None:
        """把一次操作构建成响应帧。

        异常变体按 Modbus 规范回异常响应（功能码 | 0x80 + 异常码）；
        畸形帧没有可解析的响应，返回 None。
        """
        layout, plan = self._plan(op)
        if op.variant is Variant.MALFORMED:
            return None
        if plan.is_exception:
            code = int(plan.metadata.get("exception_code", DEFAULT_EXCEPTION_CODE))
            response_pdu = bytes([plan.func_code | 0x80, code])
        else:
            response_pdu = framing.build_pdu(
                plan.func_code,
                encode(layout.response, plan.response_values),
            )
        metadata: dict[str, Any] = {
            "fc": plan.func_code,
            "unit_id": ctx.unit_id,
            "transport": ctx.transport,
        }
        return ProtocolFrame(payload=self._frame(response_pdu, ctx), metadata=metadata)

    def _plan(self, op: Operation) -> tuple[Layout, VariantPlan]:
        """解析一次操作：catalog 缺省值 + 场景参数 → 布局与取值方案。"""
        entry: OperationEntry = self.catalog.get(op.op)
        layout = get_layout(entry.layout)
        # 场景没给的参数用 catalog 声明的缺省值补齐
        defaults = {
            name: spec["default"]
            for name, spec in entry.params.items()
            if isinstance(spec, dict) and "default" in spec
        }
        # 边界变体的上界：标量参数取 maximum，数组参数取元素上界
        maxima = {
            name: int(spec["maximum"])
            for name, spec in entry.params.items()
            if isinstance(spec, dict) and "maximum" in spec
        }
        maxima.update(
            {
                name: int(spec["items"]["maximum"])
                for name, spec in entry.params.items()
                if isinstance(spec, dict)
                and spec.get("type") == "array"
                and isinstance(spec.get("items"), dict)
                and "maximum" in spec["items"]
            }
        )
        # 数组参数的元素个数上界：只顶元素值而不顶个数，帧里的计数标量
        # 会与实际内容对不上
        max_counts = {
            name: int(spec["maxItems"])
            for name, spec in entry.params.items()
            if isinstance(spec, dict)
            and spec.get("type") == "array"
            and "maxItems" in spec
        }
        func_code = entry.func_code if entry.func_code is not None else 0
        plan = plan_variant(
            layout=layout,
            op_name=op.op,
            func_code=func_code,
            params={**defaults, **op.params},
            variant=op.variant,
            maxima=maxima,
            max_counts=max_counts,
        )
        return layout, plan

    @staticmethod
    def _frame(pdu: bytes, ctx: BuildContext) -> bytes:
        """按传输方式把 PDU 组成完整帧。"""
        if ctx.transport == "rtu":
            return framing.build_rtu(ctx.unit_id, pdu)
        return framing.build_mbap(ctx.transaction_id, ctx.unit_id, pdu)


def load_modbus_adapter() -> ModbusAdapter:
    """加载内置 catalog 并构造适配器。"""
    return ModbusAdapter(load_catalog(CATALOG_PATH))
