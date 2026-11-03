"""生成流水线：把场景变成分层数据集。

流程：场景 → 逐条操作构建请求帧与响应帧 → 封装链路 → 登记为产物 → 写盘。
请求与响应连续进入同一会话的 pcap，保持会话内可配对。
"""

from __future__ import annotations

from pathlib import Path

from .emit.dataset import Artifact, DatasetBuilder
from .protocols.base import BuildContext, ProtocolAdapter
from .spec.model import Scenario
from .transport.link import encapsulate
from .transport.spec import TransportSpec


def _transport_spec(scenario: Scenario) -> TransportSpec:
    raw = dict(scenario.transport)
    kind = raw.pop("kind", "tcp")
    return TransportSpec(kind=kind, **raw)


def build_dataset(
    scenario: Scenario,
    adapter: ProtocolAdapter,
    root: Path,
    name: str | None = None,
) -> Path:
    """按场景生成数据集，返回数据集根路径。"""
    spec = _transport_spec(scenario)
    builder = DatasetBuilder(name or scenario.name, root, transport=spec.to_dict())

    for index, op in enumerate(scenario.operations):
        ctx = BuildContext(
            transaction_id=index,
            unit_id=0xFF,
            transport="rtu" if spec.kind == "serial" else "tcp",
            seed=index,
        )
        frame = adapter.build(op, ctx)
        response_frame = adapter.build_response(op, ctx) if op.expect_response else None
        artifact = Artifact(
            id=f"{op.op}#{index + 1:03d}",
            protocol=adapter.name,
            transport="rtu" if spec.kind == "serial" else "tcp",
            op=op.op,
            variant=op.variant.value,
            tier=op.tier.value if op.tier is not None else "legit",
            payload=frame.payload,
            response=response_frame.payload if response_frame is not None else None,
            metadata=frame.metadata,
        )
        builder.add(artifact)
        # 请求与响应连续进入同一会话：响应由服务端发回，链路方向相反
        seq = index * 10
        packets = [encapsulate(frame.payload, spec, seq=seq, ack=seq)]
        if response_frame is not None:
            packets.append(
                encapsulate(
                    response_frame.payload,
                    spec.reversed(),
                    seq=seq + len(frame.payload),
                    ack=seq + len(frame.payload),
                )
            )
        builder.add_linked_packets(artifact.id, packets)

    return builder.write()
