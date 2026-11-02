"""原始协议帧导出。

.bin 为纯协议字节，.hex 为其空格分隔的十六进制文本，便于在测试中直接
断言字节或人工粘贴到其他工具中。
"""

from __future__ import annotations

from pathlib import Path


def write_raw(directory: Path, name: str, payload: bytes) -> tuple[Path, Path]:
    """写出 .bin 与 .hex 两个文件，返回它们的路径。"""
    directory.mkdir(parents=True, exist_ok=True)
    bin_path = directory / f"{name}.bin"
    hex_path = directory / f"{name}.hex"
    bin_path.write_bytes(payload)
    hex_path.write_text(payload.hex(" "), encoding="utf-8")
    return bin_path, hex_path
