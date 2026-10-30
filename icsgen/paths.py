"""项目内默认路径常量。"""

from pathlib import Path

#: 项目根目录（icsgen 包的父目录）
PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: 内置场景目录
SCENARIOS_DIR = PROJECT_ROOT / "scenarios"

#: 数据集默认输出目录
DATASETS_DIR = PROJECT_ROOT / "datasets"
