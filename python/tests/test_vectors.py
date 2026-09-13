import json
from pathlib import Path

import pytest

from lattice_weather.kernels import run_kernel

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "conformance" / "vectors.json").read_text())


@pytest.mark.parametrize("v", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(v):
    out = run_kernel(v["input"])
    assert out == v["expected"], f"{v['id']}: got {json.dumps(out)} want {json.dumps(v['expected'])}"
