"""
The README shows the output of examples/clone_demo.py: run the demo and
compare, so the documented scores cannot drift from the engine (#69).
"""

import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.mark.parametrize("readme", ["README.md", "README.it.md"])
def test_readme_shows_the_clone_demo_output(readme):
    with open(os.path.join(ROOT, readme), encoding="utf-8") as f:
        text = f.read()
    block = re.search(r"\$ python examples/clone_demo\.py\n(.*?)\n```", text, re.S)
    assert block, f"{readme} has no clone_demo block"
    run = subprocess.run([sys.executable, os.path.join(ROOT, "examples", "clone_demo.py")],
                         capture_output=True, text=True, check=True, cwd=ROOT,
                         env={**os.environ, "PYTHONPATH": ROOT})
    assert block.group(1).strip() == run.stdout.strip()
