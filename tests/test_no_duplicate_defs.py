import ast
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_no_module_defines_a_top_level_function_twice():
    repeats = []

    for path in sorted((REPO / "xray").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        seen = set()

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                if node.name in seen:
                    repeats.append(f"{path.name}: {node.name}")

                seen.add(node.name)

    assert repeats == []
