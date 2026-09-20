import sys
from pathlib import Path


def discover_local_modules(project_root):
    project_root = Path(project_root).resolve()

    modules = set()

    for path in project_root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue

        relative = path.relative_to(project_root)

        if path.name == "__init__.py":
            parts = list(relative.parent.parts)

            if parts:
                modules.add(".".join(parts))

            continue

        parts = list(relative.with_suffix("").parts)

        if parts:
            modules.add(".".join(parts))

    return modules


def classify_dependency(module, local_modules=None):
    if module.startswith("."):
        return "local"

    module = module.strip()

    if not module:
        return "unknown"

    if local_modules:
        if module in local_modules:
            return "local"

        for local_module in local_modules:
            if module.startswith(local_module + "."):
                return "local"

    root = module.split(".")[0]

    if root in sys.stdlib_module_names:
        return "stdlib"

    return "third-party"
