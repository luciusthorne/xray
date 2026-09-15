import sys
from pathlib import Path


def discover_local_modules(project_root):
    project_root = Path(project_root)

    modules = set()

    for path in project_root.rglob("*.py"):
        relative = path.relative_to(project_root)

        if path.name == "__init__.py":
            parts = list(relative.parent.parts)

            if parts:
                modules.add(".".join(parts))

            continue

        parts = list(relative.with_suffix("").parts)
        modules.add(".".join(parts))

    return modules


def classify_dependency(module, local_modules=None):
    if module.startswith("."):
        return "local"
    root = module.lstrip(".").split(".")[0]

    if local_modules and root in local_modules:
        return "local"

    if root in sys.stdlib_module_names:
        return "stdlib"

    return "third-party"
