import sys
from pathlib import Path


def discover_local_modules(project_root):
    project_root = Path(project_root)

    modules = set()

    for path in project_root.rglob("*.py"):
        if path.name == "__init__.py":
            continue

        modules.add(path.stem)

    return modules


def classify_dependency(module, local_modules=None):
    root = module.split(".")[0]

    if local_modules and root in local_modules:
        return "local"

    if root in sys.stdlib_module_names:
        return "stdlib"

    return "third-party"
