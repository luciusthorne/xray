import ast

from .dependencies import classify_dependency, discover_local_modules
from .errors import FileError, AnalysisError


def analyze_python(path, project_root=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError as error:
        raise FileError(
            f"Unable to read file: {path}"
        ) from error
    except UnicodeError as error:
        raise FileError(
            f"Unable to decode file: {path}"
        ) from error

    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as error:
        raise AnalysisError(
            f"Invalid Python syntax: {path}"
        ) from error

    imports = []
    dependencies = []
    functions = []
    classes = []
    variables = []
    calls = []

    if project_root is None:
        project_root = path.parent
    
    local_modules = discover_local_modules(project_root)

    for node in ast.walk(tree):

        if isinstance(node, ast.Import):
            for name in node.names:
                imports.append({
                    "module": name.name,
                    "name": None,
                    "alias": name.asname,
                    "relative": False,
                })

                dependencies.append({
                    "module": name.name,
                    "name": None,
                    "type": classify_dependency(
                        name.name,
                        local_modules,
                    ),
                    "relative": False,
                })

        elif isinstance(node, ast.ImportFrom):
            module_name = node.module or ""

            if node.level:
                module_name = "." * node.level + module_name

            for name in node.names:
                imports.append({
                    "module": module_name,
                    "name": name.name,
                    "alias": name.asname,
                    "relative": node.level > 0,
                })

                dependencies.append({
                    "module": module_name,
                    "name": name.name,
                    "type": classify_dependency(
                        module_name,
                        local_modules,
                    ),
                    "relative": node.level > 0,
                })

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append({
                "name": node.name,
                "line": node.lineno,
            })

        elif isinstance(node, ast.ClassDef):
            classes.append({
                "name": node.name,
                "line": node.lineno,
            })

        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    variables.append({
                        "name": target.id,
                        "line": target.lineno,
                    })

        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.append({
                    "name": node.func.id,
                    "line": node.lineno,
                })

            elif isinstance(node.func, ast.Attribute):
                calls.append({
                    "name": node.func.attr,
                    "line": node.lineno,
                })

    return {
        "language": "Python",
        "imports": imports,
        "dependencies": dependencies,
        "functions": functions,
        "classes": classes,
        "variables": variables,
        "calls": calls,
    }
