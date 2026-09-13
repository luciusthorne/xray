import ast

from .dependencies import classify_dependency, discover_local_modules


def analyze_python(path):
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()

    tree = ast.parse(source, filename=path)

    imports = []
    dependencies = []
    functions = []
    classes = []
    variables = []
    calls = []

    project_root = path.parent.parent if path.parent.name == "test_programs" else path.parent
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
            if node.module:
                module_name = node.module

                if node.level:
                    module_name = "." * node.level + module_name

                for name in node.names:
                    imports.append({
                        "module": module_name,
                        "name": name.name,
                        "alias": name.asname,
                        "relative": node.level > 0,
                    })

                    dependency_module = node.module

                    dependencies.append({
                        "module": module_name,
                        "name": name.name,
                        "type": classify_dependency(
                            dependency_module,
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
