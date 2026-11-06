"""Software bills of materials from the evidence graph: CycloneDX 1.6 and SPDX 2.3 (JSON).

Unlike a bill of materials built from a lock file, this one lists what a
program actually reaches on this machine: the program, every script,
binary, library and module file it runs or loads (with SHA-256), and the
packages that own them (with package URLs). Each dependency keeps XRAY's
evidence: the link kind and its basis (observed, declared, inferred,
guessed), as properties in CycloneDX and in relationship comments in SPDX.
"""

from __future__ import annotations

import datetime
import hashlib
import uuid
from pathlib import Path

from . import __version__
from .evidencehtml import view_data


def _sha256(path, algorithm="sha256"):
    digest = hashlib.new(algorithm)
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def _purl(label, manager):
    name, _, version = label.partition(" ")
    if manager == "pacman":
        return f"pkg:alpm/arch/{name}@{version}" if version else f"pkg:alpm/arch/{name}"
    if manager == "rpm":
        return f"pkg:rpm/{name}@{version}" if version else f"pkg:rpm/{name}"
    return None


def _packages(graph):
    """{file id: (package name, version, manager)}"""

    owned = {}
    for link in graph.links.values():
        if link.kind == "owned_by":
            node = graph.nodes[link.target]
            name, _, version = node.label.partition(" ")
            owned[link.source] = (name, version, node.attrs.get("manager"))
    return owned


def cyclonedx(graph):
    data = view_data(graph)
    owned = _packages(graph)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    components, packages = [], {}
    root_ref = data["root"]
    for node in data["nodes"]:
        if not node["path"] or node["id"] == root_ref:
            continue
        component = {
            "type": "library" if node["kind"] in ("library", "python", "perl", "ruby", "javascript", "lua") else "file",
            "bom-ref": node["id"],
            "name": Path(node["id"]).name,
            "properties": [{"name": "xray:path", "value": node["id"]}, {"name": "xray:kind", "value": node["kind"]}],
        }
        digest = _sha256(node["id"])
        if digest:
            component["hashes"] = [{"alg": "SHA-256", "content": digest}]
        if node["id"] in owned:
            name, version, manager = owned[node["id"]]
            component["properties"].append({"name": "xray:package", "value": f"{name} {version}".strip()})
            packages.setdefault(name, (version, manager))
        components.append(component)
    for name, (version, manager) in sorted(packages.items()):
        package = {"type": "library", "bom-ref": f"package:{name}", "name": name, "version": version or None}
        purl = _purl(f"{name} {version}", manager)
        if purl:
            package["purl"] = purl
        components.append({key: value for key, value in package.items() if value is not None})

    depends = {}
    for edge in data["edges"]:
        if edge["target"].startswith("/"):
            depends.setdefault(edge["source"], set()).add(edge["target"])
    for file_id, (name, _version, _manager) in owned.items():
        depends.setdefault(file_id, set()).add(f"package:{name}")
    root_digest = _sha256(root_ref)
    root = {"type": "application", "bom-ref": root_ref, "name": Path(root_ref).name,
            "properties": [{"name": "xray:path", "value": root_ref}]}
    if root_digest:
        root["hashes"] = [{"alg": "SHA-256", "content": root_digest}]
    if root_ref in owned:
        root["properties"].append({"name": "xray:package", "value": " ".join(owned[root_ref][:2]).strip()})
    evidence = [
        {"name": f"xray:link:{edge['source']}->{edge['target']}",
         "value": f"{','.join(edge['kinds'])} [{edge['basis']}]" + (f" via {edge['via']}" if edge.get("via") else "")}
        for edge in data["edges"] if edge["target"].startswith("/")
    ]
    refs = {component["bom-ref"] for component in components} | {root_ref}
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {"components": [{"type": "application", "name": "xray", "version": __version__}]},
            "component": root,
            "properties": [{"name": "xray:basis-order", "value": "observed > declared > inferred > guessed"},
                           *({"name": "xray:blind-spot", "value": spot["message"]} for spot in data["blind_spots"]),
                           *evidence],
        },
        "components": components,
        "dependencies": [{"ref": ref, "dependsOn": sorted(target for target in targets if target in refs)}
                         for ref, targets in sorted(depends.items()) if ref in refs],
    }


def spdx(graph):
    data = view_data(graph)
    owned = _packages(graph)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ids = {}

    def spdx_id(key):
        if key not in ids:
            ids[key] = f"SPDXRef-{len(ids) + 1}"
        return ids[key]

    files, packages, relationships = [], {}, []
    root_ref = data["root"]
    for node in data["nodes"]:
        if not node["path"]:
            continue
        digest, sha1 = _sha256(node["id"]), _sha256(node["id"], "sha1")
        # SPDX file names are relative to the root of what is described: ./usr/lib/...
        entry = {"SPDXID": spdx_id(node["id"]), "fileName": "." + node["id"],
                 "checksums": [{"algorithm": "SHA1", "checksumValue": sha1},
                               {"algorithm": "SHA256", "checksumValue": digest}] if digest else [],
                 "comment": f"xray kind: {node['kind']}"}
        files.append(entry)
        if node["id"] in owned:
            name, version, manager = owned[node["id"]]
            if name not in packages:
                package = {"SPDXID": spdx_id(f"package:{name}"), "name": name, "versionInfo": version or "NOASSERTION",
                           "downloadLocation": "NOASSERTION", "filesAnalyzed": False}
                purl = _purl(f"{name} {version}", manager)
                if purl:
                    package["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                                "referenceLocator": purl}]
                packages[name] = package
            # Only the files the program reaches are listed, so the package is not "analyzed" and may not
            # CONTAIN them in SPDX terms; ownership is recorded as an annotated relationship instead.
            relationships.append({"spdxElementId": spdx_id(node["id"]), "relationshipType": "OTHER",
                                  "relatedSpdxElement": spdx_id(f"package:{name}"),
                                  "comment": f"xray: owned by the installed package ({manager} database)"})
    for edge in data["edges"]:
        if edge["source"] in ids and edge["target"] in ids:
            relationships.append({
                "spdxElementId": spdx_id(edge["source"]), "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": spdx_id(edge["target"]),
                "comment": f"xray: {','.join(edge['kinds'])} [{edge['basis']}]" + (f" via {edge['via']}" if edge.get("via") else ""),
            })
    relationships.insert(0, {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                             "relatedSpdxElement": spdx_id(root_ref)})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"xray-{Path(root_ref).name}",
        "documentNamespace": f"https://github.com/luciusthorne/xray/spdx/{Path(root_ref).name}-{uuid.uuid4()}",
        "creationInfo": {"created": now, "creators": [f"Tool: xray-{__version__}"]},
        "packages": list(packages.values()),
        "files": files,
        "relationships": relationships,
    }
