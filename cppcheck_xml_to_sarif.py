#!/usr/bin/env python3
"""Convert cppcheck XML v2 output to SARIF 2.1.0 for GitHub Code Scanning."""
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path

SEVERITY_MAP = {
    "error":       "error",
    "warning":     "warning",
    "style":       "note",
    "performance": "note",
    "portability": "note",
    "information": "none",
}


def convert(xml_files, repo_root=""):
    rules = {}
    results = []

    for xml_path in xml_files:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for error in root.iter("error"):
            rule_id = error.get("id", "unknown")
            severity = error.get("severity", "information")
            msg = error.get("verbose") or error.get("msg", "")
            cwe = error.get("cwe", "")

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": msg[:100]},
                    "helpUri": f"https://cppcheck.sourceforge.io/",
                    "properties": {
                        "tags": ["security", "correctness"],
                        "problem.severity": SEVERITY_MAP.get(severity, "note"),
                    },
                }
                if cwe:
                    rules[rule_id]["properties"]["cwe"] = f"CWE-{cwe}"

            locations = error.findall("location")
            if not locations:
                continue
            for loc in locations[:1]:  # primary location only
                file_path = loc.get("file", "unknown")
                line = int(loc.get("line", 1))
                col = int(loc.get("column", 1)) if loc.get("column") else 1

                rel_path = file_path
                if repo_root and file_path.startswith(repo_root):
                    rel_path = file_path[len(repo_root):].lstrip("/")

                results.append({
                    "ruleId": rule_id,
                    "level": SEVERITY_MAP.get(severity, "note"),
                    "message": {"text": msg},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": rel_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": line,
                                "startColumn": col,
                            },
                        }
                    }],
                    "properties": {"severity": severity, "cwe": f"CWE-{cwe}" if cwe else ""},
                })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Cppcheck",
                    "version": "2.10",
                    "informationUri": "https://cppcheck.sourceforge.io/",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "originalUriBaseIds": {
                "%SRCROOT%": {"uri": "file:///src/"}
            },
        }]
    }
    return sarif


if __name__ == "__main__":
    xml_files = sys.argv[1:] or list(Path(".").glob("results/*.xml"))
    sarif = convert(xml_files)
    out = "results/cppcheck.sarif"
    with open(out, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"Written {out}: {len(sarif['runs'][0]['results'])} findings, {len(sarif['runs'][0]['tool']['driver']['rules'])} rules")
