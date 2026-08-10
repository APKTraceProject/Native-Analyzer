"""
Configuration Loader Module for loading YAML rules and CLI test configuration files.
"""

import os
try:
    import yaml
except ImportError:
    yaml = None

from typing import Tuple, Dict, List, Optional, Any
from native_analysis.models.rule import Rule, RulePattern

class ConfigLoader:
    """
    Utility loader providing YAML configuration parsing and vulnerability rule loading.
    
    Supports both PyYAML standard parsing and a lightweight zero-dependency fallback YAML parser
    to ensure seamless execution across constrained runtime environments.
    """

    @staticmethod
    def _fallback_parse_yaml(file_content: str) -> Dict[str, Any]:
        """
        Lightweight fallback YAML parser for environments without PyYAML installed.
        
        @param file_content Raw text content of YAML configuration file.
        @return Dict[str, Any] Parsed rule dictionary structure.
        """
        rules = []
        current_rule = None
        current_pattern = None
        in_patterns = False
        cli_dict = {}

        # Line-by-line parsing of basic YAML key-value pairs and rule blocks
        for raw_line in file_content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse top-level key-value settings
            if ":" in raw_line and not raw_line.strip().startswith("- "):
                key, val = raw_line.split(":", 1)
                key = key.strip()
                val = val.strip()
                if "#" in val:
                    val = val.split("#", 1)[0].strip()
                val = val.strip().strip('"').strip("'")
                if val and not current_rule:
                    cli_dict[key] = val

            # Parse list rule items
            if line.startswith("- id:") and not in_patterns:
                current_rule = {"id": line.split(":", 1)[1].strip(), "patterns": []}
                rules.append(current_rule)
                in_patterns = False
                current_pattern = None
            elif current_rule is not None:
                if line.startswith("name:"):
                    current_rule["name"] = line.split(":", 1)[1].strip()
                elif line.startswith("severity:") and not current_pattern:
                    current_rule["severity"] = line.split(":", 1)[1].strip()
                elif line.startswith("confidence:") and not current_pattern:
                    current_rule["confidence"] = line.split(":", 1)[1].strip()
                elif line.startswith("category:"):
                    current_rule["category"] = line.split(":", 1)[1].strip()
                elif line.startswith("description:") and not in_patterns:
                    current_rule["description"] = line.split(":", 1)[1].strip()
                elif line.startswith("patterns:"):
                    in_patterns = True
                elif in_patterns:
                    if line.startswith("- id:"):
                        p_id = line.split(":", 1)[1].strip()
                        current_pattern = {"id": p_id}
                        current_rule["patterns"].append(current_pattern)
                    elif current_pattern is not None:
                        if line.startswith("pattern:"):
                            current_pattern["pattern"] = line.split(":", 1)[1].strip().strip('"').strip("'")
                        elif line.startswith("severity:"):
                            current_pattern["severity"] = line.split(":", 1)[1].strip()
                        elif line.startswith("confidence:"):
                            current_pattern["confidence"] = line.split(":", 1)[1].strip()
                        elif line.startswith("description:"):
                            current_pattern["description"] = line.split(":", 1)[1].strip().strip('"').strip("'")
                    elif line.startswith("- "):
                        # String pattern fallback
                        pattern_val = line[2:].strip().strip('"').strip("'")
                        current_rule["patterns"].append({"id": current_rule["id"], "pattern": pattern_val})

        return {"rules": rules, **cli_dict}

    @staticmethod
    def load_rules(rules_path: str = "config/rules.yaml") -> List[Rule]:
        """
        Loads signature rules from YAML file into strongly-typed Rule dataclass objects with nested RulePattern objects.
        
        @param rules_path Filesystem path to rules.yaml file.
        @return List[Rule] List of loaded Rule dataclass instances.
        """
        if not os.path.exists(rules_path):
            # Resolve alternative relative path if invoked from nested directory
            alt_path = os.path.join(os.path.dirname(__file__), "..", "..", rules_path)
            if os.path.exists(alt_path):
                rules_path = alt_path

        rules: List[Rule] = []
        if os.path.exists(rules_path):
            with open(rules_path, "r", encoding="utf-8") as f:
                content = f.read()
                if yaml is not None:
                    data = yaml.safe_load(content)
                else:
                    data = ConfigLoader._fallback_parse_yaml(content)

                if data and "rules" in data:
                    for r_dict in data["rules"]:
                        raw_patterns = r_dict.get("patterns", [])
                        pattern_objs: List[RulePattern] = []

                        default_sev = r_dict.get("severity", "LOW")
                        default_conf = r_dict.get("confidence", "LOW")
                        default_rule_id = r_dict.get("id", "GEN-001")

                        for p in raw_patterns:
                            if isinstance(p, dict):
                                pattern_objs.append(
                                    RulePattern(
                                        id=p.get("id", default_rule_id),
                                        pattern=p.get("pattern", ""),
                                        severity=p.get("severity", default_sev),
                                        confidence=p.get("confidence", default_conf),
                                        description=p.get("description", None)
                                    )
                                )
                            elif isinstance(p, str):
                                pattern_objs.append(
                                    RulePattern(
                                        id=default_rule_id,
                                        pattern=p,
                                        severity=default_sev,
                                        confidence=default_conf,
                                        description=None
                                    )
                                )

                        rule_obj = Rule(
                            id=default_rule_id,
                            name=r_dict.get("name", "Generic Rule"),
                            severity=default_sev,
                            confidence=default_conf,
                            category=r_dict.get("category", "General"),
                            patterns=pattern_objs,
                            description=r_dict.get("description", "")
                        )
                        rules.append(rule_obj)
        return rules

    @staticmethod
    def resolve_target_path(path: Optional[str]) -> Optional[str]:
        """
        Resolves relative or absolute target file paths against current working directory and project root.
        
        @param path Path string to resolve.
        @return Optional[str] Absolute normalized file path if found on disk, or original path if not found.
        """
        if not path:
            return None

        # 1. Direct path check (relative to CWD or absolute)
        if os.path.exists(path):
            return os.path.abspath(path)

        # 2. Check relative to project root (two levels above config_loader.py)
        proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
        rel_proj_path = os.path.join(proj_root, path)
        if os.path.exists(rel_proj_path):
            return os.path.abspath(rel_proj_path)

        return path

    @staticmethod
    def load_cli_config(config_path: str = "config/cli_config.yaml") -> Dict[str, Any]:
        """
        Loads CLI configuration containing default target library paths and Ghidra settings.
        Checks config/cli_config.yaml first, falling back to config/cli_config.example.yaml.
        
        @param config_path Path to cli_config.yaml configuration file.
        @return Dict[str, Any] Configuration options dictionary.
        """
        target_config_file = config_path

        # If primary config path does not exist, check for cli_config.example.yaml
        if not os.path.exists(target_config_file):
            dir_name = os.path.dirname(config_path) or "."
            example_candidate = os.path.join(dir_name, "cli_config.example.yaml")
            if os.path.exists(example_candidate):
                target_config_file = example_candidate
            elif os.path.exists("config/cli_config.example.yaml"):
                target_config_file = "config/cli_config.example.yaml"

        if os.path.exists(target_config_file):
            with open(target_config_file, "r", encoding="utf-8") as f:
                content = f.read()
                if yaml is not None:
                    res = yaml.safe_load(content) or {}
                else:
                    res = ConfigLoader._fallback_parse_yaml(content)

                if "target_so_path" in res and "target_path" not in res:
                    res["target_path"] = res["target_so_path"]

                if "engine" not in res:
                    res["engine"] = "ghidra"

                if res.get("target_path"):
                    res["target_path"] = ConfigLoader.resolve_target_path(res["target_path"])

                if res.get("output_engine_path"):
                    e_path = os.path.abspath(res["output_engine_path"])
                    os.makedirs(e_path, exist_ok=True)
                    res["output_engine_path"] = e_path
                elif res.get("output_ghidra_path"):
                    # Support backwards-compatibility key fallback
                    e_path = os.path.abspath(res["output_ghidra_path"])
                    os.makedirs(e_path, exist_ok=True)
                    res["output_engine_path"] = e_path

                res["_config_file_used"] = target_config_file
                return res

        # Default configuration fallback dictionary (no hardcoded test target defaults)
        return {
            "target_path": None,
            "output_json_path": "./output/report.json",
            "output_engine_path": "./output/engine_artifacts",
            "engine": "ghidra",
            "decompiler_path": None,
            "_config_file_used": None
        }

