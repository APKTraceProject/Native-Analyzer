"""
Configuration Loader Module for loading YAML rules and CLI test configuration files.
"""

import os
try:
    import yaml
except ImportError:
    yaml = None

from typing import Tuple, Dict, List, Optional, Any
from native_analysis.models.rule import Rule

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
                val = val.strip().strip('"').strip("'")
                if val:
                    cli_dict[key] = val

            # Parse list rule items
            if line.startswith("- id:"):
                current_rule = {"id": line.split(":", 1)[1].strip(), "patterns": []}
                rules.append(current_rule)
                in_patterns = False
            elif current_rule is not None:
                if line.startswith("name:"):
                    current_rule["name"] = line.split(":", 1)[1].strip()
                elif line.startswith("severity:"):
                    current_rule["severity"] = line.split(":", 1)[1].strip()
                elif line.startswith("confidence:"):
                    current_rule["confidence"] = line.split(":", 1)[1].strip()
                elif line.startswith("category:"):
                    current_rule["category"] = line.split(":", 1)[1].strip()
                elif line.startswith("description:"):
                    current_rule["description"] = line.split(":", 1)[1].strip()
                elif line.startswith("patterns:"):
                    in_patterns = True
                elif in_patterns and line.startswith("- "):
                    pattern_val = line[2:].strip().strip('"').strip("'")
                    current_rule["patterns"].append(pattern_val)

        return {"rules": rules, **cli_dict}

    @staticmethod
    def load_rules(rules_path: str = "config/rules.yaml") -> List[Rule]:
        """
        Loads signature rules from YAML file into strongly-typed Rule dataclass objects.
        
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
                        rule_obj = Rule(
                            id=r_dict.get("id", "GEN-001"),
                            name=r_dict.get("name", "Generic Rule"),
                            severity=r_dict.get("severity", "LOW"),
                            confidence=r_dict.get("confidence", "LOW"),
                            category=r_dict.get("category", "General"),
                            patterns=r_dict.get("patterns", []),
                            description=r_dict.get("description", "")
                        )
                        rules.append(rule_obj)
        return rules

    @staticmethod
    def load_cli_config(config_path: str = "config/cli_config.yaml") -> Dict[str, Any]:
        """
        Loads CLI configuration containing default target library paths and Ghidra settings.
        
        @param config_path Path to cli_config.yaml configuration file.
        @return Dict[str, Any] Configuration options dictionary.
        """
        if not os.path.exists(config_path):
            example_path = config_path + ".example"
            if os.path.exists(example_path):
                config_path = example_path

        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()
                if yaml is not None:
                    return yaml.safe_load(content) or {}
                else:
                    return ConfigLoader._fallback_parse_yaml(content)
        
        # Default configuration fallback dictionary
        return {
            "target_so_path": "./tests/libnative.so",
            "output_json_path": "./output/report.json",
            "ghidra_headless_path": None
        }
