import json
import os
import re
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from sqlalchemy.orm import Session

from backend.app.models.detection_rule import DetectionRule
from backend.app.models.enums import Severity

logger = logging.getLogger(__name__)

# Safe operators allowed in rule conditions - NO arbitrary code execution
SAFE_OPERATORS = frozenset({"eq", "ne", "contains", "gte", "lte", "in", "regex", "count_distinct", "requires_prior"})

REQUIRED_RULE_FIELDS = frozenset({"rule_id", "name", "description", "event_types", "conditions", "severity", "enabled"})

MAX_THRESHOLD = 10000
MAX_WINDOW_SECONDS = 86400  # 24 hours
MAX_RULE_NAME_LENGTH = 255
MAX_RULE_ID_LENGTH = 80

def validate_conditions(conditions: Dict[str, Any]) -> List[str]:
    """Validate that rule conditions only use safe operators. Returns list of validation errors."""
    errors = []
    if not isinstance(conditions, dict):
        errors.append("conditions must be a dict")
        return errors
    for key, value in conditions.items():
        if key == "requires_prior" and isinstance(value, dict):
            for p_key, p_val in value.items():
                if p_key in ("min_count", "window_seconds", "event_types"):
                    continue
                if isinstance(p_val, dict):
                    for op in p_val.keys():
                        if op not in SAFE_OPERATORS:
                            errors.append(f"Unsafe operator '{op}' in nested condition '{p_key}' inside requires_prior")
            continue
        if isinstance(value, dict):
            for op in value.keys():
                if op not in SAFE_OPERATORS:
                    errors.append(f"Unsafe operator '{op}' in condition '{key}'. Allowed: {sorted(SAFE_OPERATORS)}")
    return errors

def validate_rule(rule_data: Dict[str, Any]) -> List[str]:
    """Validate a rule definition against schema constraints. Returns list of validation errors."""
    errors = []
    
    # Required fields
    missing = REQUIRED_RULE_FIELDS - set(rule_data.keys())
    if missing:
        errors.append(f"Missing required fields: {sorted(missing)}")
        return errors  # Cannot validate further without required fields
    
    # Type checks
    if not isinstance(rule_data["rule_id"], str) or len(rule_data["rule_id"]) > MAX_RULE_ID_LENGTH:
        errors.append(f"rule_id must be a string with max length {MAX_RULE_ID_LENGTH}")
    if not isinstance(rule_data["name"], str) or len(rule_data["name"]) > MAX_RULE_NAME_LENGTH:
        errors.append(f"name must be a string with max length {MAX_RULE_NAME_LENGTH}")
    if not isinstance(rule_data["event_types"], list) or not all(isinstance(e, str) for e in rule_data["event_types"]):
        errors.append("event_types must be a list of strings")
    if not isinstance(rule_data["enabled"], bool):
        errors.append("enabled must be a boolean")
    
    # Severity validation
    try:
        Severity(rule_data["severity"])
    except ValueError:
        errors.append(f"Invalid severity: {rule_data['severity']}. Must be one of {[s.value for s in Severity]}")
    
    # Threshold bounds
    threshold = rule_data.get("threshold")
    if threshold is not None:
        if not isinstance(threshold, int) or threshold < 1 or threshold > MAX_THRESHOLD:
            errors.append(f"threshold must be an integer between 1 and {MAX_THRESHOLD}")
    
    # Window bounds
    window = rule_data.get("window_seconds")
    if window is not None:
        if not isinstance(window, int) or window < 1 or window > MAX_WINDOW_SECONDS:
            errors.append(f"window_seconds must be an integer between 1 and {MAX_WINDOW_SECONDS}")
    
    # Risk weight bounds
    risk_weight = rule_data.get("risk_weight", 50)
    if not isinstance(risk_weight, int) or risk_weight < 0 or risk_weight > 100:
        errors.append("risk_weight must be an integer between 0 and 100")
    
    # Condition safety validation
    errors.extend(validate_conditions(rule_data.get("conditions", {})))
    
    return errors

def load_rules_from_directory(rules_dir: str) -> List[Dict[str, Any]]:
    """Load and validate all JSON rule files from the specified directory."""
    rules = []
    rules_path = Path(rules_dir)
    
    if not rules_path.is_dir():
        logger.warning(f"Rules directory does not exist: {rules_dir}")
        return rules
    
    for rule_file in sorted(rules_path.glob("CW-*.json")):
        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                rule_data = json.load(f)
            
            errors = validate_rule(rule_data)
            if errors:
                logger.error(f"Invalid rule {rule_file.name}: {errors}")
                continue
            
            rules.append(rule_data)
            logger.info(f"Loaded rule: {rule_data['rule_id']} ({rule_data['name']})")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse {rule_file.name}: {e}")
        except Exception as e:
            logger.error(f"Failed to load {rule_file.name}: {e}")
    
    return rules

def sync_rules_to_db(rules: List[Dict[str, Any]], db: Session) -> int:
    """Sync validated rules into the detection_rules table. Returns count of synced rules."""
    synced = 0
    for rule_data in rules:
        existing = db.query(DetectionRule).filter(DetectionRule.rule_id == rule_data["rule_id"]).first()
        
        if existing:
            # Update if version is newer
            new_version = rule_data.get("version", 1)
            if new_version > existing.version:
                existing.name = rule_data["name"]
                existing.description = rule_data["description"]
                existing.category = rule_data.get("category")
                existing.event_types = rule_data["event_types"]
                existing.conditions = rule_data["conditions"]
                existing.group_by = rule_data.get("group_by")
                existing.threshold = rule_data.get("threshold")
                existing.window_seconds = rule_data.get("window_seconds")
                existing.severity = Severity(rule_data["severity"])
                existing.risk_weight = rule_data.get("risk_weight", 50)
                existing.mitre_metadata = rule_data.get("mitre_metadata", {})
                existing.enabled = rule_data["enabled"]
                existing.version = new_version
                synced += 1
                logger.info(f"Updated rule {rule_data['rule_id']} to version {new_version}")
        else:
            db_rule = DetectionRule(
                rule_id=rule_data["rule_id"],
                name=rule_data["name"],
                description=rule_data["description"],
                category=rule_data.get("category"),
                event_types=rule_data["event_types"],
                conditions=rule_data["conditions"],
                group_by=rule_data.get("group_by"),
                threshold=rule_data.get("threshold"),
                window_seconds=rule_data.get("window_seconds"),
                severity=Severity(rule_data["severity"]),
                risk_weight=rule_data.get("risk_weight", 50),
                mitre_metadata=rule_data.get("mitre_metadata", {}),
                enabled=rule_data["enabled"],
                version=rule_data.get("version", 1),
            )
            db.add(db_rule)
            synced += 1
            logger.info(f"Created rule {rule_data['rule_id']}")
    
    db.commit()
    return synced


class RuleLoader:
    """Loads and manages detection rules from disk and database."""
    
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self._rules: List[Dict[str, Any]] = []
    
    def load(self) -> List[Dict[str, Any]]:
        """Load all valid rules from the rules directory."""
        self._rules = load_rules_from_directory(self.rules_dir)
        return self._rules
    
    def sync(self, db: Session) -> int:
        """Load rules from disk and sync to database. Returns count synced."""
        if not self._rules:
            self.load()
        return sync_rules_to_db(self._rules, db)
    
    @property
    def rules(self) -> List[Dict[str, Any]]:
        return list(self._rules)
