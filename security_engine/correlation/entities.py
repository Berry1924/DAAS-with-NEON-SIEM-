import hashlib
from typing import Dict, Any, Optional
from backend.app.models.alert import Alert
from backend.app.models.event import Event

class EntityExtractor:
    """Extracts and formats security entities from Alerts and Events deterministically."""

    @staticmethod
    def extract_from_alert(alert: Alert) -> Dict[str, Optional[str]]:
        """Extract canonical entities dictionary from an Alert."""
        return {
            "source_ip": alert.source_ip.strip() if alert.source_ip else None,
            "destination_ip": alert.destination_ip.strip() if alert.destination_ip else None,
            "username": alert.username.strip() if alert.username else None,
            "hostname": alert.hostname.strip() if alert.hostname else None,
        }

    @staticmethod
    def extract_from_event(event: Event) -> Dict[str, Optional[str]]:
        """Extract canonical entities dictionary from an Event."""
        return {
            "source_ip": event.source_ip.strip() if event.source_ip else None,
            "destination_ip": event.destination_ip.strip() if event.destination_ip else None,
            "username": event.username.strip() if event.username else None,
            "hostname": event.hostname.strip() if event.hostname else None,
        }

    @staticmethod
    def generate_fingerprint(entities: Dict[str, Optional[str]]) -> str:
        """Generate a deterministic SHA-256 fingerprint string from non-null entities."""
        sorted_pairs = []
        for key in ["source_ip", "destination_ip", "username", "hostname"]:
            val = entities.get(key)
            if val:
                sorted_pairs.append(f"{key}:{val}")
        
        if not sorted_pairs:
            return "empty-entity-fingerprint"
        
        raw_key = "|".join(sorted_pairs)
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]
        return f"CORR-{digest}"

    @staticmethod
    def shares_entity(entities_a: Dict[str, Optional[str]], entities_b: Dict[str, Optional[str]]) -> bool:
        """Check if two entity dicts share at least one non-null entity attribute.
        
        Priority order:
        1. same source_ip
        2. same destination_ip
        3. same hostname
        4. same username
        """
        for key in ["source_ip", "destination_ip", "hostname", "username"]:
            val_a = entities_a.get(key)
            val_b = entities_b.get(key)
            if val_a and val_b and val_a == val_b:
                return True
        return False

    @staticmethod
    def get_shared_entity_description(entities: Dict[str, Optional[str]]) -> str:
        """Build an explainable description of populated entities."""
        parts = []
        if entities.get("source_ip"):
            parts.append(f"source IP {entities['source_ip']}")
        if entities.get("destination_ip"):
            parts.append(f"destination IP {entities['destination_ip']}")
        if entities.get("hostname"):
            parts.append(f"host {entities['hostname']}")
        if entities.get("username"):
            parts.append(f"user {entities['username']}")
        
        if not parts:
            return "shared security attributes"
        return " and ".join(parts)

entity_extractor = EntityExtractor()
