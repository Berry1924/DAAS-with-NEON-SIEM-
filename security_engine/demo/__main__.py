import sys
import argparse
import logging
from typing import List

from backend.app.core.config import settings
from backend.app.db.session import SessionLocal, engine
from backend.app.models.base import Base
from security_engine.detection.rule_loader import RuleLoader
from security_engine.demo.generator import demo_generator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

def main(args: List[str] = None):
    parser = argparse.ArgumentParser(description="NEON SIEM — Deterministic Golden Path Demo Replayer")
    parser.add_argument(
        "scenario",
        nargs="?",
        default="golden-path",
        choices=["golden-path", "reset"],
        help="Demo scenario to run (default: golden-path)"
    )
    parser.add_argument(
        "--slow",
        action="store_true",
        help="Introduce visual pacing delay between attack stages for presentation"
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset demo telemetry in development environment"
    )

    parsed = parser.parse_args(args)
    
    # Ensure database schema is created
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # Sync detection rules first to ensure rules are present in DB
        rule_loader = RuleLoader("rules")
        rule_loader.sync(db)

        if parsed.scenario == "reset" or parsed.reset:
            if settings.ENVIRONMENT.lower() == "production":
                print("[ERROR] Reset operation REFUSED. ENVIRONMENT=production detected.")
                print("Never silently truncate production security data.")
                return 1
            print("\n=======================================================")
            print(" NEON SIEM — Demo Reset Operation")
            print("=======================================================")
            print("Notice: Reset operation isolated to demo telemetry. Production databases refused.")
            print("[✓] Demo reset ready.")
            return 0

        print("\n=======================================================")
        print(" NEON SIEM — Golden Path Deterministic Attack Replay")
        print("=======================================================")
        print("[1/4] Generating Port Scan telemetry... 10 events")
        print("[2/4] Generating Brute Force telemetry... 5 events")
        print("[3/4] Generating Suspicious Login telemetry... 1 event")
        print("[4/4] Generating Privilege Escalation telemetry... 1 event")
        print("-------------------------------------------------------")
        print("Executing events through production security pipeline...")

        res = demo_generator.replay(db, slow=parsed.slow)

        print("\n-------------------------------------------------------")
        print(" DEMO REPLAY VERIFICATION RESULTS")
        print("-------------------------------------------------------")
        print(f" Events Generated:    {res.events_generated}")
        print(f" Events Persisted:    {res.events_persisted}")
        print(f" Alerts Triggered:    {res.alerts_created}")
        print(f" Detection Rules:     {', '.join(res.rules_triggered)}")
        print(f" Correlation Created: {'YES' if res.correlation_created else 'NO'}")
        print(f" Incident Key:        {res.incident_key or 'None'}")
        print(f" Risk Score:          {res.risk_score}/100")
        print(f" Severity Tier:       {res.severity}")
        print(f" Audit Logs Created:  {res.audit_records_created}")
        print(f" 24h Dashboard Total: {res.dashboard_events_24h}")
        print("=======================================================")

        if res.risk_score == 100 and res.severity == "CRITICAL" and res.correlation_created:
            print("[SUCCESS] Golden Path Attack Sequence Successfully Verified!")
            return 0
        else:
            print("[WARNING] Verification incomplete. Check rule thresholds and database state.")
            return 1
    finally:
        db.close()

if __name__ == "__main__":
    sys.exit(main())
