import json
from pathlib import Path
 
RULES_PATH = Path(__file__).parent / "rules.json"

def load_rules():
    if RULES_PATH.exists():
       return json.loads(RULES_PATH.read_text(encoding="utf-8"))
    return []


RULES = load_rules()

 
def analyze_log(log_type: str, message: str) -> str:
    msg = (message or "").lower()
    lt = (log_type or "").upper()

    for rule in RULES:
        rule_lt = (rule.get("log_type", "ANY") or "ANY").upper()
        if rule_lt != "ANY" and rule_lt != lt:
             continue

        contains = [c.lower() for c in rule.get("contains", [])]
        if any(token in msg for token in contains):
            return rule.get("severity", "INFO").upper()

    return "INFO"
