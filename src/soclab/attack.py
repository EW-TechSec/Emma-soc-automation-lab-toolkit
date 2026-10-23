"""MITRE ATT&CK Enterprise tactics, in kill-chain order, as written in Sigma tags."""

TACTICS: list[str] = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

# Technique that means the attacker holds working credentials.
VALID_ACCOUNTS = "T1078"


def tactic_order(tactic: str) -> int:
    """Position in the kill chain; unknown tactics sort last."""
    return TACTICS.index(tactic) if tactic in TACTICS else len(TACTICS)
