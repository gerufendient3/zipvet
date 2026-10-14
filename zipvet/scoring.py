"""Puntuación de preparación del repositorio, transparente y pública.

La puntuación no es una nota de seguridad ni una certificación. Parte de 100
y descuenta una vez por regla fallida. Los pesos están centralizados aquí
y documentados en docs/RULES.md.
"""

from collections.abc import Iterable

from zipvet.models import Finding

WEIGHTS: dict[str, int] = {
    "DOC-LICENSE": 15,
    "DOC-README": 15,
    "HYG-GITIGNORE": 10,
    "SEC-ENV-FILE": 20,
    "SEC-SECRET-PATTERN": 15,
    "TEST-PRESENCE": 15,
    "CI-PRESENCE": 10,
}


def compute_score(findings: Iterable[Finding]) -> int:
    """Devuelve una puntuación entre 0 y 100, descontando cada regla una sola vez."""
    failed_rules = {finding.rule_id for finding in findings}
    unknown = failed_rules - WEIGHTS.keys()
    if unknown:
        raise KeyError(f"Regla sin peso definido: {sorted(unknown)}")
    deduction = sum(WEIGHTS[rule] for rule in failed_rules)
    return max(0, 100 - deduction)
