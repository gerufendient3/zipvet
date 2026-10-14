import pytest

from zipvet.models import Finding
from zipvet.scoring import WEIGHTS, compute_score


def hallazgo(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="t",
        severity="medium",
        category="c",
        path=None,
        line=None,
        message="m",
        recommendation="r",
    )


def test_pesos_suman_100():
    assert sum(WEIGHTS.values()) == 100


def test_sin_hallazgos_da_100():
    assert compute_score([]) == 100


def test_cada_regla_descuenta_una_sola_vez():
    doble = [hallazgo("DOC-LICENSE"), hallazgo("DOC-LICENSE")]
    assert compute_score(doble) == 100 - WEIGHTS["DOC-LICENSE"]


def test_varias_reglas_se_suman():
    hallazgos = [hallazgo("DOC-LICENSE"), hallazgo("TEST-PRESENCE")]
    esperado = 100 - WEIGHTS["DOC-LICENSE"] - WEIGHTS["TEST-PRESENCE"]
    assert compute_score(hallazgos) == esperado


def test_nunca_baja_de_cero():
    todos = [hallazgo(regla) for regla in WEIGHTS]
    assert compute_score(todos) == 0


def test_regla_desconocida_falla_en_vez_de_puntuar_en_silencio():
    with pytest.raises(KeyError):
        compute_score([hallazgo("REGLA-INVENTADA")])
