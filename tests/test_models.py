import dataclasses

import pytest

from zipvet.models import MIB, Finding, ScanLimits


def test_limites_por_defecto_coinciden_con_el_manual():
    limits = ScanLimits()
    assert limits.max_upload_bytes == 10 * MIB
    assert limits.max_entries == 2000
    assert limits.max_total_uncompressed_bytes == 40 * MIB
    assert limits.max_member_bytes == 1 * MIB
    assert limits.max_total_text_bytes == 5 * MIB
    assert limits.max_text_files == 500


def test_limites_son_inmutables():
    with pytest.raises(dataclasses.FrozenInstanceError):
        ScanLimits().max_entries = 10  # type: ignore[misc]


def test_hallazgo_es_inmutable_y_admite_ruta_opcional():
    hallazgo = Finding(
        rule_id="DOC-LICENSE",
        title="Licencia ausente",
        severity="high",
        category="documentacion",
        path=None,
        line=None,
        message="No se detectó un archivo de licencia en la raíz.",
        recommendation="Añade una licencia, por ejemplo MIT.",
    )
    assert hallazgo.path is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        hallazgo.severity = "low"  # type: ignore[misc]
