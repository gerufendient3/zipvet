from tests.helpers import make_zip
from zipvet.audit import build_demo_zip, decision, run_audit


def hallazgo(severidad):
    return {"severity": severidad}


def test_alerta_alta_nunca_da_estado_favorable_aunque_la_puntuacion_sea_alta():
    nivel, titulo, _ = decision(85, [hallazgo("high")])
    assert nivel == "alto" and titulo == "Requiere atención"


def test_alerta_media_da_revision_pendiente():
    nivel, titulo, _ = decision(90, [hallazgo("medium")])
    assert nivel == "medio" and titulo == "Revisión pendiente"


def test_solo_alertas_bajas_no_son_favorables_del_todo():
    nivel, titulo, _ = decision(95, [hallazgo("low")])
    assert nivel == "bajo" and titulo == "Sin alertas graves"


def test_sin_hallazgos_da_sin_senales_conocidas():
    nivel, titulo, texto = decision(100, [])
    assert titulo == "Sin señales conocidas"
    assert "no certifica" in texto


def test_demo_no_tiene_licencia_como_alerta_alta():
    report = run_audit(build_demo_zip())
    altas = [f["rule_id"] for f in report["findings"] if f["severity"] == "high"]
    assert "DOC-LICENSE" not in altas
    assert set(altas) == {"SEC-ENV-FILE", "SEC-SECRET-PATTERN"}


def test_proyecto_con_credencial_real_queda_en_requiere_atencion():
    data = make_zip({"p/app.py": 'api_key = "9f8e7d6c5b4a3210zz"\n', "p/README.md": "# p"})
    report = run_audit(data)
    nivel, _, _ = decision(report["score"], report["findings"])
    assert nivel == "alto"
