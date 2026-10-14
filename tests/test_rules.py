import json

from tests.helpers import make_zip
from zipvet.audit import build_demo_zip, run_audit


def reglas(report):
    return {f["rule_id"] for f in report["findings"]}


def test_demo_detecta_las_reglas_esperadas():
    report = run_audit(build_demo_zip())
    esperadas = {
        "DOC-LICENSE",
        "HYG-GITIGNORE",
        "SEC-ENV-FILE",
        "SEC-SECRET-PATTERN",
        "TEST-PRESENCE",
        "CI-PRESENCE",
    }
    assert esperadas <= reglas(report)
    assert "DOC-README" not in reglas(report)


def test_nunca_muestra_el_valor_completo_de_una_credencial():
    texto = json.dumps(run_audit(build_demo_zip()))
    assert "9f8e7d6c5b4a3210" not in texto


def test_placeholder_no_se_marca():
    data = make_zip({"p/app.py": 'api_key = "your_api_key_here_1234"\n', "p/README.md": "# p"})
    assert "SEC-SECRET-PATTERN" not in reglas(run_audit(data))


def test_clave_privada_se_detecta_sin_mostrar_su_contenido():
    data = make_zip({"p/k.py": "KEY = '''-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n'''"})
    report = run_audit(data)
    hallazgo = next(f for f in report["findings"] if f["rule_id"] == "SEC-SECRET-PATTERN")
    assert hallazgo["line"] == 1 and hallazgo["path"] == "k.py"
    assert "MIIBOgIBAAJBAK" not in json.dumps(report)


def test_proyecto_sin_python_no_recibe_puntuacion():
    report = run_audit(make_zip({"p/notas.md": "# notas"}))
    assert report["score"] is None and report["python_project"] is False


def test_proyecto_completo_puntua_100_sin_hallazgos():
    data = make_zip(
        {
            "p/LICENSE": "MIT",
            "p/README.md": "# p",
            "p/.gitignore": "venv/\n",
            "p/app.py": "x = 1\n",
            "p/tests/test_app.py": "def test_x():\n    assert True\n",
            "p/.github/workflows/ci.yml": "name: ci\n",
        }
    )
    report = run_audit(data)
    assert report["score"] == 100
    assert report["findings"] == []
    assert report["coverage"]["carpeta_raiz"] == "p"


def test_env_example_no_se_marca_como_riesgo():
    data = make_zip({"p/app.py": "x = 1\n", "p/.env.example": "API_URL=\n"})
    assert "SEC-ENV-FILE" not in reglas(run_audit(data))
