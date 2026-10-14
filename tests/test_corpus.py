"""Corpus de 20 casos con resultado esperado. Cada caso es una prueba automática.

Cada caso dice qué debe detectarse, qué no debe detectarse y qué estado debe mostrar.
Si una detección cambia, este archivo lo muestra antes de llegar a los usuarios.
"""

import pytest

from tests.helpers import make_zip
from zipvet.audit import decision, run_audit
from zipvet.models import MIB, ArchiveValidationError, ScanLimits

BASE = {
    "p/LICENSE": "MIT",
    "p/README.md": "# p",
    "p/.gitignore": "venv/\n",
    "p/app.py": "x = 1\n",
    "p/tests/test_app.py": "def test_x():\n    assert True\n",
    "p/.github/workflows/ci.yml": "name: ci\n",
}


def con(**cambios):
    datos = dict(BASE)
    datos.update(cambios)
    return make_zip(datos)


def sin(*rutas):
    return make_zip({k: v for k, v in BASE.items() if k not in rutas})


CASOS = [
    # Proyectos correctos y placeholders
    (
        "01 proyecto completo sin hallazgos",
        con(),
        {"ausentes": set(), "nivel": "bajo", "puntuacion": 100},
    ),
    (
        "02 credencial real en código",
        con(**{"p/app.py": 'api_key = "9f8e7d6c5b4a3210zz"\n'}),
        {"presentes": {"SEC-SECRET-PATTERN"}, "nivel": "alto"},
    ),
    (
        "03 placeholder 'your' no se marca",
        con(**{"p/app.py": 'api_key = "your_api_key_here_1234"\n'}),
        {"ausentes": {"SEC-SECRET-PATTERN"}},
    ),
    (
        "04 valor de ejemplo 'ejemplo' no se marca",
        con(**{"p/app.py": 'api_key = "ejemplo_clave_1234567890"\n'}),
        {"ausentes": {"SEC-SECRET-PATTERN"}},
    ),
    (
        "05 clave privada PEM",
        con(**{"p/k.py": "K = '''-----BEGIN RSA PRIVATE KEY-----\nMIIB\n'''"}),
        {"presentes": {"SEC-SECRET-PATTERN"}, "nivel": "alto", "linea": 1},
    ),
    (
        "06 password en YAML",
        con(**{"p/config.yml": 'password: "Xk9pQw2LmN7zRt4v"\n'}),
        {"presentes": {"SEC-SECRET-PATTERN"}, "nivel": "alto"},
    ),
    (
        "07 token en JSON",
        con(**{"p/config.json": '{"access_token": "abcd1234efgh5678ijkl"}'}),
        {"presentes": {"SEC-SECRET-PATTERN"}, "nivel": "alto"},
    ),
    (
        "08 variable sin palabra clave no se marca",
        con(**{"p/app.py": 'usuario = "juanperez_unpasswordlargo"\n'}),
        {"ausentes": {"SEC-SECRET-PATTERN"}},
    ),
    # Archivos de entorno
    (
        "09 .env real en la raíz",
        con(**{"p/.env": "DB=postgres://user:clave@host/db\n"}),
        {"presentes": {"SEC-ENV-FILE"}, "nivel": "alto"},
    ),
    (
        "10 .env dentro de subcarpeta",
        con(**{"p/config/.env": "TOKEN=abc\n"}),
        {"presentes": {"SEC-ENV-FILE"}},
    ),
    (
        "11 .env.example es plantilla, no riesgo",
        con(**{"p/.env.example": "API_URL=\n"}),
        {"ausentes": {"SEC-ENV-FILE"}},
    ),
    # ZIP maliciosos o dañados (deben rechazarse)
    (
        "12 bomba de descompresión",
        make_zip({"p/relleno.txt": "a" * (2 * MIB)}),
        {"rechaza": "zip bomb"},
    ),
    ("13 ruta con traversal", make_zip({"p/../../x.py": "x"}), {"rechaza": "'\\.\\.'"}),
    ("14 ZIP truncado", con()[:120], {"rechaza": "no es un ZIP"}),
    (
        "15 enlace simbólico",
        make_zip({"p/app.py": "x"}, symlink="p/enlace"),
        {"rechaza": "Enlace simbólico"},
    ),
    (
        "16 demasiadas entradas",
        con(),
        {"rechaza": "entradas", "limites": ScanLimits(max_entries=2)},
    ),
    # Cobertura: archivos omitidos
    (
        "17 binario omitido y declarado",
        con(**{"p/logo.png": b"\x89PNG\x00\x01\x02"}),
        {"omitido": ("logo.png", "skipped_type")},
    ),
    (
        "18 texto grande omitido por tamaño",
        con(**{"p/grande.txt": "".join(f"valor_{i:07d}\n" for i in range(90000))}),
        {"omitido": ("grande.txt", "skipped_size")},
    ),
    # Casos de forma del proyecto
    (
        "19 proyecto sin Python no recibe puntuación",
        make_zip({"p/notas.md": "# notas", "p/LICENSE": "MIT"}),
        {"puntuacion": None, "nivel": "medio"},
    ),
    (
        "20 carpeta raíz única y nombre con tilde",
        make_zip(
            {
                "Proyecto Ñandú/src/app.py": "x = 1\n",
                "Proyecto Ñandú/README.md": "# Ñandú\n",
            }
        ),
        {"ausentes": {"DOC-README"}},
    ),
]


@pytest.mark.parametrize("nombre,data,esperado", CASOS, ids=[c[0] for c in CASOS])
def test_corpus(nombre, data, esperado):
    if "rechaza" in esperado:
        limites = esperado.get("limites")
        with pytest.raises(ArchiveValidationError, match=esperado["rechaza"]):
            run_audit(data, limites)
        return

    report = run_audit(data)
    reglas = {f["rule_id"] for f in report["findings"]}

    if "presentes" in esperado:
        assert esperado["presentes"] <= reglas, (
            f"Faltan detecciones: {esperado['presentes'] - reglas}"
        )
    if "ausentes" in esperado:
        assert not (esperado["ausentes"] & reglas), (
            f"Falsos positivos: {esperado['ausentes'] & reglas}"
        )
    if "puntuacion" in esperado:
        assert report["score"] == esperado["puntuacion"]
    if "nivel" in esperado:
        nivel, _, _ = decision(report["score"], report["findings"])
        assert nivel == esperado["nivel"]
    if "linea" in esperado:
        hallazgos = [f for f in report["findings"] if f["rule_id"] == "SEC-SECRET-PATTERN"]
        assert hallazgos[0]["line"] == esperado["linea"]
    if "omitido" in esperado:
        archivo, motivo = esperado["omitido"]
        detalle = {d["archivo"]: d["motivo"] for d in report["coverage"]["omitidos_detalle"]}
        assert detalle.get(archivo) == motivo


def test_el_corpus_tiene_20_casos():
    assert len(CASOS) == 20
