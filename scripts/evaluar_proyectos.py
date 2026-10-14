"""Ejecuta ZipVet sobre una carpeta de ZIP y genera un CSV para comparar resultados.

Uso:
    python scripts/evaluar_proyectos.py carpeta_con_zips salida.csv

El CSV incluye el hash SHA-256 de cada ZIP, la puntuación, el estado y las reglas
detectadas. Completa a mano las columnas de resultado esperado y falsos positivos.
"""

import csv
import hashlib
import sys
from pathlib import Path

from zipvet.audit import decision, run_audit
from zipvet.models import ArchiveValidationError

COLUMNAS = [
    "archivo",
    "sha256",
    "estado",
    "puntuacion",
    "nivel",
    "reglas_detectadas",
    "archivos_omitidos",
    "error",
    "esperado",
    "falsos_positivos",
    "notas",
]


def evaluar(carpeta: Path, salida: Path) -> int:
    zips = sorted(carpeta.glob("*.zip"))
    if not zips:
        print(f"No se encontraron ZIP en {carpeta}", file=sys.stderr)
        return 2
    with salida.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNAS)
        writer.writeheader()
        for ruta in zips:
            data = ruta.read_bytes()
            fila = {c: "" for c in COLUMNAS}
            fila["archivo"] = ruta.name
            fila["sha256"] = hashlib.sha256(data).hexdigest()
            try:
                informe = run_audit(data)
                nivel, titulo, _ = decision(informe["score"], informe["findings"])
                fila.update(
                    {
                        "estado": "analizado",
                        "puntuacion": "" if informe["score"] is None else informe["score"],
                        "nivel": f"{nivel}: {titulo}",
                        "reglas_detectadas": ";".join(
                            sorted({f["rule_id"] for f in informe["findings"]})
                        ),
                        "archivos_omitidos": informe["coverage"]["omitidos"],
                    }
                )
            except ArchiveValidationError as error:
                fila.update({"estado": "rechazado", "error": str(error)})
            except Exception as error:  # noqa: BLE001 - registrar, no caer
                fila.update({"estado": "error_inesperado", "error": type(error).__name__})
            writer.writerow(fila)
            print(f"{ruta.name}: {fila['estado']}")
    print(f"CSV generado en {salida}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(evaluar(Path(sys.argv[1]), Path(sys.argv[2])))
