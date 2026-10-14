"""Orquesta el análisis completo y produce el informe exportable."""

from __future__ import annotations

import json
from dataclasses import asdict

from zipvet.archive import read_archive
from zipvet.models import ScanLimits
from zipvet.rules import run_rules
from zipvet.scoring import compute_score

DISCLAIMER = (
    "ZipVet indica señales de preparación a revisar. No certifica seguridad, calidad "
    "ni funcionamiento del proyecto, y no ejecuta ni instala su código."
)
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def run_audit(data: bytes, limits: ScanLimits | None = None) -> dict:
    snapshot = read_archive(data, limits)
    findings = run_rules(snapshot.files)
    python_project = any(f.path.endswith(".py") for f in snapshot.files)
    skipped = [f for f in snapshot.files if f.scan_status != "scanned"]
    ordered = sorted(
        findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.path or "", f.line or 0)
    )
    return {
        "score": compute_score(findings) if python_project else None,
        "python_project": python_project,
        "findings": [asdict(f) for f in ordered],
        "coverage": {
            "entradas_zip": snapshot.total_entries,
            "archivos": len(snapshot.files),
            "analizados_como_texto": sum(f.scan_status == "scanned" for f in snapshot.files),
            "omitidos": len(skipped),
            "omitidos_detalle": [
                {"archivo": f.path, "motivo": f.scan_status} for f in skipped[:100]
            ],
            "carpeta_raiz": snapshot.root_folder or None,
        },
        "disclaimer": DISCLAIMER,
    }


def to_json(report: dict) -> bytes:
    return json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")


def build_demo_zip() -> bytes:
    """Proyecto sintético con fallos intencionados. Las credenciales son ficticias."""
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "mi-proyecto/app.py",
            'def run():\n    api_key = "demo_9f8e7d6c5b4a3210"\n    return api_key\n',
        )
        zf.writestr("mi-proyecto/.env", "DATABASE_URL=sqlite:///demo.db\n")
        zf.writestr(
            "mi-proyecto/README.md", "# Proyecto de ejemplo\n\nDemostración sintética de ZipVet.\n"
        )
        zf.writestr("mi-proyecto/requirements.txt", "requests\n")
    return buffer.getvalue()


def decision(score: int | None, findings: list[dict]) -> tuple[str, str, str]:
    """Estado de publicación a partir de la gravedad de los hallazgos.

    Nunca devuelve un estado favorable si existen alertas altas o medias.
    """
    severidades = {f["severity"] for f in findings}
    if "high" in severidades:
        return (
            "alto",
            "Requiere atención",
            "Hay alertas de gravedad alta. Corrígelas antes de compartir o publicar el proyecto.",
        )
    if "medium" in severidades:
        return (
            "medio",
            "Revisión pendiente",
            "No hay alertas altas, pero quedan señales que conviene revisar antes de publicar.",
        )
    if score is None:
        return (
            "medio",
            "Sin puntuación",
            "No se detectó un proyecto Python. Revisa las alertas igualmente.",
        )
    if "low" in severidades:
        return (
            "bajo",
            "Sin alertas graves",
            "Quedan señales menores. Esto no certifica que el proyecto sea seguro.",
        )
    return (
        "bajo",
        "Sin señales conocidas",
        "Las reglas actuales no encontraron señales. Esto no certifica que el proyecto sea seguro.",
    )
