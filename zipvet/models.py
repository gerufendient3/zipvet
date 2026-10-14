"""Modelos de dominio: hallazgos, límites de escaneo y errores de validación."""

from dataclasses import dataclass
from typing import Literal

Severity = Literal["info", "low", "medium", "high"]
Status = Literal["pass", "warn", "fail", "skipped", "not_applicable"]

MIB = 1024 * 1024


class ArchiveValidationError(ValueError):
    """El archivo aportado no cumple los límites seguros del escáner."""


@dataclass(frozen=True)
class Finding:
    """Una señal concreta detectada por una regla."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    path: str | None
    line: int | None
    message: str
    recommendation: str
    confidence: str = "medium"
    evidence: str | None = None


@dataclass(frozen=True)
class ScanLimits:
    """Límites de seguridad y tamaño. Cambiarlos debe quedar cubierto por pruebas."""

    max_upload_bytes: int = 10 * MIB
    max_entries: int = 2000
    max_total_uncompressed_bytes: int = 40 * MIB
    max_member_bytes: int = 1 * MIB
    max_total_text_bytes: int = 5 * MIB
    max_text_files: int = 500
