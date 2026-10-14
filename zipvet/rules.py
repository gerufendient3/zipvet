"""Reglas estáticas deterministas. Cada hallazgo se apoya en un archivo o patrón concreto."""

from __future__ import annotations

import re

from zipvet.archive import ScannedFile
from zipvet.models import Finding

MAX_SECRET_FINDINGS = 50
PLACEHOLDER_HINTS = (
    "example",
    "ejemplo",
    "your",
    "changeme",
    "placeholder",
    "dummy",
    "xxxx",
    "<",
    "tu_",
)
_KEY_ASSIGNMENT = re.compile(
    r"""(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|password)['"]?\s*[=:]\s*['"]([^'"\s]{16,})['"]"""
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    message: str,
    recommendation: str,
    path: str | None = None,
    line: int | None = None,
    evidence: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        path=path,
        line=line,
        message=message,
        recommendation=recommendation,
        evidence=evidence,
    )


def _mask(value: str) -> str:
    return f"[oculto: {len(value)} caracteres]"


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def run_rules(files: tuple[ScannedFile, ...]) -> list[Finding]:
    findings: list[Finding] = []
    all_paths = [f.path for f in files]
    root_paths = [p for p in all_paths if "/" not in p]

    if not any(re.fullmatch(r"(?i)(license|copying)(\.(md|txt))?", p) for p in root_paths):
        findings.append(
            _finding(
                "DOC-LICENSE",
                "Licencia no detectada",
                "medium",
                "Documentación",
                "No se detectó un archivo de licencia en la raíz del proyecto.",
                "Añade un archivo LICENSE. MIT es una opción sencilla y permisiva.",
            )
        )

    if not any(re.fullmatch(r"(?i)readme(\.(md|rst|txt))?", p) for p in root_paths):
        findings.append(
            _finding(
                "DOC-README",
                "README no detectado",
                "medium",
                "Documentación",
                "No se detectó un README en la raíz del proyecto.",
                "Crea un README con qué hace el proyecto, cómo instalarlo y un ejemplo de uso.",
            )
        )

    if ".gitignore" not in root_paths:
        findings.append(
            _finding(
                "HYG-GITIGNORE",
                ".gitignore no detectado",
                "medium",
                "Higiene",
                "No se encontró .gitignore en la raíz.",
                "Añade un .gitignore que excluya entornos, __pycache__ y archivos locales.",
            )
        )

    for f in files:
        name = f.path.rsplit("/", 1)[-1]
        if name.startswith(".env") and not name.endswith(".example"):
            findings.append(
                _finding(
                    "SEC-ENV-FILE",
                    "Archivo de entorno incluido",
                    "high",
                    "Seguridad",
                    "Se incluyó un archivo de variables de entorno con posibles valores privados.",
                    "Elimínalo, añade .env al .gitignore y comparte solo .env.example.",
                    path=f.path,
                )
            )

    secret_count = 0
    for f in files:
        if f.text is None:
            continue
        for match in _PRIVATE_KEY.finditer(f.text):
            if secret_count >= MAX_SECRET_FINDINGS:
                break
            secret_count += 1
            findings.append(
                _finding(
                    "SEC-SECRET-PATTERN",
                    "Clave privada en texto plano",
                    "high",
                    "Seguridad",
                    "Se encontró el encabezado de una clave privada en un archivo del proyecto.",
                    "Revoca la clave, quítala del código y usa variables de entorno.",
                    path=f.path,
                    line=f.text.count("\n", 0, match.start()) + 1,
                    evidence="[contenido no mostrado]",
                )
            )
        for match in _KEY_ASSIGNMENT.finditer(f.text):
            value = match.group(1)
            if secret_count >= MAX_SECRET_FINDINGS or _is_placeholder(value):
                continue
            secret_count += 1
            findings.append(
                _finding(
                    "SEC-SECRET-PATTERN",
                    "Posible credencial en el código",
                    "high",
                    "Seguridad",
                    "Una asignación parece contener una credencial real.",
                    "Revoca la credencial y léela desde variables de entorno, no desde el código.",
                    path=f.path,
                    line=f.text.count("\n", 0, match.start()) + 1,
                    evidence=_mask(value),
                )
            )

    has_tests = any(
        p.startswith("tests/")
        and p.endswith(".py")
        and (p.rsplit("/", 1)[-1].startswith("test_") or p.endswith("_test.py"))
        for p in all_paths
    )
    if not has_tests:
        findings.append(
            _finding(
                "TEST-PRESENCE",
                "Pruebas automatizadas no detectadas",
                "medium",
                "Calidad",
                "No se encontró una carpeta tests/ con archivos test_*.py.",
                "Añade pruebas con pytest para comprobar el comportamiento principal del proyecto.",
            )
        )

    if not any(
        p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml")) for p in all_paths
    ):
        findings.append(
            _finding(
                "CI-PRESENCE",
                "Integración continua no detectada",
                "low",
                "Calidad",
                "No se encontró un workflow en .github/workflows/.",
                "Crea un workflow de GitHub Actions que ejecute las pruebas en cada cambio.",
            )
        )

    return findings
