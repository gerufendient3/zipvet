"""Validación y lectura segura de un ZIP en memoria. Nunca extrae nada al disco."""

from __future__ import annotations

import io
import re
import stat
import zipfile
from dataclasses import dataclass

from zipvet.models import ArchiveValidationError, ScanLimits

TEXT_EXTENSIONS = (".py", ".md", ".rst", ".txt", ".toml", ".cfg", ".ini", ".yml", ".yaml", ".json")
TEXT_NAMES = frozenset({".gitignore", "LICENSE", "COPYING", "README", "Makefile"})
MAX_RATIO = 100
RATIO_MIN_BYTES = 1024 * 1024
ENCRYPTED_FLAG = 0x1
_DRIVE = re.compile(r"^[A-Za-z]:")


@dataclass(frozen=True)
class ScannedFile:
    path: str
    size_bytes: int
    text: str | None
    scan_status: str  # scanned | skipped_type | skipped_size | skipped_binary


@dataclass(frozen=True)
class ArchiveSnapshot:
    files: tuple[ScannedFile, ...]
    total_entries: int
    total_declared_bytes: int
    root_folder: str


def normalize_member(name: str) -> str:
    """Devuelve una ruta relativa normalizada o lanza error si es peligrosa."""
    path = name.replace("\\", "/")
    if path.startswith("/") or _DRIVE.match(path):
        raise ArchiveValidationError(f"Ruta absoluta no permitida: {name}")
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise ArchiveValidationError(f"Ruta con '..' no permitida: {name}")
    return "/".join(parts)


def is_text_candidate(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name in TEXT_NAMES or name.lower().endswith(TEXT_EXTENSIONS) or name.startswith(".env")


def _common_root(paths: list[str]) -> str:
    if not paths or any("/" not in p for p in paths):
        return ""
    firsts = {p.split("/", 1)[0] for p in paths}
    return firsts.pop() if len(firsts) == 1 else ""


def _decode(raw: bytes) -> str | None:
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def read_archive(data: bytes, limits: ScanLimits | None = None) -> ArchiveSnapshot:
    limits = limits or ScanLimits()
    if not data:
        raise ArchiveValidationError("El archivo está vacío.")
    if len(data) > limits.max_upload_bytes:
        raise ArchiveValidationError("El archivo supera el límite de 10 MiB.")
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise ArchiveValidationError("El archivo no es un ZIP válido o está dañado.")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArchiveValidationError("El archivo no es un ZIP válido o está dañado.") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_entries:
            raise ArchiveValidationError(f"El ZIP tiene más de {limits.max_entries} entradas.")
        entries: list[tuple[zipfile.ZipInfo, str]] = []
        seen: set[str] = set()
        total_declared = 0
        for info in infos:
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ArchiveValidationError(f"Enlace simbólico no permitido: {info.filename}")
            if info.flag_bits & ENCRYPTED_FLAG:
                raise ArchiveValidationError("Los ZIP cifrados no se pueden analizar.")
            path = normalize_member(info.filename)
            if info.is_dir() or not path:
                continue
            if path in seen:
                raise ArchiveValidationError(f"Nombre duplicado tras normalizar: {path}")
            seen.add(path)
            total_declared += info.file_size
            if total_declared > limits.max_total_uncompressed_bytes:
                raise ArchiveValidationError(
                    "El tamaño descomprimido total supera el límite de 40 MiB."
                )
            if (
                info.file_size > RATIO_MIN_BYTES
                and info.file_size / max(info.compress_size, 1) > MAX_RATIO
            ):
                raise ArchiveValidationError("Proporción de compresión anómala (posible zip bomb).")
            entries.append((info, path))

        root = _common_root([path for _, path in entries])
        files: list[ScannedFile] = []
        text_budget = 0
        scanned_count = 0
        for info, path in entries:
            rel = path[len(root) + 1 :] if root else path
            size = info.file_size
            if not is_text_candidate(rel):
                files.append(ScannedFile(rel, size, None, "skipped_type"))
                continue
            too_big = (
                size > limits.max_member_bytes or text_budget + size > limits.max_total_text_bytes
            )
            if too_big or scanned_count >= limits.max_text_files:
                files.append(ScannedFile(rel, size, None, "skipped_size"))
                continue
            try:
                with zf.open(info) as handle:
                    raw = handle.read(limits.max_member_bytes + 1)
            except (
                zipfile.BadZipFile,
                NotImplementedError,
                RuntimeError,
                OSError,
                ValueError,
            ) as exc:
                raise ArchiveValidationError(f"No se pudo leer el archivo {rel} del ZIP.") from exc
            if len(raw) > limits.max_member_bytes:
                files.append(ScannedFile(rel, size, None, "skipped_size"))
                continue
            text = _decode(raw)
            if text is None:
                files.append(ScannedFile(rel, size, None, "skipped_binary"))
                continue
            text_budget += len(raw)
            scanned_count += 1
            files.append(ScannedFile(rel, size, text, "scanned"))

    return ArchiveSnapshot(tuple(files), len(infos), total_declared, root)
