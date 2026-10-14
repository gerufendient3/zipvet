import io
import zipfile


def make_zip(entries: dict, symlink: str | None = None) -> bytes:
    """Crea un ZIP en memoria. Solo para pruebas; nunca toca el disco."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = 0o120777 << 16
            zf.writestr(info, "destino")
    return buffer.getvalue()
