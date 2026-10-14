import pytest

from tests.helpers import make_zip
from zipvet.archive import normalize_member, read_archive
from zipvet.models import ArchiveValidationError, ScanLimits


def test_rechaza_datos_que_no_son_zip():
    with pytest.raises(ArchiveValidationError, match="no es un ZIP"):
        read_archive(b"hola, no soy un zip")


def test_rechaza_archivo_vacio():
    with pytest.raises(ArchiveValidationError, match="vacío"):
        read_archive(b"")


def test_rechaza_archivo_mayor_al_limite():
    data = make_zip({"p/app.py": "x = 1\n" * 500})
    with pytest.raises(ArchiveValidationError, match="límite"):
        read_archive(data, ScanLimits(max_upload_bytes=50))


@pytest.mark.parametrize("nombre", ["../evil.py", "p/../../evil.py", "/etc/passwd", "C:/evil.py"])
def test_rechaza_rutas_peligrosas(nombre):
    with pytest.raises(ArchiveValidationError):
        read_archive(make_zip({nombre: "x"}))


def test_rechaza_enlace_simbolico():
    with pytest.raises(ArchiveValidationError, match="Enlace simbólico"):
        read_archive(make_zip({"p/app.py": "x"}, symlink="p/enlace"))


def test_rechaza_duplicados_tras_normalizar():
    with pytest.raises(ArchiveValidationError, match="Nombre duplicado"):
        read_archive(make_zip({"p\\b.py": "1", "p/b.py": "2"}))


def test_rechaza_demasiadas_entradas():
    data = make_zip({f"p/a{i}.txt": "x" for i in range(3)})
    with pytest.raises(ArchiveValidationError, match="entradas"):
        read_archive(data, ScanLimits(max_entries=2))


def test_rechaza_bomba_de_compresion():
    data = make_zip({"p/relleno.txt": "a" * (2 * 1024 * 1024)})
    with pytest.raises(ArchiveValidationError, match="zip bomb"):
        read_archive(data)


def test_rechaza_exceso_de_tamano_descomprimido():
    with pytest.raises(ArchiveValidationError, match="descomprimido"):
        read_archive(make_zip({"p/a.txt": "a" * 200}), ScanLimits(max_total_uncompressed_bytes=100))


def test_quita_carpeta_raiz_y_lee_textos():
    snapshot = read_archive(make_zip({"proyecto/app.py": "print(1)", "proyecto/README.md": "# x"}))
    assert snapshot.root_folder == "proyecto"
    rutas = {f.path: f for f in snapshot.files}
    assert set(rutas) == {"app.py", "README.md"}
    assert rutas["app.py"].scan_status == "scanned"
    assert rutas["app.py"].text == "print(1)"


def test_omite_binarios_y_tipos_no_permitidos():
    snapshot = read_archive(
        make_zip({"p/imagen.png": b"\x89PNG\x00data", "p/datos.txt": b"\x00\x01"})
    )
    estados = {f.path: f.scan_status for f in snapshot.files}
    assert estados["imagen.png"] == "skipped_type"
    assert estados["datos.txt"] == "skipped_binary"


def test_omite_textos_que_superan_el_limite_por_archivo():
    snapshot = read_archive(make_zip({"p/a.txt": "x" * 50}), ScanLimits(max_member_bytes=10))
    assert snapshot.files[0].scan_status == "skipped_size"


def test_normalize_member_limpia_separadores():
    assert normalize_member("a\\b//c/./d.py") == "a/b/c/d.py"
