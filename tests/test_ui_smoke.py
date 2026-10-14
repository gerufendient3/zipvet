from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "app.py"


def boton_ejemplo(at):
    return next(b for b in at.button if "ejemplo" in b.label.lower())


def test_la_app_arranca_sin_excepciones():
    at = AppTest.from_file(str(APP)).run()
    assert not at.exception
    assert any("ejemplo" in b.label.lower() for b in at.button)


def test_el_ejemplo_muestra_puntuacion_y_hallazgos():
    at = AppTest.from_file(str(APP)).run()
    boton_ejemplo(at).click().run()
    assert not at.exception
    etiquetas = [m.label for m in at.metric]
    assert "Preparación" in etiquetas
    assert "Alertas altas" in etiquetas
    assert len(at.expander) >= 3
