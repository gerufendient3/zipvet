"""Interfaz web de ZipVet. Toda la lógica vive en el paquete zipvet."""

import streamlit as st

from zipvet.audit import build_demo_zip, decision, run_audit, to_json
from zipvet.models import ArchiveValidationError

ICONS = {"high": "🔴", "medium": "🟡", "low": "🔵", "info": "⚪"}
LABELS = {"high": "Alta", "medium": "Media", "low": "Baja", "info": "Informativa"}

CSS = """
<style>
#MainMenu, footer {visibility: hidden;}
.block-container {max-width: 900px; padding-top: 2.5rem;}
.zv-hero h1 {font-size: 2.6rem; margin-bottom: 0.1rem; letter-spacing: -0.02em;}
.zv-hero p {color: #94a3b8; font-size: 1.08rem; margin-top: 0;}
.zv-verdict {border-radius: 16px; padding: 18px 22px; margin: 8px 0 18px 0;}
.zv-alto {background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.5);}
.zv-medio {background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.5);}
.zv-bajo {background: rgba(34, 197, 94, 0.12); border: 1px solid rgba(34, 197, 94, 0.5);}
[data-testid="stMetric"] {background: #161b26; border: 1px solid #262d3d;
  border-radius: 14px; padding: 14px 18px;}
[data-testid="stMetricLabel"] p {color: #94a3b8;}
</style>
"""

st.set_page_config(page_title="ZipVet", page_icon="🛡️", layout="centered")
st.markdown(CSS, unsafe_allow_html=True)
st.markdown(
    '<div class="zv-hero"><h1>🛡️ ZipVet</h1>'
    "<p>Tu código merece una última mirada antes de salir al mundo.</p></div>",
    unsafe_allow_html=True,
)

with st.expander("Qué revisa y qué no"):
    st.markdown(
        "**Revisa:** licencia, README, .gitignore, archivos .env, posibles credenciales, "
        "carpeta de pruebas y workflow de CI.\n\n"
        "**No hace:** ejecutar tu código, instalar dependencias, acceder a GitHub ni certificar "
        "seguridad. Los archivos se procesan en memoria. Consulta la política de privacidad."
    )

col_upload, col_demo = st.columns([3, 2])
uploaded = col_upload.file_uploader("Sube tu proyecto en ZIP (máximo 10 MiB)", type=["zip"])
demo_clicked = col_demo.button("Probar con un ejemplo", use_container_width=True)

if demo_clicked:
    st.session_state["demo"] = True
if uploaded is not None:
    st.session_state["demo"] = False

data = None
if st.session_state.get("demo"):
    data = build_demo_zip()
elif uploaded is not None:
    data = uploaded.getvalue()

if data is None:
    st.info("Sube un ZIP o prueba el ejemplo para ver tu informe.")
    st.stop()

report = None
error_message = None
try:
    report = run_audit(data)
except ArchiveValidationError as error:
    error_message = f"No se pudo analizar el archivo: {error}"
except Exception:  # noqa: BLE001 - nunca mostrar trazas al usuario
    error_message = "Ocurrió un error inesperado. Intenta de nuevo con otro archivo."

if error_message:
    st.error(error_message)
    st.stop()

score = report["score"]
findings = report["findings"]
nivel, titulo, texto = decision(score, findings)
st.markdown(
    f'<div class="zv-verdict zv-{nivel}"><strong>{titulo}</strong><br>{texto}</div>',
    unsafe_allow_html=True,
)

c1, c2, c3 = st.columns(3)
c1.metric(
    "Preparación",
    f"{score}/100" if score is not None else "No aplica",
    help="Mide las señales de preparación de las 7 reglas. No mide seguridad.",
)
c2.metric("Archivos", report["coverage"]["archivos"])
c3.metric("Alertas altas", sum(f["severity"] == "high" for f in findings))

st.subheader("Hallazgos")
if not findings:
    st.success("No se detectaron señales en las reglas actuales.")
for f in findings:
    where = "Proyecto"
    if f["path"]:
        where = f["path"] + (f":{f['line']}" if f["line"] else "")
    with st.expander(f"{ICONS[f['severity']]} {f['title']} · {where}"):
        st.write(f["message"])
        st.caption(f"Severidad: {LABELS[f['severity']]} · Regla: {f['rule_id']}")
        if f["evidence"]:
            st.code(f["evidence"], language=None)
        st.info(f"💡 {f['recommendation']}")

with st.expander("Cobertura del análisis"):
    cov = report["coverage"]
    st.write(
        f"Entradas: {cov['entradas_zip']} · Analizadas como texto: "
        f"{cov['analizados_como_texto']} · Omitidas: {cov['omitidos']}"
    )
    if cov["omitidos_detalle"]:
        st.dataframe(cov["omitidos_detalle"], use_container_width=True)

st.download_button(
    "Descargar informe JSON", to_json(report), "zipvet-informe.json", "application/json"
)
st.caption(report["disclaimer"])
