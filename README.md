# ZipVet 🛡️

Revisa un proyecto Python en ZIP antes de publicarlo y obtén una lista clara de señales a corregir: licencia, README, .gitignore, archivos de entorno, posibles credenciales, pruebas y CI.

- **No ejecuta tu código** ni instala dependencias.
- **No se conecta a internet** ni a GitHub.
- **No guarda archivos:** todo se procesa en memoria durante la sesión.
- **No certifica seguridad ni calidad.** Indica señales a revisar.

## Ejecutar en tu equipo (Windows)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m streamlit run app.py
```

## Pruebas y lint

```powershell
python -m pytest -q
python -m ruff check .
```

## Cómo se calcula la puntuación

Parte de 100 y descuenta una vez por cada regla fallida. Los pesos y la lista de reglas están en [docs/RULES.md](docs/RULES.md). Si el proyecto no contiene Python, la puntuación no aplica.

## Seguridad al leer el ZIP

Se rechazan ZIP dañados o cifrados, archivos de más de 10 MiB, más de 2.000 entradas, rutas con `..` o absolutas, enlaces simbólicos, nombres duplicados y proporciones de compresión sospechosas. Solo se leen como texto los archivos permitidos y dentro de los límites; los binarios se omiten.

## Privacidad

Los valores que parecen credenciales nunca se muestran completos: la interfaz indica solo su longitud. Usa el ejemplo incluido para probar la herramienta; no subas credenciales reales a ningún servicio de demostración.

## Limitaciones

- Análisis estático: no prueba que el código funcione ni que sea seguro.
- La detección de credenciales se basa en patrones; puede dar falsos positivos y falsos negativos.
- Solo reconoce las reglas de este documento; no sustituye herramientas profesionales de seguridad.

## Licencia

MIT. Ver [LICENSE](LICENSE).
