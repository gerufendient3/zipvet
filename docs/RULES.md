# Reglas y puntuación (borrador v0.1)

La puntuación parte de 100 y descuenta una vez por cada regla fallida. No es una nota de seguridad.

| Regla | Descripción | Peso |
|---|---|---|
| DOC-LICENSE | No hay archivo LICENSE en la raíz | 15 |
| DOC-README | No hay README en la raíz | 15 |
| HYG-GITIGNORE | No hay .gitignore | 10 |
| SEC-ENV-FILE | Hay un .env dentro del proyecto | 20 |
| SEC-SECRET-PATTERN | Patrón que parece una credencial | 15 |
| TEST-PRESENCE | No hay carpeta tests/ con archivos test_*.py | 15 |
| CI-PRESENCE | No hay workflow en .github/workflows/ | 10 |

Total: 100 puntos. Los pesos viven en `zipvet/scoring.py`. Cualquier cambio debe actualizar este documento y sus pruebas.

## Severidades

- **Alta:** credenciales, claves privadas y archivos .env, porque pueden exponer acceso real.
- **Media:** licencia, README, .gitignore y pruebas, porque afectan a la calidad y al uso del proyecto.
- **Baja:** CI, porque es una mejora recomendable pero no un riesgo.

Un estado favorable nunca se muestra mientras exista una alerta alta o media.
