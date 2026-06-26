# =============================================================================
# Dockerfile — Triage Forense Digital
# =============================================================================
# PROPÓSITO:
#   Proporcionar un entorno reproducible para DESARROLLAR y TESTEAR el script
#   de triage en Linux. También sirve para procesar evidencias ya recolectadas.
#
# LIMITACIÓN IMPORTANTE:
#   La recolección forense REAL debe ejecutarse siempre en la máquina comprometida
#   de forma nativa (no en Docker), porque dentro de un contenedor el acceso a
#   /proc, memoria RAM e interfaces de red del host está restringido por el kernel.
#
# USOS VÁLIDOS EN DOCKER:
#   1. Desarrollo y tests en local (macOS, Windows, Linux).
#   2. CI/CD (GitHub Actions, GitLab CI).
#   3. Procesado posterior de evidencias ya recolectadas.
#   4. Demostración en entorno controlado (TFM, presentación).
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="TFM Triage Forense"
LABEL description="Entorno de desarrollo y test para triage-forense"
LABEL version="2.0.0"

# Instalar uv (gestor de entornos moderno)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Herramientas forenses disponibles en la imagen (para testing)
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps       \
    net-tools    \
    iproute2     \
    lsof         \
    chkrootkit   \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copiar ficheros de dependencias primero (aprovecha la caché de Docker)
COPY pyproject.toml ./
RUN uv sync --frozen --no-dev 2>/dev/null || uv sync --no-dev

# Copiar el código fuente
COPY src/ ./src/
COPY tests/ ./tests/

# Crear directorio de salida montable
RUN mkdir -p /output

# Variables de entorno
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Por defecto ejecuta los tests; para triage real, sobrescribir el CMD
CMD ["uv", "run", "pytest", "-v"]

# =============================================================================
# EJEMPLOS DE USO:
#
# Construir la imagen:
#   docker build -t triage-forense:2.0 .
#
# Ejecutar los tests:
#   docker run --rm triage-forense:2.0
#
# Ejecutar el triage Linux dentro del contenedor (entorno de demostración):
#   docker run --rm -v $(pwd)/output:/output triage-forense:2.0 \
#     uv run triage-linux
#
# Ejecutar con acceso al sistema host (aproximación forense):
#   docker run --rm --privileged --pid=host --network=host \
#     -v /:/host:ro -v $(pwd)/output:/output \
#     triage-forense:2.0 uv run triage-linux
# =============================================================================
