"""
tests/test_basico.py — Tests básicos del proyecto triage forense.

Cubren los bugs identificados en el informe de análisis:
    Bug#1 — TriageContext inicializa el logger correctamente (no AttributeError).
    Bug#2 — generar_reporte maneja zip_path=None sin excepción.
    Bug#3 — Formato de hashes unificado (sha256sum estándar).
    Bug#4 — ejecutar_comando crea subdirectorios si no existen.
    Bug#5 — error_parcial se cuenta como resultado con datos útiles.

Ejecución:
    uv run pytest
    uv run pytest -v
    uv run pytest tests/test_basico.py -v
"""

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

# Añadir src/ al path para importar sin instalar
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from triage.common import (
    TriageContext,
    calcular_hashes,
    copiar_fichero,
    empaquetar,
    ejecutar_comando,
    ejecutar_lista,
    generar_reporte,
)
from triage.config import HASH_BLOCK_SIZE, TIMEOUT_CMD, TRIAGE_VERSION


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx(tmp_path):
    """Crea un TriageContext en un directorio temporal para cada test."""
    output_dir = tmp_path / "triage_test"
    return TriageContext(output_dir=output_dir)


# ---------------------------------------------------------------------------
# Bug#1 — Logger siempre inicializado
# ---------------------------------------------------------------------------


def test_ctx_logger_no_es_none(ctx):
    """Bug#1: TriageContext debe inicializar el logger; nunca debe ser None."""
    assert ctx.logger is not None


def test_ctx_logger_es_utilizable(ctx):
    """Bug#1: El logger debe aceptar llamadas sin lanzar excepciones."""
    ctx.logger.info("test mensaje info")
    ctx.logger.debug("test mensaje debug")
    ctx.logger.warning("test mensaje warning")


def test_ctx_crea_directorio_salida(ctx):
    """TriageContext debe crear el directorio de salida al instanciarse."""
    assert ctx.output_dir.exists()


def test_ctx_crea_log_file(ctx):
    """TriageContext debe crear el fichero de log al instanciarse."""
    ctx.logger.info("inicializando")
    assert ctx.log_file.exists()


# ---------------------------------------------------------------------------
# Bug#2 — generar_reporte con zip_path=None no debe lanzar excepción
# ---------------------------------------------------------------------------


def test_reporte_con_zip_none_no_lanza_excepcion(ctx):
    """Bug#2: generar_reporte debe funcionar aunque zip_path sea None."""
    try:
        generar_reporte(ctx, info_general={}, hashes={}, zip_path=None)
    except Exception as exc:
        pytest.fail(f"generar_reporte lanzó excepción con zip_path=None: {exc}")


def test_reporte_genera_fichero_json(ctx):
    """generar_reporte debe crear el fichero resumen_triage.json."""
    generar_reporte(ctx, info_general={"hostname": "test"}, hashes={}, zip_path=None)
    assert ctx.report_file.exists()


def test_reporte_json_valido(ctx):
    """El JSON del reporte debe ser parseable y contener claves clave."""
    generar_reporte(ctx, info_general={"hostname": "test"}, hashes={}, zip_path=None)
    data = json.loads(ctx.report_file.read_text(encoding="utf-8"))
    assert "triage_version" in data
    assert "estadisticas" in data
    assert data["triage_version"] == TRIAGE_VERSION


# ---------------------------------------------------------------------------
# Bug#3 — Formato de hashes unificado (sha256sum estándar)
# ---------------------------------------------------------------------------


def test_hashes_formato_sha256sum(ctx):
    """Bug#3: El fichero de hashes debe usar el formato '<hash>  <fichero>'."""
    # Crear un fichero de prueba
    (ctx.output_dir / "fichero_prueba.txt").write_text("datos de prueba", encoding="utf-8")

    hashes = calcular_hashes(ctx)
    hash_file = ctx.output_dir / "09_hashes_sha256.txt"

    assert hash_file.exists(), "El fichero de hashes debe existir"

    lineas_datos = [
        l for l in hash_file.read_text(encoding="utf-8").splitlines()
        if l and not l.startswith("#")
    ]
    assert len(lineas_datos) > 0, "Debe haber al menos una línea de hash"

    for linea in lineas_datos:
        partes = linea.split("  ", 1)
        assert len(partes) == 2, f"Formato incorrecto (debe ser '<hash>  <fichero>'): {linea}"
        hash_hex, _ = partes
        assert len(hash_hex) == 64, f"Hash SHA-256 debe tener 64 caracteres: {hash_hex}"
        assert all(c in "0123456789abcdef" for c in hash_hex), "Hash debe ser hexadecimal"


def test_hashes_valor_correcto(ctx):
    """Los hashes calculados deben coincidir con sha256 calculado manualmente."""
    contenido = b"contenido de prueba para hash"
    fichero = ctx.output_dir / "prueba_hash.bin"
    fichero.write_bytes(contenido)

    hashes = calcular_hashes(ctx)

    sha256 = hashlib.sha256(contenido).hexdigest()
    assert hashes.get("prueba_hash.bin") == sha256


# ---------------------------------------------------------------------------
# Bug#4 — ejecutar_comando crea subdirectorios si no existen
# ---------------------------------------------------------------------------


def test_ejecutar_comando_crea_subdirectorio(ctx):
    """Bug#4: ejecutar_comando debe crear el subdirectorio de salida si no existe."""
    resultado = ejecutar_comando(
        ctx,
        comando="echo hola",
        archivo_salida="subdir/nuevo/fichero.txt",
        descripcion="Test creación subdirectorio",
    )
    ruta = ctx.output_dir / "subdir" / "nuevo" / "fichero.txt"
    assert ruta.exists(), "El fichero debe existir aunque el subdirectorio no existiera"


def test_ejecutar_comando_guarda_salida(ctx):
    """ejecutar_comando debe guardar la salida del comando en el fichero."""
    resultado = ejecutar_comando(
        ctx,
        comando="echo triage_test_output",
        archivo_salida="01_test.txt",
        descripcion="Test salida de comando",
    )
    fichero = ctx.output_dir / "01_test.txt"
    assert fichero.exists()
    assert "triage_test_output" in fichero.read_text(encoding="utf-8")


def test_ejecutar_comando_devuelve_dict(ctx):
    """ejecutar_comando debe devolver un diccionario con las claves esperadas."""
    resultado = ejecutar_comando(ctx, "echo ok", "test_dict.txt", "Test dict")
    claves = {"descripcion", "comando", "archivo", "estado", "error", "bytes", "timestamp"}
    assert claves.issubset(resultado.keys())


def test_ejecutar_comando_estado_ok(ctx):
    """Un comando válido debe devolver estado 'ok'."""
    resultado = ejecutar_comando(ctx, "echo ok", "test_ok.txt", "Test estado ok")
    assert resultado["estado"] == "ok"


def test_ejecutar_comando_timeout(ctx):
    """Un comando que supera el timeout debe devolver estado 'timeout'."""
    import triage.config as cfg
    original = cfg.TIMEOUT_CMD
    cfg.TIMEOUT_CMD = 1  # timeout de 1 segundo para el test

    try:
        resultado = ejecutar_comando(ctx, "sleep 5", "test_timeout.txt", "Test timeout")
        assert resultado["estado"] == "timeout"
    finally:
        cfg.TIMEOUT_CMD = original


# ---------------------------------------------------------------------------
# Bug#5 — error_parcial cuenta como resultado con datos útiles
# ---------------------------------------------------------------------------


def test_error_parcial_no_se_cuenta_como_fallo_total(ctx):
    """
    Bug#5: error_parcial tiene salida útil y no debe contarse igual que
    un error total. generar_reporte debe diferenciarlos.
    """
    # Forzar un resultado error_parcial manualmente
    ctx.resultados = [
        {"descripcion": "cmd ok",      "estado": "ok"},
        {"descripcion": "cmd parcial", "estado": "error_parcial"},
        {"descripcion": "cmd error",   "estado": "error"},
        {"descripcion": "cmd timeout", "estado": "timeout"},
    ]

    generar_reporte(ctx, info_general={}, hashes={}, zip_path=None)
    data = json.loads(ctx.report_file.read_text(encoding="utf-8"))

    # ok + error_parcial = exitosos (tienen datos útiles)
    assert data["estadisticas"]["exitosos"] == 2
    # error + timeout = fallos reales
    assert data["estadisticas"]["con_errores"] == 2


# ---------------------------------------------------------------------------
# ejecutar_lista (DRY helper)
# ---------------------------------------------------------------------------


def test_ejecutar_lista_longitud(ctx):
    """ejecutar_lista debe devolver tantos resultados como comandos recibe."""
    comandos = [
        ("echo uno",  "lista_01.txt", "Comando uno"),
        ("echo dos",  "lista_02.txt", "Comando dos"),
        ("echo tres", "lista_03.txt", "Comando tres"),
    ]
    resultados = ejecutar_lista(ctx, comandos)
    assert len(resultados) == len(comandos)


# ---------------------------------------------------------------------------
# copiar_fichero
# ---------------------------------------------------------------------------


def test_copiar_fichero_existente(ctx, tmp_path):
    """copiar_fichero debe copiar un fichero existente correctamente."""
    origen = tmp_path / "origen.txt"
    origen.write_text("contenido original", encoding="utf-8")

    resultado = copiar_fichero(ctx, str(origen), "copia/origen.txt", "Test copia")
    assert resultado["estado"] == "ok"
    assert (ctx.output_dir / "copia" / "origen.txt").exists()


def test_copiar_fichero_no_existente(ctx):
    """copiar_fichero debe devolver estado 'no_existe' si el origen no existe."""
    resultado = copiar_fichero(ctx, "/ruta/que/no/existe.txt", "destino.txt", "Test no existe")
    assert resultado["estado"] == "no_existe"


# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------


def test_timeout_cmd_es_entero_positivo():
    """TIMEOUT_CMD debe ser un entero positivo."""
    assert isinstance(TIMEOUT_CMD, int)
    assert TIMEOUT_CMD > 0


def test_hash_block_size_es_potencia_de_dos():
    """HASH_BLOCK_SIZE debe ser potencia de 2 (eficiencia de I/O)."""
    assert HASH_BLOCK_SIZE > 0
    assert (HASH_BLOCK_SIZE & (HASH_BLOCK_SIZE - 1)) == 0


def test_triage_version_formato_semver():
    """TRIAGE_VERSION debe seguir formato semver X.Y.Z."""
    partes = TRIAGE_VERSION.split(".")
    assert len(partes) == 3
    assert all(p.isdigit() for p in partes)


# ---------------------------------------------------------------------------
# Empaquetado ZIP
# ---------------------------------------------------------------------------


def test_empaquetar_genera_zip(ctx):
    """empaquetar debe generar un fichero ZIP en el directorio de trabajo."""
    (ctx.output_dir / "evidencia.txt").write_text("datos", encoding="utf-8")
    hashes = calcular_hashes(ctx)
    zip_path = empaquetar(ctx, hashes)

    assert zip_path is not None
    assert zip_path.exists()
    assert zip_path.suffix == ".zip"

    # Limpiar
    zip_path.unlink(missing_ok=True)
    sha_path = zip_path.with_suffix(".zip.sha256")
    sha_path.unlink(missing_ok=True)


def test_empaquetar_genera_hash_externo(ctx):
    """empaquetar debe generar un fichero .zip.sha256 junto al ZIP."""
    (ctx.output_dir / "evidencia.txt").write_text("datos", encoding="utf-8")
    hashes = calcular_hashes(ctx)
    zip_path = empaquetar(ctx, hashes)

    sha_path = zip_path.with_suffix(".zip.sha256") if zip_path else None
    assert sha_path is not None and sha_path.exists()

    # Limpiar
    zip_path.unlink(missing_ok=True)
    sha_path.unlink(missing_ok=True)
