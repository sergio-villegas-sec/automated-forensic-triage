"""
common.py — Funciones compartidas entre los scripts de triage Linux y Windows.

Contiene toda la lógica reutilizable:
  - Configuración de logging
  - Ejecución y registro de comandos
  - Copia de ficheros
  - Cálculo de hashes SHA-256
  - Empaquetado ZIP
  - Generación del reporte JSON final
  - Cadena de custodia
  - Manejo de señales (Ctrl+C)

No debe importarse nada de linux.py ni de windows.py desde aquí.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from triage.config import (
    HASH_BLOCK_SIZE,
    TIMEOUT_CMD,
    TRIAGE_VERSION,
    ZIP_COMPRESSION_LEVEL,
)

# ---------------------------------------------------------------------------
# Clase de configuración del triage (sustituye las variables globales)
# ---------------------------------------------------------------------------


class TriageContext:
    """
    Encapsula el estado de una ejecución de triage.

    En lugar de variables globales mutables, toda la configuración
    se almacena en una instancia de esta clase que se pasa explícitamente
    a cada función.

    Args:
        output_dir: Ruta al directorio de salida. Si es None se genera
                    automáticamente con timestamp.

    Raises:
        OSError: Si no se puede crear el directorio de salida.
    """

    def __init__(self, output_dir: Path | None = None) -> None:
        self.timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.hostname: str = socket.gethostname()
        self.platform: str = platform.system()

        if output_dir is None:
            output_dir = Path(f"triage_{self.hostname}_{self.timestamp}")
        self.output_dir: Path = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.log_file: Path = self.output_dir / "registro_ejecucion.log"
        self.report_file: Path = self.output_dir / "resumen_triage.json"
        self.logger: logging.Logger = _configurar_logging(self.log_file)

        # Resultados acumulados durante la ejecución
        self.resultados: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _configurar_logging(log_file: Path) -> logging.Logger:
    """
    Configura el logger con dos handlers: fichero (DEBUG) y consola (INFO).

    Args:
        log_file: Ruta del fichero de log a crear.

    Returns:
        Logger configurado listo para usar.
    """
    logger = logging.getLogger(f"triage.{os.getpid()}")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

        logger.addHandler(fh)
        logger.addHandler(ch)

    return logger


# ---------------------------------------------------------------------------
# Ejecución de comandos
# ---------------------------------------------------------------------------


def ejecutar_comando(
    ctx: TriageContext,
    comando: str,
    archivo_salida: str,
    descripcion: str,
) -> dict[str, Any]:
    """
    Ejecuta un comando shell y guarda la salida en un fichero dentro del
    directorio de triage.

    Args:
        ctx:            Contexto del triage en curso.
        comando:        Comando shell a ejecutar (soporta pipes).
        archivo_salida: Ruta relativa al directorio de salida donde se
                        guardará la salida del comando.
        descripcion:    Descripción legible del comando (aparece en el log
                        y en el reporte JSON).

    Returns:
        Diccionario con las claves: descripcion, comando, archivo, estado,
        error, bytes, timestamp. El campo ``estado`` puede ser:
        ``"ok"``, ``"timeout"``, ``"error_parcial"`` o ``"error"``.
    """
    ctx.logger.info(f"  [{archivo_salida}] {descripcion}")

    resultado: dict[str, Any] = {
        "descripcion": descripcion,
        "comando": comando,
        "archivo": archivo_salida,
        "estado": "ok",
        "error": None,
        "bytes": 0,
        "timestamp": datetime.now().isoformat(),
    }

    ruta = ctx.output_dir / archivo_salida
    ruta.parent.mkdir(parents=True, exist_ok=True)

    env = {**os.environ, "LANG": "C", "LC_ALL": "C"}

    try:
        salida = subprocess.check_output(
            comando,
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT_CMD,
            text=True,
            encoding="utf-8",
            errors="backslashreplace",  # preserva evidencia, no descarta bytes
            env=env,
        )
        ruta.write_text(salida, encoding="utf-8")
        resultado["bytes"] = ruta.stat().st_size

    except subprocess.TimeoutExpired:
        resultado["estado"] = "timeout"
        resultado["error"] = f"Timeout tras {TIMEOUT_CMD}s"
        ctx.logger.warning(f"    -> TIMEOUT: {descripcion}")

    except subprocess.CalledProcessError as exc:
        if exc.output:
            ruta.write_text(exc.output, encoding="utf-8")
            resultado["bytes"] = ruta.stat().st_size if ruta.exists() else 0
        resultado["estado"] = "error_parcial"
        resultado["error"] = str(exc)
        ctx.logger.warning(f"    -> ERROR PARCIAL: {descripcion}")

    except Exception as exc:  # noqa: BLE001
        resultado["estado"] = "error"
        resultado["error"] = str(exc)
        ctx.logger.error(f"    -> ERROR: {descripcion} — {exc}")

    return resultado


def ejecutar_lista(
    ctx: TriageContext,
    comandos: list[tuple[str, str, str]],
) -> list[dict[str, Any]]:
    """
    Ejecuta una lista de comandos y devuelve sus resultados.

    Elimina el patrón for-loop repetido en cada módulo (DRY).

    Args:
        ctx:      Contexto del triage.
        comandos: Lista de tuplas ``(comando, archivo_salida, descripcion)``.

    Returns:
        Lista de diccionarios de resultado, uno por comando.
    """
    return [ejecutar_comando(ctx, cmd, arch, desc) for cmd, arch, desc in comandos]


# ---------------------------------------------------------------------------
# Copia de ficheros
# ---------------------------------------------------------------------------


def copiar_fichero(
    ctx: TriageContext,
    origen: str,
    destino_relativo: str,
    descripcion: str,
) -> dict[str, Any]:
    """
    Copia un fichero del sistema al directorio de triage sin modificarlo.

    Útil para preservar ficheros binarios (wtmp, btmp) o de configuración
    críticos que deben analizarse con herramientas externas.

    Args:
        ctx:               Contexto del triage.
        origen:            Ruta absoluta del fichero a copiar.
        destino_relativo:  Ruta relativa dentro del directorio de salida.
        descripcion:       Descripción para el log y el reporte.

    Returns:
        Diccionario de resultado con las mismas claves que ``ejecutar_comando``.
    """
    resultado: dict[str, Any] = {
        "descripcion": descripcion,
        "comando": f"cp {origen}",
        "archivo": destino_relativo,
        "estado": "ok",
        "error": None,
        "bytes": 0,
        "timestamp": datetime.now().isoformat(),
    }

    origen_path = Path(origen)
    destino_path = ctx.output_dir / destino_relativo
    destino_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        if origen_path.exists() and origen_path.is_file():
            shutil.copy2(origen_path, destino_path)
            resultado["bytes"] = destino_path.stat().st_size
            ctx.logger.info(f"  [COPIA] {origen} -> {destino_relativo}")
        else:
            resultado["estado"] = "no_existe"
            resultado["error"] = f"Fichero no encontrado: {origen}"
            ctx.logger.warning(f"  [COPIA] No existe: {origen}")

    except PermissionError:
        resultado["estado"] = "permiso_denegado"
        resultado["error"] = "Permiso denegado"
        ctx.logger.warning(f"  [COPIA] Permiso denegado: {origen}")

    except Exception as exc:  # noqa: BLE001
        resultado["estado"] = "error"
        resultado["error"] = str(exc)

    return resultado


# ---------------------------------------------------------------------------
# Hashes de integridad
# ---------------------------------------------------------------------------


def calcular_hashes(ctx: TriageContext) -> dict[str, str]:
    """
    Calcula el hash SHA-256 de todos los ficheros del directorio de triage.

    El fichero de hashes generado (``09_hashes_sha256.txt``) es compatible
    con el comando ``sha256sum --check`` de Linux/macOS para verificación
    posterior.

    Args:
        ctx: Contexto del triage.

    Returns:
        Diccionario ``{ruta_relativa: hash_hex}``.
    """
    ctx.logger.info("=== Generando hashes de integridad SHA-256 ===")

    hashes: dict[str, str] = {}
    hash_path = ctx.output_dir / "09_hashes_sha256.txt"

    with open(hash_path, "w", encoding="utf-8") as hf:
        hf.write("# SHA-256 — Hashes de integridad del triage\n")
        hf.write(f"# Host     : {ctx.hostname}\n")
        hf.write(f"# Timestamp: {datetime.now().isoformat()}\n")
        hf.write("# Verificar : sha256sum --check 09_hashes_sha256.txt\n\n")

        for fichero in sorted(ctx.output_dir.rglob("*")):
            if not fichero.is_file() or fichero.name == "09_hashes_sha256.txt":
                continue
            sha256 = hashlib.sha256()
            try:
                with open(fichero, "rb") as f:
                    while chunk := f.read(HASH_BLOCK_SIZE):
                        sha256.update(chunk)
                digest = sha256.hexdigest()
                nombre_rel = fichero.relative_to(ctx.output_dir)
                hf.write(f"{digest}  {nombre_rel}\n")
                hashes[str(nombre_rel)] = digest
            except Exception as exc:  # noqa: BLE001
                ctx.logger.warning(f"  No se pudo hashear {fichero.name}: {exc}")

    ctx.logger.info(f"  Hashes calculados: {len(hashes)} ficheros")
    return hashes


# ---------------------------------------------------------------------------
# Empaquetado ZIP
# ---------------------------------------------------------------------------


def empaquetar(ctx: TriageContext, hashes: dict[str, str]) -> Path | None:
    """
    Empaqueta el directorio de triage en un ZIP comprimido y calcula su hash.

    El hash del ZIP se guarda en un fichero externo ``<nombre>.zip.sha256``
    para verificar su integridad en tránsito (cadena de custodia).

    Args:
        ctx:    Contexto del triage.
        hashes: Diccionario de hashes ya calculados (solo para log).

    Returns:
        Ruta al fichero ZIP generado, o None si falló la creación.
    """
    ctx.logger.info("=== Empaquetando evidencias ===")

    zip_path = Path(f"triage_{ctx.hostname}_{ctx.timestamp}.zip")

    try:
        with zipfile.ZipFile(
            zip_path, "w", zipfile.ZIP_DEFLATED,
            compresslevel=ZIP_COMPRESSION_LEVEL,
        ) as zf:
            for fichero in sorted(ctx.output_dir.rglob("*")):
                if fichero.is_file():
                    zf.write(fichero, fichero.relative_to(ctx.output_dir.parent))

        size_mb = zip_path.stat().st_size / (1024 * 1024)
        ctx.logger.info(f"  ZIP: {zip_path} ({size_mb:.2f} MB)")

        # Hash externo del ZIP (cadena de custodia)
        sha256 = hashlib.sha256()
        with open(zip_path, "rb") as f:
            while chunk := f.read(HASH_BLOCK_SIZE):
                sha256.update(chunk)
        hash_zip_path = zip_path.with_suffix(".zip.sha256")
        hash_zip_path.write_text(
            f"{sha256.hexdigest()}  {zip_path.name}\n", encoding="utf-8"
        )
        ctx.logger.info(f"  Hash ZIP: {hash_zip_path}")

        return zip_path

    except Exception as exc:  # noqa: BLE001
        ctx.logger.error(f"  Error al crear ZIP: {exc}")
        return None


# ---------------------------------------------------------------------------
# Cadena de custodia
# ---------------------------------------------------------------------------


def generar_cadena_custodia(
    ctx: TriageContext,
    zip_path: Path | None,
    hashes: dict[str, str],
) -> None:
    """
    Genera el documento de cadena de custodia en formato JSON y texto plano.

    Registra: analista, sistema analizado, hora inicio/fin, hash del ZIP,
    número de evidencias recolectadas y estado global.

    Args:
        ctx:      Contexto del triage.
        zip_path: Ruta al ZIP generado (puede ser None si falló).
        hashes:   Diccionario de hashes de los ficheros recolectados.
    """
    hash_zip = "N/A"
    if zip_path and zip_path.exists():
        sha256 = hashlib.sha256()
        with open(zip_path, "rb") as f:
            while chunk := f.read(HASH_BLOCK_SIZE):
                sha256.update(chunk)
        hash_zip = sha256.hexdigest()

    custodia = {
        "documento": "Cadena de Custodia — Triage Forense Digital",
        "version_herramienta": TRIAGE_VERSION,
        "analista": os.getenv("USER") or os.getenv("USERNAME") or str(os.getpid()),
        "sistema_analizado": ctx.hostname,
        "plataforma": ctx.platform,
        "timestamp_inicio": ctx.timestamp,
        "timestamp_fin": datetime.now().isoformat(),
        "directorio_evidencias": str(ctx.output_dir.resolve()),
        "paquete_zip": str(zip_path) if zip_path else "ERROR — no generado",
        "hash_sha256_zip": hash_zip,
        "total_ficheros_recolectados": len(hashes),
        "total_comandos_ejecutados": len(ctx.resultados),
        "comandos_exitosos": sum(
            1 for r in ctx.resultados if r.get("estado") == "ok"
        ),
    }

    # JSON
    (ctx.output_dir / "cadena_custodia.json").write_text(
        json.dumps(custodia, indent=4, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    # Texto plano legible
    lineas = [
        "=" * 60,
        "  CADENA DE CUSTODIA — TRIAGE FORENSE DIGITAL",
        "=" * 60,
    ]
    for k, v in custodia.items():
        lineas.append(f"  {k:<35}: {v}")
    lineas.append("=" * 60)
    (ctx.output_dir / "cadena_custodia.txt").write_text(
        "\n".join(lineas), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Reporte final JSON
# ---------------------------------------------------------------------------


def generar_reporte(
    ctx: TriageContext,
    info_general: dict[str, Any],
    hashes: dict[str, str],
    zip_path: Path | None,
) -> None:
    """
    Genera el reporte final del triage en formato JSON e imprime el resumen
    en consola.

    Args:
        ctx:          Contexto del triage.
        info_general: Metadatos del sistema recolectados en el módulo 0.
        hashes:       Diccionario de hashes de los ficheros recolectados.
        zip_path:     Ruta al ZIP generado (puede ser None).
    """
    estados_ok = {"ok", "error_parcial"}  # error_parcial tiene salida útil
    correctos = [r for r in ctx.resultados if r.get("estado") in estados_ok]
    errores = [r for r in ctx.resultados if r.get("estado") not in estados_ok]

    reporte = {
        "triage_version": TRIAGE_VERSION,
        "timestamp_inicio": ctx.timestamp,
        "timestamp_fin": datetime.now().isoformat(),
        "hostname": ctx.hostname,
        "plataforma": ctx.platform,
        "sistema": info_general,
        "estadisticas": {
            "total_comandos": len(ctx.resultados),
            "exitosos": len(correctos),
            "con_errores": len(errores),
            "ficheros_hashed": len(hashes),
        },
        "resultados": ctx.resultados,
        "paquete_zip": str(zip_path) if zip_path else None,
    }

    ctx.report_file.write_text(
        json.dumps(reporte, indent=4, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    # Resumen en consola
    sep = "=" * 65
    print(f"\n{sep}")
    print(f"  TRIAGE COMPLETADO — {ctx.platform.upper()}")
    print(sep)
    print(f"  Host       : {ctx.hostname}")
    print(f"  Directorio : {ctx.output_dir}")
    print(f"  ZIP        : {zip_path or 'ERROR — no generado'}")
    print(f"  Comandos   : {len(correctos)}/{len(ctx.resultados)} exitosos")

    if errores:
        print(f"\n  [!] Incidencias ({len(errores)}):")
        for err in errores:
            print(f"      - {err['descripcion']} [{err['estado']}]")

    print(f"{sep}\n")


# ---------------------------------------------------------------------------
# Manejo de señales (Ctrl+C)
# ---------------------------------------------------------------------------


def registrar_manejador_interrupcion(ctx: TriageContext) -> None:
    """
    Registra un manejador para SIGINT (Ctrl+C) que ejecuta un cierre limpio.

    Si el usuario interrumpe la ejecución, se generan los hashes y el ZIP
    con los datos recolectados hasta ese momento.

    Args:
        ctx: Contexto del triage (se usa para el cierre limpio).
    """
    def _manejador(sig: int, frame: Any) -> None:  # noqa: ANN001
        ctx.logger.warning("Triage interrumpido por el usuario (Ctrl+C).")
        print("\n[!] Triage interrumpido. Guardando evidencias parciales...")
        try:
            hashes = calcular_hashes(ctx)
            zip_path = empaquetar(ctx, hashes)
            generar_cadena_custodia(ctx, zip_path, hashes)
            generar_reporte(ctx, {}, hashes, zip_path)
        except Exception as exc:  # noqa: BLE001
            ctx.logger.error(f"Error en cierre limpio: {exc}")
        sys.exit(1)

    signal.signal(signal.SIGINT, _manejador)
