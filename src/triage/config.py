"""
config.py — Configuración centralizada del triage forense.

Todas las constantes y valores configurables del proyecto se definen aquí.
Nunca hardcodear valores en otros módulos; importarlos siempre desde config.
"""

# ---------------------------------------------------------------------------
# Ejecución
# ---------------------------------------------------------------------------

# Tiempo máximo en segundos que se espera a que un comando finalice.
TIMEOUT_CMD: int = 120

# Nivel de compresión del ZIP de salida (1=rápido … 9=máximo).
ZIP_COMPRESSION_LEVEL: int = 9

# Tamaño del bloque de lectura para calcular hashes (bytes).
HASH_BLOCK_SIZE: int = 8192

# ---------------------------------------------------------------------------
# Recolección — límites de líneas en comandos "tail / head / last"
# ---------------------------------------------------------------------------

LINES_LOG_TAIL: int = 500       # líneas a extraer de logs de texto
LINES_DMESG: int = 200          # líneas del buffer dmesg
LINES_JOURNAL: int = 500        # entradas del journal
LINES_LAST: int = 50            # entradas de last / lastb
LINES_PROC_FD: int = 500        # muestra de /proc/PID/fd
LINES_PROC_CMDLINE: int = 200   # muestra de cmdlines
LINES_PROC_MAPS: int = 10       # líneas por PID en /proc/PID/maps
LINES_PROC_ENVIRON: int = 300   # líneas totales de environ de procesos
LINES_FIND_MODULES: int = 100   # módulos del kernel a listar
LINES_WORLD_WRITABLE: int = 100 # ficheros world-writable a listar
LINES_MODIFIED_FILES: int = 500 # ficheros modificados en 24 h

# ---------------------------------------------------------------------------
# Versión y metadatos del triage
# ---------------------------------------------------------------------------

TRIAGE_VERSION: str = "2.0.0"
