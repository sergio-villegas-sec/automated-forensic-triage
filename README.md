# Triage Forense Digital — TFM

Herramienta de triage forense automatizado para **Linux** (Ubuntu, Kali) y **Windows**, desarrollada como parte del Trabajo de Fin de Máster en Ciberseguridad.

Recolecta evidencias volátiles y no volátiles siguiendo el orden de volatilidad definido en **RFC 3227** y las directrices de **NIST SP 800-86**, genera hashes SHA-256 de integridad y empaqueta todo en un ZIP con cadena de custodia.

---

## Índice

1. [Características](#características)
2. [Estructura del proyecto](#estructura-del-proyecto)
3. [Requisitos](#requisitos)
4. [Instalación](#instalación)
5. [Uso](#uso)
6. [Módulos de recolección](#módulos-de-recolección)
7. [Salida generada](#salida-generada)
8. [Verificar integridad](#verificar-integridad)
9. [Ejecutar los tests](#ejecutar-los-tests)
10. [Docker](#docker)
11. [Referencias](#referencias)

---

## Características

- **RFC 3227**: Orden de recolección de mayor a menor volatilidad.
- **Multiplataforma**: Un único codebase para Linux y Windows, sin duplicar código.
- **Trazabilidad**: Log detallado de cada comando con timestamp individual.
- **Integridad**: Hashes SHA-256 de todos los ficheros recolectados + hash externo del ZIP.
- **Cadena de custodia**: Documento JSON + texto con analista, sistema, tiempos y hashes.
- **Robusto**: Timeout por comando, manejo de errores parciales, cierre limpio con Ctrl+C.
- **Configurable**: Todas las constantes en `config.py`; sin valores hardcodeados.
- **Testeable**: Tests unitarios con pytest que cubren los bugs más críticos.

---

## Estructura del proyecto

```
triage-forense/
├── pyproject.toml            ← metadatos, dependencias y scripts de entrada
├── .python-version           ← versión exacta de Python
├── README.md                 ← este fichero
├── .gitignore
├── Dockerfile
├── src/
│   └── triage/
│       ├── __init__.py
│       ├── config.py         ← TODAS las constantes configurables
│       ├── common.py         ← funciones compartidas (DRY)
│       ├── linux.py          ← módulos de recolección Linux
│       └── windows.py        ← módulos de recolección Windows
├── tests/
│   └── test_basico.py        ← tests unitarios (pytest)
└── docs/
    ├── manual_uso.md
    └── cadena_custodia.md
```

---

## Requisitos

| Componente | Versión mínima |
|---|---|
| Python | 3.11 |
| uv | cualquiera (recomendado) |
| SO Linux | Ubuntu 20.04 / 22.04 / 24.04, Kali Linux |
| SO Windows | Windows 10 / 11, Server 2019+ |
| Privilegios | `root` en Linux · Administrador en Windows |

---

## Instalación

### Opción A — Con uv (recomendado)

```bash
# 1. Instalar uv (una sola vez)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Clonar / copiar el proyecto
cd triage-forense

# 3. uv gestiona automáticamente el entorno virtual y las dependencias
uv sync
```

### Opción B — Con pip estándar

```bash
python3 -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows

pip install -e ".[dev]"
```

---

## Uso

### Linux / Ubuntu / Kali

```bash
# Con uv (recomendado)
sudo uv run triage-linux

# Con Python directamente
sudo python3 -m triage.linux

# O ejecutando el módulo
sudo python3 src/triage/linux.py
```

### Windows

```powershell
# En terminal con privilegios de Administrador

# Con uv
uv run triage-windows

# Con Python directamente
python -m triage.windows
```

### Salida

El triage genera automáticamente:
- Un directorio `triage_<hostname>_<YYYYMMDD_HHMMSS>/` con todas las evidencias.
- Un fichero `triage_<hostname>_<YYYYMMDD_HHMMSS>.zip` comprimido.
- Un fichero `triage_<hostname>_<YYYYMMDD_HHMMSS>.zip.sha256` con el hash del ZIP.

---

## Módulos de recolección

### Linux (`linux.py`)

| Módulo | Contenido | Volatilidad RFC 3227 |
|---|---|---|
| M0 | Metadatos del triage | — |
| M1 | Fecha/hora, red, ARP, sockets, procesos, memoria, usuarios | ★★★ Máxima |
| M2 | Kernel, hardware, discos, montajes, sysctl, dmesg | ★★ |
| M3 | systemd, cron (todos los usuarios), init.d, módulos kernel, perfiles shell | ★★ |
| M4 | passwd, shadow, sudoers, SSH, SUID/SGID, capabilities, AppArmor, UFW | ★★ |
| M5 | journald, auth.log, syslog, audit, bash_history, wtmp/btmp/utmp binarios | ★ |
| M6 | Ficheros eliminados abiertos, /dev/shm, world-writable, modificados 24h, rootkits | ★ |
| M7 | dpkg, apt, snap, flatpak, netplan, NetworkManager, DNS | ★ |
| M8 | Copia binaria de ficheros críticos (/etc/passwd, shadow, wtmp…) | Custodia |

### Windows (`windows.py`)

| Módulo | Contenido | Volatilidad RFC 3227 |
|---|---|---|
| M0 | Metadatos del triage | — |
| M1 | Fecha/hora, ipconfig, ARP, netstat, NBT, procesos, sesiones | ★★★ Máxima |
| M2 | systeminfo, WMIC hardware/SO/discos/red | ★★ |
| M3 | Servicios, tareas programadas, drivers, Run/RunOnce, AppInit DLLs, Winlogon | ★★ |
| M4 | Usuarios locales, grupos, sudoers, whoami, auditoría | ★★ |
| M5 | Logs System/Security/Application/Sysmon/PowerShell + EVTX | ★ |
| M6 | Prefetch, LNKs, Jump Lists, historial PS/CMD, USB, redes conocidas, hosts | ★ |
| M7 | Software instalado (64/32 bit), parches | ★ |

---

## Salida generada

Dentro del directorio de triage encontrarás:

```
triage_mihost_20250512_143022/
├── 00_info_general.json          ← metadatos del sistema
├── 00_info_general.txt
├── 01_01_fecha_hora.txt          ← módulo 1: datos volátiles
├── ...
├── logs/                         ← módulo 5: logs del sistema
│   ├── binarios/                 ← wtmp, btmp, utmp binarios
│   └── *.txt
├── artefactos/                   ← módulo 6: artefactos forenses
├── ficheros_criticos/            ← módulo 8: copias de ficheros
├── 09_hashes_sha256.txt          ← hashes SHA-256 (formato sha256sum)
├── cadena_custodia.json          ← documento de cadena de custodia
├── cadena_custodia.txt
├── resumen_triage.json           ← reporte final con estadísticas
└── registro_ejecucion.log        ← log detallado de la ejecución
```

---

## Verificar integridad

```bash
# En Linux/macOS — verifica TODOS los ficheros de una vez
cd triage_mihost_20250512_143022/
sha256sum --check 09_hashes_sha256.txt

# Verificar el ZIP
sha256sum --check ../triage_mihost_20250512_143022.zip.sha256
```

---

## Ejecutar los tests

```bash
# Tests básicos
uv run pytest

# Con detalle de cada test
uv run pytest -v

# Con informe de cobertura
uv run pytest --cov=triage --cov-report=term-missing

# Un test específico
uv run pytest tests/test_basico.py::test_hashes_formato_sha256sum -v
```

Los tests cubren los bugs críticos identificados en el análisis del proyecto:

| Test | Bug cubierto |
|---|---|
| `test_ctx_logger_no_es_none` | Bug#1: AttributeError por logger None |
| `test_reporte_con_zip_none_no_lanza_excepcion` | Bug#2: crash con zip_path=None |
| `test_hashes_formato_sha256sum` | Bug#3: formato de hashes incompatible |
| `test_ejecutar_comando_crea_subdirectorio` | Bug#4: mkdir faltante en Windows |
| `test_error_parcial_no_se_cuenta_como_fallo_total` | Bug#5: contador de errores incorrecto |

---

## Docker

```bash
# Construir la imagen
docker build -t triage-forense:2.0 .

# Ejecutar los tests en un entorno limpio
docker run --rm triage-forense:2.0

# Ejecutar el triage (demostración / desarrollo)
docker run --rm -v $(pwd)/output:/output triage-forense:2.0 \
  uv run triage-linux
```

> **Nota forense importante:** Para recolección de evidencias reales, ejecuta siempre
> el script de forma nativa en la máquina comprometida. Docker limita el acceso a
> `/proc`, memoria RAM e interfaces de red del sistema host.

---

## Referencias

- **RFC 3227** — Guidelines for Evidence Collection and Archiving (2002)
- **NIST SP 800-86** — Guide to Integrating Forensic Techniques into Incident Response
- **SANS FOR508** — Advanced Incident Response, Threat Hunting, and Digital Forensics
- **Python uv** — https://docs.astral.sh/uv/
