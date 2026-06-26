"""
windows.py — Módulos de triage forense para Windows.

Cada función ``modulo_*`` recibe un ``TriageContext`` y devuelve la lista
de resultados. La ejecución orquestada se realiza en ``main()``.

Ejecución (como Administrador):
    python triage\\windows.py
    uv run triage-windows
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from triage.common import (
    TriageContext,
    calcular_hashes,
    empaquetar,
    ejecutar_lista,
    generar_cadena_custodia,
    generar_reporte,
    registrar_manejador_interrupcion,
)
from triage.config import (
    LINES_LAST,
    LINES_LOG_TAIL,
    TRIAGE_VERSION,
)

# ---------------------------------------------------------------------------
# Verificación del entorno
# ---------------------------------------------------------------------------


def verificar_entorno() -> None:
    """
    Verifica que el script se ejecuta en Windows con privilegios de Administrador.

    Avisa si no hay privilegios elevados pero permite continuar, ya que
    algunos módulos pueden ejecutarse sin ellos.

    Raises:
        SystemExit: Si el usuario elige no continuar.
    """
    if platform.system() != "Windows":
        print(f"[!] Sistema detectado: {platform.system()}. Este script es para Windows.")
        respuesta = input("[?] ¿Continuar de todas formas? (s/n): ").strip().lower()
        if respuesta != "s":
            sys.exit(1)

    try:
        es_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        es_admin = False

    if not es_admin:
        print("[!] ADVERTENCIA: No se ejecuta como Administrador.")
        print("    Haz clic derecho en el terminal → 'Ejecutar como administrador'")
        respuesta = input("[?] ¿Continuar sin privilegios elevados? (s/n): ").strip().lower()
        if respuesta != "s":
            sys.exit(1)


# ---------------------------------------------------------------------------
# Módulo 0 — Metadatos del triage
# ---------------------------------------------------------------------------


def modulo_info_general(ctx: TriageContext) -> dict[str, Any]:
    """
    Recopila los metadatos del sistema Windows en el que se ejecuta el triage.

    Genera ``00_info_general.json`` y ``00_info_general.txt``.

    Args:
        ctx: Contexto del triage.

    Returns:
        Diccionario con los metadatos del sistema.
    """
    ctx.logger.info("=== MÓDULO 0: Metadatos del triage ===")

    info: dict[str, Any] = {
        "timestamp_inicio": ctx.timestamp,
        "hostname": ctx.hostname,
        "so": platform.system(),
        "version_so": platform.version(),
        "release": platform.release(),
        "arquitectura": platform.architecture()[0],
        "procesador": platform.processor(),
        "python_version": platform.python_version(),
        "usuario_triage": os.getenv("USERNAME", "desconocido"),
    }

    (ctx.output_dir / "00_info_general.json").write_text(
        __import__("json").dumps(info, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )
    lineas = ["===== METADATOS DEL TRIAGE =====\n"]
    lineas += [f"{k:<25}: {v}" for k, v in info.items()]
    (ctx.output_dir / "00_info_general.txt").write_text(
        "\n".join(lineas), encoding="utf-8",
    )
    return info


# ---------------------------------------------------------------------------
# Módulo 1 — Datos volátiles (RFC 3227 — mayor volatilidad primero)
# ---------------------------------------------------------------------------


def modulo_volatil(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Captura los datos de máxima volatilidad en Windows siguiendo RFC 3227.

    Incluye: fecha/hora, configuración de red, tabla ARP, conexiones activas,
    caché NetBIOS, procesos activos y sesiones de usuario.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 1: Datos volátiles (RFC 3227) ===")

    comandos = [
        # Fecha / hora
        ("date /t && time /t",                             "01_01_fecha_hora.txt",        "Fecha y hora del sistema"),
        # Red
        ("ipconfig /all",                                  "01_02_config_red.txt",        "Configuración de red"),
        ("arp -a",                                         "01_03_tabla_arp.txt",         "Tabla ARP"),
        ("netstat -ano",                                   "01_04_conexiones_red.txt",    "Conexiones de red activas"),
        ("netstat -rn",                                    "01_05_tabla_enrutamiento.txt","Tabla de enrutamiento"),
        ("nbtstat -c",                                     "01_06_cache_netbios.txt",     "Caché NetBIOS"),
        # Procesos
        ("tasklist /v /fo csv",                            "01_07_procesos_activos.csv",  "Procesos activos (CSV)"),
        ("tasklist /svc /fo csv",                          "01_08_procesos_servicios.csv","Procesos y servicios"),
        ("wmic process get ProcessId,Name,CommandLine,ParentProcessId /format:csv",
                                                           "01_09_procesos_detalle.csv",  "Detalle procesos (WMIC)"),
        # Sesiones
        ("query user",                                     "01_10_usuarios_sesion.txt",   "Sesiones de usuario"),
        ("query session",                                  "01_11_sesiones.txt",          "Sesiones de terminal"),
        ("net session",                                    "01_12_sesiones_red.txt",      "Sesiones de red"),
        ("net use",                                        "01_13_unidades_mapeadas.txt", "Unidades de red mapeadas"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 2 — Sistema operativo y hardware
# ---------------------------------------------------------------------------


def modulo_sistema(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Recopila información del SO, hardware, discos y configuración de red.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 2: Sistema operativo y hardware ===")

    comandos = [
        ("systeminfo",                                     "02_01_systeminfo.txt",        "Información del sistema"),
        ("wmic os get * /format:csv",                      "02_02_so_wmic.csv",           "SO vía WMIC"),
        ("wmic computersystem get * /format:csv",          "02_03_hardware.csv",          "Hardware del equipo"),
        ("wmic bios get * /format:csv",                    "02_04_bios.csv",              "Información BIOS"),
        ("wmic diskdrive get * /format:csv",               "02_05_discos.csv",            "Discos físicos"),
        ("wmic logicaldisk get * /format:csv",             "02_06_particiones.csv",       "Particiones lógicas"),
        ("fsutil fsinfo drives",                           "02_07_unidades.txt",          "Letras de unidad"),
        ("wmic nic get * /format:csv",                     "02_08_interfaces_red.csv",    "Interfaces de red"),
        ("wmic nicconfig get * /format:csv",               "02_09_config_interfaces.csv", "Config. interfaces"),
        ("net share",                                      "02_10_carpetas_compartidas.txt","Recursos compartidos"),
        ("wmic share get * /format:csv",                   "02_11_shares_wmic.csv",       "Shares vía WMIC"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 3 — Servicios y persistencia
# ---------------------------------------------------------------------------


def modulo_persistencia(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Recolecta mecanismos de persistencia en Windows: servicios, tareas
    programadas, claves Run/RunOnce, drivers, AppInit DLLs y Winlogon.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 3: Servicios y persistencia ===")

    comandos = [
        # Servicios
        ("sc query type= all state= all",                  "03_01_servicios_todos.txt",   "Todos los servicios"),
        ("wmic service get * /format:csv",                 "03_02_servicios_wmic.csv",    "Servicios vía WMIC"),
        # Tareas programadas
        ("schtasks /query /fo csv /v",                     "03_03_tareas_programadas.csv","Tareas programadas"),
        # Drivers
        ("driverquery /fo csv /v",                         "03_04_drivers.csv",           "Drivers instalados"),
        ("sc query type= driver",                          "03_05_drivers_activos.txt",   "Drivers activos"),
        # Registro — autoarranque
        (r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"',
                                                           "03_06_run_hklm.txt",          "HKLM Run"),
        (r'reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"',
                                                           "03_07_run_hkcu.txt",          "HKCU Run"),
        (r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"',
                                                           "03_08_runonce_hklm.txt",      "HKLM RunOnce"),
        (r'reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"',
                                                           "03_09_runonce_hkcu.txt",      "HKCU RunOnce"),
        (r'reg query "HKLM\SYSTEM\CurrentControlSet\Services"',
                                                           "03_10_servicios_reg.txt",     "Servicios en registro"),
        # Técnicas de inyección
        (r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs',
                                                           "03_11_appinit_dlls.txt",      "AppInit DLLs"),
        (r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"',
                                                           "03_12_winlogon.txt",          "Winlogon entries"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 4 — Usuarios y seguridad
# ---------------------------------------------------------------------------


def modulo_usuarios(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Recopila información de cuentas locales, grupos, política de seguridad
    y auditoría en Windows.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 4: Usuarios y seguridad ===")

    comandos = [
        ("net user",                                       "04_01_usuarios_locales.txt",  "Usuarios locales"),
        ("wmic useraccount get * /format:csv",             "04_02_cuentas_wmic.csv",      "Cuentas (WMIC)"),
        ("net localgroup",                                 "04_03_grupos_locales.txt",    "Grupos locales"),
        ("net localgroup Administrators",                  "04_04_administradores.txt",   "Grupo Administradores"),
        ("whoami /all",                                    "04_05_contexto_actual.txt",   "Contexto de seguridad"),
        ("auditpol /get /category:*",                      "04_06_politica_auditoria.txt","Política de auditoría"),
        ("net accounts",                                   "04_07_politica_contrasenas.txt","Política contraseñas"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 5 — Logs de eventos
# ---------------------------------------------------------------------------


def modulo_logs(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Extrae los logs de eventos de Windows más relevantes (System, Security,
    Application, Sysmon, PowerShell) en texto y formato EVTX.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 5: Logs de eventos ===")

    logs_texto = [
        ("System",       LINES_LOG_TAIL, "05_01_log_sistema.txt",     "Log System"),
        ("Security",     500,            "05_02_log_seguridad.txt",   "Log Security"),
        ("Application",  LINES_LOG_TAIL, "05_03_log_aplicacion.txt",  "Log Application"),
        ("Microsoft-Windows-Sysmon/Operational", 500,
                                         "05_04_log_sysmon.txt",      "Log Sysmon"),
        ("Microsoft-Windows-PowerShell/Operational", LINES_LOG_TAIL,
                                         "05_05_log_powershell.txt",  "Log PowerShell"),
    ]

    resultados = []
    for canal, cantidad, archivo, desc in logs_texto:
        cmd = f'wevtutil qe "{canal}" /c:{cantidad} /f:text /rd:true 2>nul'
        resultados.append(
            ejecutar_lista(ctx, [(cmd, archivo, desc)])[0]
        )

    # Exportar también en EVTX para análisis con herramientas forenses
    evtx_canales = ["System", "Security", "Application"]
    for canal in evtx_canales:
        archivo_evtx = f"evtx/{canal}.evtx"
        cmd = f'wevtutil epl "{canal}" "{ctx.output_dir / archivo_evtx}"'
        resultados += ejecutar_lista(ctx, [(cmd, archivo_evtx, f"Exportar EVTX: {canal}")])

    return resultados


# ---------------------------------------------------------------------------
# Módulo 6 — Artefactos forenses Windows
# ---------------------------------------------------------------------------


def modulo_artefactos(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Recolecta artefactos forenses específicos de Windows: Prefetch, LNKs,
    Jump Lists, historial PowerShell/CMD, USB, redes conocidas y hosts file.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 6: Artefactos forenses Windows ===")

    comandos = [
        # Prefetch (evidencia de ejecución de programas)
        (r"dir /a /b C:\Windows\Prefetch\*.pf 2>nul",
         "artefactos/06_01_prefetch.txt",               "Lista Prefetch"),
        # Ficheros recientes
        (r'dir /a /b "%APPDATA%\Microsoft\Windows\Recent\" 2>nul',
         "artefactos/06_02_ficheros_recientes.txt",      "Ficheros recientes (LNK)"),
        # Jump Lists
        (r'dir /a /b "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\" 2>nul',
         "artefactos/06_03_jumplists.txt",               "Jump Lists automáticas"),
        # Historial PowerShell
        (r'type "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul',
         "artefactos/06_04_powershell_history.txt",      "Historial PowerShell"),
        # Historial CMD (registro MRU)
        (r'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"',
         "artefactos/06_05_run_mru.txt",                 "Historial cuadro Ejecutar"),
        # URLs tipeadas
        (r'reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" 2>nul',
         "artefactos/06_06_typed_urls.txt",              "URLs tipeadas IE"),
        # USB conectados
        (r'reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s',
         "artefactos/06_07_usb_conectados.txt",          "Dispositivos USB"),
        # Redes conocidas
        (r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s',
         "artefactos/06_08_redes_conocidas.txt",         "Perfiles de red históricos"),
        # Papelera
        (r"dir /a /b C:\$Recycle.Bin\ /s 2>nul",
         "artefactos/06_09_papelera.txt",                "Papelera de reciclaje"),
        # Ficheros de configuración críticos
        (r"type C:\Windows\System32\drivers\etc\hosts",
         "artefactos/06_10_hosts_file.txt",              "Fichero hosts"),
        ("set",
         "artefactos/06_11_variables_entorno.txt",       "Variables de entorno"),
        ("tzutil /g",
         "artefactos/06_12_zona_horaria.txt",            "Zona horaria"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 7 — Software instalado
# ---------------------------------------------------------------------------


def modulo_software(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Inventario completo del software instalado en Windows, incluyendo
    aplicaciones de 32 y 64 bits y parches de seguridad.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 7: Software instalado ===")

    comandos = [
        ("wmic product get Name,Version,Vendor,InstallDate /format:csv",
         "07_01_software_wmic.csv",    "Software instalado (WMIC)"),
        (r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s',
         "07_02_software_hklm.txt",   "Software HKLM"),
        (r'reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s',
         "07_03_software_hkcu.txt",   "Software HKCU"),
        (r'reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s',
         "07_04_software_wow64.txt",  "Software 32-bit (WOW64)"),
        ("wmic qfe get HotFixID,InstalledOn,Description /format:csv",
         "07_05_parches.csv",         "Parches y actualizaciones"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Orquesta la ejecución completa del triage forense Windows.

    Orden de módulos según RFC 3227 (mayor volatilidad primero).
    Captura Ctrl+C para generar un cierre limpio con los datos parciales.
    """
    verificar_entorno()

    ctx = TriageContext()
    registrar_manejador_interrupcion(ctx)

    ctx.logger.info("=" * 65)
    ctx.logger.info(f"TRIAGE FORENSE WINDOWS v{TRIAGE_VERSION}")
    ctx.logger.info(f"Host: {ctx.hostname}  |  Timestamp: {ctx.timestamp}")
    ctx.logger.info(f"Usuario: {os.getenv('USERNAME', 'desconocido')}")
    ctx.logger.info("=" * 65)

    info_general = modulo_info_general(ctx)

    ctx.resultados += modulo_volatil(ctx)       # M1 — máxima volatilidad
    ctx.resultados += modulo_sistema(ctx)       # M2 — hardware y SO
    ctx.resultados += modulo_persistencia(ctx)  # M3 — persistencia
    ctx.resultados += modulo_usuarios(ctx)      # M4 — usuarios y seguridad
    ctx.resultados += modulo_logs(ctx)          # M5 — logs de eventos
    ctx.resultados += modulo_artefactos(ctx)    # M6 — artefactos forenses
    ctx.resultados += modulo_software(ctx)      # M7 — software

    hashes = calcular_hashes(ctx)              # M8 — integridad SHA-256
    zip_path = empaquetar(ctx, hashes)         # M9 — empaquetado
    generar_cadena_custodia(ctx, zip_path, hashes)
    generar_reporte(ctx, info_general, hashes, zip_path)

    from triage.reporter import generar_informe_html  # M10 — informe HTML
    generar_informe_html(ctx, info_general, hashes, zip_path)

    ctx.logger.info("TRIAGE WINDOWS FINALIZADO")


if __name__ == "__main__":
    main()
