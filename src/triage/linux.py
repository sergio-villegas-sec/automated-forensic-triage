"""
linux.py — Módulos de triage forense para Linux (Ubuntu, Kali, Debian…).

Cada función ``modulo_*`` recibe un ``TriageContext`` y devuelve la lista
de resultados de sus comandos. La ejecución orquestada se realiza en ``main()``.

Ejecución:
    sudo python3 -m triage.linux
    uv run triage-linux          # si se instaló con pyproject.toml
"""

from __future__ import annotations

import os
import platform
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from triage.common import (
    TriageContext,
    calcular_hashes,
    copiar_fichero,
    empaquetar,
    ejecutar_lista,
    generar_cadena_custodia,
    generar_reporte,
    registrar_manejador_interrupcion,
)
from triage.config import (
    LINES_DMESG,
    LINES_FIND_MODULES,
    LINES_JOURNAL,
    LINES_LAST,
    LINES_LOG_TAIL,
    LINES_MODIFIED_FILES,
    LINES_PROC_CMDLINE,
    LINES_PROC_ENVIRON,
    LINES_PROC_FD,
    LINES_PROC_MAPS,
    LINES_WORLD_WRITABLE,
)

# ---------------------------------------------------------------------------
# Verificación del entorno
# ---------------------------------------------------------------------------


def verificar_entorno() -> None:
    """
    Verifica que el script se ejecuta en Linux y con permisos adecuados.

    Avisa (no bloquea) si no hay privilegios root, ya que algunos módulos
    requieren acceso a ficheros restringidos.

    Raises:
        SystemExit: Si el usuario elige no continuar sin los permisos.
    """
    if platform.system() != "Linux":
        print(f"[!] Sistema detectado: {platform.system()}. Este script es para Linux.")
        respuesta = input("[?] ¿Continuar de todas formas? (s/n): ").strip().lower()
        if respuesta != "s":
            sys.exit(1)

    if os.geteuid() != 0:
        nombre_script = Path(sys.argv[0]).name
        print("[!] ADVERTENCIA: No se está ejecutando como root.")
        print(f"    Ejecuta con: sudo python3 {nombre_script}")
        respuesta = input("[?] ¿Continuar sin root? (s/n): ").strip().lower()
        if respuesta != "s":
            sys.exit(1)


# ---------------------------------------------------------------------------
# Módulo 0 — Metadatos del triage
# ---------------------------------------------------------------------------


def modulo_info_general(ctx: TriageContext) -> dict[str, Any]:
    """
    Recopila los metadatos del sistema en el que se ejecuta el triage.

    Genera ``00_info_general.json`` y ``00_info_general.txt``.

    Args:
        ctx: Contexto del triage.

    Returns:
        Diccionario con los metadatos del sistema.
    """
    ctx.logger.info("=== MÓDULO 0: Metadatos del triage ===")

    def _cmd(c: str) -> str:
        try:
            return subprocess.check_output(c, shell=True, text=True,
                                           encoding="utf-8", errors="replace").strip()
        except Exception:
            return "desconocido"

    info: dict[str, Any] = {
        "timestamp_inicio": ctx.timestamp,
        "hostname": ctx.hostname,
        "so": platform.system(),
        "kernel": _cmd("uname -r"),
        "distro": _cmd("cat /etc/os-release"),
        "arquitectura": platform.machine(),
        "python_version": platform.python_version(),
        "usuario_triage": os.getenv("USER", str(os.getuid())),
        "uid": os.getuid(),
        "es_root": os.getuid() == 0,
    }

    (ctx.output_dir / "00_info_general.json").write_text(
        __import__("json").dumps(info, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )
    lineas = ["===== METADATOS DEL TRIAGE =====\n"]
    lineas += [f"{k:<25}: {v}" for k, v in info.items()]
    (ctx.output_dir / "00_info_general.txt").write_text(
        "\n".join(lineas), encoding="utf-8"
    )
    return info


# ---------------------------------------------------------------------------
# Módulo 1 — Datos volátiles (RFC 3227 — mayor volatilidad primero)
# ---------------------------------------------------------------------------


def modulo_volatil(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Captura los datos de máxima volatilidad siguiendo el orden RFC 3227.

    Incluye: fecha/hora, interfaces de red, tabla ARP, sockets abiertos,
    conexiones activas, /proc/net, procesos, memoria, usuarios activos y
    variables de entorno.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 1: Datos volátiles (RFC 3227) ===")

    comandos = [
        # Fecha / hora
        ("date",
         "01_01_fecha_hora.txt", "Fecha y hora del sistema"),
        ("hwclock --show 2>/dev/null || timedatectl",
         "01_02_reloj_hardware.txt", "Reloj hardware / timedatectl"),
        ("uptime",
         "01_03_uptime.txt", "Tiempo de actividad"),
        # Red
        ("ip addr show",
         "01_04_ip_interfaces.txt", "Interfaces de red"),
        ("ip route show",
         "01_05_tabla_enrutamiento.txt", "Tabla de enrutamiento"),
        ("ip neigh show",
         "01_06_tabla_arp.txt", "Tabla ARP/NDP"),
        ("ss -tulnpa",
         "01_07_sockets_abiertos.txt", "Sockets abiertos (ss)"),
        ("netstat -anp 2>/dev/null || ss -anp",
         "01_08_conexiones_todas.txt", "Todas las conexiones con PIDs"),
        ("cat /proc/net/tcp",
         "01_09_proc_net_tcp.txt", "/proc/net/tcp"),
        ("cat /proc/net/tcp6",
         "01_10_proc_net_tcp6.txt", "/proc/net/tcp6"),
        ("cat /proc/net/udp",
         "01_11_proc_net_udp.txt", "/proc/net/udp"),
        ("cat /proc/net/arp",
         "01_12_proc_net_arp.txt", "/proc/net/arp"),
        ("iptables -L -v -n 2>/dev/null",
         "01_13_iptables.txt", "Reglas iptables"),
        # Procesos
        ("ps auxf",
         "01_14_procesos_arbol.txt", "Árbol de procesos"),
        ("ps -eo pid,ppid,user,stat,start,time,comm,args",
         "01_15_procesos_detalle.txt", "Procesos con detalle"),
        (f"ls -la /proc/[0-9]*/exe 2>/dev/null",
         "01_16_proc_exe_links.txt", "Links /proc/PID/exe"),
        (f"ls -la /proc/[0-9]*/fd 2>/dev/null | head -{LINES_PROC_FD}",
         "01_17_proc_fd.txt", "Descriptores de fichero (muestra)"),
        (f"cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' ' | head -{LINES_PROC_CMDLINE}",
         "01_18_proc_cmdlines.txt", "Líneas de comando de procesos"),
        # Memoria
        ("free -h",
         "01_19_memoria_libre.txt", "Uso de memoria"),
        ("cat /proc/meminfo",
         "01_20_meminfo.txt", "/proc/meminfo"),
        ("vmstat -s",
         "01_21_vmstat.txt", "Estadísticas de memoria virtual"),
        # Usuarios activos
        ("who -a",
         "01_22_usuarios_activos.txt", "Usuarios con sesión activa"),
        ("w",
         "01_23_actividad_usuarios.txt", "Actividad de usuarios"),
        (f"last -F -n {LINES_LAST}",
         "01_24_ultimos_logins.txt", f"Últimos {LINES_LAST} inicios de sesión"),
        (f"lastb -F -n {LINES_LAST} 2>/dev/null",
         "01_25_logins_fallidos.txt", f"Últimos {LINES_LAST} logins fallidos"),
        ("lastlog",
         "01_26_lastlog.txt", "Último login por usuario"),
        # Variables de entorno
        ("env",
         "01_27_variables_entorno.txt", "Variables de entorno"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 2 — Sistema operativo y hardware
# ---------------------------------------------------------------------------


def modulo_sistema(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Recopila información del SO, kernel, hardware, discos y montajes.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 2: Sistema operativo y hardware ===")

    comandos = [
        ("uname -a",                              "02_01_uname.txt",               "Información del kernel"),
        ("cat /etc/os-release",                   "02_02_os_release.txt",          "Distribución Linux"),
        ("lsb_release -a 2>/dev/null",            "02_03_lsb_release.txt",         "LSB release"),
        ("cat /proc/version",                     "02_04_proc_version.txt",        "/proc/version"),
        ("cat /proc/cpuinfo",                     "02_05_cpuinfo.txt",             "Información de CPU"),
        ("lscpu",                                 "02_06_lscpu.txt",               "Resumen CPU"),
        ("dmidecode 2>/dev/null",                 "02_07_dmidecode.txt",           "BIOS/UEFI/hardware"),
        ("lshw -short 2>/dev/null",               "02_08_lshw.txt",                "Hardware (lshw)"),
        ("lspci -vv 2>/dev/null",                 "02_09_lspci.txt",               "Dispositivos PCI"),
        ("lsusb -v 2>/dev/null",                  "02_10_lsusb.txt",               "Dispositivos USB"),
        ("lsblk -a -f",                           "02_11_lsblk.txt",               "Dispositivos de bloque"),
        ("fdisk -l 2>/dev/null",                  "02_12_fdisk.txt",               "Tabla de particiones"),
        ("blkid 2>/dev/null",                     "02_13_blkid.txt",               "IDs de dispositivos"),
        ("df -h",                                 "02_14_espacio_disco.txt",       "Espacio en disco"),
        ("df -ih",                                "02_15_inodos.txt",              "Uso de inodos"),
        ("mount",                                 "02_16_puntos_montaje.txt",      "Puntos de montaje"),
        ("cat /proc/mounts",                      "02_17_proc_mounts.txt",         "/proc/mounts"),
        ("sysctl -a 2>/dev/null",                 "02_18_sysctl.txt",              "Parámetros del kernel"),
        (f"dmesg --time-format iso 2>/dev/null | tail -{LINES_DMESG}",
                                                  "02_19_dmesg_reciente.txt",      f"dmesg ({LINES_DMESG} líneas)"),
        ("timedatectl",                           "02_20_zona_horaria.txt",        "Zona horaria y NTP"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 3 — Persistencia y mecanismos de arranque
# ---------------------------------------------------------------------------


def modulo_persistencia(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Recolecta todos los mecanismos de persistencia del sistema.

    Cubre: systemd, cron (todos los usuarios), /etc/init.d, rc.local,
    módulos del kernel, perfiles shell y at jobs.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 3: Persistencia y mecanismos de arranque ===")

    comandos = [
        # systemd
        ("systemctl list-units --all --no-pager",           "03_01_systemd_units.txt",     "Unidades systemd"),
        ("systemctl list-unit-files --no-pager",            "03_02_systemd_unit_files.txt","Ficheros de unidad"),
        ("systemctl list-timers --no-pager",                "03_03_systemd_timers.txt",    "Timers systemd"),
        ("systemctl list-sockets --no-pager",               "03_04_systemd_sockets.txt",   "Sockets systemd"),
        # Cron
        ("crontab -l 2>/dev/null",                          "03_05_cron_root.txt",         "Cron usuario actual"),
        ("cat /etc/crontab 2>/dev/null",                    "03_06_etc_crontab.txt",       "/etc/crontab"),
        ("ls -la /etc/cron.d/ && cat /etc/cron.d/* 2>/dev/null",
                                                            "03_07_cron_d.txt",            "/etc/cron.d/"),
        ("ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null",
                                                            "03_08_cron_periodico.txt",    "Scripts cron periódicos"),
        ("for u in $(cut -f1 -d: /etc/passwd); do echo \"=== $u ===\"; crontab -u $u -l 2>/dev/null; done",
                                                            "03_09_cron_usuarios.txt",     "Cron de todos los usuarios"),
        # Init
        ("ls -la /etc/init.d/ 2>/dev/null",                 "03_10_init_d.txt",            "/etc/init.d/"),
        ("cat /etc/rc.local 2>/dev/null",                   "03_11_rc_local.txt",          "/etc/rc.local"),
        # Módulos del kernel
        ("lsmod",                                           "03_12_modulos_kernel.txt",    "Módulos del kernel"),
        ("cat /proc/modules",                               "03_13_proc_modules.txt",      "/proc/modules"),
        (f"find /lib/modules -name '*.ko' 2>/dev/null | head -{LINES_FIND_MODULES}",
                                                            "03_14_modulos_disponibles.txt","Módulos disponibles"),
        # Perfiles shell
        ("cat /etc/profile 2>/dev/null",                    "03_15_etc_profile.txt",       "/etc/profile"),
        ("ls -la /etc/profile.d/ && cat /etc/profile.d/*.sh 2>/dev/null",
                                                            "03_16_profile_d.txt",         "/etc/profile.d/"),
        ("cat /root/.bashrc 2>/dev/null",                   "03_17_root_bashrc.txt",       "/root/.bashrc"),
        ("find /home -name '.bashrc' -o -name '.profile' 2>/dev/null | xargs cat 2>/dev/null",
                                                            "03_18_user_profiles.txt",     "Perfiles usuarios"),
        # at
        ("atq 2>/dev/null",                                 "03_19_at_jobs.txt",           "Jobs programados (at)"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 4 — Usuarios, grupos y seguridad
# ---------------------------------------------------------------------------


def modulo_usuarios(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Recopila información de cuentas, grupos, sudo, SSH, capabilities,
    SUID/SGID y estado de AppArmor / SELinux / UFW.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 4: Usuarios, grupos y seguridad ===")

    comandos = [
        ("cat /etc/passwd",                                 "04_01_passwd.txt",            "/etc/passwd"),
        ("cat /etc/group",                                  "04_02_group.txt",             "/etc/group"),
        ("cat /etc/shadow 2>/dev/null",                     "04_03_shadow.txt",            "/etc/shadow (root)"),
        ("cat /etc/sudoers 2>/dev/null",                    "04_04_sudoers.txt",           "/etc/sudoers"),
        ("cat /etc/sudoers.d/* 2>/dev/null",                "04_05_sudoers_d.txt",         "/etc/sudoers.d/"),
        ("id",                                              "04_06_id_actual.txt",         "Identidad actual"),
        ("whoami",                                          "04_07_whoami.txt",            "Usuario actual"),
        ("passwd -S -a 2>/dev/null",                        "04_08_estado_cuentas.txt",    "Estado de cuentas"),
        ("cat /etc/login.defs 2>/dev/null",                 "04_09_login_defs.txt",        "Política contraseñas"),
        # SSH
        ("cat /etc/ssh/sshd_config 2>/dev/null",            "04_10_sshd_config.txt",       "Config SSH servidor"),
        ("find /root /home -name 'authorized_keys' 2>/dev/null | xargs cat 2>/dev/null",
                                                            "04_11_authorized_keys.txt",   "Claves SSH autorizadas"),
        ("find /root /home -name 'known_hosts' 2>/dev/null | xargs cat 2>/dev/null",
                                                            "04_12_known_hosts.txt",       "Hosts SSH conocidos"),
        # Capabilities / SUID / SGID
        ("getcap -r / 2>/dev/null",                         "04_13_capabilities.txt",      "Linux capabilities"),
        ("find / -perm /4000 -type f 2>/dev/null",          "04_14_suid_files.txt",        "Ficheros SUID"),
        ("find / -perm /2000 -type f 2>/dev/null",          "04_15_sgid_files.txt",        "Ficheros SGID"),
        # Seguridad del SO
        ("aa-status 2>/dev/null || apparmor_status 2>/dev/null",
                                                            "04_16_apparmor.txt",          "Estado AppArmor"),
        ("sestatus 2>/dev/null",                            "04_17_selinux.txt",           "Estado SELinux"),
        ("ufw status verbose 2>/dev/null",                  "04_18_ufw_status.txt",        "Estado UFW"),
        ("nft list ruleset 2>/dev/null",                    "04_19_nftables.txt",          "Reglas nftables"),
        ("iptables -L -v -n 2>/dev/null",                   "04_20_iptables_reglas.txt",   "Reglas iptables"),
        ("auditpol 2>/dev/null || auditctl -l 2>/dev/null", "04_21_audit_policy.txt",      "Política de auditoría"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 5 — Logs y registros
# ---------------------------------------------------------------------------


def modulo_logs(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Extrae logs del sistema: journald, auth.log, syslog, kern.log,
    audit, bash_history y copia binaria de wtmp/btmp/utmp.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando o copia ejecutada.
    """
    ctx.logger.info("=== MÓDULO 5: Logs y registros ===")

    comandos = [
        (f"journalctl -n {LINES_JOURNAL} --no-pager 2>/dev/null",
         "logs/05_01_journal_reciente.txt",    f"Journal ({LINES_JOURNAL} líneas)"),
        ("journalctl -p err -n 200 --no-pager 2>/dev/null",
         "logs/05_02_journal_errores.txt",      "Errores en journal"),
        ("journalctl _COMM=sudo --no-pager -n 200 2>/dev/null",
         "logs/05_03_journal_sudo.txt",         "Eventos sudo"),
        ("journalctl _COMM=sshd --no-pager -n 200 2>/dev/null",
         "logs/05_04_journal_ssh.txt",          "Eventos SSH"),
        (f"tail -{LINES_LOG_TAIL} /var/log/auth.log 2>/dev/null",
         "logs/05_05_auth_log.txt",             f"auth.log ({LINES_LOG_TAIL} líneas)"),
        (f"tail -{LINES_LOG_TAIL} /var/log/syslog 2>/dev/null",
         "logs/05_06_syslog.txt",               f"syslog ({LINES_LOG_TAIL} líneas)"),
        (f"tail -{LINES_DMESG} /var/log/kern.log 2>/dev/null",
         "logs/05_07_kern_log.txt",             "kern.log"),
        (f"tail -{LINES_LOG_TAIL} /var/log/dpkg.log 2>/dev/null",
         "logs/05_08_dpkg_log.txt",             "dpkg.log"),
        ("tail -100 /var/log/apt/history.log 2>/dev/null",
         "logs/05_09_apt_history.txt",          "APT history"),
        ("ausearch -i 2>/dev/null | tail -300",
         "logs/05_10_audit_log.txt",            "Audit log"),
        ("aureport --summary 2>/dev/null",
         "logs/05_11_audit_summary.txt",        "Resumen audit"),
        ("find /root /home -name '.bash_history' 2>/dev/null | while read f; do echo \"\\n=== $f ===\"; cat \"$f\"; done",
         "logs/05_12_bash_history.txt",         "Bash history (todos los usuarios)"),
        (f"last -F 2>/dev/null",
         "logs/05_13_wtmp_last.txt",            "wtmp (last -F)"),
        ("lastb -F 2>/dev/null",
         "logs/05_14_btmp_lastb.txt",           "btmp — logins fallidos"),
        ("who /var/run/utmp 2>/dev/null",
         "logs/05_15_utmp_actual.txt",          "utmp — sesiones actuales"),
        ("tail -100 /var/log/apache2/access.log 2>/dev/null",
         "logs/05_16_apache_access.txt",        "Apache access log"),
        ("tail -100 /var/log/nginx/access.log 2>/dev/null",
         "logs/05_17_nginx_access.txt",         "Nginx access log"),
        ("tail -100 /var/log/mysql/error.log 2>/dev/null",
         "logs/05_18_mysql_error.txt",          "MySQL error log"),
    ]

    resultados = ejecutar_lista(ctx, comandos)

    # Copias binarias para análisis off-line con herramientas forenses
    for origen, destino in [
        ("/var/log/wtmp",  "logs/binarios/wtmp"),
        ("/var/log/btmp",  "logs/binarios/btmp"),
        ("/var/run/utmp",  "logs/binarios/utmp"),
    ]:
        resultados.append(copiar_fichero(ctx, origen, destino, f"Copia binaria: {origen}"))

    return resultados


# ---------------------------------------------------------------------------
# Módulo 6 — Artefactos forenses Linux
# ---------------------------------------------------------------------------


def modulo_artefactos(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Recolecta artefactos forenses específicos de Linux: ficheros eliminados
    con handles abiertos, /dev/shm, ficheros ocultos, world-writable,
    modificados recientemente, inmutables y verificación de rootkits.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 6: Artefactos forenses Linux ===")

    comandos = [
        # Ficheros eliminados pero aún abiertos (crítico en malware fileless)
        ("lsof 2>/dev/null | grep '(deleted)'",
         "artefactos/06_01_ficheros_eliminados_abiertos.txt",
         "Ficheros eliminados con handles abiertos"),

        # /tmp, /dev/shm, /run (zonas de ejecución en memoria)
        ("find /tmp /dev/shm /run /var/tmp -type f -ls 2>/dev/null",
         "artefactos/06_02_tmp_shm_files.txt",
         "Ficheros en /tmp, /dev/shm, /run"),
        ("ls -laR /dev/shm 2>/dev/null",
         "artefactos/06_03_dev_shm.txt",
         "/dev/shm (memoria compartida)"),

        # Permisos peligrosos
        (f"find / -perm -o+w -type f ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -{LINES_WORLD_WRITABLE}",
         "artefactos/06_04_world_writable.txt",
         f"Ficheros world-writable (máx. {LINES_WORLD_WRITABLE})"),

        # Ficheros modificados recientemente
        (f"find / -mtime -1 -type f ! -path '/proc/*' ! -path '/sys/*' ! -path '/run/*' 2>/dev/null | sort | head -{LINES_MODIFIED_FILES}",
         "artefactos/06_05_modificados_24h.txt",
         "Ficheros modificados últimas 24h"),
        ("find /etc /bin /sbin /usr/bin /usr/sbin -mtime -7 -type f -ls 2>/dev/null",
         "artefactos/06_06_binarios_modificados_7d.txt",
         "Binarios sistema modificados últimos 7 días"),

        # Ficheros ocultos
        ("find /tmp /home /root -name '.*' -type f -ls 2>/dev/null",
         "artefactos/06_07_ficheros_ocultos.txt",
         "Ficheros ocultos en home y /tmp"),

        # Ficheros inmutables (técnica de rootkits: chattr +i)
        ("lsattr -Ra /etc /bin /sbin /usr/bin 2>/dev/null | grep -- '-i-'",
         "artefactos/06_08_ficheros_inmutables.txt",
         "Ficheros con atributo inmutable (chattr +i)"),

        # Mapas de memoria de procesos
        (f"for pid in $(ls /proc | grep -E '^[0-9]+$'); do echo \"\\n=== PID $pid ===\"; cat /proc/$pid/maps 2>/dev/null | head -{LINES_PROC_MAPS}; done",
         "artefactos/06_09_proc_maps.txt",
         f"Mapas de memoria /proc/PID/maps ({LINES_PROC_MAPS} líneas/PID)"),

        # Variables de entorno de procesos
        (f"for pid in $(ls /proc | grep -E '^[0-9]+$'); do echo \"\\n=== PID $pid ===\"; cat /proc/$pid/environ 2>/dev/null | tr '\\0' '\\n'; done | head -{LINES_PROC_ENVIRON}",
         "artefactos/06_10_proc_environ.txt",
         "Variables de entorno de procesos"),

        # Sockets y pipes
        ("ss -xlp 2>/dev/null",
         "artefactos/06_11_unix_sockets.txt",
         "Unix domain sockets"),
        ("find / -type p ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null",
         "artefactos/06_12_named_pipes.txt",
         "Named pipes (FIFOs)"),

        # Detección de rootkits (si las herramientas están disponibles)
        ("chkrootkit 2>/dev/null || echo 'chkrootkit no instalado'",
         "artefactos/06_13_chkrootkit.txt",
         "Detección rootkits (chkrootkit)"),
        ("rkhunter --check --skip-keypress --rwo 2>/dev/null || echo 'rkhunter no instalado'",
         "artefactos/06_14_rkhunter.txt",
         "Detección rootkits (rkhunter)"),

        # Verificación de integridad de paquetes instalados
        ("dpkg --verify 2>/dev/null || rpm -Va 2>/dev/null",
         "artefactos/06_15_paquetes_verificacion.txt",
         "Verificación integridad paquetes"),

        # Ficheros de configuración críticos
        ("cat /etc/hosts",           "artefactos/06_16_hosts.txt",       "/etc/hosts"),
        ("cat /etc/resolv.conf",     "artefactos/06_17_resolv_conf.txt", "/etc/resolv.conf"),
        ("cat /etc/fstab",           "artefactos/06_18_fstab.txt",       "/etc/fstab"),
        ("cat /etc/nsswitch.conf",   "artefactos/06_19_nsswitch.txt",    "/etc/nsswitch.conf"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 7 — Software y red
# ---------------------------------------------------------------------------


def modulo_software_red(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Inventario de software instalado y configuración avanzada de red.

    Cubre: dpkg, apt, snap, flatpak, netplan, NetworkManager y DNS.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada comando ejecutado.
    """
    ctx.logger.info("=== MÓDULO 7: Software y red ===")

    comandos = [
        ("dpkg -l 2>/dev/null",                             "07_01_paquetes_dpkg.txt",     "Paquetes instalados (dpkg)"),
        ("apt list --installed 2>/dev/null",                "07_02_apt_installed.txt",     "Paquetes (apt)"),
        ("snap list 2>/dev/null",                           "07_03_snap.txt",              "Paquetes Snap"),
        ("flatpak list 2>/dev/null",                        "07_04_flatpak.txt",           "Paquetes Flatpak"),
        ("ip -s link",                                      "07_05_ip_stats.txt",          "Estadísticas interfaces"),
        ("cat /etc/network/interfaces 2>/dev/null",         "07_06_interfaces_config.txt", "/etc/network/interfaces"),
        ("ls /etc/netplan/ 2>/dev/null && cat /etc/netplan/*.yaml 2>/dev/null",
                                                            "07_07_netplan.txt",           "Netplan"),
        ("nmcli connection show 2>/dev/null",               "07_08_nmcli_connections.txt", "NetworkManager connections"),
        ("nmcli device show 2>/dev/null",                   "07_09_nmcli_devices.txt",     "NetworkManager devices"),
        ("cat /etc/systemd/resolved.conf 2>/dev/null",      "07_10_resolved_conf.txt",     "systemd-resolved"),
        ("resolvectl status 2>/dev/null",                   "07_11_resolvectl.txt",        "Estado DNS"),
        ("ss -tlnp",                                        "07_12_servicios_tcp.txt",     "Servicios TCP escuchando"),
        ("ss -ulnp",                                        "07_13_servicios_udp.txt",     "Servicios UDP escuchando"),
    ]

    return ejecutar_lista(ctx, comandos)


# ---------------------------------------------------------------------------
# Módulo 8 — Copias de ficheros críticos
# ---------------------------------------------------------------------------


def modulo_copias_criticas(ctx: TriageContext) -> list[dict[str, Any]]:
    """
    Copia los ficheros críticos del sistema para análisis off-line.

    Preserva ficheros en su estado original sin modificarlos.

    Args:
        ctx: Contexto del triage.

    Returns:
        Lista de resultados de cada copia.
    """
    ctx.logger.info("=== MÓDULO 8: Copias de ficheros críticos ===")

    ficheros = [
        ("/etc/passwd",          "ficheros_criticos/passwd"),
        ("/etc/group",           "ficheros_criticos/group"),
        ("/etc/shadow",          "ficheros_criticos/shadow"),
        ("/etc/gshadow",         "ficheros_criticos/gshadow"),
        ("/etc/sudoers",         "ficheros_criticos/sudoers"),
        ("/etc/hosts",           "ficheros_criticos/hosts"),
        ("/etc/resolv.conf",     "ficheros_criticos/resolv.conf"),
        ("/etc/hostname",        "ficheros_criticos/hostname"),
        ("/etc/fstab",           "ficheros_criticos/fstab"),
        ("/etc/crontab",         "ficheros_criticos/crontab"),
        ("/etc/os-release",      "ficheros_criticos/os-release"),
        ("/etc/ssh/sshd_config", "ficheros_criticos/sshd_config"),
        ("/var/log/wtmp",        "ficheros_criticos/wtmp"),
        ("/var/log/btmp",        "ficheros_criticos/btmp"),
    ]

    return [copiar_fichero(ctx, origen, destino, f"Copia: {origen}")
            for origen, destino in ficheros]


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Orquesta la ejecución completa del triage forense Linux.

    Orden de módulos según RFC 3227 (mayor volatilidad primero).
    Captura Ctrl+C para generar un cierre limpio con los datos parciales.
    """
    verificar_entorno()

    ctx = TriageContext()
    registrar_manejador_interrupcion(ctx)

    ctx.logger.info("=" * 65)
    ctx.logger.info(f"TRIAGE FORENSE LINUX v{__import__('triage.config', fromlist=['TRIAGE_VERSION']).TRIAGE_VERSION}")
    ctx.logger.info(f"Host: {ctx.hostname}  |  Timestamp: {ctx.timestamp}")
    ctx.logger.info(f"Usuario: {os.getenv('USER', str(os.getuid()))}  |  UID: {os.getuid()}")
    ctx.logger.info("=" * 65)

    info_general = modulo_info_general(ctx)

    ctx.resultados += modulo_volatil(ctx)        # M1 — máxima volatilidad
    ctx.resultados += modulo_sistema(ctx)        # M2 — hardware y SO
    ctx.resultados += modulo_persistencia(ctx)   # M3 — persistencia
    ctx.resultados += modulo_usuarios(ctx)       # M4 — usuarios y seguridad
    ctx.resultados += modulo_logs(ctx)           # M5 — logs
    ctx.resultados += modulo_artefactos(ctx)     # M6 — artefactos forenses
    ctx.resultados += modulo_software_red(ctx)   # M7 — software y red
    ctx.resultados += modulo_copias_criticas(ctx)# M8 — copias de ficheros

    hashes = calcular_hashes(ctx)               # M9 — integridad SHA-256
    zip_path = empaquetar(ctx, hashes)           # M10 — empaquetado
    generar_cadena_custodia(ctx, zip_path, hashes)
    generar_reporte(ctx, info_general, hashes, zip_path)

    from triage.reporter import generar_informe_html  # M11 — informe HTML
    generar_informe_html(ctx, info_general, hashes, zip_path)

    ctx.logger.info("TRIAGE LINUX FINALIZADO")


if __name__ == "__main__":
    main()
