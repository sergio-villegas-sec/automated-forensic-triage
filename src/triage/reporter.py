"""
reporter.py — Generador del informe HTML del triage forense.

Genera un fichero ``informe_triage.html`` autocontenido (sin dependencias
externas) dentro del directorio de triage. El analista puede abrirlo
directamente en cualquier navegador sin instalar nada.

Integración (no modifica common.py ni linux.py ni windows.py):
    from triage.reporter import generar_informe_html
    generar_informe_html(ctx, info_general, hashes, zip_path)
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from triage.common import TriageContext


# ---------------------------------------------------------------------------
# Helpers de lectura
# ---------------------------------------------------------------------------

def _leer(ctx: TriageContext, ruta: str, max_lineas: int = 50) -> str:
    p = ctx.output_dir / ruta
    if not p.exists():
        return "(fichero no disponible)"
    try:
        lineas = p.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lineas) > max_lineas:
            lineas = lineas[:max_lineas] + [f"... ({len(lineas)-max_lineas} líneas más)"]
        return "\n".join(lineas)
    except Exception:
        return "(error de lectura)"

def _existe(ctx: TriageContext, ruta: str) -> bool:
    return (ctx.output_dir / ruta).exists()

def _esc(t: str) -> str:
    return str(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")


# ---------------------------------------------------------------------------
# Extracción de datos clave
# ---------------------------------------------------------------------------

def _conexiones(ctx: TriageContext) -> list[str]:
    for c in ["01_07_sockets_abiertos.txt","01_08_conexiones_todas.txt","01_04_conexiones_red.txt"]:
        p = ctx.output_dir / c
        if p.exists():
            return [l.strip() for l in p.read_text(encoding="utf-8",errors="replace").splitlines()
                    if any(k in l.upper() for k in ["ESTABLISHED","LISTEN","TIME_WAIT"])][:30]
    return []

def _proc_sospechosos(ctx: TriageContext) -> list[str]:
    NAMES = ["nc","ncat","netcat","nmap","python","perl","ruby","bash","sh","cmd",
             "powershell","mshta","wscript","cscript","regsvr32","rundll32","certutil",
             "bitsadmin","wget","curl","socat","msfconsole","mimikatz","empire","cobalt",
             "beacon","reverse","shell","exploit","metasploit"]
    for c in ["01_14_procesos_arbol.txt","01_16_procesos_arbol.txt","01_07_procesos_activos.csv"]:
        p = ctx.output_dir / c
        if p.exists():
            t = p.read_text(encoding="utf-8",errors="replace").lower()
            found = [l.strip() for l in t.splitlines() if any(n in l for n in NAMES)]
            if found:
                return found[:20]
    return []

def _primero(ctx: TriageContext, rutas: list[str], max_l: int = 40) -> str:
    for r in rutas:
        if _existe(ctx, r):
            return _leer(ctx, r, max_l)
    return "(no disponible)"

def _stats(ctx: TriageContext) -> tuple[int,int]:
    p = ctx.output_dir / "resumen_triage.json"
    if p.exists():
        try:
            d = json.loads(p.read_text(encoding="utf-8",errors="replace"))
            s = d.get("estadisticas", {})
            return s.get("total_comandos",0), s.get("con_errores",0)
        except Exception:
            pass
    return 0, 0


# ---------------------------------------------------------------------------
# Componentes HTML
# ---------------------------------------------------------------------------

def _card(titulo: str, contenido: str, icono: str = "📄", alerta: bool = False) -> str:
    cls = "card" + (" alerta" if alerta else "")
    return f"""<div class="{cls}">
  <div class="ch"><span>{icono}</span><span class="ct">{_esc(titulo)}</span></div>
  <pre class="cc">{_esc(contenido)}</pre>
</div>"""

def _card_list(titulo: str, items: list[str], icono: str = "🔍", alerta: bool = False) -> str:
    if not items:
        return _card(titulo, "(sin resultados)", icono)
    cls = "card" + (" alerta" if alerta else "")
    filas = "".join(f'<div class="li">{_esc(i)}</div>' for i in items)
    return f"""<div class="{cls}">
  <div class="ch"><span>{icono}</span><span class="ct">{_esc(titulo)}</span>
  <span class="badge">{len(items)}</span></div>
  <div class="lc">{filas}</div>
</div>"""

def _seccion(id_: str, titulo: str, icono: str, *cards: str) -> str:
    return f"""<section id="{id_}" class="sec">
  <h2 class="st"><span>{icono}</span>{_esc(titulo)}</h2>
  <div class="grid">{"".join(cards)}</div>
</section>"""


# ---------------------------------------------------------------------------
# Generador principal
# ---------------------------------------------------------------------------

def generar_informe_html(
    ctx: TriageContext,
    info_general: dict[str, Any],
    hashes: dict[str, str],
    zip_path: "Path | None",
) -> Path:
    """
    Genera el informe HTML autocontenido del triage.

    Puede abrirse directamente en cualquier navegador sin instalar nada.
    No modifica ningún otro módulo del proyecto.

    Args:
        ctx:          Contexto del triage en curso.
        info_general: Metadatos del sistema (módulo 0).
        hashes:       Diccionario {fichero: hash_sha256}.
        zip_path:     Ruta al ZIP generado (puede ser None).

    Returns:
        Ruta al fichero informe_triage.html generado.
    """
    ctx.logger.info("=== Generando informe HTML ===")

    conx   = _conexiones(ctx)
    procs  = _proc_sospechosos(ctx)
    total, errores = _stats(ctx)
    n_hash = len(hashes)
    plat   = ctx.platform

    hostname = _esc(str(info_general.get("hostname", ctx.hostname)))
    so       = _esc(str(info_general.get("so", info_general.get("version_so","—"))))
    kernel   = _esc(str(info_general.get("kernel", info_general.get("release","—"))))
    arch     = _esc(str(info_general.get("arquitectura","—")))
    analista = _esc(str(info_general.get("usuario_triage","—")))
    es_root  = info_general.get("es_root", None)
    ts       = _esc(ctx.timestamp)
    ts_fin   = _esc(datetime.now().strftime("%Y%m%d_%H%M%S"))
    zip_n    = _esc(zip_path.name if zip_path else "— no generado —")

    root_badge = ""
    if es_root is True:
        root_badge = '<span class="badge ok">root ✓</span>'
    elif es_root is False:
        root_badge = '<span class="badge err">sin root ✗</span>'

    # ── Secciones ──────────────────────────────────────────────────────────
    S = {}

    # Resumen ejecutivo (hero especial)
    stat = lambda n, lbl, warn=False: f"""<div class="card stat {'alerta' if warn else ''}">
  <div class="sn">{n}</div><div class="sl">{lbl}</div></div>"""

    hero = f"""<section id="resumen" class="sec">
  <h2 class="st"><span>🏠</span>Resumen ejecutivo</h2>
  <div class="hero">
    <div class="card meta-card">
      <div class="ch"><span>🖥️</span><span class="ct">Sistema analizado</span></div>
      <div class="meta-body">
        <div class="mr"><span class="mk">Hostname</span><span class="mv">{hostname}</span></div>
        <div class="mr"><span class="mk">Sistema operativo</span><span class="mv">{so}</span></div>
        <div class="mr"><span class="mk">Kernel / Release</span><span class="mv">{kernel}</span></div>
        <div class="mr"><span class="mk">Arquitectura</span><span class="mv">{arch}</span></div>
        <div class="mr"><span class="mk">Analista</span><span class="mv">{analista} {root_badge}</span></div>
        <div class="mr"><span class="mk">Plataforma</span><span class="mv">{_esc(plat)}</span></div>
        <div class="mr"><span class="mk">Inicio triage</span><span class="mv">{ts}</span></div>
        <div class="mr"><span class="mk">Fin triage</span><span class="mv">{ts_fin}</span></div>
        <div class="mr"><span class="mk">Paquete ZIP</span><span class="mv mono">{zip_n}</span></div>
      </div>
    </div>
    <div class="stats-wrap">
      {stat(total,   "Comandos ejecutados")}
      {stat(errores, "Errores / Timeouts",  warn=errores > 5)}
      {stat(n_hash,  "Ficheros hasheados")}
      {stat(len(procs), "Procesos sospechosos", warn=len(procs)>0)}
      {stat(len(conx),  "Conexiones de red",    warn=len(conx)>20)}
    </div>
  </div>
</section>"""

    S["red"] = _seccion("red","Red y conexiones","🌐",
        _card_list("Conexiones activas (ESTABLISHED / LISTEN / TIME_WAIT)",
                   conx, "🔌", alerta=len(conx)>20),
        _card("Tabla ARP — vecinos conocidos en la red",
              _primero(ctx,["01_06_tabla_arp.txt","01_03_tabla_arp.txt"]), "📡"),
        _card("Tabla de enrutamiento",
              _primero(ctx,["01_05_tabla_enrutamiento.txt"]), "🗺️"),
        _card("Fichero /etc/hosts  ⚠️ comprobar redirecciones maliciosas",
              _primero(ctx,["artefactos/06_16_hosts.txt","artefactos/06_10_hosts_file.txt",
                            "ficheros_criticos/hosts"]), "⚠️", alerta=True),
        _card("Reglas de firewall (iptables / UFW / nftables)",
              _primero(ctx,["04_20_iptables_reglas.txt","01_14_iptables.txt",
                            "04_25_ufw_status.txt","04_26_nftables.txt"]), "🧱"),
    )

    S["procesos"] = _seccion("procesos","Procesos en ejecución","⚙️",
        _card_list("⚠️ Procesos con nombres potencialmente sospechosos",
                   procs, "🚨", alerta=len(procs)>0),
        _card("Árbol de procesos completo (ps auxf)",
              _primero(ctx,["01_14_procesos_arbol.txt","01_16_procesos_arbol.txt",
                            "01_07_procesos_activos.csv"]), "🌲"),
        _card("Detalle de procesos (PID, PPID, CMD)",
              _primero(ctx,["01_15_procesos_detalle.txt","01_09_procesos_detalle.csv"]), "🔎"),
        _card("Ficheros eliminados con handles abiertos  (malware fileless)",
              _primero(ctx,["artefactos/06_01_ficheros_eliminados_abiertos.txt"]),
              "💀", alerta=True),
        _card("/dev/shm y /tmp — zonas de ejecución en memoria",
              _primero(ctx,["artefactos/06_02_tmp_shm_files.txt",
                            "artefactos/06_03_dev_shm.txt"]), "🗑️", alerta=True),
    )

    S["persistencia"] = _seccion("persistencia","Persistencia y mecanismos de arranque","🔁",
        _card("Claves Run / RunOnce / Cron  — autoarranque al inicio",
              _primero(ctx,["03_06_run_hklm.txt","03_05_cron_root.txt",
                            "03_06_etc_crontab.txt"]), "🔑", alerta=True),
        _card("Tareas programadas (schtasks / cron todos los usuarios)",
              _primero(ctx,["03_03_tareas_programadas.csv","03_09_cron_usuarios.txt",
                            "03_08_cron_periodico.txt"]), "🕐"),
        _card("Servicios y unidades systemd activos",
              _primero(ctx,["03_01_servicios_todos.txt","03_01_systemd_units.txt"]), "🛠️"),
        _card("Módulos del kernel cargados  (rootkits, drivers maliciosos)",
              _primero(ctx,["03_15_modulos_kernel.txt","03_12_modulos_kernel.txt"]),
              "🧩", alerta=True),
        _card("AppInit DLLs / Winlogon  (inyección en Windows)",
              _primero(ctx,["03_11_appinit_dlls.txt","03_12_winlogon.txt"]), "💉", alerta=True),
        _card("Perfiles shell (.bashrc / .profile) — persistencia de usuario",
              _primero(ctx,["03_21_root_bashrc.txt","03_17_root_bashrc.txt",
                            "03_23_user_profiles.txt"]), "🐚"),
    )

    S["usuarios"] = _seccion("usuarios","Usuarios y control de acceso","👤",
        _card("Sesiones de usuario activas",
              _primero(ctx,["01_22_usuarios_activos.txt","01_25_usuarios_logados.txt",
                            "01_10_usuarios_sesion.txt"]), "🟢"),
        _card("Intentos de login fallidos  ⚠️ posible fuerza bruta",
              _primero(ctx,["01_28_logins_fallidos.txt","logs/05_16_btmp_lastb.txt",
                            "01_25_logins_fallidos.txt"]), "🔴", alerta=True),
        _card("Historial de inicios de sesión (last)",
              _primero(ctx,["01_27_ultimos_logins.txt","01_24_ultimos_logins.txt"]), "📅"),
        _card("Usuarios locales (/etc/passwd o net user)",
              _primero(ctx,["04_01_passwd.txt","04_01_usuarios_locales.txt"]), "📋"),
        _card("Grupo Administradores / sudoers",
              _primero(ctx,["04_04_sudoers.txt","04_05_sudoers_d.txt",
                            "04_04_administradores.txt"]), "🛡️"),
        _card("Ficheros SUID  — vectores de escalada de privilegios",
              _primero(ctx,["04_14_suid_files.txt","04_20_suid_files.txt"]),
              "⬆️", alerta=True),
        _card("Linux capabilities  (getcap)",
              _primero(ctx,["04_13_capabilities.txt","04_19_capabilities.txt"]),
              "🎯", alerta=True),
        _card("Claves SSH autorizadas (authorized_keys)",
              _primero(ctx,["04_11_authorized_keys.txt","04_15_authorized_keys.txt"]),
              "🔐", alerta=True),
        _card("AppArmor / SELinux — estado de seguridad MAC",
              _primero(ctx,["04_16_apparmor.txt","04_22_apparmor.txt",
                            "04_17_selinux.txt"]), "🏰"),
    )

    S["artefactos"] = _seccion("artefactos","Artefactos forenses","🔬",
        _card("Ficheros modificados en las últimas 24 h",
              _primero(ctx,["artefactos/06_05_modificados_24h.txt"]), "📝", alerta=True),
        _card("Binarios del sistema modificados en los últimos 7 días",
              _primero(ctx,["artefactos/06_06_binarios_modificados_7d.txt"]),
              "💾", alerta=True),
        _card("Ficheros ocultos en /home y /tmp",
              _primero(ctx,["artefactos/06_07_ficheros_ocultos.txt"]), "👁️"),
        _card("Ficheros con atributo inmutable  (chattr +i — técnica de rootkits)",
              _primero(ctx,["artefactos/06_08_ficheros_inmutables.txt"]),
              "🔒", alerta=True),
        _card("Historial de comandos bash (todos los usuarios)",
              _primero(ctx,["logs/05_12_bash_history.txt","logs/05_14_bash_history.txt"]), "💻"),
        _card("Prefetch / ficheros recientes / Jump Lists (Windows)",
              _primero(ctx,["artefactos/06_01_prefetch.txt",
                            "artefactos/06_02_ficheros_recientes.txt"]), "📂"),
        _card("Dispositivos USB conectados",
              _primero(ctx,["artefactos/06_07_usb_conectados.txt",
                            "artefactos/06_08_usb_conectados.txt"]), "🔌"),
        _card("Redes Wi-Fi / perfiles de red conocidos",
              _primero(ctx,["artefactos/06_08_redes_conectadas.txt",
                            "artefactos/06_08_redes_conocidas.txt"]), "📶"),
        _card("Verificación integridad de paquetes instalados  (dpkg --verify)",
              _primero(ctx,["artefactos/06_15_paquetes_verificacion.txt"]), "✅"),
        _card("Detección de rootkits (chkrootkit / rkhunter)",
              _primero(ctx,["artefactos/06_13_chkrootkit.txt",
                            "artefactos/06_14_rkhunter.txt"]), "🦠", alerta=True),
    )

    S["logs"] = _seccion("logs","Logs del sistema","📋",
        _card("auth.log / Log Security — autenticaciones y sudo",
              _primero(ctx,["logs/05_05_auth_log.txt",
                            "logs/05_02_log_seguridad.txt"]), "🔐"),
        _card("Journal / Syslog — eventos recientes del sistema",
              _primero(ctx,["logs/05_01_journal_reciente.txt",
                            "logs/05_06_syslog.txt"]), "📰"),
        _card("Errores del journal (prioridad err/crit)",
              _primero(ctx,["logs/05_02_journal_errores.txt"]), "🔴", alerta=True),
        _card("Eventos SSH en el journal",
              _primero(ctx,["logs/05_04_journal_ssh.txt"]), "🔑"),
        _card("Eventos sudo en el journal",
              _primero(ctx,["logs/05_03_journal_sudo.txt"]), "⚡"),
        _card("Historial APT / dpkg — paquetes instalados recientemente",
              _primero(ctx,["logs/05_09_apt_history.txt","logs/05_08_dpkg_log.txt"]), "📦"),
        _card("Log PowerShell / Audit (Windows)",
              _primero(ctx,["logs/05_05_log_powershell.txt",
                            "logs/05_10_audit_log.txt"]), "🖥️"),
        _card("Logs de servidor web (Apache / Nginx)",
              _primero(ctx,["logs/05_18_apache_access.txt",
                            "logs/05_20_nginx_access.txt"]), "🌐"),
    )

    hash_preview = "\n".join(f"{v}  {k}" for k,v in list(hashes.items())[:25])
    if len(hashes) > 25:
        hash_preview += f"\n... ({len(hashes)-25} ficheros más)"

    S["integridad"] = _seccion("integridad","Integridad y cadena de custodia","🔒",
        _card("Hashes SHA-256 de las evidencias recolectadas",
              hash_preview or _leer(ctx,"09_hashes_sha256.txt",30), "🔏"),
        _card("Documento de cadena de custodia",
              _primero(ctx,["cadena_custodia.txt"]), "📜"),
        _card("Reporte JSON del triage (estadísticas)",
              _leer(ctx,"resumen_triage.json",40), "📊"),
    )

    S["software"] = _seccion("software","Software instalado","📦",
        _card("Paquetes instalados (dpkg / apt / wmic)",
              _primero(ctx,["07_01_paquetes_dpkg.txt","07_02_apt_installed.txt",
                            "07_01_software_wmic.csv"]), "📦"),
        _card("Parches y actualizaciones de seguridad",
              _primero(ctx,["07_05_parches_instalados.csv","07_05_parches.csv"]), "🩹"),
        _card("Paquetes Snap / Flatpak",
              _primero(ctx,["07_03_snap.txt","07_03_snap_packages.txt",
                            "07_04_flatpak.txt"]), "📦"),
    )

    # ── Nav ────────────────────────────────────────────────────────────────
    nav_items = [
        ("resumen","Resumen","🏠"),("red","Red","🌐"),
        ("procesos","Procesos","⚙️"),("persistencia","Persistencia","🔁"),
        ("usuarios","Usuarios","👤"),("artefactos","Artefactos","🔬"),
        ("logs","Logs","📋"),("integridad","Integridad","🔒"),
        ("software","Software","📦"),
    ]
    nav = "".join(f'<a href="#{i}" class="nl">{ic} {_esc(t)}</a>' for i,t,ic in nav_items)

    # ── CSS ────────────────────────────────────────────────────────────────
    css = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080d18;--sur:#0f1724;--sur2:#162135;--bor:#1c2b42;
  --acc:#00d4ff;--acc2:#7c3aed;--dan:#ef4444;--ok:#10b981;--warn:#f59e0b;
  --txt:#dde4f0;--mut:#4a5d78;
  --mono:'Courier New',Courier,monospace;
  --head:Georgia,'Times New Roman',serif;
  --r:8px;
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--txt);font-family:var(--mono);font-size:13px;line-height:1.6;min-height:100vh}
body::before{content:'';position:fixed;inset:0;z-index:-1;
  background:
    radial-gradient(ellipse 70% 50% at 5% 15%,rgba(0,212,255,.07) 0%,transparent 55%),
    radial-gradient(ellipse 60% 40% at 95% 85%,rgba(124,58,237,.08) 0%,transparent 55%);
  pointer-events:none}

/* Layout */
.layout{display:flex;min-height:100vh}

/* Sidebar */
.sidebar{width:210px;flex-shrink:0;background:var(--sur);border-right:1px solid var(--bor);
  position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column;
  padding:22px 0;z-index:100}
.logo{font-family:var(--head);font-size:14px;color:var(--acc);padding:0 18px 20px;
  border-bottom:1px solid var(--bor);letter-spacing:.4px}
.logo span{display:block;font-size:10px;color:var(--mut);margin-top:3px}
.nl{display:block;padding:9px 18px;color:var(--mut);text-decoration:none;font-size:11.5px;
  transition:all .15s;border-left:3px solid transparent}
.nl:hover{color:var(--acc);background:rgba(0,212,255,.05);border-left-color:var(--acc)}

/* Main */
.main{flex:1;padding:36px 28px;max-width:1200px;overflow-x:hidden}
.pt{font-family:var(--head);font-size:26px;color:var(--acc);margin-bottom:4px;letter-spacing:-.3px}
.ps{color:var(--mut);font-size:11.5px;margin-bottom:36px}

/* Secciones */
.sec{margin-bottom:52px}
.st{font-family:var(--head);font-size:17px;color:var(--txt);margin-bottom:16px;
  padding-bottom:9px;border-bottom:1px solid var(--bor);display:flex;align-items:center;gap:10px}

/* Hero */
.hero{display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start}
@media(max-width:800px){.hero{grid-template-columns:1fr}}
.meta-card{padding:0!important}
.meta-body{padding:8px 0}
.mr{display:flex;gap:10px;padding:8px 16px;border-bottom:1px solid var(--bor);align-items:baseline}
.mr:last-child{border-bottom:none}
.mk{color:var(--mut);min-width:145px;font-size:10.5px;text-transform:uppercase;letter-spacing:.4px;flex-shrink:0}
.mv{color:var(--txt);font-size:12.5px}
.mono{font-family:var(--mono);font-size:11px}
.stats-wrap{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px}
.stat{text-align:center;padding:18px 10px!important}
.sn{font-family:var(--head);font-size:34px;color:var(--acc);line-height:1;margin-bottom:5px}
.sl{font-size:10.5px;color:var(--mut);text-transform:uppercase;letter-spacing:.4px}

/* Grid de cards */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,500px),1fr));gap:14px}

/* Card */
.card{background:var(--sur);border:1px solid var(--bor);border-radius:var(--r);overflow:hidden;transition:border-color .2s}
.card:hover{border-color:rgba(0,212,255,.28)}
.card.alerta{border-color:rgba(239,68,68,.38)}
.card.alerta .ch{background:rgba(239,68,68,.09)}
.ch{display:flex;align-items:center;gap:8px;padding:11px 15px;background:var(--sur2);
  border-bottom:1px solid var(--bor);font-size:11.5px;font-weight:bold;
  text-transform:uppercase;letter-spacing:.4px}
.ct{flex:1}
.cc{padding:13px 15px;font-size:11px;color:var(--txt);white-space:pre-wrap;
  word-break:break-all;max-height:280px;overflow-y:auto;line-height:1.65}
.cc::-webkit-scrollbar{width:3px}
.cc::-webkit-scrollbar-track{background:var(--sur)}
.cc::-webkit-scrollbar-thumb{background:var(--bor);border-radius:3px}
.lc{max-height:280px;overflow-y:auto}
.li{padding:7px 15px;font-size:11px;border-bottom:1px solid var(--bor);word-break:break-all}
.li:last-child{border-bottom:none}
.li:hover{background:var(--sur2)}

/* Badges */
.badge{display:inline-block;padding:2px 7px;border-radius:99px;font-size:10px;
  background:rgba(0,212,255,.14);color:var(--acc);font-weight:bold}
.badge.ok{background:rgba(16,185,129,.14);color:var(--ok)}
.badge.err{background:rgba(239,68,68,.14);color:var(--dan)}

/* Aviso */
.aviso{margin-top:56px;padding:18px 22px;background:var(--sur);border:1px solid var(--bor);
  border-radius:var(--r);font-size:11px;color:var(--mut);line-height:1.8}
.aviso strong{color:var(--warn)}

/* Footer */
.footer{margin-top:36px;padding:18px 0;border-top:1px solid var(--bor);
  color:var(--mut);font-size:11px;text-align:center}
"""

    # ── Ensamblado ─────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Triage Forense — {hostname}</title>
<style>{css}</style>
</head>
<body>
<div class="layout">
  <nav class="sidebar">
    <div class="logo">🔍 Triage Forense<span>{_esc(plat)} · {hostname}</span></div>
    {nav}
  </nav>
  <main class="main">
    <h1 class="pt">Informe de Triage Forense</h1>
    <p class="ps">Sistema: <strong>{hostname}</strong> &nbsp;·&nbsp;
       Plataforma: <strong>{_esc(plat)}</strong> &nbsp;·&nbsp;
       Generado: <strong>{ts_fin}</strong></p>
    {hero}
    {S["red"]}
    {S["procesos"]}
    {S["persistencia"]}
    {S["usuarios"]}
    {S["artefactos"]}
    {S["logs"]}
    {S["integridad"]}
    {S["software"]}
    <div class="aviso">
      <strong>⚠️ Aviso forense:</strong>
      Este informe ha sido generado de forma automatizada y constituye una primera visión
      de los datos recolectados. Toda conclusión debe verificarse contra los ficheros
      originales del directorio de triage. Los hashes SHA-256 garantizan la integridad
      de las evidencias. Este documento es confidencial y está sujeto a la cadena de
      custodia documentada en <code>cadena_custodia.json</code>.
    </div>
    <div class="footer">
      Triage Forense Digital v2.0.0 &nbsp;·&nbsp; RFC 3227 &nbsp;·&nbsp; NIST SP 800-86
      &nbsp;·&nbsp; {n_hash} ficheros hasheados &nbsp;·&nbsp; {total} comandos ejecutados
    </div>
  </main>
</div>
</body>
</html>"""

    out = ctx.output_dir / "informe_triage.html"
    out.write_text(html, encoding="utf-8")
    ctx.logger.info(f"  Informe HTML: {out}")
    return out
