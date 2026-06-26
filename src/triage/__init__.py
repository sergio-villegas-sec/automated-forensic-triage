"""
triage — Herramienta de triage forense digital para Linux y Windows.

Módulos:
    config  — Constantes y configuración centralizada.
    common  — Funciones compartidas (ejecutor, hashes, ZIP, reporte).
    linux   — Módulos de recolección para Linux/Ubuntu/Kali.
    windows — Módulos de recolección para Windows.
"""

from triage.config import TRIAGE_VERSION

__version__ = TRIAGE_VERSION
__all__ = ["TRIAGE_VERSION"]
