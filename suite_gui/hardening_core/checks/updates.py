"""Verificacion (solo informativa) de actualizaciones de Windows
pendientes. Instalar actualizaciones automaticamente queda fuera de esta
herramienta porque puede requerir reinicio y tiempo prolongado; se
recomienda hacerlo manualmente."""
from __future__ import annotations

from datetime import datetime, timedelta

from ..models import CheckResult, Severity
from ..ps import run_ps_json

_STALE_DAYS = 60


def check_pending_updates() -> CheckResult:
    data = run_ps_json(
        "Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending "
        "| Select-Object -First 1 InstalledOn"
    )
    if not data or not data.get("InstalledOn"):
        return CheckResult(
            check_id="pending_updates",
            title="Actualizaciones de Windows posiblemente desactualizadas",
            category="Falta de actualizaciones y parches",
            severity=Severity.MEDIUM,
            vulnerable=False,
            determinable=False,
            detail="No se pudo determinar la fecha de la ultima actualizacion instalada.",
            recommendation="Ejecutar Windows Update manualmente y revisar el historial de actualizaciones.",
            fixable=False,
            manual_only=True,
        )

    try:
        # Get-HotFix devuelve /Date(169.....)/ al convertir a JSON; se maneja ambos formatos.
        raw = data["InstalledOn"]
        if isinstance(raw, dict) and "DateTime" in raw:
            installed_on = datetime.fromisoformat(raw["DateTime"])
        else:
            installed_on = datetime.fromisoformat(str(raw).replace("Z", ""))
    except Exception:
        return CheckResult(
            check_id="pending_updates",
            title="Actualizaciones de Windows posiblemente desactualizadas",
            category="Falta de actualizaciones y parches",
            severity=Severity.MEDIUM,
            vulnerable=False,
            determinable=False,
            detail="No se pudo interpretar la fecha de la ultima actualizacion.",
            recommendation="Ejecutar Windows Update manualmente.",
            fixable=False,
            manual_only=True,
        )

    stale = installed_on < datetime.now() - timedelta(days=_STALE_DAYS)
    return CheckResult(
        check_id="pending_updates",
        title="Actualizaciones de Windows posiblemente desactualizadas",
        category="Falta de actualizaciones y parches",
        severity=Severity.MEDIUM,
        vulnerable=stale,
        detail=f"Ultima actualizacion instalada detectada: {installed_on.date()}.",
        recommendation=(
            f"Han pasado mas de {_STALE_DAYS} dias desde la ultima actualizacion detectada. "
            "Ejecutar Windows Update (Configuracion > Windows Update > Buscar actualizaciones) "
            "e instalar las pendientes. Esta herramienta no instala actualizaciones "
            "automaticamente por el tiempo/reinicio que puede requerir."
        ),
        fixable=False,
        manual_only=True,
    )
