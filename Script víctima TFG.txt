#!/usr/bin/env python3
"""
detector.py - Detector de patrones de acceso no autorizado en logs SSH

Lee los logs de SSH desde journalctl y detecta tres patrones tipicos:
1. Fuerza bruta: multiples fallos contra mismo usuario desde misma IP
2. Password spraying: una IP intenta acceder a multiples usuarios
3. Compromiso: fallos seguidos de un acceso exitoso (mismo usuario+IP)

Genera un informe en consola y un fichero JSON con los IoCs extraidos.
"""

import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime

# === CONFIGURACION ===
HOURS_BACK = 1               # Cuanto tiempo hacia atras analizar
BRUTE_FORCE_THRESHOLD = 5    # Fallos mismo usuario/IP para considerar fuerza bruta
SPRAY_USER_THRESHOLD = 5     # Usuarios distintos desde misma IP para spraying
COMPROMISE_PRIOR_FAILS = 3   # Fallos previos antes de un exito para compromiso

# === PATRONES DE EXTRACCION ===
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\S+)"
)
ACCEPTED_PATTERN = re.compile(
    r"Accepted password for (\S+) from (\S+)"
)


def obtener_logs_ssh():
    """Obtiene los logs del sistema desde journalctl en formato JSON."""
    try:
        resultado = subprocess.run(
            ["journalctl",
             "--since", f"{HOURS_BACK} hour ago",
             "--output=json", "--no-pager"],
            capture_output=True, text=True, check=True
        )
        return resultado.stdout.strip().split("\n")
    except subprocess.CalledProcessError as e:
        print(f"Error obteniendo logs: {e}", file=sys.stderr)
        sys.exit(1)


def parsear_eventos(lineas_log):
    """Parsea los eventos relevantes de SSH (login fallido / exitoso)."""
    eventos = []
    for linea in lineas_log:
        if not linea.strip():
            continue
        try:
            entrada = json.loads(linea)
        except json.JSONDecodeError:
            continue

        mensaje = entrada.get("MESSAGE", "")
        ts_us = int(entrada.get("__REALTIME_TIMESTAMP", 0))
        timestamp = datetime.fromtimestamp(ts_us / 1_000_000)

        m = FAILED_PATTERN.search(mensaje)
        if m:
            eventos.append({
                "timestamp": timestamp,
                "tipo": "fallido",
                "usuario": m.group(1),
                "ip_origen": m.group(2),
            })
            continue

        m = ACCEPTED_PATTERN.search(mensaje)
        if m:
            eventos.append({
                "timestamp": timestamp,
                "tipo": "exitoso",
                "usuario": m.group(1),
                "ip_origen": m.group(2),
            })
    return eventos


def detectar_fuerza_bruta(eventos):
    """Detecta patrones de fuerza bruta: muchos fallos mismo (IP, usuario)."""
    detecciones = []
    grupos = defaultdict(list)
    for e in eventos:
        if e["tipo"] == "fallido":
            grupos[(e["ip_origen"], e["usuario"])].append(e["timestamp"])

    for (ip, usuario), tiempos in grupos.items():
        if len(tiempos) >= BRUTE_FORCE_THRESHOLD:
            tiempos.sort()
            ventana_min = (tiempos[-1] - tiempos[0]).total_seconds() / 60
            detecciones.append({
                "patron": "fuerza_bruta",
                "severidad": "alta",
                "ip_origen": ip,
                "usuario_objetivo": usuario,
                "intentos": len(tiempos),
                "primer_intento": tiempos[0].isoformat(),
                "ultimo_intento": tiempos[-1].isoformat(),
                "duracion_minutos": round(ventana_min, 2),
            })
    return detecciones


def detectar_password_spraying(eventos):
    """Detecta password spraying: misma IP contra muchos usuarios."""
    detecciones = []
    usuarios_por_ip = defaultdict(set)
    tiempos_por_ip = defaultdict(list)

    for e in eventos:
        if e["tipo"] == "fallido":
            usuarios_por_ip[e["ip_origen"]].add(e["usuario"])
            tiempos_por_ip[e["ip_origen"]].append(e["timestamp"])

    for ip, usuarios in usuarios_por_ip.items():
        if len(usuarios) >= SPRAY_USER_THRESHOLD:
            tiempos = sorted(tiempos_por_ip[ip])
            ventana_min = (tiempos[-1] - tiempos[0]).total_seconds() / 60
            detecciones.append({
                "patron": "password_spraying",
                "severidad": "alta",
                "ip_origen": ip,
                "usuarios_objetivo": sorted(list(usuarios)),
                "numero_usuarios": len(usuarios),
                "primer_intento": tiempos[0].isoformat(),
                "ultimo_intento": tiempos[-1].isoformat(),
                "duracion_minutos": round(ventana_min, 2),
            })
    return detecciones


def detectar_compromiso(eventos):
    """Detecta compromisos: fallos previos seguidos de exito mismo (IP+usuario)."""
    detecciones = []
    eventos_ordenados = sorted(eventos, key=lambda x: x["timestamp"])

    for i, e in enumerate(eventos_ordenados):
        if e["tipo"] != "exitoso":
            continue
        fallos_previos = [
            ev for ev in eventos_ordenados[:i]
            if ev["tipo"] == "fallido"
            and ev["ip_origen"] == e["ip_origen"]
            and ev["usuario"] == e["usuario"]
        ]
        if len(fallos_previos) >= COMPROMISE_PRIOR_FAILS:
            detecciones.append({
                "patron": "compromiso_exitoso",
                "severidad": "critica",
                "ip_origen": e["ip_origen"],
                "usuario_comprometido": e["usuario"],
                "fallos_previos": len(fallos_previos),
                "primer_fallo": fallos_previos[0]["timestamp"].isoformat(),
                "hora_compromiso": e["timestamp"].isoformat(),
            })
    return detecciones


def imprimir_informe(detecciones):
    """Imprime el informe en consola."""
    print()
    print("=" * 70)
    print("  INFORME DE DETECCION: PATRONES DE ACCESO NO AUTORIZADO")
    print("=" * 70)
    print(f"  Generado: {datetime.now().isoformat()}")
    print(f"  Total de detecciones: {len(detecciones)}")
    print("=" * 70)
    print()

    if not detecciones:
        print("  No se han detectado patrones sospechosos.")
        return

    for i, d in enumerate(detecciones, 1):
        nombre = d["patron"].upper().replace("_", " ")
        print(f"[{i}] {nombre}")
        print(f"    Severidad:       {d['severidad']}")
        print(f"    IP origen:       {d['ip_origen']}")
        if "usuario_objetivo" in d:
            print(f"    Usuario:         {d['usuario_objetivo']}")
            print(f"    Intentos:        {d['intentos']}")
            print(f"    Duracion:        {d['duracion_minutos']} minutos")
        elif "usuarios_objetivo" in d:
            print(f"    Numero usuarios: {d['numero_usuarios']}")
            print(f"    Usuarios:        {', '.join(d['usuarios_objetivo'])}")
            print(f"    Duracion:        {d['duracion_minutos']} minutos")
        elif "usuario_comprometido" in d:
            print(f"    Usuario:         {d['usuario_comprometido']}")
            print(f"    Fallos previos:  {d['fallos_previos']}")
            print(f"    Compromiso:      {d['hora_compromiso']}")
        print()


def main():
    print("[*] Recogiendo logs de SSH desde journalctl...")
    lineas_log = obtener_logs_ssh()
    print(f"[*] Lineas de log recuperadas: {len(lineas_log)}")

    print("[*] Parseando eventos de autenticacion...")
    eventos = parsear_eventos(lineas_log)
    print(f"[*] Eventos relevantes detectados: {len(eventos)}")

    print("[*] Analizando patrones...")
    detecciones = []
    detecciones.extend(detectar_fuerza_bruta(eventos))
    detecciones.extend(detectar_password_spraying(eventos))
    detecciones.extend(detectar_compromiso(eventos))

    imprimir_informe(detecciones)

    fichero_salida = f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fichero_salida, "w") as f:
        json.dump({
            "generado": datetime.now().isoformat(),
            "total_detecciones": len(detecciones),
            "detecciones": detecciones,
        }, f, indent=2, ensure_ascii=False)
    print(f"[*] IoCs guardados en: {fichero_salida}")


if __name__ == "__main__":
    main()