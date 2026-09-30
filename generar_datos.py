"""Lee DB.xlsx y las nóminas de RUTS/ y genera datos.json para publicar.

La parte pública solo trae el ramo y las iniciales del estudiante. Las notas y la
asistencia de cada estudiante van cifradas (AES-GCM) con una clave derivada de su
RUT sin puntos ni dígito verificador (PBKDF2-SHA256).
"""
import base64
import glob
import hashlib
import json
import os
from datetime import datetime

import openpyxl
import xlrd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERACIONES = 1_000_000


def iniciales(correo):
    return "".join(p[0].upper() for p in correo.split("@")[0].split(".") if p)


def asignar_ids(correos):
    """Dos iniciales; si dos estudiantes coinciden, se usan todas sus iniciales."""
    cortos = {}
    for c in correos:
        cortos.setdefault(iniciales(c)[:2], set()).add(c)
    ids = {}
    for corto, grupo in cortos.items():
        for c in grupo:
            ids[c] = corto if len(grupo) == 1 else iniciales(c)
    if len(set(ids.values())) != len(ids):
        raise SystemExit("Hay identificadores repetidos incluso con todas las iniciales")
    return ids


def valor(v):
    if isinstance(v, datetime):
        return v.strftime("%d-%m-%Y")
    if isinstance(v, str):
        return v.strip()
    return "" if v is None else v


def leer_ruts():
    """correo -> RUT sin puntos ni dígito verificador, desde las nóminas .xls."""
    ruts = {}
    for archivo in glob.glob("RUTS/*.xls"):
        ws = xlrd.open_workbook(archivo).sheet_by_index(0)
        for i in range(ws.nrows):
            fila = [str(c).strip() for c in ws.row_values(i) if str(c).strip()]
            correos = [c for c in fila if "@" in c]
            runs = [c for c in fila if "-" in c and c.replace(".", "").split("-")[0].isdigit()]
            if correos and runs:
                ruts[correos[0].lower()] = runs[0].replace(".", "").split("-")[0]
    return ruts


def leer_hoja(ws):
    filas = [r for r in ws.iter_rows(values_only=True) if any(c is not None for c in r)]
    inicio = min(next(i for i, c in enumerate(r) if c is not None) for r in filas)
    filas = [[valor(c) for c in r[inicio:]] for r in filas]
    return filas[0], filas[1:]


def b64(b):
    return base64.b64encode(b).decode()


def cifrar(datos, rut):
    sal, iv = os.urandom(16), os.urandom(12)
    clave = hashlib.pbkdf2_hmac("sha256", rut.encode(), sal, ITERACIONES, 32)
    texto = json.dumps(datos, ensure_ascii=False).encode()
    return {"sal": b64(sal), "iv": b64(iv), "datos": b64(AESGCM(clave).encrypt(iv, texto, None))}


ruts = leer_ruts()
wb = openpyxl.load_workbook("DB.xlsx", data_only=True)
hojas = {"notas": leer_hoja(wb["Notas"]), "asistencia": leer_hoja(wb["Asistencia"])}
ids = asignar_ids({f[enc.index("Estudiante")].lower() for enc, filas in hojas.values() for f in filas})
salida = {"iteraciones": ITERACIONES, "estudiantes": {}}
privado = {}  # id -> {"rut": ..., "notas": [...], "asistencia": [...]}

for clave, (encabezado, filas) in hojas.items():
    col = encabezado.index("Estudiante")
    publicas = []
    for f in filas:
        correo = f[col].lower()
        if correo not in ruts:
            raise SystemExit(f"No encontré el RUT de {correo} en RUTS/")
        ident = ids[correo]
        otro = privado.setdefault(ident, {"rut": ruts[correo], "notas": [], "asistencia": []})
        f[col] = ident
        publicas.append([f[0], ident])
        otro[clave].append(f)
    salida[clave] = {"encabezado": encabezado, "filas": publicas}

for ident, p in privado.items():
    salida["estudiantes"][ident] = cifrar({"notas": p["notas"], "asistencia": p["asistencia"]}, p["rut"])

with open("datos.json", "w", encoding="utf-8") as f:
    json.dump(salida, f, ensure_ascii=False, indent=1)
print(f"datos.json generado ({len(privado)} estudiantes)")
