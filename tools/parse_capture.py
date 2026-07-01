#!/usr/bin/env python3
"""
Парсер живого захвата трафика Android-клиента «Третий мир» (ThirdWorld).

Формат лога (что снял клиент/прокси):
    <O|I> <длина> <hex>
    O = исходящий (клиент -> сервер), I = входящий (сервер -> клиент)

Протокол (восстановлен из захвата, отличается от старого J2ME-FLAP):
  - поток TCP; в начале сессии обмен магией 0x38 0x0f;
  - данные идут ТОКЕНАМИ с маркером 0x66:
        66 39  [0x80|len]  [len*2 байт UTF-16BE]     -> строка
        66 09  [int32 BE]                            -> число (значение)
        66 17  [int32 BE]                            -> число (id/счётчик)
        66 31  [int8]                                -> байт/флаг
        66 0f  [8 байт]                              -> id объекта (long)
        66 3b / 66 29 / 66 93 / 66 cb ...            -> прочие теги (доснять)
  - между группами токенов идут заголовки кадров с сигнатурой 80 80 80
    (маршрутизация/контекст) — здесь печатаем их как HDR.

Запуск:
    python3 tools/parse_capture.py capture.log            # транскрипт
    python3 tools/parse_capture.py capture.log --limit 80
"""
from __future__ import annotations
import argparse
import sys

TAG = 0x66


def load(path: str):
    O = bytearray()
    I = bytearray()
    recs = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        p = ln.split(None, 2)
        if len(p) < 3 or p[0] not in ("O", "I"):
            continue
        try:
            b = bytes.fromhex(p[2].replace(" ", ""))
        except ValueError:
            continue
        recs.append((p[0], b))
        (O if p[0] == "O" else I).extend(b)
    return recs, bytes(O), bytes(I)


def utf16(b: bytes) -> str:
    try:
        return b.decode("utf-16-be")
    except Exception:
        return repr(b)


def tokenize(buf: bytes):
    """Линейно разбирает поток на токены; неизвестное отдаёт как HDR/raw."""
    i, n = 0, len(buf)
    out = []
    while i < n:
        if buf[i] == TAG and i + 1 < n:
            t = buf[i + 1]
            i += 2
            if t == 0x39:  # строка
                ln = buf[i] & 0x7F
                i += 1
                s = utf16(buf[i:i + ln * 2])
                i += ln * 2
                out.append(("STR", s))
            elif t in (0x09, 0x17):  # int32
                v = int.from_bytes(buf[i:i + 4], "big")
                i += 4
                out.append((f"I32.{t:02x}", v))
            elif t == 0x0f:  # id объекта (8 байт)
                v = buf[i:i + 8].hex()
                i += 8
                out.append(("OID", v))
            elif t == 0x31:  # байт/флаг
                v = buf[i]
                i += 1
                out.append(("I8", v))
            else:
                out.append(("TAG?", f"66{t:02x}"))
        else:
            # собираем сырой заголовок до следующего маркера 0x66
            j = i
            while j < n and buf[j] != TAG:
                j += 1
            out.append(("HDR", buf[i:j].hex()))
            i = j
    return out


def transcript(recs, limit: int):
    for k, (d, b) in enumerate(recs):
        if k >= limit:
            print(f"... (ещё {len(recs) - limit} записей)")
            break
        arrow = "C->S" if d == "O" else "S->C"
        toks = tokenize(b)
        # компактно: строки и числа в приоритете
        parts = []
        for kind, val in toks:
            if kind == "STR":
                parts.append(f'"{val}"')
            elif kind.startswith("I32"):
                parts.append(str(val))
            elif kind == "I8":
                parts.append(f"b{val}")
            elif kind == "OID":
                parts.append(f"oid:{val}")
            elif kind == "HDR":
                if val:
                    parts.append(f"[{val}]")
        print(f"#{k:03d} {arrow} {len(b):>5}б  " + "  ".join(parts))


def strings_only(O, I):
    for name, buf in (("C->S", O), ("S->C", I)):
        print(f"\n===== строки {name} =====")
        seen = []
        for kind, val in tokenize(buf):
            if kind == "STR" and val and val not in ("null", "none"):
                seen.append(val)
        for s in seen:
            print("  ", repr(s))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--strings", action="store_true", help="только текстовые поля")
    args = ap.parse_args()
    recs, O, I = load(args.log)
    print(f"записей: {len(recs)};  C->S {len(O)}б,  S->C {len(I)}б\n")
    if args.strings:
        strings_only(O, I)
    else:
        transcript(recs, args.limit)
