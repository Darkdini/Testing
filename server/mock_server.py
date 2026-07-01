#!/usr/bin/env python3
"""
Учебный мок-сервер для клиента «Третий мир» (ThirdWorld, J2ME).

Реализует протокол, восстановленный из клиентского JAR
(см. docs/02_PROTOCOL.md, docs/03_LOGIN_FLOW.md):

  - кадр FLAP:  [0x2A][channel:1][seq:2][len:2][payload:len]
  - канал 1 — логин (TLV: 1=login, 2=password, 4=str, 8=version)
  - канал 2 — данные: [group:2][subtype:2][data]
  - числа  — big-endian; текст — CP1251

Задача сервера-скелета: принять соединение, провести handshake, пустить
клиента в игру и ПОДРОБНО логировать всё, что он шлёт, — чтобы дальше
доснимать номера игровых команд (group/subtype) вживую.

Запуск:
    python3 server/mock_server.py            # слушает 0.0.0.0:2500
    python3 server/mock_server.py --port 2500

Чтобы клиент пошёл на localhost вместо mmog1.com — направьте туда DNS/hosts
или соберите клиент с изменённым al.q. Для протокольных экспериментов удобнее
натравить на этот сервер собственный тест-клиент (см. self-test внизу файла).
"""
from __future__ import annotations

import argparse
import socket
import struct
import threading

FLAP_MARKER = 0x2A  # '*'

# каналы FLAP
CH_LOGIN = 1
CH_DATA = 2
CH_ERROR = 3
CH_DISCONNECT = 4
CH_KEEPALIVE = 5


# --------------------------------------------------------------------------
# Кодирование чисел/текста (аналог класса `t` в клиенте)
# --------------------------------------------------------------------------
def u16(v: int) -> bytes:
    return struct.pack(">H", v & 0xFFFF)


def u32(v: int) -> bytes:
    return struct.pack(">I", v & 0xFFFFFFFF)


def read_u16(buf: bytes, off: int) -> int:
    return struct.unpack_from(">H", buf, off)[0]


def cp1251_encode(s: str) -> bytes:
    return s.encode("cp1251", errors="replace")


def cp1251_decode(b: bytes) -> str:
    return b.decode("cp1251", errors="replace")


# --------------------------------------------------------------------------
# TLV (аналог класса `aj`):  [type:2][length:2][value]
# --------------------------------------------------------------------------
def tlv_encode(type_: int, value: bytes) -> bytes:
    return u16(type_) + u16(len(value)) + value


def tlv_iter(buf: bytes):
    """Разбирает подряд идущие TLV, отдаёт (type, value)."""
    off = 0
    while off + 4 <= len(buf):
        t = read_u16(buf, off)
        ln = read_u16(buf, off + 2)
        off += 4
        value = buf[off:off + ln]
        off += ln
        yield t, value


# --------------------------------------------------------------------------
# Кадр FLAP (аналог класса `ae`)
# --------------------------------------------------------------------------
def flap_encode(channel: int, payload: bytes, seq: int = 1) -> bytes:
    return bytes([FLAP_MARKER, channel & 0xFF]) + u16(seq) + u16(len(payload)) + payload


def data_payload(group: int, subtype: int, data: bytes = b"") -> bytes:
    """Payload канала 2 (аналог `f.b()`): [group:2][subtype:2][data]."""
    return u16(group) + u16(subtype) + data


def read_frame(sock: socket.socket) -> tuple[int, bytes] | None:
    """Читает один кадр FLAP из сокета. Возвращает (channel, payload) или None."""
    header = _recv_exact(sock, 6)
    if header is None:
        return None
    if header[0] != FLAP_MARKER:
        raise ValueError(f"bad FLAP marker: 0x{header[0]:02X} (ожидался 0x2A)")
    channel = header[1]
    length = read_u16(header, 4)
    payload = _recv_exact(sock, length) if length else b""
    if payload is None:
        return None
    return channel, payload


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


# --------------------------------------------------------------------------
# Логика сессии
# --------------------------------------------------------------------------
def handle_client(sock: socket.socket, addr) -> None:
    log = lambda *a: print(f"[{addr[0]}:{addr[1]}]", *a)
    log("подключился")
    next_uid = 1001  # выдаваемый «уникальный ID устройства»

    try:
        # Шаг 2: приглашаем клиента представиться (group=1, subtype=0)
        sock.sendall(flap_encode(CH_DATA, data_payload(1, 0)))
        log("-> handshake (g1/s0)")

        while True:
            frame = read_frame(sock)
            if frame is None:
                log("отключился")
                return
            channel, payload = frame

            if channel == CH_KEEPALIVE:
                sock.sendall(flap_encode(CH_KEEPALIVE, b""))  # эхо-пинг
                continue

            if channel == CH_LOGIN:
                _log_login_packet(log, payload)
                continue

            if channel == CH_DATA:
                if len(payload) < 4:
                    log("<- пустой data-кадр")
                    continue
                group = read_u16(payload, 0)
                subtype = read_u16(payload, 2)
                data = payload[4:]
                log(f"<- data g{group}/s{subtype}  {len(data)} байт: {data[:64].hex()}")

                # разбираем то, что уже знаем из клиента
                if group == 1 and subtype == 0:
                    log("   версия/экран клиента:", _try_text(data))
                elif group == 4 and subtype == 12:
                    log("   уникальный ID устройства:", data.hex())
                elif group == 4 and subtype == 5:
                    for t, v in tlv_iter(data):
                        name = {1: "login", 2: "password"}.get(t, f"tlv{t}")
                        log(f"   {name} = {cp1251_decode(v)!r}")
                    # Шаг 6: выдаём ID и подтверждаем логин
                    sock.sendall(flap_encode(CH_DATA, data_payload(4, 5, u32(next_uid))))
                    sock.sendall(flap_encode(CH_DATA, data_payload(4, 0)))
                    log(f"-> выдал ID={next_uid} (g4/s5) и LOGIN OK (g4/s0)")
                continue

            log(f"<- неизвестный канал {channel}: {payload.hex()}")
    except (ConnectionError, ValueError) as e:
        log("ошибка:", e)
    finally:
        sock.close()


def _log_login_packet(log, payload: bytes) -> None:
    log("<- login-пакет (канал 1):")
    for t, v in tlv_iter(payload):
        if t in (1, 2, 4):
            log(f"   tlv{t} = {cp1251_decode(v)!r}")
        else:
            log(f"   tlv{t} = {v.hex()}")


def _try_text(data: bytes) -> str:
    printable = bytes(b for b in data if 32 <= b < 127)
    return cp1251_decode(printable)


def serve(host: str, port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(16)
    print(f"ThirdWorld mock-server слушает {host}:{port}")
    print("Ctrl+C для остановки.\n")
    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nостановлен")
    finally:
        srv.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Учебный мок-сервер ThirdWorld")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=2500)
    ap.add_argument("--self-test", action="store_true",
                    help="проверить кодеки без запуска сервера")
    args = ap.parse_args()

    if args.self_test:
        # round-trip кадра и TLV — быстрая проверка формата
        pay = data_payload(4, 5, tlv_encode(1, cp1251_encode("вася")) +
                                 tlv_encode(2, cp1251_encode("secret")))
        frame = flap_encode(CH_DATA, pay, seq=1)
        assert frame[0] == FLAP_MARKER and frame[1] == CH_DATA
        assert read_u16(frame, 4) == len(pay)
        ch, back = CH_DATA, frame[6:]
        assert read_u16(back, 0) == 4 and read_u16(back, 2) == 5
        tlvs = dict(tlv_iter(back[4:]))
        assert cp1251_decode(tlvs[1]) == "вася"
        assert cp1251_decode(tlvs[2]) == "secret"
        print("self-test OK: FLAP + TLV + CP1251 сходятся")
    else:
        serve(args.host, args.port)
