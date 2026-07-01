#!/usr/bin/env python3
"""
Разведывательный мок-сервер для клиента «Третий мир» (ThirdWorld, J2ME).

Назначение: инструмент для ВОССТАНОВЛЕНИЯ протокола по наблюдению
(см. docs/04_HOW_TO_REBUILD.md). Сервер:

  1. проводит handshake и логин (клиент уходит с экрана логина);
  2. подробно ЛОГИРУЕТ каждый входящий пакет (канал, group, subtype, hex,
     ASCII, попытку декода CP1251 и разбор TLV) — так ты видишь, что клиент
     хочет от сервера;
  3. позволяет РЕГИСТРИРОВАТЬ обработчики на (group, subtype) декоратором @on,
     чтобы отвечать и итеративно достраивать логику.

Протокол (из клиентского JAR, см. docs/02_PROTOCOL.md):
    кадр FLAP:  [0x2A][channel:1][seq:2][len:2][payload]
    канал 1 — логин (TLV 1=login, 2=password, 4=str, 8=version)
    канал 2 — данные: [group:2][subtype:2][data]
    числа big-endian; текст CP1251.

Запуск:
    python3 server/mock_server.py                 # 0.0.0.0:2500
    python3 server/mock_server.py --port 2500
    python3 server/mock_server.py --self-test     # проверка кодеков
"""
from __future__ import annotations

import argparse
import socket
import struct
import threading

FLAP_MARKER = 0x2A  # '*'
CH_LOGIN, CH_DATA, CH_ERROR, CH_DISCONNECT, CH_KEEPALIVE = 1, 2, 3, 4, 5


# ---------------------------------------------------------------- кодеки (класс t)
def u16(v: int) -> bytes: return struct.pack(">H", v & 0xFFFF)
def u32(v: int) -> bytes: return struct.pack(">I", v & 0xFFFFFFFF)
def read_u16(b: bytes, o: int) -> int: return struct.unpack_from(">H", b, o)[0]
def cp1251_encode(s: str) -> bytes: return s.encode("cp1251", "replace")
def cp1251_decode(b: bytes) -> str: return b.decode("cp1251", "replace")


# ---------------------------------------------------------------- TLV (класс aj)
def tlv_encode(type_: int, value: bytes) -> bytes:
    return u16(type_) + u16(len(value)) + value


def tlv_iter(buf: bytes):
    off = 0
    while off + 4 <= len(buf):
        t, ln = read_u16(buf, off), read_u16(buf, off + 2)
        off += 4
        yield t, buf[off:off + ln]
        off += ln


# ---------------------------------------------------------------- кадр FLAP (класс ae)
def flap_encode(channel: int, payload: bytes, seq: int = 1) -> bytes:
    return bytes([FLAP_MARKER, channel & 0xFF]) + u16(seq) + u16(len(payload)) + payload


def data_payload(group: int, subtype: int, data: bytes = b"") -> bytes:
    return u16(group) + u16(subtype) + data


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket.socket):
    header = _recv_exact(sock, 6)
    if header is None:
        return None
    if header[0] != FLAP_MARKER:
        raise ValueError(f"bad FLAP marker 0x{header[0]:02X} (ждали 0x2A)")
    channel, length = header[1], read_u16(header, 4)
    payload = _recv_exact(sock, length) if length else b""
    if payload is None:
        return None
    return channel, payload


# ---------------------------------------------------------------- дамп неизвестного
def hexdump(data: bytes, indent: str = "     ") -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk).ljust(16 * 3 - 1)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        cyr = cp1251_decode(bytes(b for b in chunk))
        lines.append(f"{indent}{i:04x}  {hexs}  |{ascii_}|  {cyr}")
    return "\n".join(lines) if lines else f"{indent}(пусто)"


# ---------------------------------------------------------------- реестр обработчиков
# handler(session, group, subtype, data) -> None; отвечает через session.send_data(...)
_HANDLERS: dict[tuple[int, int], callable] = {}


def on(group: int, subtype: int):
    def deco(fn):
        _HANDLERS[(group, subtype)] = fn
        return fn
    return deco


class Session:
    def __init__(self, sock: socket.socket, addr):
        self.sock, self.addr = sock, addr
        self.seq = 0
        self.uid = None
        self.login = None

    def log(self, *a):
        print(f"[{self.addr[0]}:{self.addr[1]}]", *a)

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq

    def send_data(self, group: int, subtype: int, data: bytes = b""):
        self.sock.sendall(flap_encode(CH_DATA, data_payload(group, subtype, data), self._next_seq()))
        self.log(f"-> g{group}/s{subtype}  {len(data)} байт")

    def send_raw(self, channel: int, payload: bytes):
        self.sock.sendall(flap_encode(channel, payload, self._next_seq()))


# ============================================================ ЛОГИКА (достраивай здесь)
NEXT_UID = 1001


@on(1, 0)
def h_handshake(s: Session, g, st, data):
    """Клиент прислал версию/экран — просто фиксируем."""
    s.log("   версия/экран:", _printable(data))


@on(4, 12)
def h_device_id(s: Session, g, st, data):
    s.log("   уникальный ID устройства:", data.hex())


@on(4, 5)
def h_login(s: Session, g, st, data):
    """Логин+пароль (TLV 1,2). Отвечаем: выданный ID + LOGIN OK."""
    global NEXT_UID
    creds = {t: cp1251_decode(v) for t, v in tlv_iter(data)}
    s.login = creds.get(1)
    s.log(f"   ЛОГИН login={creds.get(1)!r} password={creds.get(2)!r}")
    s.uid = NEXT_UID
    NEXT_UID += 1
    s.send_data(4, 5, u32(s.uid))   # выданный ID (клиент сохранит в RMS)
    s.send_data(4, 0)               # LOGIN OK -> клиент уходит на игровой экран
    s.log(f"   выдал ID={s.uid}, отправил LOGIN OK")
    # TODO Этап 2: тут прислать снапшот замка/ресурсов, когда разгадаешь формат.


# TODO: по мере разгадывания добавляй сюда:
#   @on(GROUP, SUBTYPE)
#   def handler(s, g, st, data): ...
# Всё, что без обработчика, попадает в подробный лог ниже — используй его,
# чтобы понять, что клиент шлёт, и дописать ответ.
# ============================================================================


def _printable(data: bytes) -> str:
    return cp1251_decode(bytes(b for b in data if b >= 32))


def handle_client(sock: socket.socket, addr):
    s = Session(sock, addr)
    s.log("подключился")
    try:
        # Шаг 2: приглашаем представиться
        s.send_data(1, 0)
        while True:
            frame = read_frame(sock)
            if frame is None:
                s.log("отключился")
                return
            channel, payload = frame

            if channel == CH_KEEPALIVE:
                s.send_raw(CH_KEEPALIVE, b"")
                continue

            if channel == CH_LOGIN:
                s.log("<- login-пакет (канал 1):")
                for t, v in tlv_iter(payload):
                    s.log(f"   tlv{t} = {cp1251_decode(v)!r}")
                continue

            if channel != CH_DATA:
                s.log(f"<- канал {channel}, {len(payload)} байт:\n{hexdump(payload)}")
                continue

            if len(payload) < 4:
                s.log(f"<- пустой data-кадр: {payload.hex()}")
                continue

            group, subtype, data = read_u16(payload, 0), read_u16(payload, 2), payload[4:]
            handler = _HANDLERS.get((group, subtype))
            if handler:
                s.log(f"<- g{group}/s{subtype}  {len(data)} байт  [известный]")
                handler(s, group, subtype, data)
            else:
                # ГЛАВНОЕ для разведки: подробный дамп неизвестной команды
                s.log(f"<- g{group}/s{subtype}  {len(data)} байт  [НЕИЗВЕСТНО]")
                print(hexdump(data))
                tlvs = list(tlv_iter(data))
                if tlvs and sum(4 + len(v) for _, v in tlvs) == len(data):
                    s.log("   похоже на TLV:")
                    for t, v in tlvs:
                        s.log(f"     tlv{t} = {cp1251_decode(v)!r} / {v.hex()}")
    except (ConnectionError, ValueError) as e:
        s.log("ошибка:", e)
    finally:
        sock.close()


def serve(host: str, port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(16)
    print(f"ThirdWorld recon-server слушает {host}:{port}")
    print(f"Известных команд: {len(_HANDLERS)}. Ctrl+C для остановки.\n")
    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nостановлен")
    finally:
        srv.close()


def _self_test():
    pay = data_payload(4, 5, tlv_encode(1, cp1251_encode("вася")) +
                             tlv_encode(2, cp1251_encode("secret")))
    frame = flap_encode(CH_DATA, pay, seq=1)
    assert frame[0] == FLAP_MARKER and frame[1] == CH_DATA
    assert read_u16(frame, 4) == len(pay)
    body = frame[6:]
    assert read_u16(body, 0) == 4 and read_u16(body, 2) == 5
    tlvs = dict(tlv_iter(body[4:]))
    assert cp1251_decode(tlvs[1]) == "вася" and cp1251_decode(tlvs[2]) == "secret"
    assert (4, 5) in _HANDLERS and (1, 0) in _HANDLERS
    print("self-test OK: FLAP + TLV + CP1251 + реестр обработчиков")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Разведывательный мок-сервер ThirdWorld")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=2500)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    _self_test() if args.self_test else serve(args.host, args.port)
