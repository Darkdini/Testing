# ThirdWorld — реверс протокола и учебный сервер

В репозитории лежит клиент старой J2ME-MMO «Третий мир»
(`Tretij_mir(SE-Nokia-176x208-rus)-spaces.im.jar`, Fenix-Soft, 2009). Сервер
(`mmog1.com:2500`) давно недоступен. Здесь разобрано, **как клиент общается с
сервером**, и лежит учебный скелет сервера, чтобы учиться писать свой.

## Что где

| Файл | Что внутри |
|------|-----------|
| [`docs/01_ARCHITECTURE.md`](docs/01_ARCHITECTURE.md) | карта обфусцированных классов: где какая логика |
| [`docs/02_PROTOCOL.md`](docs/02_PROTOCOL.md) | формат кадра FLAP, пакеты, TLV, кодировки |
| [`docs/03_LOGIN_FLOW.md`](docs/03_LOGIN_FLOW.md) | сценарий «коннект → handshake → логин → игра» |
| [`server/mock_server.py`](server/mock_server.py) | учебный мок-сервер (Python, без зависимостей) |

## Кратко о протоколе

- Транспорт: обычный **TCP** (`socket://mmog1.com:2500`).
- Кадр **FLAP**: `[0x2A][channel:1][seq:2][len:2][payload]`, числа big-endian.
- Каналы: `1`=логин, `2`=данные (group+subtype), `5`=keep-alive.
- Текст — **Windows-1251 (CP1251)**.

Подробности и таблицы команд — в `docs/`.

## Быстрый старт

```bash
# проверить кодеки (FLAP + TLV + CP1251)
python3 server/mock_server.py --self-test

# поднять мок-сервер
python3 server/mock_server.py --port 2500
```

Сервер логирует всё, что шлёт клиент, — так доснимаются номера остальных
игровых команд (`group`/`subtype`).

## Как разбирался клиент

JAR — это ZIP; классы обфусцированы (`a.class`, `b.class`…). Дизассемблировано
штатным `javap`:

```bash
mkdir out && cd out && unzip -o ../*.jar
javap -p -c -constants -classpath . g      # транспорт (TCP-сокет)
javap -p -c -constants -classpath . ae     # кадр FLAP
javap -p -c -constants -classpath . t aj   # кодеки и TLV
javap -p -c -constants -classpath . k      # логин/сессия
```

> Только для изучения протокола и совместимости (взаимодействие с собственным
> сервером). Игровые ассеты принадлежат правообладателям.
