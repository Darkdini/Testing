#!/usr/bin/env bash
# Хелпер «статического снифа»: печатает байткод метода клиента, который
# РАЗБИРАЕТ серверный ответ. Так узнаёшь, какие байты сервер обязан прислать,
# не имея живого сервера. См. docs/05_SNIFFING.md.
#
# Использование:
#   1) один раз распаковать JAR:
#        mkdir -p out && (cd out && unzip -o ../*.jar >/dev/null)
#   2) смотреть парсеры:
#        server/disasm.sh out p        # весь класс p (главная модель)
#        server/disasm.sh out p e       # только метод e (главный роутер пакетов)
#        server/disasm.sh out k a       # k.a(f) — разбор ответов логина
#
# Ключевые точки приёма (что сервер шлёт клиенту):
#   ar.run() -> ar.h() (читает кадр) -> k.b(f) [группы 1,4] / p.e(f) [10,11,12]
#   p.e(f):  group 10 -> p.p(f) (замок, subtype 0..20)
#            group 11 -> p.n(f) (subtype 4..7)
#            group 12 -> p.i(f)
#   Числа big-endian (t.a=4б, t.c=2б, t.b=1б), строки CP1251 (t.b(buf,off,len)).

set -euo pipefail
DIR="${1:?укажи каталог с распакованными .class (напр. out)}"
CLS="${2:?укажи класс, напр. p}"
METHOD="${3:-}"

cd "$DIR"
if [[ -z "$METHOD" ]]; then
  javap -p -c -constants -classpath . "$CLS"
else
  # вырезаем только нужный метод (до пустой строки-разделителя)
  javap -p -c -constants -classpath . "$CLS" \
    | awk -v m="$METHOD" '
        $0 ~ "(void|int|byte\\[\\]|Lae;|Lf;) " m "\\(" {f=1}
        f{print}
        f && /^$/ {exit}'
fi
