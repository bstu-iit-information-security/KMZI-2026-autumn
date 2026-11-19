#!/bin/bash
# Вариант 8: срок действия (запуск из каталога pki/)
echo "== сроки действия"; for f in root/root inter/inter server/server; do echo "$f: $(openssl x509 -in $f.crt -noout -startdate -enddate | tr '\n' ' ')"; done
T() { date -j -v+$1d +%s; }
echo "== verify сейчас";            openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
echo "== verify +364 дня";          openssl verify -attime $(T 364) -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
echo "== [НЕГАТИВНЫЙ] verify +366 дней"; openssl verify -attime $(T 366) -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt 2>&1 | sed -n 2,4p
echo "== [НЕГАТИВНЫЙ] verify +400 дней"; openssl verify -attime $(T 400) -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt 2>&1 | sed -n 2,4p
echo "== verify +400 дней, цепочка CA без листа (inter ещё действует)"; openssl verify -attime $(T 400) -CAfile root/root.crt inter/inter.crt
pkill -f "s_server -accept 8453" 2>/dev/null; sleep 0.5
openssl s_server -accept 8453 -cert server/server.crt -key server/server.key -cert_chain inter/inter.crt -tls1_3 -groups X25519 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -www >/dev/null 2>&1 & SP=$!; sleep 1
cl() { ( sleep 1 ) | openssl s_client -connect localhost:8453 -servername localhost -CAfile root/root.crt -tls1_3 -groups X25519 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 "$@"; }
echo "== TLS 1.3 handshake"; cl -brief 2>&1 | head -10
echo "== [НЕГАТИВНЫЙ] клиент с временем +400 дней"; cl -attime $(T 400) -brief 2>&1 | grep -E "Verif|error|expired|ESTABLISHED" | head -5
kill $SP
