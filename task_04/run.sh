#!/usr/bin/env bash
# Лабораторная работа №4, вариант 12: PKI, HTTPS и mTLS (TLS 1.3).
#
#   Ключ корня / промежуточного CA : RSA-2048
#   Ключ сервера                   : Ed25519
#   Группа ECDHE                   : X25519
#   Набор шифров TLS 1.3           : TLS_AES_256_GCM_SHA384
#   Задача варианта                : mTLS с клиентским сертификатом Ed25519; без сертификата nginx
#                                    отвечает HTTP 400 "No required SSL certificate was sent", а не TLS-alert
#
# Запуск:   ./run.sh              - собрать PKI, поднять nginx, выполнить все проверки
#           ./run.sh clean        - удалить каталог out/ (сгенерированные ключи, логи, конфиг)
#           CAPTURE=1 ./run.sh    - дополнительно записать handshake.pcap (tcpdump, потребуется sudo) и разобрать tshark
#           PORT=9443 ./run.sh    - другой порт nginx (по умолчанию 8443)
#
# Нужны: openssl 3.x (не LibreSSL), nginx, curl с OpenSSL (macOS: brew install openssl nginx curl wireshark).
# Всё создаётся в каталоге out/ рядом со скриптом; root и sudo не нужны (кроме CAPTURE=1).

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/out"
PORT="${PORT:-8443}"

if [ "${1:-}" = "clean" ]; then
    rm -rf "$OUT"
    echo "Каталог $OUT удалён."
    exit 0
fi

# ---------------------------------------------------------------- поиск инструментов
pick() { for c in "$@"; do if [ -x "$c" ] || command -v "$c" >/dev/null 2>&1; then echo "$c"; return; fi; done; }
OPENSSL="$(pick /opt/homebrew/bin/openssl /usr/local/opt/openssl/bin/openssl openssl)"
NGINX="$(pick /opt/homebrew/bin/nginx /usr/local/bin/nginx nginx)"
CURL="$(pick /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl curl)"
TSHARK="$(pick /opt/homebrew/bin/tshark /usr/local/bin/tshark tshark)"

need() { if [ -z "$2" ]; then echo "Не найден $1. Установите: $3" >&2; exit 2; fi; }
need openssl "$OPENSSL" "brew install openssl"
need nginx   "$NGINX"   "brew install nginx"
need curl    "$CURL"    "brew install curl"
if ! "$OPENSSL" version | grep -q '^OpenSSL'; then
    echo "Нужен OpenSSL 3.x (найден: $("$OPENSSL" version)). Установите: brew install openssl" >&2; exit 2
fi
if ! "$CURL" --version | head -1 | grep -qi curl; then echo "curl не работает" >&2; exit 2; fi
if ! "$CURL" -V | grep -qi 'OpenSSL'; then
    echo "ВНИМАНИЕ: curl собран не с OpenSSL ($("$CURL" -V | head -1)); Ed25519 и TLS 1.3 могут не работать." >&2
fi
if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
    echo "Порт $PORT уже занят. Запустите с другим портом: PORT=9443 ./run.sh" >&2; exit 2
fi

mkdir -p "$OUT"
LOG="$OUT/results.txt"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$1"; }
expect() { # описание, условие (0 = успех)
    if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi
}
section() { printf '\n==== %s ====\n' "$1"; }
neg() { printf '\n--- [НЕГАТИВНЫЙ ТЕСТ] %s\n' "$1"; }

NGX_PREFIX="$OUT/nginx"
cleanup() {
    if [ -f "$NGX_PREFIX/nginx.pid" ]; then "$NGINX" -p "$NGX_PREFIX" -c "$NGX_PREFIX/nginx.conf" -s stop 2>/dev/null; fi
}
trap cleanup EXIT

echo "Инструменты:"
echo "  openssl: $("$OPENSSL" version)"
echo "  nginx:   $("$NGINX" -v 2>&1)"
echo "  curl:    $("$CURL" --version | head -1)"

cd "$OUT" || exit 1
mkdir -p root inter server client other

# ================================================================ 1. PKI
section "1. Корневой CA (RSA-2048), промежуточный CA (RSA-2048)"
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out root/root.key 2>/dev/null
chmod 600 root/root.key
"$OPENSSL" req -new -x509 -key root/root.key -sha256 -days 3650 -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' -out root/root.crt

cat > inter/inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out inter/inter.key 2>/dev/null
chmod 600 inter/inter.key
"$OPENSSL" req -new -key inter/inter.key -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' -out inter/inter.csr
"$OPENSSL" x509 -req -in inter/inter.csr -CA root/root.crt -CAkey root/root.key -CAcreateserial -sha256 \
    -days 1825 -extfile inter/inter.ext -out inter/inter.crt 2>&1 | sed 's/^/  /'

section "2. База промежуточного CA; серверный (Ed25519) и клиентский (Ed25519) сертификаты"
( cd inter && : > index.txt && echo 01 > crlnumber && echo 1000 > serial )
cat > inter/ca.cnf <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir              = $OUT/inter
database         = \$dir/index.txt
new_certs_dir    = \$dir
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
certificate      = \$dir/inter.crt
private_key      = \$dir/inter.key
default_md       = sha256
default_days     = 365
default_crl_days = 30
unique_subject   = no
copy_extensions  = none
policy           = policy_any
[ policy_any ]
commonName       = supplied
EOF

cat > server/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
cat > client/client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

"$OPENSSL" genpkey -algorithm ED25519 -out server/server.key; chmod 600 server/server.key
"$OPENSSL" req -new -key server/server.key -subj '/C=BY/O=Lab PKI/CN=localhost' -out server/server.csr
"$OPENSSL" ca -config inter/ca.cnf -batch -in server/server.csr -extfile server/server.ext -notext -out server/server.crt 2>&1 | grep -E 'Write out|updated' | sed 's/^/  server: /'

"$OPENSSL" genpkey -algorithm ED25519 -out client/client.key; chmod 600 client/client.key
"$OPENSSL" req -new -key client/client.key -subj '/C=BY/O=Lab PKI/CN=lab-client' -out client/client.csr
"$OPENSSL" ca -config inter/ca.cnf -batch -in client/client.csr -extfile client/client.ext -notext -out client/client.crt 2>&1 | grep -E 'Write out|updated' | sed 's/^/  client: /'

cat server/server.crt inter/inter.crt > server/fullchain.pem       # лист + промежуточный
cat root/root.crt inter/inter.crt > server/client-ca.pem           # доверенные CA для проверки клиента

section "3. Поля сертификатов"
for c in root/root inter/inter server/server client/client; do
    echo "--- $c.crt"
    "$OPENSSL" x509 -in "$c.crt" -noout -subject -issuer -dates \
        -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName 2>/dev/null | grep -v '^$' | sed 's/^/  /'
    "$OPENSSL" x509 -in "$c.crt" -noout -text | grep -E 'Public Key Algorithm|Signature Algorithm' | sort -u | sed 's/^ */  /'
done

section "4. Проверка цепочки"
"$OPENSSL" verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt client/client.crt >chain.txt 2>&1
cat chain.txt | sed 's/^/  /'
[ "$(grep -c ': OK' chain.txt)" -eq 2 ]; expect "цепочка сервера и клиента проверена до корня" $?

neg "без промежуточного сертификата"
"$OPENSSL" verify -CAfile root/root.crt server/server.crt 2>&1 | sed 's/^/  /'
"$OPENSSL" verify -CAfile root/root.crt server/server.crt >/dev/null 2>&1; expect "неполная цепочка отвергается" $((1 - ($? != 0)))

neg "чужой корень (самоподписанный Ed25519)"
"$OPENSSL" genpkey -algorithm ED25519 -out other/other.key
"$OPENSSL" req -new -x509 -key other/other.key -subj '/CN=Other Root' -days 1 -out other/other.crt
"$OPENSSL" verify -CAfile other/other.crt -untrusted inter/inter.crt server/server.crt 2>&1 | sed 's/^/  /'
"$OPENSSL" verify -CAfile other/other.crt -untrusted inter/inter.crt server/server.crt >/dev/null 2>&1; expect "чужой корень отвергается" $((1 - ($? != 0)))

neg "истёкший сертификат (-attime через 400 дней)"
FUTURE=$(date -u -d '+400 days' +%s 2>/dev/null || date -u -v+400d +%s)
"$OPENSSL" verify -attime "$FUTURE" -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt 2>&1 | sed 's/^/  /'
"$OPENSSL" verify -attime "$FUTURE" -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt >/dev/null 2>&1; expect "лист через 400 дней просрочен" $((1 - ($? != 0)))

neg "серверный сертификат как клиентский (EKU serverAuth)"
"$OPENSSL" verify -purpose sslclient -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt 2>&1 | sed 's/^/  /'
"$OPENSSL" verify -purpose sslclient -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt >/dev/null 2>&1; expect "сертификат сервера не годится для роли клиента" $((1 - ($? != 0)))

# ================================================================ 2. nginx
section "5. nginx: HTTPS только TLS 1.3, mTLS (ssl_verify_client on)"
mkdir -p "$NGX_PREFIX/logs"
cat > "$NGX_PREFIX/nginx.conf" <<EOF
worker_processes 1;
pid $NGX_PREFIX/nginx.pid;
error_log $NGX_PREFIX/logs/error.log info;
events { worker_connections 64; }
http {
    access_log $NGX_PREFIX/logs/access.log;
    client_body_temp_path $NGX_PREFIX/tmp_body;
    proxy_temp_path       $NGX_PREFIX/tmp_proxy;
    fastcgi_temp_path     $NGX_PREFIX/tmp_fcgi;
    uwsgi_temp_path       $NGX_PREFIX/tmp_uwsgi;
    scgi_temp_path        $NGX_PREFIX/tmp_scgi;
    server {
        listen 127.0.0.1:$PORT ssl;
        server_name localhost;
        ssl_certificate     $OUT/server/fullchain.pem;
        ssl_certificate_key $OUT/server/server.key;
        ssl_protocols TLSv1.3;
        ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;
        ssl_ecdh_curve X25519;
        ssl_session_tickets on;
        ssl_client_certificate $OUT/server/client-ca.pem;
        ssl_verify_client on;
        ssl_verify_depth 2;
        location / { return 200 'mtls ok'; }
    }
}
EOF
echo "Конфигурация (ключевые строки):"
grep -E 'ssl_|listen' "$NGX_PREFIX/nginx.conf" | sed 's/^ */  /'
"$NGINX" -p "$NGX_PREFIX" -c "$NGX_PREFIX/nginx.conf" -t 2>&1 | sed 's/^/  nginx -t: /'
"$NGINX" -p "$NGX_PREFIX" -c "$NGX_PREFIX/nginx.conf" -t >/dev/null 2>&1; expect "nginx -t: конфигурация корректна" $?
"$NGINX" -p "$NGX_PREFIX" -c "$NGX_PREFIX/nginx.conf" 2>&1 | sed 's/^/  /'
for i in 1 2 3 4 5 6 7 8 9 10; do
    if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then break; fi
    sleep 0.3
done
(exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; expect "nginx слушает порт $PORT" $?

URL="https://localhost:$PORT/"
CERT_ARGS=(--cert "$OUT/client/client.crt" --key "$OUT/client/client.key")

# ================================================================ 3. mTLS-проверки
section "6. mTLS: клиент с сертификатом Ed25519"
CODE=$("$CURL" -sS -v --cacert root/root.crt "${CERT_ARGS[@]}" -o ok_body.txt -w '%{http_code}' "$URL" 2>ok_verbose.txt)
echo "  HTTP-код: $CODE; тело ответа: $(cat ok_body.txt)"
grep -E 'SSL connection using|TLSv1\.3|Server certificate|subject:|issuer:|SSL certificate verify' ok_verbose.txt | sed 's/^/  /' | head -8
[ "$CODE" = "200" ]; expect "с клиентским сертификатом: HTTP 200" $?
grep -q 'TLSv1.3' ok_verbose.txt; expect "версия протокола TLSv1.3" $?
grep -qE 'TLS_AES_256_GCM_SHA384|AES256-GCM' ok_verbose.txt; expect "шифр TLS_AES_256_GCM_SHA384" $?
[ "$(cat ok_body.txt)" = "mtls ok" ]; expect "тело ответа: mtls ok" $?

neg "без клиентского сертификата (задача варианта 12)"
CODE=$("$CURL" -sS --cacert root/root.crt -o noc_body.txt -w '%{http_code}' "$URL" 2>noc_err.txt)
echo "  HTTP-код: $CODE"
sed 's/<[^>]*>//g' noc_body.txt | grep -v '^\s*$' | sed 's/^/  /'
[ "$CODE" = "400" ]; expect "без сертификата: HTTP 400, а не TLS-alert" $?
grep -q 'No required SSL certificate was sent' noc_body.txt; expect "текст: No required SSL certificate was sent" $?

neg "клиентский сертификат от чужого CA (Ed25519, самоподписанный)"
"$OPENSSL" req -new -x509 -key other/other.key -subj '/CN=Evil Client' -days 1 -out other/evilclient.crt
CODE=$("$CURL" -sS --cacert root/root.crt --cert other/evilclient.crt --key other/other.key -o evil_body.txt -w '%{http_code}' "$URL" 2>evil_err.txt)
RC=$?
echo "  curl exit: $RC; HTTP-код: $CODE"
sed 's/<[^>]*>//g' evil_body.txt | grep -v '^\s*$' | sed 's/^/  /'
[ -s evil_err.txt ] && sed 's/^/  curl stderr: /' evil_err.txt
[ "$CODE" != "200" ]; expect "чужой клиентский сертификат не даёт HTTP 200" $?

neg "клиентский сертификат с EKU serverAuth (сертификат сервера в роли клиента)"
CODE=$("$CURL" -sS --cacert root/root.crt --cert server/server.crt --key server/server.key -o srvasclient_body.txt -w '%{http_code}' "$URL" 2>srvasclient_err.txt)
echo "  curl exit: $?; HTTP-код: $CODE"
[ "$CODE" != "200" ]; expect "серверный сертификат не принимается как клиентский" $?

section "7. Проверка сервера клиентом (негативные тесты HTTPS)"
neg "curl без --cacert (корень не в доверенных)"
"$CURL" -sS "${CERT_ARGS[@]}" -o /dev/null "$URL" 2> e1.txt; RC=$?
sed 's/^/  /' e1.txt | head -3; echo "  exit: $RC"
[ "$RC" -eq 60 ]; expect "curl exit 60 (не удалось проверить сертификат сервера)" $?

neg "имя вне SAN: https://127.0.0.2"
# --connect-to: имя 127.0.0.2 в URL, но TCP-соединение идёт на 127.0.0.1 (на macOS 127.0.0.2 не настроен)
"$CURL" -sS --max-time 10 --connect-to "127.0.0.2:$PORT:127.0.0.1:$PORT" --cacert root/root.crt "${CERT_ARGS[@]}" \
    -o /dev/null "https://127.0.0.2:$PORT/" 2> e2.txt; RC=$?
sed 's/^/  /' e2.txt | head -3; echo "  exit: $RC"
[ "$RC" -eq 60 ]; expect "curl exit 60: имя 127.0.0.2 не совпадает с SAN (CN не помогает)" $?
grep -qiE "no alternative certificate subject name matches|subject alternative name|does not match" e2.txt; expect "причина: адрес отсутствует в SAN" $?

neg "TLS 1.2 (nginx разрешает только TLS 1.3)"
( sleep 1 ) | "$OPENSSL" s_client -connect localhost:$PORT -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol|error' | sed 's/^/  /' | head -4
( sleep 1 ) | "$OPENSSL" s_client -connect localhost:$PORT -tls1_2 -CAfile root/root.crt 2>&1 | grep -q 'alert protocol version'
expect "TLS 1.2 отвергается: alert protocol version (70)" $?

# ================================================================ 4. рукопожатие
section "8. Рукопожатие TLS 1.3 при mTLS (s_client -trace, журнал ключей)"
rm -f keys.log
( printf 'GET / HTTP/1.0\r\n\r\n'; sleep 1 ) | "$OPENSSL" s_client -connect localhost:$PORT -servername localhost \
    -CAfile root/root.crt -cert client/client.crt -key client/client.key -tls1_3 \
    -groups X25519 -ciphersuites TLS_AES_256_GCM_SHA384 -trace -keylogfile keys.log > trace.txt 2>&1
echo "  Сообщения рукопожатия (порядок как в трассе):"
grep -E '^ +(ClientHello|ServerHello|EncryptedExtensions|CertificateRequest|Certificate|CertificateVerify|Finished|NewSessionTicket),' trace.txt | sed 's/^ */    /'
grep -q 'CertificateRequest' trace.txt; expect "сервер прислал CertificateRequest (type 13)" $?
[ "$(grep -cE '^ +Certificate,' trace.txt)" -ge 2 ]; expect "Certificate отправлен и сервером, и клиентом" $?
grep -qE 'key_share|group=x25519|x25519' trace.txt; expect "в рукопожатии используется X25519" $?
grep -q 'HTTP/1.1 200' trace.txt; expect "ответ сервера в mTLS-сессии: HTTP 200" $?
echo "  keys.log: $(wc -l < keys.log | tr -d ' ') строк; метки: $(cut -d' ' -f1 keys.log | grep -v '^#' | sort -u | tr '\n' ' ')"

if [ "${CAPTURE:-0}" = "1" ]; then
    section "9. Захват трафика и разбор в tshark (CAPTURE=1)"
    LO=lo; [ "$(uname)" = "Darwin" ] && LO=lo0
    echo "  Запуск tcpdump на $LO (потребуется sudo)..."
    sudo tcpdump -i "$LO" -w handshake.pcap "tcp port $PORT" >/dev/null 2>&1 &
    TD=$!
    sleep 2
    SSLKEYLOGFILE="$OUT/keys_curl.log" "$CURL" -sS --cacert root/root.crt "${CERT_ARGS[@]}" -o /dev/null "$URL"
    sleep 1
    sudo kill "$TD" 2>/dev/null; sleep 1
    sudo chown "$USER" handshake.pcap 2>/dev/null
    if [ -n "$TSHARK" ] && [ -s handshake.pcap ]; then
        echo "  Без журнала ключей (видны только ClientHello и ServerHello):"
        "$TSHARK" -r handshake.pcap -Y tls.handshake -T fields -e frame.number -e tls.handshake.type 2>/dev/null | sed 's/^/    /'
        echo "  С журналом ключей (13 - CertificateRequest, 11 - Certificate, 15 - CertificateVerify, 20 - Finished):"
        "$TSHARK" -r handshake.pcap -o tls.keylog_file:"$OUT/keys_curl.log" -Y tls.handshake -T fields -e frame.number -e tls.handshake.type 2>/dev/null | sed 's/^/    /'
        "$TSHARK" -r handshake.pcap -o tls.keylog_file:"$OUT/keys_curl.log" -Y 'tls.handshake.type == 13' 2>/dev/null | grep -q . ; expect "в захвате есть CertificateRequest (type 13)" $?
    else
        echo "  Захват не получился (нет tshark или pcap пуст)."
    fi
fi

section "Итог"
echo "  Пройдено: $PASS, не пройдено: $FAIL"
echo "  Все файлы и подробный вывод: $OUT (results.txt, trace.txt, keys.log, nginx/logs/)"
[ "$FAIL" -eq 0 ]
