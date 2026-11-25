#!/usr/bin/env bash
# Лабораторная работа №4, вариант 1: PKI, HTTPS и TLS 1.3.
#   Ключи корня / промежуточного CA / сервера : ECDSA P-256
#   Группа ECDHE : X25519;  шифр : TLS_AES_128_GCM_SHA256
#   Задача: Name Constraints - промежуточный CA разрешает только DNS:.lab.local
#           лист для localhost -> permitted subtree violation; лист для app.lab.local -> OK
# Запуск: ./run.sh   (PORT=9443 ./run.sh - другой порт;  ./run.sh clean - удалить out/)
# Нужны openssl 3.x (не LibreSSL), nginx, curl с OpenSSL. Всё создаётся в out/, sudo не нужен.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/out"
PORT="${PORT:-8443}"
[ "${1:-}" = "clean" ] && { rm -rf "$OUT"; echo "out/ удалён"; exit 0; }

pick() { for c in "$@"; do if [ -x "$c" ] || command -v "$c" >/dev/null 2>&1; then echo "$c"; return; fi; done; }
OPENSSL="$(pick /opt/homebrew/bin/openssl /usr/local/opt/openssl/bin/openssl openssl)"
NGINX="$(pick /opt/homebrew/bin/nginx /usr/local/bin/nginx nginx)"
CURL="$(pick /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl curl)"
"$OPENSSL" version | grep -q '^OpenSSL' || { echo "нужен OpenSSL 3.x" >&2; exit 2; }
[ -n "$NGINX" ] || { echo "нужен nginx (brew install nginx)" >&2; exit 2; }
if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then echo "порт $PORT занят: PORT=9443 ./run.sh" >&2; exit 2; fi

mkdir -p "$OUT"; LOG="$OUT/results.txt"; : > "$LOG"; exec > >(tee -a "$LOG") 2>&1
PASS=0; FAIL=0
expect() { if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "  [PASS] $1"; else FAIL=$((FAIL+1)); echo "  [FAIL] $1"; fi; }
fails() { "$@" >/dev/null 2>&1; [ $? -ne 0 ]; }       # команда должна завершиться ошибкой
section() { printf '\n==== %s ====\n' "$1"; }
neg() { printf '\n--- [НЕГАТИВНЫЙ ТЕСТ] %s\n' "$1"; }
NGX="$OUT/nginx"
trap '[ -f "$NGX/nginx.pid" ] && "$NGINX" -p "$NGX" -c "$NGX/nginx.conf" -s stop 2>/dev/null' EXIT

echo "openssl: $("$OPENSSL" version)"; echo "nginx: $("$NGINX" -v 2>&1)"; echo "curl: $("$CURL" --version | head -1)"
cd "$OUT" || exit 1; mkdir -p root inter server client other

section "1. Корневой CA (ECDSA P-256)"
"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root/root.key; chmod 600 root/root.key
"$OPENSSL" req -new -x509 -key root/root.key -sha256 -days 3650 -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' -out root/root.crt

section "2. Промежуточный CA с nameConstraints (только .lab.local), pathlen:0"
cat > inter/inter.ext <<'X'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
nameConstraints=critical,permitted;DNS:.lab.local
X
"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key; chmod 600 inter/inter.key
"$OPENSSL" req -new -key inter/inter.key -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' -out inter/inter.csr
"$OPENSSL" x509 -req -in inter/inter.csr -CA root/root.crt -CAkey root/root.key -CAcreateserial -sha256 \
  -days 1825 -extfile inter/inter.ext -out inter/inter.crt
"$OPENSSL" x509 -in inter/inter.crt -noout -ext basicConstraints,keyUsage,nameConstraints | sed 's/^/  /'

section "3. База промежуточного CA и листовые сертификаты (openssl ca)"
( cd inter && : > index.txt && echo 01 > crlnumber && echo 1000 > serial )
cat > inter/ca.cnf <<X
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
X
mkleaf() { # имя, CN, SAN
  cat > server/$1.ext <<X
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=$3
X
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server/$1.key; chmod 600 server/$1.key
  "$OPENSSL" req -new -key server/$1.key -subj "/C=BY/O=Lab PKI/CN=$2" -out server/$1.csr
  "$OPENSSL" ca -config inter/ca.cnf -batch -in server/$1.csr -extfile server/$1.ext -notext -out server/$1.crt 2>&1 | grep -E 'Write out|Updated' | sed "s/^/  $1: /"
}
mkleaf app app.lab.local 'DNS:app.lab.local'
mkleaf localhost localhost 'DNS:localhost,IP:127.0.0.1'
cat server/app.crt inter/inter.crt > server/fullchain.pem
for c in root/root inter/inter server/app server/localhost; do
  echo "--- $c.crt"; "$OPENSSL" x509 -in $c.crt -noout -subject -issuer -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName,nameConstraints 2>/dev/null | grep -v '^$' | sed 's/^/  /'
done

section "4. Проверка цепочки (задача варианта)"
"$OPENSSL" verify -CAfile root/root.crt -untrusted inter/inter.crt server/app.crt 2>&1 | sed 's/^/  /'
"$OPENSSL" verify -CAfile root/root.crt -untrusted inter/inter.crt server/app.crt >/dev/null 2>&1; expect "лист app.lab.local: OK" $?
neg "лист для localhost вне поддерева .lab.local"
"$OPENSSL" verify -CAfile root/root.crt -untrusted inter/inter.crt server/localhost.crt 2>&1 | sed 's/^/  /'
"$OPENSSL" verify -CAfile root/root.crt -untrusted inter/inter.crt server/localhost.crt 2>&1 | grep -q 'permitted subtree violation'; expect "localhost: permitted subtree violation" $?
neg "без промежуточного сертификата"
"$OPENSSL" verify -CAfile root/root.crt server/app.crt 2>&1 | sed 's/^/  /'
fails "$OPENSSL" verify -CAfile root/root.crt server/app.crt; expect "неполная цепочка отвергается" $?

section "5. nginx: только TLS 1.3, TLS_AES_128_GCM_SHA256, X25519"
mkdir -p "$NGX/logs"
cat > "$NGX/nginx.conf" <<X
worker_processes 1;
pid $NGX/nginx.pid;
error_log $NGX/logs/error.log info;
events { worker_connections 64; }
http {
    access_log $NGX/logs/access.log;
    client_body_temp_path $NGX/t1; proxy_temp_path $NGX/t2; fastcgi_temp_path $NGX/t3;
    uwsgi_temp_path $NGX/t4; scgi_temp_path $NGX/t5;
    server {
        listen 127.0.0.1:$PORT ssl;
        server_name app.lab.local;
        ssl_certificate     $OUT/server/fullchain.pem;
        ssl_certificate_key $OUT/server/app.key;
        ssl_protocols TLSv1.3;
        ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256;
        ssl_ecdh_curve X25519;
        ssl_session_tickets on;
        location / { return 200 'tls13 ok'; }
    }
}
X
grep -E 'ssl_|listen' "$NGX/nginx.conf" | sed 's/^ */  /'
"$NGINX" -p "$NGX" -c "$NGX/nginx.conf" -t 2>&1 | sed 's/^/  nginx -t: /'
"$NGINX" -p "$NGX" -c "$NGX/nginx.conf" 2>&1; sleep 1
(exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; expect "nginx слушает порт $PORT" $?

URL="https://app.lab.local:$PORT/"; RES=(--resolve "app.lab.local:$PORT:127.0.0.1")
section "6. Клиент"
CODE=$("$CURL" -sS -v "${RES[@]}" --cacert root/root.crt -o body.txt -w '%{http_code}' "$URL" 2>verbose.txt)
echo "  HTTP $CODE, тело: $(cat body.txt)"; grep -E 'SSL connection|TLSv1.3' verbose.txt | head -3 | sed 's/^/  /'
[ "$CODE" = "200" ]; expect "curl --cacert root.crt: HTTP 200" $?
grep -q 'TLSv1.3' verbose.txt; expect "TLSv1.3" $?
grep -qE 'TLS_AES_128_GCM_SHA256|AES128-GCM' verbose.txt; expect "шифр TLS_AES_128_GCM_SHA256" $?

neg "curl без --cacert"
"$CURL" -sS "${RES[@]}" -o /dev/null "$URL" 2>&1 | head -2 | sed 's/^/  /'
"$CURL" -sS "${RES[@]}" -o /dev/null "$URL" 2>/dev/null; [ $? -eq 60 ]; expect "exit 60" $?
neg "имя вне SAN (127.0.0.2)"
"$CURL" -sS --connect-to "127.0.0.2:$PORT:127.0.0.1:$PORT" --cacert root/root.crt -o /dev/null "https://127.0.0.2:$PORT/" 2>&1 | head -2 | sed 's/^/  /'
"$CURL" -sS --connect-to "127.0.0.2:$PORT:127.0.0.1:$PORT" --cacert root/root.crt -o /dev/null "https://127.0.0.2:$PORT/" 2>/dev/null; [ $? -eq 60 ]; expect "exit 60: имя не в SAN" $?
neg "чужой корень"
"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out other/other.key
"$OPENSSL" req -new -x509 -key other/other.key -subj '/CN=Other Root' -days 1 -out other/other.crt
"$CURL" -sS "${RES[@]}" --cacert other/other.crt -o /dev/null "$URL" 2>&1 | head -2 | sed 's/^/  /'
"$CURL" -sS "${RES[@]}" --cacert other/other.crt -o /dev/null "$URL" 2>/dev/null; [ $? -eq 60 ]; expect "exit 60" $?
neg "TLS 1.2"
( sleep 1 ) | "$OPENSSL" s_client -connect 127.0.0.1:$PORT -servername app.lab.local -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol' | sed 's/^/  /'
( sleep 1 ) | "$OPENSSL" s_client -connect 127.0.0.1:$PORT -servername app.lab.local -tls1_2 -CAfile root/root.crt 2>&1 | grep -q 'alert protocol version'; expect "alert protocol version (70)" $?

section "7. Рукопожатие (s_client -trace) и журнал ключей"
rm -f keys.log
( sleep 1 ) | "$OPENSSL" s_client -connect 127.0.0.1:$PORT -servername app.lab.local -CAfile root/root.crt -tls1_3 \
  -groups X25519 -trace -keylogfile keys.log > trace.txt 2>&1
grep -E '^ +(ClientHello|ServerHello|EncryptedExtensions|Certificate|CertificateVerify|Finished|NewSessionTicket),' trace.txt | sed 's/^ */  /'
grep -E 'Cipher Suite|server_name|group' trace.txt | sort -u | head -6 | sed 's/^ */  /'
grep -q 'Verification: OK\|Verify return code: 0' trace.txt; expect "проверка цепочки в s_client: OK" $?
echo "  keys.log: $(wc -l < keys.log | tr -d ' ') строк; метки: $(cut -d' ' -f1 keys.log | sort -u | tr '\n' ' ')"

section "Итог"; echo "  Пройдено: $PASS, не пройдено: $FAIL"
[ "$FAIL" -eq 0 ]
