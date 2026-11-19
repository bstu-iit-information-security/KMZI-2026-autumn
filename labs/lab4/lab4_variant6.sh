#!/usr/bin/env bash
# Лабораторная работа №4. Вариант 6.
# Один модуль-оркестратор: openssl + nginx + curl + tcpdump + tshark.
# Криптография не реализуется самостоятельно — только вызовы CLI-инструментов.
set -euo pipefail

LAB=~/lab4
REPORT=$LAB/report.txt
NGINX_CONF=/etc/nginx/conf.d/lab4.conf
PORT_HTTPS=8443
PORT_SSERVER=8453

# --- проверка инструментов ---------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "НЕТ: $1"; exit 1; }; }
need openssl; need nginx; need curl; need tcpdump; need tshark

# --- чистая пересборка -------------------------------------------------------
rm -rf "$LAB"
mkdir -p "$LAB"/{root,inter,server,client}
cd "$LAB"

log() { echo "$@" | tee -a "$REPORT"; }
section() { log ""; log "=== $* ==="; }

section "0. Версии инструментов"
openssl version | tee -a "$REPORT"
nginx -v 2>&1 | tee -a "$REPORT"
curl --version | head -n1 | tee -a "$REPORT"
tshark --version | head -n1 | tee -a "$REPORT"

# =============================================================================
# 1. Корневой CA — ECDSA P-384
# =============================================================================
section "1. Корневой CA (ECDSA P-384)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out root/root.key
chmod 600 root/root.key
openssl req -new -x509 -key root/root.key -sha384 -days 3650 \
  -subj '/C=BY/O=Lab PKI/CN=Lab Root CA P384' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -out root/root.crt
openssl x509 -in root/root.crt -noout -text \
  | grep -E 'Basic Constraints|CA:|Key Usage' -A1 | tee -a "$REPORT"

# =============================================================================
# 2. Промежуточный CA — ECDSA P-384, pathlen:0
# =============================================================================
section "2. Промежуточный CA (ECDSA P-384, pathlen:0)"
cat > inter/inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out inter/inter.key
chmod 600 inter/inter.key
openssl req -new -key inter/inter.key \
  -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA P384' -out inter/inter.csr
openssl x509 -req -in inter/inter.csr -CA root/root.crt -CAkey root/root.key \
  -CAcreateserial -sha384 -days 1825 -extfile inter/inter.ext -out inter/inter.crt
openssl x509 -in inter/inter.crt -noout -text \
  | grep -E 'Basic Constraints|CA:TRUE|pathlen' -A1 | tee -a "$REPORT"

# =============================================================================
# 3. База данных промежуточного CA
# =============================================================================
section "3. База openssl ca"
cd inter
touch index.txt
echo 01 > crlnumber
echo 1000 > serial
cd ..
cat > inter/ca.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = $LAB/inter
database         = \$dir/index.txt
new_certs_dir    = \$dir
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
certificate      = \$dir/inter.crt
private_key      = \$dir/inter.key
default_md       = sha384
default_days     = 365
default_crl_days = 30
unique_subject   = no
copy_extensions  = none
policy           = policy_any

[ policy_any ]
commonName       = supplied
EOF

# =============================================================================
# 4. Серверный сертификат — ECDSA P-256, SAN localhost + 127.0.0.1
# =============================================================================
section "4. Серверный сертификат (ECDSA P-256)"
cat > server/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server/server.key
chmod 600 server/server.key
openssl req -new -key server/server.key \
  -subj '/C=BY/O=Lab PKI/CN=localhost' -out server/server.csr
openssl ca -config inter/ca.cnf -batch -in server/server.csr \
  -extfile server/server.ext -notext -out server/server.crt 2>&1 | tee -a "$REPORT"
openssl x509 -in server/server.crt -noout -text \
  | grep -E 'Subject Alternative Name|DNS:|IP Address|Extended Key Usage|TLS Web Server' -A1 | tee -a "$REPORT"

# =============================================================================
# 5. Проверка цепочки
# =============================================================================
section "5. Проверка цепочки"
log "[+] полная цепочка (root + intermediate):"
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt | tee -a "$REPORT"
log "[+] без intermediate (ожидаемо ошибка):"
openssl verify -CAfile root/root.crt server/server.crt 2>&1 | tee -a "$REPORT" || true

# =============================================================================
# 6. fullchain.pem + nginx
# =============================================================================
section "6. nginx: TLS 1.3, P-384, AES-256-GCM"
cat server/server.crt inter/inter.crt > server/fullchain.pem
sudo tee "$NGINX_CONF" >/dev/null <<EOF
server {
    listen $PORT_HTTPS ssl;
    server_name localhost;
    ssl_certificate     $LAB/server/fullchain.pem;
    ssl_certificate_key $LAB/server/server.key;
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;
    ssl_ecdh_curve P-384;
    ssl_session_tickets on;
    location / { return 200 'tls13 ok variant6'; }
}
EOF
sudo nginx -t 2>&1 | tee -a "$REPORT"
sudo systemctl restart nginx

# =============================================================================
# 7. Позитивный тест
# =============================================================================
section "7. Позитивный тест curl"
curl -sv --cacert root/root.crt "https://localhost:$PORT_HTTPS/" 2>&1 \
  | grep -E 'HTTP/|TLSv1|subject:|issuer:|tls13 ok' | tee -a "$REPORT"

# =============================================================================
# 8. Негативные тесты
# =============================================================================
section "8. НЕГАТИВНЫЕ тесты"

log "[neg 1] curl без --cacert (нет доверия корню):"
curl -sS "https://localhost:$PORT_HTTPS/" 2>&1 | head -n2 | tee -a "$REPORT" || true

log "[neg 2] curl с чужим корнем:"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/other.key
openssl req -new -x509 -key /tmp/other.key -subj '/CN=Other Root' -days 1 -out /tmp/other.crt
curl -sS --cacert /tmp/other.crt "https://localhost:$PORT_HTTPS/" 2>&1 | head -n2 | tee -a "$REPORT" || true

log "[neg 3] curl на 127.0.0.2 (имя вне SAN):"
curl -sS --cacert root/root.crt "https://127.0.0.2:$PORT_HTTPS/" 2>&1 | head -n2 | tee -a "$REPORT" || true

log "[neg 4] TLS 1.2 отвергается сервером:"
( sleep 1 ) | openssl s_client -connect "localhost:$PORT_HTTPS" -tls1_2 \
  -CAfile root/root.crt 2>&1 \
  | grep -Ei 'alert|protocol' | tee -a "$REPORT" || true

# =============================================================================
# 9. Задача варианта 6: HelloRetryRequest
#    Сервер s_server принимает только P-384, клиент сначала предлагает X25519.
# =============================================================================
section "9. HelloRetryRequest: s_server P-384 vs клиент X25519"

openssl s_server -accept "$PORT_SSERVER" \
  -cert server/server.crt -key server/server.key \
  -cert_chain inter/inter.crt \
  -tls1_3 -groups P-384 \
  -ciphersuites TLS_AES_256_GCM_SHA384 -www \
  >server/s_server.log 2>&1 &
SERVER_PID=$!
sleep 2

log "[+] s_client: -groups X25519:P-384 (сервер выберет P-384 через HRR)"
( sleep 1 ) | openssl s_client -connect "localhost:$PORT_SSERVER" \
  -servername localhost \
  -CAfile root/root.crt \
  -tls1_3 \
  -groups X25519:P-384 \
  -keylogfile client/keys.log \
  -brief 2>&1 \
  | grep -E 'Server Temp Key|Verification|Protocol' | tee -a "$REPORT" || true

# =============================================================================
# 10. Захват tcpdump + повторный клиент с журналом ключей
# =============================================================================
section "10. Захват рукопожатия и анализ tshark"

sudo tcpdump -i lo -w client/hrr.pcap "tcp port $PORT_SSERVER" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 2

( sleep 1 ) | openssl s_client -connect "localhost:$PORT_SSERVER" \
  -servername localhost -CAfile root/root.crt -tls1_3 \
  -groups X25519:P-384 -keylogfile client/keys.log -brief >/dev/null 2>&1 || true
sleep 1

sudo kill "$TCPDUMP_PID" 2>/dev/null || true
sleep 1
sudo chown "$USER" client/hrr.pcap

kill "$SERVER_PID" 2>/dev/null || true

log "[+] метки в keys.log:"
cut -d' ' -f1 client/keys.log 2>/dev/null | sort -u | tee -a "$REPORT" || true

log "[+] без журнала ключей (видны только ClientHello/ServerHello):"
tshark -r client/hrr.pcap -Y tls \
  -T fields -e frame.number -e tls.record.content_type -e tls.handshake.type \
  2>/dev/null | tee -a "$REPORT"

log "[+] с журналом ключей (полный набор типов сообщений):"
tshark -r client/hrr.pcap -o tls.keylog_file:client/keys.log \
  -Y tls.handshake -T fields -e frame.number -e tls.handshake.type \
  2>/dev/null | tee -a "$REPORT"

log "[+] подсчёт ClientHello/ServerHello (для варианта 6 должно быть 2 и 2):"
tshark -r client/hrr.pcap -o tls.keylog_file:client/keys.log \
  -Y 'tls.handshake.type == 1' -T fields -e frame.number 2>/dev/null \
  | wc -l | tee -a "$REPORT"
tshark -r client/hrr.pcap -o tls.keylog_file:client/keys.log \
  -Y 'tls.handshake.type == 2' -T fields -e frame.number 2>/dev/null \
  | wc -l | tee -a "$REPORT"

log "[+] HRR: поиск Hello Retry Request и Selected Group:"
tshark -r client/hrr.pcap -o tls.keylog_file:client/keys.log \
  -Y 'tls.handshake.type == 2' -V 2>/dev/null \
  | grep -Ei 'Hello Retry Request|Selected Group|Supported Groups' | tee -a "$REPORT" || true

log "[+] шифр и группа key_share в ServerHello:"
tshark -r client/hrr.pcap -o tls.keylog_file:client/keys.log \
  -Y 'tls.handshake.type == 2' -T fields \
  -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group \
  2>/dev/null | tee -a "$REPORT"

log "[+] SNI в ClientHello:"
tshark -r client/hrr.pcap -o tls.keylog_file:client/keys.log \
  -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name \
  2>/dev/null | tee -a "$REPORT"

log "[+] SAN сертификата сервера из захвата:"
tshark -r client/hrr.pcap -o tls.keylog_file:client/keys.log \
  -Y 'tls.handshake.type == 11' -V 2>/dev/null \
  | grep -E 'dNSName|iPAddress' | tee -a "$REPORT" || true

section "Готово"
log "Отчёт: $REPORT"
log "pcap:   $LAB/client/hrr.pcap"
log "keys:   $LAB/client/keys.log"