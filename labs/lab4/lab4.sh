#!/usr/bin/env bash
# Лабораторная №4, ВАРИАНТ 1 (Name Constraints .lab.local)
set -euo pipefail

LAB="$HOME/lab4"
USER_NAME="$(whoami)"
PORT=8443
EXPECT_DOMAIN="app.lab.local"
NC_DOMAIN=".lab.local"

# ---------- проверка инструментов ----------
need() { command -v "$1" >/dev/null 2>&1 || { echo "НЕТ: $1 — установи: sudo apt install -y $2"; exit 1; }; }
need openssl  openssl
need nginx    nginx-light
need curl     curl
need tcpdump  tcpdump
need tshark   tshark

echo "==> [0] Подготовка каталогов"
rm -rf "$LAB"
mkdir -p "$LAB"/{root,inter,server,client,test}
cd "$LAB"

# ---------- 1. Корневой CA ----------
echo "==> [1] Корневой CA (ECDSA P-256)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root/root.key
chmod 600 root/root.key

openssl req -new -x509 -key root/root.key -sha256 -days 3650 \
  -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -out root/root.crt

openssl x509 -in root/root.crt -noout -ext basicConstraints,keyUsage

# ---------- 2. Промежуточный CA + nameConstraints ----------
echo "==> [2] Промежуточный CA (ECDSA P-256, nameConstraints=$NC_DOMAIN)"
cat > inter/inter.ext <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
nameConstraints=critical,permitted;DNS:$NC_DOMAIN
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
chmod 600 inter/inter.key

openssl req -new -key inter/inter.key \
  -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' \
  -out inter/inter.csr

# По варианту 1 промежуточный CA выпускается через openssl x509 -req
openssl x509 -req -in inter/inter.csr \
  -CA root/root.crt -CAkey root/root.key -CAcreateserial \
  -sha256 -days 1825 -extfile inter/inter.ext \
  -out inter/inter.crt

openssl x509 -in inter/inter.crt -noout -ext basicConstraints,keyUsage,nameConstraints

# ---------- 3. База промежуточного CA ----------
echo "==> [3] База промежуточного CA (index.txt, serial, crlnumber)"
touch inter/index.txt
echo 01 > inter/crlnumber
echo 1000 > inter/serial

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
default_md       = sha256
default_days     = 365
default_crl_days = 30
unique_subject   = no
copy_extensions  = none
policy           = policy_any

[ policy_any ]
commonName       = supplied
EOF

# ---------- 4. Серверный сертификат ----------
echo "==> [4] Серверный сертификат (SAN=$EXPECT_DOMAIN)"
cat > server/server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:$EXPECT_DOMAIN
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server/server.key
chmod 600 server/server.key

openssl req -new -key server/server.key \
  -subj '/C=BY/O=Lab PKI/CN=localhost' \
  -out server/server.csr

openssl ca -config inter/ca.cnf -batch \
  -in server/server.csr -extfile server/server.ext \
  -notext -out server/server.crt

cat server/server.crt inter/inter.crt > server/fullchain.pem

# ---------- 5. Проверка цепочки ----------
echo "==> [5] Проверка цепочки"
echo "--- ожидаемо OK ---"
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
echo "--- ожидаемо FAIL (без промежуточного) ---"
openssl verify -CAfile root/root.crt server/server.crt || true
echo "--- расширения листа ---"
openssl x509 -in server/server.crt -noout -ext subjectAltName,extendedKeyUsage,basicConstraints

# ---------- 6. nginx ----------
echo "==> [6] nginx: TLS 1.3, TLS_AES_128_GCM_SHA256, P-256"
NGINX_CONF=/etc/nginx/conf.d/lab4.conf
sudo tee "$NGINX_CONF" >/dev/null <<EOF
server {
    listen $PORT ssl;
    server_name $EXPECT_DOMAIN localhost;
    ssl_certificate     $LAB/server/fullchain.pem;
    ssl_certificate_key $LAB/server/server.key;
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256;
    ssl_ecdh_curve P-256;
    ssl_session_tickets on;
    location / { return 200 'tls13 ok'; }
}
EOF

sudo nginx -t
sudo systemctl restart nginx

# ---------- 7. Проверка клиентом ----------
echo "==> [7] curl (ожидаемо 200 + tls13 ok)"
curl -sS --cacert root/root.crt \
  --resolve "$EXPECT_DOMAIN:$PORT:127.0.0.1" \
  "https://$EXPECT_DOMAIN:$PORT/"
echo
echo "--- Негативные тесты (ожидаемо ошибки) ---"
curl https://localhost:$PORT/ || true
curl --cacert root/root.crt https://127.0.0.2:$PORT/ || true
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/other.key
openssl req -new -x509 -key /tmp/other.key -subj '/CN=Other Root' -days 1 -out /tmp/other.crt
curl --cacert /tmp/other.crt https://localhost:$PORT/ || true
( sleep 1 ) | openssl s_client -connect localhost:$PORT -tls1_2 -CAfile root/root.crt 2>&1 \
  | grep -E 'alert|Protocol' || true

# ---------- 8. Захват + SSLKEYLOGFILE ----------
echo "==> [8] Захват рукопожатия + журнал ключей"
cd "$LAB/client"
sudo tcpdump -i lo -w handshake.pcap "tcp port $PORT" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

SSLKEYLOGFILE="$LAB/client/keys.log" curl -sS --cacert ../root/root.crt \
  --resolve "$EXPECT_DOMAIN:$PORT:127.0.0.1" \
  "https://$EXPECT_DOMAIN:$PORT/" >/dev/null

sleep 1
sudo kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
sudo chown "$USER_NAME" handshake.pcap
echo "Метки в keys.log:"; cut -d' ' -f1 keys.log | sort -u

# ---------- 9. tshark ----------
echo "==> [9] tshark"
echo "--- Без ключей (тип 1 и 2) ---"
tshark -r handshake.pcap -Y 'tls.handshake.type' -T fields \
  -e frame.number -e tls.record.content_type -e tls.handshake.type

echo "--- С ключами (8,11,15,20) ---"
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y tls.handshake -T fields \
  -e frame.number -e tls.handshake.type

echo "--- Cipher / group ---"
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 2' \
  -T fields -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group

echo "--- SNI ---"
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 1' \
  -T fields -e tls.handshake.extensions_server_name

echo "--- SAN из Certificate ---"
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 11' -V \
  | grep -E 'dNSName|iPAddress' || true

echo "--- CertificateVerify sig alg ---"
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 15' \
  -T fields -e tls.handshake.sig_hash_alg

# ---------- 10. Name Constraints: good vs bad ----------
cd "$LAB"
echo "==> [10] Name Constraints: good ($EXPECT_DOMAIN) vs bad (localhost)"

# good
cat > test/good.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$EXPECT_DOMAIN
EOF
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out test/good.key
chmod 600 test/good.key
openssl req -new -key test/good.key -subj "/CN=$EXPECT_DOMAIN" -out test/good.csr
openssl ca -config inter/ca.cnf -batch -in test/good.csr \
  -extfile test/good.ext -notext -out test/good.crt

# bad
cat > test/bad.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
EOF
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out test/bad.key
chmod 600 test/bad.key
openssl req -new -key test/bad.key -subj '/CN=localhost' -out test/bad.csr
openssl ca -config inter/ca.cnf -batch -in test/bad.csr \
  -extfile test/bad.ext -notext -out test/bad.crt

echo "--- good (ожидаемо OK) ---"
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt test/good.crt

echo "--- bad (ожидаемо permitted subtree violation) ---"
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt test/bad.crt || true

echo "--- реальное рукопожатие s_server с bad.crt ---"
( sleep 4 ) | openssl s_server -accept 9443 -cert test/bad.crt -key test/bad.key \
  -cert_chain inter/inter.crt -tls1_3 \
  -ciphersuites TLS_AES_128_GCM_SHA256 \
  -groups P-256 \
  -www >/dev/null 2>&1 &
SS_PID=$!
sleep 1
( sleep 1 ) | openssl s_client -connect localhost:9443 -servername localhost \
  -CAfile root/root.crt -tls1_3 -brief || true
kill "$SS_PID" 2>/dev/null || true

# ---------- 11. Структура сертификатов ----------
echo
echo "==> [11] Структура сертификатов"
openssl x509 -in ~/lab4/server/server.crt -noout -text

echo
echo "==> Готово."