#!/usr/bin/env bash
# lab4-variant4.sh — лабораторная №4, вариант 4 (mTLS)
# Стенд: Ubuntu 24.04, OpenSSL 3.0.13, nginx 1.24.0, curl 8.5.0, tshark 4.2.2
#
# Параметры варианта 4:
#   root/inter  — Ed25519
#   server      — ECDSA P-384 (secp384r1)
#   client      — ECDSA P-256 (prime256v1)   ← mTLS
#   ECDHE       — P-384
#   шифр        — TLS_AES_256_GCM_SHA384 (0x1302)
#   протокол    — только TLSv1.3
#   mTLS        — ssl_verify_client on + ssl_client_certificate (root+inter)
#   порт        — 8443, каталог — ~/lab4

set -eu
LAB="${LAB:-$HOME/lab4}"
PORT="${PORT:-8443}"
SUDO="${SUDO:-sudo}"
ME="$(id -un)"

log() { printf '\n=== %s ===\n' "$*"; }

# запуск негативного теста: печатает команду и exit-код, но не роняет скрипт
neg() {
  printf '\n$ %s\n' "$*"
  set +e
  "$@" 2>&1
  local rc=$?
  set -e
  printf '[exit=%s]\n' "$rc"
}

check_deps() {
  for t in openssl curl nginx tshark tcpdump; do
    command -v "$t" >/dev/null || { echo "не найден: $t"; exit 1; }
  done
  openssl version | grep -q '^OpenSSL 3\.' || { echo 'нужен OpenSSL 3.x'; exit 1; }
}

# ---------- clean ----------
do_clean() {
  log "clean: сносим $LAB и /etc/nginx/conf.d/lab4.conf"
  rm -rf "$LAB"
  $SUDO rm -f /etc/nginx/conf.d/lab4.conf
  $SUDO systemctl restart nginx 2>/dev/null || true
}

# ---------- ca ----------
do_ca() {
  log "ca: корневой и промежуточный CA (Ed25519)"
  mkdir -p "$LAB"/{root,inter,server,client,structure}
  cd "$LAB"

  # Корень: самоподписанный
  openssl genpkey -algorithm ED25519 -out root/root.key
  chmod 600 root/root.key
  openssl req -new -x509 -key root/root.key -days 3650 \
    -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -out root/root.crt

  # Промежуточный: pathlen:0
  cat > inter/inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
  openssl genpkey -algorithm ED25519 -out inter/inter.key
  chmod 600 inter/inter.key
  openssl req -new -key inter/inter.key \
    -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' -out inter/inter.csr
  openssl x509 -req -in inter/inter.csr \
    -CA root/root.crt -CAkey root/root.key -CAcreateserial \
    -days 1825 -extfile inter/inter.ext -out inter/inter.crt

  # База CA (нужна openssl ca и отзыву)
  cd "$LAB/inter"
  : > index.txt
  echo 01   > crlnumber
  echo 1000 > serial
  cd "$LAB"
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
}

# ---------- certs ----------
do_certs() {
  log "certs: server (P-384), client (P-256), revoked (P-256)"
  cd "$LAB"

  # --- server ---
  cat > server/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out server/server.key
  chmod 600 server/server.key
  openssl req -new -key server/server.key \
    -subj '/C=BY/O=Lab PKI/CN=localhost' -out server/server.csr
  openssl ca -config inter/ca.cnf -batch -in server/server.csr \
    -extfile server/server.ext -notext -out server/server.crt

  # --- client (mTLS) ---
  cat > client/client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:client.lab.local
EOF
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client/client.key
  chmod 600 client/client.key
  openssl req -new -key client/client.key \
    -subj '/C=BY/O=Lab PKI/CN=client.lab.local' -out client/client.csr
  openssl ca -config inter/ca.cnf -batch -in client/client.csr \
    -extfile client/client.ext -notext -out client/client.crt

  # --- revoked (тестовый, для CRL) ---
  cat > server/revoked.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:revoked.local
EOF
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server/revoked.key
  chmod 600 server/revoked.key
  openssl req -new -key server/revoked.key \
    -subj '/CN=revoked.local' -out server/revoked.csr
  openssl ca -config inter/ca.cnf -batch -in server/revoked.csr \
    -extfile server/revoked.ext -notext -out server/revoked.crt

  # --- цепочки ---
  cat server/server.crt inter/inter.crt > server/fullchain.pem
  cat client/client.crt inter/inter.crt > client/client-fullchain.pem
  cat root/root.crt     inter/inter.crt > client/ca-bundle.pem

  # --- verify ---
  log "verify: с промежуточным (OK) и без (негатив)"
  neg openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
  neg openssl verify -CAfile client/ca-bundle.pem client/client.crt
  neg openssl verify -CAfile root/root.crt server/server.crt
}

# ---------- nginx ----------
do_nginx() {
  log "nginx: конфиг, nginx -t, restart"
  cat <<EOF | $SUDO tee /etc/nginx/conf.d/lab4.conf >/dev/null
server {
    listen $PORT ssl;
    server_name localhost;

    ssl_certificate     $LAB/server/fullchain.pem;
    ssl_certificate_key $LAB/server/server.key;

    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;
    ssl_ecdh_curve P-384;

    ssl_verify_client      on;
    ssl_verify_depth       2;   # root→inter→client, с запасом
    ssl_client_certificate $LAB/client/ca-bundle.pem;

    location / { return 200 'mtls tls13 ok\n'; }
}
EOF
  $SUDO nginx -t
  $SUDO systemctl restart nginx
  ss -ltnp 2>/dev/null | grep ":$PORT" || true
}

# ---------- tests: позитив + негативы Н1–Н6 ----------
do_tests() {
  cd "$LAB"
  log "позитив: curl с --cacert + клиентский серт (ожидаем HTTP 200, TLSv1.3)"
  curl -v --cacert root/root.crt \
       --cert client/client-fullchain.pem --key client/client.key \
       "https://localhost:$PORT/" 2>&1 | grep -E \
       'SSL connection|subjectAltName|HTTP/|Request CERT|Certificate \(11\)' || true

  log "Н1: без клиентского серта (HTTP 400, НЕ TLS-alert)"
  neg curl -sv --cacert root/root.crt "https://localhost:$PORT/"

  log "Н2: без --cacert (exit 60)"
  neg curl -sS --cert client/client-fullchain.pem --key client/client.key \
    "https://localhost:$PORT/"

  log "Н3: 127.0.0.2 вне SAN (exit 60)"
  neg curl -sS --cacert root/root.crt \
    --cert client/client-fullchain.pem --key client/client.key \
    "https://127.0.0.2:$PORT/"

  log "Н4: чужой корень (exit 60)"
  [ -f /tmp/other.key ] || openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/other.key
  [ -f /tmp/other.crt ] || openssl req -new -x509 -key /tmp/other.key -subj '/CN=Other Root' -days 1 -out /tmp/other.crt
  neg curl -sS --cacert /tmp/other.crt \
    --cert client/client-fullchain.pem --key client/client.key \
    "https://localhost:$PORT/"

  log "Н5: TLS 1.2 (alert protocol version 70)"
  neg sh -c "( sleep 1 ) | openssl s_client -connect localhost:$PORT -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'"

  log "Н6: -attime через 400 дней (certificate has expired)"
  local FUTURE=$(( $(date +%s) + 400*24*3600 ))
  neg openssl verify -attime "$FUTURE" -CAfile root/root.crt \
    -untrusted inter/inter.crt server/server.crt
}

# ---------- crl: отзыв + CRL + Н7 ----------
do_crl() {
  cd "$LAB"
  log "crl: отзыв revoked.crt + генерация CRL"

  # идемпотентность: если 1002 уже R, повторно не отзываем
  if ! grep -q $'\tR\t' inter/index.txt 2>/dev/null; then
    openssl ca -config inter/ca.cnf -revoke server/revoked.crt
  else
    echo "revoked.crt уже отозван — пропускаем"
  fi
  openssl ca -config inter/ca.cnf -gencrl -out inter/crl.pem

  log "контроль: неотозванный server.crt с CRL проходит (OK)"
  neg openssl verify -CAfile root/root.crt -untrusted inter/inter.crt \
    -crl_check -CRLfile inter/crl.pem server/server.crt

  log "Н7: отозванный revoked.crt (certificate revoked)"
  neg openssl verify -CAfile root/root.crt -untrusted inter/inter.crt \
    -crl_check -CRLfile inter/crl.pem server/revoked.crt
}

# ---------- capture ----------
do_capture() {
  cd "$LAB"
  log "capture: tcpdump + curl с SSLKEYLOGFILE"
  : > client/keys.log
  $SUDO tcpdump -i lo -w "$LAB/client/handshake.pcap" "tcp port $PORT" &
  local TPID=$!
  sleep 1
  SSLKEYLOGFILE="$LAB/client/keys.log" \
    curl -sS --cacert root/root.crt \
         --cert client/client-fullchain.pem --key client/client.key \
         "https://localhost:$PORT/"
  sleep 1
  $SUDO kill -INT "$TPID" 2>/dev/null || true
  wait "$TPID" 2>/dev/null || true
  $SUDO chown "$ME" "$LAB/client/handshake.pcap"
  wc -l client/keys.log
  cut -d' ' -f1 client/keys.log | sort -u
}

# ---------- analyze ----------
do_analyze() {
  cd "$LAB"
  log "tshark БЕЗ ключей"
  tshark -r client/handshake.pcap -Y tls -T fields \
    -e frame.number -e tls.record.content_type -e tls.handshake.type

  log "tshark С ключами"
  tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
    -Y tls.handshake -T fields \
    -e frame.number -e ip.src -e tls.handshake.type

  log "шифр и группа (ServerHello)"
  tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
    -Y 'tls.handshake.type == 2' -T fields \
    -e frame.number -e tls.handshake.ciphersuite \
    -e tls.handshake.extensions_key_share_group

  log "SNI (ClientHello)"
  tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
    -Y 'tls.handshake.type == 1' -T fields \
    -e frame.number -e tls.handshake.extensions_server_name

  log "SAN (Certificate — серверный и клиентский)"
  tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
    -Y 'tls.handshake.type == 11' -V 2>/dev/null \
    | grep -E 'dNSName|iPAddress' || true

  log "CertificateRequest (mTLS)"
  tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
    -Y 'tls.handshake.type == 13' -T fields \
    -e frame.number -e tls.handshake.sig_hash_alg
}

# ---------- collect ----------
do_collect() {
  cd "$LAB"
  mkdir -p structure
  log "collect: полный -text по всем сертификатам"
  for f in root/root.crt inter/inter.crt server/server.crt client/client.crt; do
    local out="structure/$(basename "${f%.crt}").txt"
    openssl x509 -in "$f" -noout -text > "$out"
  done
  [ -f server/revoked.crt ] && openssl x509 -in server/revoked.crt -noout -text > structure/revoked.txt

  log "collect: база CA"
  cp inter/index.txt    structure/index.txt
  cp inter/serial       structure/serial.txt
  cp inter/crlnumber    structure/crlnumber.txt

  log "collect: serial | status | subject"
  awk -F'\t' '{print $4"\t"$1"\t"$6}' inter/index.txt > structure/serials.txt

  log "collect: поля из pcap"
  if [ -f client/handshake.pcap ] && [ -f client/keys.log ]; then
    {
      echo "--- ServerHello: ciphersuite / key_share_group ---"
      tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
        -Y 'tls.handshake.type == 2' -T fields \
        -e frame.number -e tls.handshake.ciphersuite \
        -e tls.handshake.extensions_key_share_group 2>/dev/null
      echo "--- ClientHello: SNI ---"
      tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
        -Y 'tls.handshake.type == 1' -T fields \
        -e frame.number -e tls.handshake.extensions_server_name 2>/dev/null
      echo "--- Certificate: dNSName / iPAddress ---"
      tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
        -Y 'tls.handshake.type == 11' -V 2>/dev/null \
        | grep -E 'dNSName|iPAddress' || true
      echo "--- CertificateRequest: sig_hash_alg ---"
      tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
        -Y 'tls.handshake.type == 13' -T fields \
        -e frame.number -e tls.handshake.sig_hash_alg 2>/dev/null
    } > structure/pcap-summary.txt
  fi

  echo "готово: $LAB/structure/"
  ls -1 structure/
}

# ---------- dispatcher ----------
check_deps
case "${1:-all}" in
  clean)   do_clean ;;
  ca)      do_ca ;;
  certs)   do_certs ;;
  nginx)   do_nginx ;;
  tests)   do_tests ;;
  crl)     do_crl ;;
  capture) do_capture ;;
  analyze) do_analyze ;;
  collect) do_collect ;;
  all)     do_ca; do_certs; do_nginx; do_tests; do_crl; do_capture; do_analyze; do_collect ;;
  *) echo "usage: $0 {clean|ca|certs|nginx|tests|crl|capture|analyze|collect|all}"; exit 1 ;;
esac