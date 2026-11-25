#!/usr/bin/env bash
# lab4-variant8.sh — лабораторная №4, вариант 8
# Стенд: Ubuntu 24.04, OpenSSL 3.0.13, nginx 1.24.0, curl 8.5.0, tshark 4.2.2
#
# Вариант 8:
#   root/inter/server — Ed25519
#   ECDHE             — X25519
#   шифр              — TLS_CHACHA20_POLY1305_SHA256 (0x1303)
#   протокол          — только TLSv1.3
#   mTLS              — НЕТ
#   задача варианта   — срок действия: openssl verify -attime +400 дней
#   порт              — 8443, каталог — ~/lab4
set -eu

WORK="${LAB:-$HOME/lab4}"
HTTPS_PORT="${PORT:-8443}"
ESCALATE="${SUDO:-sudo}"
CALLER="$(id -un)"

say()  { printf '\n>>> %s\n' "$*"; }
hr()   { printf '%s\n' '------------------------------------------------------------'; }

# Выполнить команду, зафиксировать exit-код, не уронить скрипт.
# Используется и для позитивных, и для негативных проверок.
attempt() {
  local label="$1"; shift
  printf '\n[%s]\n$ %s\n' "$label" "$*"
  set +e
  "$@" 2>&1
  local rc=$?
  set -e
  printf '<<< exit=%s\n' "$rc"
  return 0
}

require_tools() {
  local missing=0 t
  for t in openssl curl nginx tshark tcpdump; do
    if ! command -v "$t" >/dev/null 2>&1; then
      echo "ОТСУТСТВУЕТ: $t" >&2
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 1
  openssl version | grep -q '^OpenSSL 3\.' \
    || { echo 'Требуется OpenSSL 3.x (не LibreSSL)' >&2; exit 1; }
}

# ============================================================
#  1. ПОДГОТОВКА КАТАЛОГОВ
# ============================================================
prepare_tree() {
  say "prepare_tree: $WORK/{root,inter,server,client,structure}"
  mkdir -p "$WORK"/root "$WORK"/inter "$WORK"/server \
           "$WORK"/client "$WORK"/structure
  cd "$WORK"
}

wipe_all() {
  say "wipe_all: удаляю $WORK и /etc/nginx/conf.d/lab4.conf"
  rm -rf "$WORK"
  $ESCALATE rm -f /etc/nginx/conf.d/lab4.conf
  $ESCALATE systemctl restart nginx 2>/dev/null || true
}

# ============================================================
#  2. УДОСТОВЕРЯЮЩИЙ ЦЕНТР
# ============================================================
build_root_ca() {
  say "build_root_ca: Ed25519, CA:TRUE pathlen:1"
  cd "$WORK"

  openssl genpkey -algorithm ED25519 -out root/root.key
  chmod 600 root/root.key

  openssl req -new -x509 -key root/root.key -days 3650 \
    -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -out root/root.crt
}

build_intermediate_ca() {
  say "build_intermediate_ca: Ed25519, CA:TRUE pathlen:0"
  cd "$WORK"

  cat > inter/inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

  openssl genpkey -algorithm ED25519 -out inter/inter.key
  chmod 600 inter/inter.key
  openssl req -new -key inter/inter.key \
    -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' \
    -out inter/inter.csr
  openssl x509 -req -in inter/inter.csr \
    -CA root/root.crt -CAkey root/root.key -CAcreateserial \
    -days 1825 -extfile inter/inter.ext -out inter/inter.crt
}

init_ca_database() {
  say "init_ca_database: index.txt / serial / crlnumber / ca.cnf"
  cd "$WORK/inter"
  : > index.txt
  echo 01   > crlnumber
  echo 1000 > serial
  cd "$WORK"

  cat > inter/ca.cnf <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir              = $WORK/inter
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

# ============================================================
#  3. СЕРТИФИКАТ СЕРВЕРА
# ============================================================
issue_server_leaf() {
  say "issue_server_leaf: Ed25519, SAN localhost + 127.0.0.1"
  cd "$WORK"

  cat > server/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

  openssl genpkey -algorithm ED25519 -out server/server.key
  chmod 600 server/server.key
  openssl req -new -key server/server.key \
    -subj '/C=BY/O=Lab PKI/CN=localhost' \
    -out server/server.csr
  openssl ca -config inter/ca.cnf -batch \
    -in server/server.csr -extfile server/server.ext \
    -notext -out server/server.crt

  cat server/server.crt inter/inter.crt > server/fullchain.pem
}

# ============================================================
#  4. NGINX
# ============================================================
render_nginx_conf() {
  say "render_nginx_conf: TLS1.3 / CHACHA20 / X25519 → /etc/nginx/conf.d/lab4.conf"
  cat <<EOF | $ESCALATE tee /etc/nginx/conf.d/lab4.conf >/dev/null
server {
    listen $HTTPS_PORT ssl;
    server_name localhost;

    ssl_certificate     $WORK/server/fullchain.pem;
    ssl_certificate_key $WORK/server/server.key;

    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_CHACHA20_POLY1305_SHA256;
    ssl_ecdh_curve X25519;

    ssl_session_tickets on;

    location / { return 200 'tls13 variant8 ok\n'; }
}
EOF
}

reload_nginx() {
  say "reload_nginx: nginx -t + restart"
  $ESCALATE nginx -t
  $ESCALATE systemctl restart nginx
  ss -ltnp 2>/dev/null | grep ":$HTTPS_PORT" || true
}

# ============================================================
#  5. ПРОВЕРКИ (в т.ч. задача варианта 8)
# ============================================================
check_chain() {
  say "check_chain: с intermediate (OK) и без (негатив)"
  cd "$WORK"
  attempt "chain+intermediate" \
    openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
  attempt "chain-without-intermediate (негатив)" \
    openssl verify -CAfile root/root.crt server/server.crt
}

check_positive_https() {
  say "check_positive_https: curl --cacert (ожидаем 200 / TLSv1.3 / CHACHA20)"
  cd "$WORK"
  curl -v --cacert root/root.crt "https://localhost:$HTTPS_PORT/" 2>&1 \
    | grep -E 'SSL connection|HTTP/|tls13 variant8' || true
}

run_negative_suite() {
  say "run_negative_suite: Н1–Н4 (стандартные негативы методички)"
  cd "$WORK"

  attempt "Н1: без --cacert" \
    curl -sS "https://localhost:$HTTPS_PORT/"

  attempt "Н2: 127.0.0.2 вне SAN" \
    curl -sS --cacert root/root.crt "https://127.0.0.2:$HTTPS_PORT/"

  if [ ! -f /tmp/other.key ] || [ ! -f /tmp/other.crt ]; then
    openssl genpkey -algorithm ED25519 -out /tmp/other.key
    openssl req -new -x509 -key /tmp/other.key \
      -subj '/CN=Other Root' -days 1 -out /tmp/other.crt
  fi
  attempt "Н3: чужой корень" \
    curl -sS --cacert /tmp/other.crt "https://localhost:$HTTPS_PORT/"

  attempt "Н4: TLS 1.2 (alert protocol version 70)" \
    sh -c "( sleep 1 ) | openssl s_client -connect localhost:$HTTPS_PORT -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'"
}

# ============================================================
#  ЗАДАЧА ВАРИАНТА 8 — срок действия
# ============================================================
check_expiry_task() {
  say "check_expiry_task: -attime +400 дней (негатив) и +100 дней (контроль)"
  cd "$WORK"

  local future ok_date
  future=$(( $(date +%s) + 400*24*3600 ))
  ok_date=$(( $(date +%s) + 100*24*3600 ))

  echo "attime(+400) = $future ($(date -d @$future))"
  attempt "Н5 (задача 8): +400 дней → certificate has expired" \
    openssl verify -attime "$future" -CAfile root/root.crt \
      -untrusted inter/inter.crt server/server.crt

  attempt "контроль: +100 дней → OK" \
    openssl verify -attime "$ok_date" -CAfile root/root.crt \
      -untrusted inter/inter.crt server/server.crt
}

# ============================================================
#  6. ЗАХВАТ И АНАЛИЗ
# ============================================================
capture_handshake() {
  say "capture_handshake: tcpdump + curl с SSLKEYLOGFILE"
  cd "$WORK"
  : > client/keys.log

  $ESCALATE tcpdump -i lo -w "$WORK/client/handshake.pcap" "tcp port $HTTPS_PORT" &
  local dumper=$!
  sleep 1

  SSLKEYLOGFILE="$WORK/client/keys.log" \
    curl -sS --cacert root/root.crt "https://localhost:$HTTPS_PORT/"

  sleep 1
  $ESCALATE kill -INT "$dumper" 2>/dev/null || true
  wait "$dumper" 2>/dev/null || true
  $ESCALATE chown "$CALLER" "$WORK/client/handshake.pcap"

  wc -l client/keys.log
  cut -d' ' -f1 client/keys.log | sort -u
}

dump_pcap_fields() {
  say "dump_pcap_fields: шифр, группа, SNI, SAN, sig alg"
  cd "$WORK"
  local k="client/keys.log"
  local p="client/handshake.pcap"

  echo '--- ServerHello: ciphersuite / key_share_group ---'
  tshark -r "$p" -o tls.keylog_file:"$k" \
    -Y 'tls.handshake.type == 2' -T fields \
    -e frame.number -e tls.handshake.ciphersuite \
    -e tls.handshake.extensions_key_share_group

  echo '--- ClientHello: SNI ---'
  tshark -r "$p" -o tls.keylog_file:"$k" \
    -Y 'tls.handshake.type == 1' -T fields \
    -e frame.number -e tls.handshake.extensions_server_name

  echo '--- Certificate: dNSName / iPAddress ---'
  tshark -r "$p" -o tls.keylog_file:"$k" \
    -Y 'tls.handshake.type == 11' -V 2>/dev/null \
    | grep -E 'dNSName|iPAddress' || true

  echo '--- CertificateVerify: sig_hash_alg ---'
  tshark -r "$p" -o tls.keylog_file:"$k" \
    -Y 'tls.handshake.type == 15' -T fields \
    -e frame.number -e tls.handshake.sig_hash_alg
}

show_handshake_types() {
  say "show_handshake_types: без ключей и с ключами"
  cd "$WORK"
  local p="client/handshake.pcap"
  local k="client/keys.log"

  echo '--- без ключей ---'
  tshark -r "$p" -Y tls -T fields \
    -e frame.number -e tls.record.content_type -e tls.handshake.type

  echo '--- с ключами ---'
  tshark -r "$p" -o tls.keylog_file:"$k" \
    -Y tls.handshake -T fields \
    -e frame.number -e ip.src -e tls.handshake.type
}

# ============================================================
#  7. СБОРКА АРТЕФАКТОВ ДЛЯ ОТЧЁТА
# ============================================================
gather_artifacts() {
  say "gather_artifacts: structure/*.txt"
  cd "$WORK"
  mkdir -p structure

  local c
  for c in root/root.crt inter/inter.crt server/server.crt; do
    openssl x509 -in "$c" -noout -text \
      > "structure/$(basename "${c%.crt}").txt"
  done

  cp inter/index.txt    structure/index.txt
  cp inter/serial       structure/serial.txt
  cp inter/crlnumber    structure/crlnumber.txt 2>/dev/null || true

  awk -F'\t' '{print $4"\t"$1"\t"$6}' inter/index.txt \
    > structure/serials.txt

  local future
  future=$(( $(date +%s) + 400*24*3600 ))
  openssl verify -attime "$future" -CAfile root/root.crt \
    -untrusted inter/inter.crt server/server.crt \
    > structure/attime-400d.txt 2>&1 || true

  if [ -f client/handshake.pcap ] && [ -f client/keys.log ]; then
    {
      echo '--- ServerHello: ciphersuite / key_share_group ---'
      tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
        -Y 'tls.handshake.type == 2' -T fields \
        -e frame.number -e tls.handshake.ciphersuite \
        -e tls.handshake.extensions_key_share_group 2>/dev/null
      echo '--- ClientHello: SNI ---'
      tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
        -Y 'tls.handshake.type == 1' -T fields \
        -e frame.number -e tls.handshake.extensions_server_name 2>/dev/null
      echo '--- Certificate: dNSName / iPAddress ---'
      tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
        -Y 'tls.handshake.type == 11' -V 2>/dev/null \
        | grep -E 'dNSName|iPAddress' || true
      echo '--- CertificateVerify: sig_hash_alg ---'
      tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
        -Y 'tls.handshake.type == 15' -T fields \
        -e frame.number -e tls.handshake.sig_hash_alg 2>/dev/null
    } > structure/pcap-summary.txt
  fi

  say "готово: $WORK/structure/"
  ls -1 structure/
}

# ============================================================
#  8. ДИСПЕТЧЕР
# ============================================================
require_tools

action="${1:-all}"
case "$action" in
  clean)     wipe_all ;;
  tree)      prepare_tree ;;
  ca)        prepare_tree; build_root_ca; build_intermediate_ca; init_ca_database ;;
  leaf)      prepare_tree; issue_server_leaf ;;
  nginx)     render_nginx_conf; reload_nginx ;;
  chain)     prepare_tree; check_chain ;;
  https)     prepare_tree; check_positive_https ;;
  negatives) prepare_tree; run_negative_suite ;;
  expiry)    prepare_tree; check_expiry_task ;;
  capture)   prepare_tree; capture_handshake ;;
  analyze)   prepare_tree; show_handshake_types; dump_pcap_fields ;;
  collect)   prepare_tree; gather_artifacts ;;
  all)
    prepare_tree
    build_root_ca
    build_intermediate_ca
    init_ca_database
    issue_server_leaf
    render_nginx_conf
    reload_nginx
    check_chain
    check_positive_https
    run_negative_suite
    check_expiry_task
    capture_handshake
    show_handshake_types
    dump_pcap_fields
    gather_artifacts
    ;;
  *)
    cat <<EOF
usage: $0 <команда>

  clean      снести $WORK и конфиг nginx
  tree       создать каталоги
  ca         root + intermediate CA + база
  leaf       серверный сертификат + fullchain
  nginx      сгенерировать конфиг + nginx -t + restart
  chain      verify с intermediate и без (негатив)
  https      позитивный curl
  negatives  Н1–Н4 (без --cacert, 127.0.0.2, чужой корень, TLS 1.2)
  expiry     задача варианта 8: -attime +400 дней / +100 дней
  capture    tcpdump + curl с SSLKEYLOGFILE
  analyze    tshark: типы сообщений + поля варианта
  collect    собрать structure/*.txt для отчёта
  all        всё по порядку
EOF
    exit 1
    ;;
esac