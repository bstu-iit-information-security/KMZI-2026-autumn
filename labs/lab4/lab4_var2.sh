#!/usr/bin/env bash
# lab4_var2.sh — лабораторная работа №4, вариант 2
# Стенд: Ubuntu 24.04, OpenSSL 3.0.13, nginx 1.24.0, curl 8.5.0, tshark 4.2.2
#
# Вариант 2:
#   ключ корня / промежуточного CA — RSA-3072
#   ключ сервера                  — RSA-2048
#   группа ECDHE                  — P-256 (secp256r1, код 23)
#   набор шифров TLS 1.3          — TLS_AES_256_GCM_SHA384 (0x1302)
#   протокол                      — только TLSv1.3
#   mTLS                          — нет
#   задача варианта               — pathlen: корень с pathlen:0 и промежуточный CA
#                                   под ним → path length constraint exceeded
#   порт — 8443, рабочий каталог — ~/lab4
#
# Криптография не реализуется самостоятельно: только CLI openssl/nginx/curl/
# tcpdump/tshark. Проверка сертификатов нигде не отключается (-k/--insecure нет).
set -eu

WORK="${LAB:-$HOME/lab4}"
HTTPS_PORT="${PORT:-8443}"
CALLER="$(id -un)"
if [ "$(id -u)" -eq 0 ]; then
  ESCALATE=""
else
  ESCALATE="${SUDO:-sudo}"
fi

say() { printf '\n>>> %s\n' "$*"; }
hr()  { printf '%s\n' '------------------------------------------------------------'; }

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
  say "prepare_tree: $WORK/{root,inter,server,client,structure,pathlen}"
  mkdir -p "$WORK"/root "$WORK"/inter "$WORK"/server \
           "$WORK"/client "$WORK"/structure "$WORK"/pathlen
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
  say "build_root_ca: RSA-3072, CA:TRUE pathlen:1"
  cd "$WORK"

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root/root.key
  chmod 600 root/root.key

  openssl req -new -x509 -key root/root.key -sha256 -days 3650 \
    -subj '/C=BY/O=Lab PKI/CN=Lab Root CA RSA3072' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -out root/root.crt
}

build_intermediate_ca() {
  say "build_intermediate_ca: RSA-3072, CA:TRUE pathlen:0"
  cd "$WORK"

  cat > inter/inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out inter/inter.key
  chmod 600 inter/inter.key
  openssl req -new -key inter/inter.key \
    -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA RSA' \
    -out inter/inter.csr
  openssl x509 -req -in inter/inter.csr -sha256 \
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
  say "issue_server_leaf: RSA-2048, SAN localhost + 127.0.0.1"
  cd "$WORK"

  cat > server/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server/server.key
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
  say "render_nginx_conf: TLS1.3 / AES-256-GCM / P-256 → /etc/nginx/conf.d/lab4.conf"
  cat <<EOF | $ESCALATE tee /etc/nginx/conf.d/lab4.conf >/dev/null
server {
    listen $HTTPS_PORT ssl;
    server_name localhost;

    ssl_certificate     $WORK/server/fullchain.pem;
    ssl_certificate_key $WORK/server/server.key;

    # Вариант 2: только TLS 1.3, AES-256-GCM, P-256
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;
    ssl_ecdh_curve P-256;

    ssl_session_tickets on;

    location / { return 200 'tls13 variant2 ok\n'; }
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
#  5. ПРОВЕРКИ (в т.ч. задача варианта 2)
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
  say "check_positive_https: curl --cacert (ожидаем 200 / TLSv1.3 / AES-256-GCM)"
  cd "$WORK"
  curl -v --cacert root/root.crt "https://localhost:$HTTPS_PORT/" 2>&1 \
    | grep -E 'SSL connection|HTTP/|tls13 variant2' || true
}

run_negative_suite() {
  say "run_negative_suite: Н1–Н4 (стандартные негативы методички)"
  cd "$WORK"

  attempt "Н1: без --cacert" \
    curl -sS "https://localhost:$HTTPS_PORT/"

  attempt "Н2: 127.0.0.2 вне SAN" \
    curl -sS --cacert root/root.crt "https://127.0.0.2:$HTTPS_PORT/"

  if [ ! -f /tmp/other.key ] || [ ! -f /tmp/other.crt ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/other.key
    openssl req -new -x509 -key /tmp/other.key -sha256 \
      -subj '/CN=Other Root' -days 1 -out /tmp/other.crt
  fi
  attempt "Н3: чужой корень" \
    curl -sS --cacert /tmp/other.crt "https://localhost:$HTTPS_PORT/"

  attempt "Н4: TLS 1.2 (alert protocol version 70)" \
    sh -c "( sleep 1 ) | openssl s_client -connect localhost:$HTTPS_PORT -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'"
}

# ============================================================
#  ЗАДАЧА ВАРИАНТА 2 — ограничение pathlen
#
#  Строим отдельную ветку: корень с pathlen:0, под ним промежуточный CA,
#  под ним лист. Корень допускает 0 промежуточных CA ниже себя, поэтому
#  проверка обязана упасть с path length constraint exceeded (error 25).
#  Контроль: тот же корень подписывает лист напрямую — путь корректен,
#  то есть pathlen ограничивает только CA, но не листовые сертификаты.
# ============================================================
check_pathlen_task() {
  say "check_pathlen_task: корень pathlen:0 → промежуточный CA → error 25"
  local d="$WORK/pathlen"
  mkdir -p "$d"
  cd "$WORK"

  echo '--- Шаг 1: корень с pathlen:0 ---'
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$d/root_pl.key"
  openssl req -new -x509 -key "$d/root_pl.key" -sha256 -days 3650 \
    -subj '/C=BY/O=Lab PKI/CN=Lab Root Pathlen0' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -out "$d/root_pl.crt"
  openssl x509 -in "$d/root_pl.crt" -noout -ext basicConstraints

  echo '--- Шаг 2: промежуточный CA под этим корнем ---'
  cat > "$d/inter.ext" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$d/inter_pl.key"
  openssl req -new -key "$d/inter_pl.key" \
    -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate Under Pathlen0' \
    -out "$d/inter_pl.csr"
  openssl x509 -req -in "$d/inter_pl.csr" -sha256 \
    -CA "$d/root_pl.crt" -CAkey "$d/root_pl.key" -CAcreateserial \
    -days 1825 -extfile "$d/inter.ext" -out "$d/inter_pl.crt"

  echo '--- Шаг 3: лист под промежуточным CA ---'
  cat > "$d/leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$d/leaf.key"
  openssl req -new -key "$d/leaf.key" \
    -subj '/C=BY/O=Lab PKI/CN=localhost' -out "$d/leaf.csr"
  openssl x509 -req -in "$d/leaf.csr" -sha256 \
    -CA "$d/inter_pl.crt" -CAkey "$d/inter_pl.key" -CAcreateserial \
    -days 365 -extfile "$d/leaf.ext" -out "$d/leaf.crt"

  attempt "Н5 (задача 2): root(pathlen:0) → inter → leaf, ожидаем error 25" \
    openssl verify -CAfile "$d/root_pl.crt" -untrusted "$d/inter_pl.crt" "$d/leaf.crt"

  echo '--- Контроль: лист подписан тем же корнем напрямую ---'
  openssl x509 -req -in "$d/leaf.csr" -sha256 \
    -CA "$d/root_pl.crt" -CAkey "$d/root_pl.key" -CAcreateserial \
    -days 365 -extfile "$d/leaf.ext" -out "$d/leaf_direct.crt"
  attempt "контроль: root(pathlen:0) → leaf напрямую, ожидаем OK" \
    openssl verify -CAfile "$d/root_pl.crt" "$d/leaf_direct.crt"

  echo '--- Справка: основная цепочка лабораторной (корень pathlen:1) ---'
  attempt "root(pathlen:1) → inter(pathlen:0) → leaf, ожидаем OK" \
    openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
}

# ============================================================
#  6. ЗАХВАТ И АНАЛИЗ
# ============================================================
capture_handshake() {
  say "capture_handshake: tcpdump + curl с SSLKEYLOGFILE"
  cd "$WORK"
  : > client/keys.log

  # timeout завершает tcpdump сам — не зависим от доставки сигнала через sudo
  $ESCALATE timeout 12 tcpdump -i lo -w "$WORK/client/handshake.pcap" \
    "tcp port $HTTPS_PORT" >/dev/null 2>&1 &
  local dumper=$!
  sleep 2

  SSLKEYLOGFILE="$WORK/client/keys.log" \
    curl -sS --cacert root/root.crt "https://localhost:$HTTPS_PORT/"

  wait "$dumper" 2>/dev/null || true
  $ESCALATE chown "$CALLER" "$WORK/client/handshake.pcap" 2>/dev/null || true

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

  cp inter/index.txt structure/index.txt
  cp inter/serial    structure/serial.txt
  cp inter/crlnumber structure/crlnumber.txt 2>/dev/null || true
  awk -F'\t' '{print $4"\t"$1"\t"$6}' inter/index.txt \
    > structure/serials.txt

  # Задача варианта 2 — сохраняем обе проверки pathlen
  {
    echo '--- root(pathlen:0) → inter → leaf ---'
    openssl verify -CAfile pathlen/root_pl.crt \
      -untrusted pathlen/inter_pl.crt pathlen/leaf.crt 2>&1 || true
    echo '--- контроль: root(pathlen:0) → leaf напрямую ---'
    openssl verify -CAfile pathlen/root_pl.crt pathlen/leaf_direct.crt 2>&1 || true
    echo '--- справка: основная цепочка root(pathlen:1) → inter → leaf ---'
    openssl verify -CAfile root/root.crt \
      -untrusted inter/inter.crt server/server.crt 2>&1 || true
  } > structure/pathlen.txt

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
main() {
  local action="${1:-all}"

  if [ "$action" != "clean" ]; then
    require_tools
  fi

  case "$action" in
    clean)     wipe_all ;;
    tree)      prepare_tree ;;
    ca)        prepare_tree; build_root_ca; build_intermediate_ca; init_ca_database ;;
    leaf)      prepare_tree; issue_server_leaf ;;
    nginx)     render_nginx_conf; reload_nginx ;;
    chain)     prepare_tree; check_chain ;;
    https)     prepare_tree; check_positive_https ;;
    negatives) prepare_tree; run_negative_suite ;;
    pathlen)   prepare_tree; check_pathlen_task ;;
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
      check_pathlen_task
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
  ca         root + intermediate CA + база openssl ca
  leaf       серверный сертификат + fullchain.pem
  nginx      сгенерировать конфиг + nginx -t + restart
  chain      verify с intermediate и без (негатив)
  https      позитивный curl
  negatives  Н1–Н4 (без --cacert, 127.0.0.2, чужой корень, TLS 1.2)
  pathlen    задача варианта 2: корень pathlen:0 → error 25 + контроль
  capture    tcpdump + curl с SSLKEYLOGFILE
  analyze    tshark: типы сообщений + поля варианта
  collect    собрать structure/*.txt для отчёта
  all        всё по порядку
EOF
      exit 1
      ;;
  esac
}

# Позволяет загрузить функции без запуска (используется при отладке).
if [ "${LAB4_NO_MAIN:-0}" != "1" ]; then
  main "$@"
fi
