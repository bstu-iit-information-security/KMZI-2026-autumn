#!/usr/bin/env bash
# Лабораторная работа №4, вариант 11.
# PKI: ECDSA P-256 (root/inter), ECDSA P-384 (server), P-384,
# TLS_AES_128_GCM_SHA256 и OCSP good -> revoked.
#
# Использование:
#   ./lab4.sh init          создать PKI и конфигурацию nginx
#   ./lab4.sh verify        проверить цепочку и негативные случаи
#   ./lab4.sh ocsp          сценарий варианта 11: OCSP + CRL
#   ./lab4.sh nginx-start   проверить конфиг и запустить nginx
#   ./lab4.sh nginx-stop    остановить nginx
#   ./lab4.sh capture       tcpdump + s_client + tshark
#   ./lab4.sh clean         удалить сгенерированные файлы
set -euo pipefail

LAB4_DIR=${LAB4_DIR:-$HOME/lab4}
TLS_PORT=${TLS_PORT:-8443}
OCSP_PORT=${OCSP_PORT:-2560}
OCSP_URL=${OCSP_URL:-http://127.0.0.1:$OCSP_PORT}
ROOT=$LAB4_DIR/root
INTER=$LAB4_DIR/inter
SERVER=$LAB4_DIR/server
REVOKED=$LAB4_DIR/revoked
EXPIRED=$LAB4_DIR/expired
CLIENT=$LAB4_DIR/client
NGINX_DIR=$LAB4_DIR/nginx

step() { printf '\n=== %s ===\n' "$1"; }
ok()   { printf '[OK] %s\n' "$1"; }
die()  { printf 'ОШИБКА: %s\n' "$1" >&2; exit 1; }

find_openssl() {
    local c v
    for c in "${OPENSSL:-}" openssl \
        /opt/homebrew/opt/openssl@3/bin/openssl \
        /usr/local/opt/openssl@3/bin/openssl \
        /opt/homebrew/bin/openssl
    do
        [ -n "$c" ] || continue
        command -v "$c" >/dev/null 2>&1 || continue
        v=$("$c" version 2>/dev/null || true)
        case "$v" in
            OpenSSL\ 3.*) printf '%s\n' "$c"; return 0 ;;
        esac
    done
    return 1
}
OPENSSL=$(find_openssl) || die "нужен OpenSSL 3.x (macOS: brew install openssl@3)"
export OPENSSL

find_nginx() {
    local c
    for c in "${NGINX:-}" nginx /opt/homebrew/bin/nginx /usr/local/bin/nginx /usr/sbin/nginx
    do
        [ -n "$c" ] || continue
        command -v "$c" >/dev/null 2>&1 && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}
NGINX=$(find_nginx || true)

port_open() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

wait_port() {
    local i=0
    while [ "$i" -lt 50 ]; do
        port_open "$1" && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

wait_port_closed() {
    local i=0
    while [ "$i" -lt 50 ]; do
        port_open "$1" || return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}

require_pki() {
    local f
    for f in "$ROOT/root.crt" "$INTER/inter.crt" "$SERVER/server.crt" \
             "$SERVER/fullchain.pem" "$REVOKED/revoked.crt"; do
        [ -f "$f" ] || die "нет $f; выполните ./lab4.sh init"
    done
}

is_revoked() {
    local serial
    serial=$("$OPENSSL" x509 -in "$1" -noout -serial | cut -d= -f2)
    awk -F'\t' -v s="$serial" '
        toupper($4) == toupper(s) && $1 == "R" { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$INTER/index.txt"
}

render_nginx() {
    mkdir -p "$NGINX_DIR/tmp"/{client_body,proxy,fastcgi,uwsgi,scgi}
    cat > "$NGINX_DIR/lab4.conf" <<EOF
server {
    listen $TLS_PORT ssl;
    server_name localhost;

    ssl_certificate     $SERVER/fullchain.pem;
    ssl_certificate_key $SERVER/server.key;

    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256;
    ssl_ecdh_curve P-384;
    ssl_session_tickets on;

    location / { return 200 'tls13 ok'; }
}
EOF
    cat > "$NGINX_DIR/nginx.conf" <<EOF
worker_processes 1;
pid $NGINX_DIR/nginx.pid;
error_log $NGINX_DIR/error.log info;
events { worker_connections 64; }
http {
    access_log $NGINX_DIR/access.log;
    client_body_temp_path $NGINX_DIR/tmp/client_body;
    proxy_temp_path       $NGINX_DIR/tmp/proxy;
    fastcgi_temp_path     $NGINX_DIR/tmp/fastcgi;
    uwsgi_temp_path       $NGINX_DIR/tmp/uwsgi;
    scgi_temp_path        $NGINX_DIR/tmp/scgi;
    include $NGINX_DIR/lab4.conf;
}
EOF
}

cmd_init() {
    [ ! -e "$ROOT/root.key" ] || die "PKI уже существует: $LAB4_DIR (сначала ./lab4.sh clean)"
    umask 077
    mkdir -p "$ROOT" "$INTER" "$SERVER" "$REVOKED" "$EXPIRED" "$CLIENT" "$NGINX_DIR"

    step "1. Корневой CA: ECDSA P-256"
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$ROOT/root.key"
    chmod 600 "$ROOT/root.key"
    "$OPENSSL" req -new -x509 -key "$ROOT/root.key" -sha256 -days 3650 \
        -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' \
        -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -addext 'subjectKeyIdentifier=hash' \
        -out "$ROOT/root.crt"

    step "2. Промежуточный CA: ECDSA P-256, pathlen:0"
    cat > "$INTER/inter.ext" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$INTER/inter.key"
    chmod 600 "$INTER/inter.key"
    "$OPENSSL" req -new -key "$INTER/inter.key" \
        -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' -out "$INTER/inter.csr"
    "$OPENSSL" x509 -req -in "$INTER/inter.csr" \
        -CA "$ROOT/root.crt" -CAkey "$ROOT/root.key" -CAcreateserial \
        -sha256 -days 1825 -extfile "$INTER/inter.ext" -out "$INTER/inter.crt"

    step "3. База промежуточного CA"
    : > "$INTER/index.txt"
    printf '01\n' > "$INTER/crlnumber"
    printf '1000\n' > "$INTER/serial"
    cat > "$INTER/ca.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = $INTER
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

    step "4. Серверный сертификат: ECDSA P-384, SAN localhost/127.0.0.1"
    cat > "$SERVER/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:localhost,IP:127.0.0.1
authorityInfoAccess=OCSP;URI:$OCSP_URL
EOF
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$SERVER/server.key"
    chmod 600 "$SERVER/server.key"
    "$OPENSSL" req -new -key "$SERVER/server.key" \
        -subj '/C=BY/O=Lab PKI/CN=localhost' -out "$SERVER/server.csr"
    "$OPENSSL" ca -config "$INTER/ca.cnf" -batch \
        -in "$SERVER/server.csr" -extfile "$SERVER/server.ext" \
        -notext -out "$SERVER/server.crt"
    cat "$SERVER/server.crt" "$INTER/inter.crt" > "$SERVER/fullchain.pem"

    step "5. Тестовый лист для отзыва: ECDSA P-384"
    cat > "$REVOKED/revoked.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:revoked.localhost
authorityInfoAccess=OCSP;URI:$OCSP_URL
EOF
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$REVOKED/revoked.key"
    chmod 600 "$REVOKED/revoked.key"
    "$OPENSSL" req -new -key "$REVOKED/revoked.key" \
        -subj '/C=BY/O=Lab PKI/CN=revoked.localhost' -out "$REVOKED/revoked.csr"
    "$OPENSSL" ca -config "$INTER/ca.cnf" -batch \
        -in "$REVOKED/revoked.csr" -extfile "$REVOKED/revoked.ext" \
        -notext -out "$REVOKED/revoked.crt"

    step "6. Лист с истёкшим сроком"
    cat > "$EXPIRED/expired.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:expired.localhost
EOF
    "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$EXPIRED/expired.key"
    chmod 600 "$EXPIRED/expired.key"
    "$OPENSSL" req -new -key "$EXPIRED/expired.key" \
        -subj '/C=BY/O=Lab PKI/CN=expired.localhost' -out "$EXPIRED/expired.csr"
    "$OPENSSL" ca -config "$INTER/ca.cnf" -batch \
        -in "$EXPIRED/expired.csr" -extfile "$EXPIRED/expired.ext" \
        -startdate 20200101000000Z -enddate 20210101000000Z \
        -notext -out "$EXPIRED/expired.crt"

    render_nginx
    step "PKI создан"
    "$OPENSSL" verify -CAfile "$ROOT/root.crt" -untrusted "$INTER/inter.crt" "$SERVER/server.crt"
    printf 'Каталог: %s\n' "$LAB4_DIR"
}

cmd_verify() {
    require_pki
    local fail=0

    check_negative() {
        local desc=$1 pattern=$2
        shift 2
        local out
        set +e
        out=$("$@" 2>&1)
        set -e
        if printf '%s' "$out" | grep -q "$pattern"; then
            ok "$desc"
            return 0
        fi
        printf '[FAIL] %s\n%s\n' "$desc" "$out"
        return 1
    }

    step "Положительные проверки"
    "$OPENSSL" verify -CAfile "$ROOT/root.crt" -untrusted "$INTER/inter.crt" "$SERVER/server.crt"
    "$OPENSSL" verify -CAfile "$ROOT/root.crt" -untrusted "$INTER/inter.crt" \
        -verify_hostname localhost "$SERVER/server.crt"
    "$OPENSSL" verify -CAfile "$ROOT/root.crt" -untrusted "$INTER/inter.crt" \
        -verify_ip 127.0.0.1 "$SERVER/server.crt"

    step "Негативные проверки"
    check_negative "без промежуточного сертификата" 'unable to get local issuer' \
        "$OPENSSL" verify -CAfile "$ROOT/root.crt" "$SERVER/server.crt" || fail=1
    check_negative "имя вне SAN" 'hostname mismatch' \
        "$OPENSSL" verify -CAfile "$ROOT/root.crt" -untrusted "$INTER/inter.crt" \
        -verify_hostname wrong.localhost "$SERVER/server.crt" || fail=1
    check_negative "IP вне SAN" 'IP address mismatch' \
        "$OPENSSL" verify -CAfile "$ROOT/root.crt" -untrusted "$INTER/inter.crt" \
        -verify_ip 127.0.0.2 "$SERVER/server.crt" || fail=1
    check_negative "истёкший сертификат" 'certificate has expired' \
        "$OPENSSL" verify -CAfile "$ROOT/root.crt" -untrusted "$INTER/inter.crt" \
        "$EXPIRED/expired.crt" || fail=1

    [ "$fail" -eq 0 ] || die "часть проверок не прошла"
    ok "все проверки цепочки пройдены"
}

stop_responder() {
    if [ -n "${RPID:-}" ] && kill -0 "$RPID" 2>/dev/null; then
        kill "$RPID" 2>/dev/null || true
        wait "$RPID" 2>/dev/null || true
    fi
    RPID=""
}

start_responder() {
    stop_responder
    if port_open "$OCSP_PORT"; then
        die "порт $OCSP_PORT занят"
    fi
    mkdir -p "$CLIENT"
    "$OPENSSL" ocsp -index "$INTER/index.txt" -port "$OCSP_PORT" \
        -rsigner "$INTER/inter.crt" -rkey "$INTER/inter.key" \
        -CA "$INTER/inter.crt" -ignore_err -text \
        > "$CLIENT/ocsp.log" 2>&1 &
    RPID=$!
    local i=0
    while [ "$i" -lt 50 ]; do
        kill -0 "$RPID" 2>/dev/null || die "OCSP responder завершился"
        if grep -q 'waiting for OCSP client connections' "$CLIENT/ocsp.log" 2>/dev/null; then
            return 0
        fi
        sleep 0.1; i=$((i + 1))
    done
    die "OCSP responder не запустился"
}

query_ocsp() {
    "$OPENSSL" ocsp -issuer "$INTER/inter.crt" -cert "$1" \
        -url "$OCSP_URL" -CAfile "$ROOT/root.crt" -no_nonce
}

cmd_ocsp() {
    require_pki
    mkdir -p "$CLIENT"
    trap stop_responder EXIT

    step "OCSP: сертификаты действительны"
    start_responder
    query_ocsp "$SERVER/server.crt"
    query_ocsp "$REVOKED/revoked.crt"
    stop_responder

    step "Отзыв тестового листа и CRL"
    if is_revoked "$REVOKED/revoked.crt"; then
        printf 'revoked.crt уже отозван\n'
    else
        "$OPENSSL" ca -config "$INTER/ca.cnf" -batch -revoke "$REVOKED/revoked.crt"
    fi
    "$OPENSSL" ca -config "$INTER/ca.cnf" -batch -gencrl -out "$INTER/inter.crl"

    step "OCSP после перезапуска responder"
    start_responder
    query_ocsp "$SERVER/server.crt"
    query_ocsp "$REVOKED/revoked.crt"
    stop_responder

    step "CRL"
    "$OPENSSL" crl -in "$INTER/inter.crl" -noout -text | sed -n '1,22p'
    "$OPENSSL" verify -crl_check -CAfile "$ROOT/root.crt" \
        -untrusted "$INTER/inter.crt" -CRLfile "$INTER/inter.crl" "$SERVER/server.crt"
    local out
    set +e
    out=$("$OPENSSL" verify -crl_check -CAfile "$ROOT/root.crt" \
        -untrusted "$INTER/inter.crt" -CRLfile "$INTER/inter.crl" "$REVOKED/revoked.crt" 2>&1)
    set -e
    if printf '%s' "$out" | grep -q 'certificate revoked'; then
        ok "revoked.crt отозван по CRL"
    else
        printf '%s\n' "$out"
        die "CRL не подтвердил отзыв"
    fi
}

cmd_nginx_start() {
    [ -n "$NGINX" ] || die "nginx не найден"
    [ -f "$NGINX_DIR/nginx.conf" ] || die "сначала ./lab4.sh init"
    "$NGINX" -t -c "$NGINX_DIR/nginx.conf"
    if port_open "$TLS_PORT"; then
        ok "порт $TLS_PORT уже слушается"
        return 0
    fi
    "$NGINX" -c "$NGINX_DIR/nginx.conf"
    wait_port "$TLS_PORT" || die "nginx не начал слушать $TLS_PORT"
    ok "nginx запущен на https://localhost:$TLS_PORT/"
}

cmd_nginx_stop() {
    [ -n "$NGINX" ] || die "nginx не найден"
    "$NGINX" -s stop -c "$NGINX_DIR/nginx.conf" 2>/dev/null || true
    wait_port_closed "$TLS_PORT" || true
    ok "nginx остановлен"
}

cmd_capture() {
    require_pki
    command -v tshark >/dev/null 2>&1 || die "tshark не найден"
    local iface=lo
    [ "$(uname -s)" = Darwin ] && iface=lo0
    if ! port_open "$TLS_PORT"; then
        cmd_nginx_start
    fi
    rm -f "$CLIENT/handshake.pcap" "$CLIENT/keys.log"
    tcpdump -U -i "$iface" -w "$CLIENT/handshake.pcap" "tcp port $TLS_PORT" \
        > "$CLIENT/tcpdump.log" 2>&1 &
    local tpid=$!
    sleep 1
    ( sleep 1 ) | "$OPENSSL" s_client -connect "127.0.0.1:$TLS_PORT" \
        -servername localhost -CAfile "$ROOT/root.crt" \
        -tls1_3 -groups P-384 -keylogfile "$CLIENT/keys.log" -brief
    kill -INT "$tpid" 2>/dev/null || true
    wait "$tpid" 2>/dev/null || true
    tshark -r "$CLIENT/handshake.pcap" -o tls.keylog_file:"$CLIENT/keys.log" \
        -Y 'tls.handshake.type == 2' -T fields \
        -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group
    tshark -r "$CLIENT/handshake.pcap" -Y tls -T fields \
        -e frame.number -e tls.record.content_type -e tls.handshake.type
}

cmd_clean() {
    [ "$LAB4_DIR" != "/" ] || die "нельзя удалять /"
    rm -rf "$ROOT" "$INTER" "$SERVER" "$REVOKED" "$EXPIRED" "$CLIENT" "$NGINX_DIR"
    ok "удалены сгенерированные файлы в $LAB4_DIR"
}

case "${1:-}" in
    init)         cmd_init ;;
    verify)       cmd_verify ;;
    ocsp)         cmd_ocsp ;;
    nginx-start)  cmd_nginx_start ;;
    nginx-stop)   cmd_nginx_stop ;;
    capture)      cmd_capture ;;
    clean)        cmd_clean ;;
    *)            sed -n '2,16p' "$0"; exit 1 ;;
esac
