#!/bin/bash
# usage: gen_pki.sh DIR CA_ALG SERVER_ALG [CLIENT_ALG]   (ALG: P-256 | P-384 | ED25519 | RSA-2048)
set -e
D=$(cd "$(dirname "$1")" 2>/dev/null && pwd)/$(basename "$1"); CA=$2; SRV=$3; CLI=$4
mkdir -p "$D"/{root,inter,server,client}; cd "$D"
genkey() { case $1 in
  P-256|P-384) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$1 -out $2 2>/dev/null;;
  ED25519) openssl genpkey -algorithm ED25519 -out $2;;
  RSA-2048) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $2 2>/dev/null;; esac; chmod 600 $2; }
genkey $CA root/root.key
openssl req -new -x509 -key root/root.key -days 3650 -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' -out root/root.crt
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' > inter/inter.ext
genkey $CA inter/inter.key
openssl req -new -key inter/inter.key -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' -out inter/inter.csr
openssl x509 -req -in inter/inter.csr -CA root/root.crt -CAkey root/root.key -CAcreateserial -days 1825 -extfile inter/inter.ext -out inter/inter.crt
rm -f root/root.srl
( cd inter && touch index.txt && echo 01 > crlnumber && echo 1000 > serial )
cat > inter/ca.cnf <<EOC
[ ca ]
default_ca = CA_default
[ CA_default ]
dir              = $D/inter
database         = \$dir/index.txt
new_certs_dir    = \$dir
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
certificate      = \$dir/inter.crt
private_key      = \$dir/inter.key
default_md       = default
default_days     = 365
default_crl_days = 30
unique_subject   = no
copy_extensions  = none
policy           = policy_any
[ policy_any ]
commonName       = supplied
EOC
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > server/server.ext
genkey $SRV server/server.key
openssl req -new -key server/server.key -subj '/C=BY/O=Lab PKI/CN=localhost' -out server/server.csr
openssl ca -config inter/ca.cnf -batch -in server/server.csr -extfile server/server.ext -notext -out server/server.crt 2>&1 | tail -2
cat server/server.crt inter/inter.crt > server/fullchain.pem
cat root/root.crt inter/inter.crt > server/client-ca.pem
if [ -n "$CLI" ]; then
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' > client/client.ext
  genkey $CLI client/client.key
  openssl req -new -key client/client.key -subj '/C=BY/O=Lab PKI/CN=lab-client' -out client/client.csr
  openssl ca -config inter/ca.cnf -batch -in client/client.csr -extfile client/client.ext -notext -out client/client.crt 2>&1 | tail -2
fi
