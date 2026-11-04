Среда: Ubuntu 24.04 (WSL2), OpenSSL 3.0.13, curl 8.5.0, nginx 1.24.0, tshark 4.2.2

Примечание: в соответствии с вариантом 13, для корневого и промежуточного CA использован алгоритм Ed25519 (вместо EC P-256 из базового примера методички), а для серверного сертификата — ECDSA P-256. Флаг -sha256 при создании Ed25519-сертификатов опущен, так как алгоритм хэширования встроен в Ed25519.

## 1. Выполненные команды и вывод

### 1.1. Корневой и промежуточный CA
```
mkdir -p ~/lab4/root ~/lab4/inter ~/lab4/server ~/lab4/client && cd ~/lab4

# Корневой CA (Ed25519)
openssl genpkey -algorithm ED25519 -out root/root.key
chmod 600 root/root.key
openssl req -new -x509 -key root/root.key -days 3650 \
  -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -out root/root.crt

# Промежуточный CA (Ed25519)
cat > inter/inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
openssl genpkey -algorithm ED25519 -out inter/inter.key
chmod 600 inter/inter.key
openssl req -new -key inter/inter.key -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' -out inter/inter.csr
openssl x509 -req -in inter/inter.csr -CA root/root.crt -CAkey root/root.key -CAcreateserial -days 1825 -extfile inter/inter.ext -out inter/inter.crt
```
### 1.2. База CA и серверный сертификат
```
cd ~/lab4/inter && touch index.txt && echo 01 > crlnumber && echo 1000 > serial && cd ~/lab4

cat > inter/ca.cnf <<'EOF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir              = /home/kvimi/lab4/inter
database         = $dir/index.txt
new_certs_dir    = $dir
serial           = $dir/serial
crlnumber        = $dir/crlnumber
certificate      = $dir/inter.crt
private_key      = $dir/inter.key
default_md       = sha256
default_days     = 365
default_crl_days = 30
unique_subject   = no
copy_extensions  = none
policy           = policy_any
[ policy_any ]
commonName       = supplied
EOF

# Серверный сертификат (ECDSA P-256)
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
openssl req -new -key server/server.key -subj '/C=BY/O=Lab PKI/CN=localhost' -out server/server.csr
openssl ca -config inter/ca.cnf -batch -in server/server.csr -extfile server/server.ext -notext -out server/server.crt
```
Вывод:
```
Using configuration from inter/ca.cnf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'BY'
organizationName      :ASN.1 12:'Lab PKI'
commonName            :ASN.1 12:'localhost'
Certificate is to be certified until Nov  4 16:33:41 2027 GMT (365 days)

Write out database with 1 new entries
Database updated
```
## 2. Фрагменты вывода сертификатов (openssl x509)
root.crt
```
        Signature Algorithm: ED25519
        Issuer: C = BY, O = Lab PKI, CN = Lab Root CA
        Subject: C = BY, O = Lab PKI, CN = Lab Root CA
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                15:40:D6:37:FC:92:42:A6:BA:6C:50:92:AE:61:65:FA:B5:FB:75:AB
```
inter.crt
```
        Signature Algorithm: ED25519
        Issuer: C = BY, O = Lab PKI, CN = Lab Root CA
        Subject: C = BY, O = Lab PKI, CN = Lab Intermediate CA
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                CC:AE:A1:79:09:7E:E0:89:FE:2C:3F:E7:DC:32:49:87:39:0B:98:F3
            X509v3 Authority Key Identifier:
                15:40:D6:37:FC:92:42:A6:BA:6C:50:92:AE:61:65:FA:B5:FB:75:AB
```
server.crt
```
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = BY, O = Lab PKI, CN = Lab Intermediate CA
        Subject: C = BY, O = Lab PKI, CN = localhost
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Alternative Name:
                DNS:localhost, IP Address:127.0.0.1
```
## 3. Конфигурация nginx
Файл /etc/nginx/conf.d/lab4.conf (логин kvimi, шифр и группа):
```
server {
    listen 8443 ssl;
    server_name localhost;
    ssl_certificate     /home/kvimi/lab4/server/fullchain.pem;
    ssl_certificate_key /home/kvimi/lab4/server/server.key;
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256;
    ssl_ecdh_curve X25519;
    ssl_session_tickets on;
    location / { return 200 'tls13 ok'; }
}
```
Проверка конфигурации:
```
$ sudo nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

## 4. Проверка цепочки и отзыв
### 4.1. Положительная проверка цепочки
```
$ openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
server/server.crt: OK
```
### 4.2. Позитивный тест клиента
```
$ curl -v --cacert root/root.crt https://localhost:8443/
...
* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256 / X25519 / id-ecPublicKey
*  subjectAltName: host "localhost" matched cert's "localhost"
*  SSL certificate verify ok.
...
< HTTP/1.1 200 OK
< Server: nginx/1.24.0 (Ubuntu)
tls13 ok
```
### 4.3. Негативные тесты
1. Неполная цепочка (нет root.crt):
```
$ curl https://localhost:8443/
curl: (60) SSL certificate problem: unable to get local issuer certificate
```
2. Имя вне SAN (127.0.0.2):
```
$ curl --cacert root/root.crt https://127.0.0.2:8443/
curl: (60) SSL: no alternative certificate subject name matches target host name '127.0.0.2'
```
3. Чужой корень:
```
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/other.key
$ openssl req -new -x509 -key /tmp/other.key -subj '/CN=Other Root' -days 1 -out /tmp/other.crt
$ curl --cacert /tmp/other.crt https://localhost:8443/
curl: (60) SSL certificate problem: unable to get local issuer certificate
```
4. Принудительный TLS 1.2 (негативный):
```
$ ( sleep 1 ) | openssl s_client -connect localhost:8443 -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'
40D7BCF2567E0000:error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version:../ssl/record/rec_layer_s3.c:1599:SSL alert number 70
    Protocol  : TLSv1.2
```
5. Истёкший сертификат (негативный, через 2 года):
```
$ FUTURE_TIME=$(date -d "+2 years" +%s)
$ openssl verify -attime $FUTURE_TIME -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
CN = localhost
error 10 at 0 depth lookup: certificate has expired
error server/server.crt: verification failed
```
6. Отозванный сертификат (CRL, негативный):
```
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/dummy.key
$ openssl req -new -key /tmp/dummy.key -subj '/CN=Dummy' -out /tmp/dummy.csr
$ openssl ca -config inter/ca.cnf -batch -in /tmp/dummy.csr -out /tmp/dummy.crt -notext
$ openssl ca -config inter/ca.cnf -revoke /tmp/dummy.crt
$ openssl ca -config inter/ca.cnf -gencrl -out inter/inter.crl
$ openssl verify -CAfile root/root.crt -untrusted inter/inter.crt -CRLfile inter/inter.crl -crl_check /tmp/dummy.crt
CN = Dummy
error 23 at 0 depth lookup: certificate revoked
error /tmp/dummy.crt: verification failed
```
## 5. Анализ в Wireshark (tshark)
### 5.1. Без журнала ключей
Видны только незашифрованные сообщения рукопожатия:
```
$ tshark -r ~/lab4/client/handshake.pcap -Y tls -T fields -e frame.number -e tls.record.content_type -e tls.handshake.type
6       22      1
8       22,20   2
10      20
...
```
### 5.2. С журналом ключей (keys.log)
Журнал содержит 5 уникальных меток:
```
$ cut -d' ' -f1 ~/lab4/client/keys.log | sort -u
CLIENT_HANDSHAKE_TRAFFIC_SECRET
CLIENT_TRAFFIC_SECRET_0
EXPORTER_SECRET
SERVER_HANDSHAKE_TRAFFIC_SECRET
SERVER_TRAFFIC_SECRET_0
```
Расшифрованный трафик показывает все этапы рукопожатия:
```
$ tshark -r ~/lab4/client/handshake.pcap -o tls.keylog_file:$HOME/lab4/client/keys.log -Y tls.handshake -T fields -e frame.number -e tls.handshake.type
6       1
8       2,8,11,15,20
10      20
13      4
14      4
```
(Типы: 1=ClientHello, 2=ServerHello, 8=EncryptedExtensions, 11=Certificate, 15=CertificateVerify, 20=Finished, 4=NewSessionTicket)
### 5.3. Извлечённые параметры рукопожатия
```
# Шифр и группа
$ tshark -r ~/lab4/client/handshake.pcap -o tls.keylog_file:$HOME/lab4/client/keys.log -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group
0x1301  29

# SNI
$ tshark -r ~/lab4/client/handshake.pcap -o tls.keylog_file:$HOME/lab4/client/keys.log -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name
localhost

# SAN из сертификата
$ tshark -r ~/lab4/client/handshake.pcap -o tls.keylog_file:$HOME/lab4/client/keys.log -Y 'tls.handshake.type == 11' -V | grep -E 'dNSName|iPAddress'
                                    GeneralName: dNSName (2)
                                        dNSName: localhost
                                    GeneralName: iPAddress (7)
                                        iPAddress: 127.0.0.1

# Алгоритм подписи CertificateVerify
$ tshark -r ~/lab4/client/handshake.pcap -o tls.keylog_file:$HOME/lab4/client/keys.log -Y 'tls.handshake.type == 15' -T fields -e tls.handshake.sig_hash_alg
0x0403
```
Шифр 0x1301 (TLS_AES_128_GCM_SHA256), группа 29 (X25519), подпись 0x0403 (ecdsa_secp256r1_sha256).
## 6. HelloRetryRequest (HRR)
Цель: Продемонстрировать HRR, когда клиент первым предлагает P-256, а сервер принимает только X25519.
Команда сервера (Терминал А):
```
openssl s_server -accept 8453 -cert server/server.crt -key server/server.key -cert_chain inter/inter.crt -tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 -www
```
Команда клиента (Терминал Б):
```
( sleep 1 ) | openssl s_client -connect localhost:8453 -servername localhost -CAfile root/root.crt -tls1_3 -groups P-256:X25519 -brief
```
Фактический вывод клиента:
```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_128_GCM_SHA256
Peer certificate: CN = localhost
Hash used: SHA256
Signature type: ECDSA
Verification: OK
Server Temp Key: X25519, 253 bits
DONE
```
Наблюдение в Wireshark (файл hrr.pcap):
```
$ echo "=== ClientHello ==="
$ tshark -r ~/lab4/client/hrr.pcap -Y 'tls.handshake.type == 1' -T fields -e frame.number
=== ClientHello ===
4
8
$ echo "=== ServerHello ==="
$ tshark -r ~/lab4/client/hrr.pcap -Y 'tls.handshake.type == 2' -T fields -e frame.number
=== ServerHello ===
6
9
```
Вывод: зафиксировано 2 сообщения ClientHello (кадры 4 и 8) и 2 сообщения ServerHello (кадры 6 и 9). Это подтверждает, что после первого ClientHello сервер отправил HelloRetryRequest (кадр 6), после чего клиент отправил второй ClientHello (кадр 8) уже с группой X25519, что и отражено в поле Server Temp Key: X25519.