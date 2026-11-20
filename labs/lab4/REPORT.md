<p align="center"> Министерство образования Республики Беларусь</p>
<p align="center">Учреждение образования</p>
<p align="center">“Брестский Государственный технический университет”</p>
<p align="center">Кафедра ИИТ</p>
<br><br><br><br><br><br><br>
<p align="center">Лабораторная работа №4</p>
<p align="center">По дисциплине “Криптографические методы защиты информации”</p>
<p align="center">Тема: “PKI, HTTPS и TLS 1.3. Развертывание тестового Удостоверяющего Центра (CA), выпуск сертификатов X.509, настройка HTTPS-сервера и анализ рукопожатия TLS 1.3 в Wireshark”</p>
<p align="center">Вариант: 4</p>
<br><br><br><br><br>
<p align="right">Выполнил:</p>
<p align="right">Студент 3 курса</p>
<p align="right">Группы ИИ-27</p>
<p align="right">Дорошенко М.Д.</p>
<p align="right">Проверил: Хацкевич А.С.</p>
<p align="right"></p>
<br><br><br><br><br>
<p align="center">Брест 2026</p>

# Цель

На собственном тестовом CA выпустить цепочку сертификатов X.509 с расширениями, настроить HTTPS-сервер, принимающий только TLS 1.3, проверить цепочку доверия и отзыв, захватить рукопожатие TLS 1.3 и разобрать его в Wireshark, в том числе после расшифровки через журнал ключей (```SSLKEYLOGFILE```).

# Ход работы

## Подготовительные работы

Для начала установим необходимые утилиты:

* `openssl`
* `curl`
* `nginx`
* `tshark`
* `tcpdump`
* `certutil`

После этого, определимся с ОС, где будем выполнять лабу. В моем случае, буду производить "танцы с бубном" на `Ubuntu`.

## Наводим движуху

Вариант для моей лабы:

| №  | Ключ корня / промежуточного CA | Ключ сервера | Группа ECDHE | Набор шифров TLS 1.3         | Задача варианта |
|---|---|---|---|---|---|
| 4 | Ed25519 | ECDSA P-384 | P-384 |TLS_AES_256_GCM_SHA384       | mTLS: nginx с ssl_verify_client on и ssl_client_certificate (файл с корнем и промежуточным CA). В захвате покажите CertificateRequest (type 13) и клиентский Certificate. Без клиентского сертификата соединение отвергается |

Далее по пунктам приведу реализацию данной лабы:

## Шаг 1: Корневой CA

```
mkdir -p ~/lab4/root ~/lab4/inter ~/lab4/server ~/lab4/client && cd ~/lab4
openssl genpkey -algorithm ED25519 -out root/root.key && chmod 600 root/root.key
                                                                            openssl req -new -x509 -key root/root.key -days 3650 -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'subjectKeyIdentifier=hash' -out root/root.crt
```

## Шаг 2: Промежуточный CA

```
cat > inter/inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key && chmod 600 inter/inter.key
openssl req -new -key inter/inter.key -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' -out inter/inter.csr
openssl x509 -req -in inter/inter.csr -CA root/root.crt -CAkey root/root.key -CAcreateserial -sha256 -days 1825 -extfile inter/inter.ext -out inter/inter.crt
```

Результат:
```
Certificate request self-signature ok
subject=C = BY, O = Lab PKI, CN = Lab Intermediate CA
```

## Шаг 3: База промежуточного CA

```
cd ~/lab4/inter && touch index.txt && echo 01 > crlnumber && echo 1000 > serial && cd ~/lab4
cat > inter/ca.cnf <<'EOF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir              = /home/matvey/lab4/inter
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
```

## Шаг 4: Серверный сертификат с SAN

```
cat > server/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server/server.key && chmod 600 server/server.key
openssl req -new -key server/server.key -subj '/C=BY/O=Lab PKI/CN=localhost' -out server/server.csr
openssl ca -config inter/ca.cnf -batch -in server/server.csr -extfile server/server.ext -notext -out server/server.crt
```

Результат:
```
Using configuration from inter/ca.cnf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'BY'
organizationName      :ASN.1 12:'Lab PKI'
commonName            :ASN.1 12:'localhost'
Certificate is to be certified until Nov 16 22:02:11 2027 GMT (365 days)

Write out database with 1 new entries
Database updated
```

## Шаг 5: Проверка цепочки

```
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
openssl verify -CAfile root/root.crt server/server.crt
openssl x509 -in server/server.crt -noout -ext subjectAltName,extendedKeyUsage,basicConstraints
```

Результат:

```
server/server.crt: OK
CN = localhost
error 20 at 0 depth lookup: unable to get local issuer certificate
error server/server.crt: verification failed
X509v3 Basic Constraints: critical
    CA:FALSE
X509v3 Extended Key Usage: 
    TLS Web Server Authentication
X509v3 Subject Alternative Name: 
    DNS:localhost, IP Address:127.0.0.1
```

## Шаг 6: nginx: HTTPS только по TLS 1.3

```
cat server/server.crt inter/inter.crt > server/fullchain.pem
```

```
server {
    listen 8443 ssl;
    server_name localhost;
    ssl_certificate     /home/matvey/lab4/server/fullchain.pem;
    ssl_certificate_key /home/matvey/lab4/server/server.key;
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;
    ssl_ecdh_curve X25519:P-256;
    ssl_session_tickets on;
    location / { return 200 'tls13 ok'; }
}
```

Введем команды:

```
sudo nginx -t && sudo systemctl restart nginx
```

Результат:

```
temctl restart nginx
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

## Шаг 7: Проверка клиентом

```
curl -v --cacert root/root.crt https://localhost:8443/
```

Результат:

```
* Host localhost:8443 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8443...
* connect to ::1 port 8443 from ::1 port 51184 failed: В соединении отказано
*   Trying 127.0.0.1:8443...
* Connected to localhost (127.0.0.1) port 8443
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
*  CAfile: root/root.crt
*  CApath: /etc/ssl/certs
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519 / id-ecPublicKey
* ALPN: server accepted http/1.1
* Server certificate:
*  subject: CN=localhost
*  start date: Nov 16 22:02:11 2026 GMT
*  expire date: Nov 16 22:02:11 2027 GMT
*  subjectAltName: host "localhost" matched cert's "localhost"
*  issuer: C=BY; O=Lab PKI; CN=Lab Intermediate CA
*  SSL certificate verify ok.
*   Certificate level 0: Public key type EC/prime256v1 (256/128 Bits/secBits), signed using ecdsa-with-SHA256
*   Certificate level 1: Public key type EC/prime256v1 (256/128 Bits/secBits), signed using ED25519
*   Certificate level 2: Public key type ED25519 (256/128 Bits/secBits), signed using ED25519
* using HTTP/1.x
> GET / HTTP/1.1
> Host: localhost:8443
> User-Agent: curl/8.5.0
> Accept: */*
> 
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
< HTTP/1.1 200 OK
< Server: nginx/1.24.0 (Ubuntu)
< Date: Mon, 16 Nov 2026 22:12:45 GMT
< Content-Type: application/octet-stream
< Content-Length: 8
< Connection: keep-alive
< 
* Connection #0 to host localhost left intact
```

Тесты:

```
curl https://localhost:8443/
curl --cacert root/root.crt https://127.0.0.2:8443/
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/other.key
openssl req -new -x509 -key /tmp/other.key -subj '/CN=Other Root' -days 1 -out /tmp/other.crt
curl --cacert /tmp/other.crt https://localhost:8443/
( sleep 1 ) | openssl s_client -connect localhost:8443 -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'
```

Результат:

```
curl: (60) SSL certificate problem: unable to get local issuer certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
curl: (60) SSL: no alternative certificate subject name matches target host name '127.0.0.2'
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
curl: (60) SSL certificate problem: unable to get local issuer certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
40C77C63CF7F0000:error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version:../ssl/record/rec_layer_s3.c:1599:SSL alert number 70
    Protocol  : TLSv1.2
```

## Шаг 8: Захват рукопожатия и журнал ключей

Терминал 1 (захват):

```
sudo tcpdump -i lo -w ~/lab4/client/handshake.pcap 'tcp port 8443'
```

Терминал 2 (клиент):

```
cd ~/lab4/client
SSLKEYLOGFILE=$HOME/lab4/client/keys.log curl -sS --cacert ../root/root.crt https://localhost:8443/
```

Результат в клиенте:

```
tls13 okmatvey@matvey-HP-250-G8-Notebook-PC:~/lab4/client$
```

После остановки tcpdump (Ctrl+C) и верните владельца файлу: `sudo chown $USER ~/lab4/client/handshake.pcap`. Проверка: `wc -l keys.log` должен показать не меньше 5 строк.

Результат:
```
5 keys.log
```

## Шаг 9: Анализ в Wireshark (`tshark`)

Без журнала ключей:

```
tshark -r handshake.pcap -Y tls -T fields -e frame.number -e tls.record.content_type -e tls.handshake.type
```

Результат:

```
6	22	1
8	22,20	2
10	20	
11		
12		
13		
15		
16
```

С журналом ключей:

```
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y tls.handshake -T fields -e frame.number -e tls.handshake.type
```

Результат:

```
6	1
8	2,8,11,15,20
10	20
12	4
13	4

```

Поля, которые нужны в отчёте:

```
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 11' -V | grep -E 'dNSName|iPAddress'
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 15' -T fields -e tls.handshake.sig_hash_alg
```

Результат:

```
0x1302	29
localhost
                                    GeneralName: dNSName (2)
                                        dNSName: localhost
                                    GeneralName: iPAddress (7)
                                        iPAddress: 127.0.0.1
0x0403
```

## Шаг 10: Индивидуальные варианты заданий

```
curl -v --cacert root/root.crt https://localhost:8443/
```

```
* Host localhost:8443 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8443...
* connect to ::1 port 8443 from ::1 port 60820 failed: В соединении отказано
*   Trying 127.0.0.1:8443...
* Connected to localhost (127.0.0.1) port 8443
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
*  CAfile: root/root.crt
*  CApath: /etc/ssl/certs
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519 / id-ecPublicKey
* ALPN: server accepted http/1.1
* Server certificate:
*  subject: CN=localhost
*  start date: Nov 16 22:02:11 2026 GMT
*  expire date: Nov 16 22:02:11 2027 GMT
*  subjectAltName: host "localhost" matched cert's "localhost"
*  issuer: C=BY; O=Lab PKI; CN=Lab Intermediate CA
*  SSL certificate verify ok.
*   Certificate level 0: Public key type EC/prime256v1 (256/128 Bits/secBits), signed using ecdsa-with-SHA256
*   Certificate level 1: Public key type EC/prime256v1 (256/128 Bits/secBits), signed using ED25519
*   Certificate level 2: Public key type ED25519 (256/128 Bits/secBits), signed using ED25519
* using HTTP/1.x
> GET / HTTP/1.1
> Host: localhost:8443
> User-Agent: curl/8.5.0
> Accept: */*
> 
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* old SSL session ID is stale, removing
< HTTP/1.1 200 OK
< Server: nginx/1.24.0 (Ubuntu)
< Date: Mon, 16 Nov 2026 22:35:55 GMT
< Content-Type: application/octet-stream
< Content-Length: 8
< Connection: keep-alive
< 
* Connection #0 to host localhost left intact
```

```
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 13 || tls.handshake.type == 11' -T fields -e frame.number -e tls.handshake.type -e tls.handshake.cert_type
```

```
8	2,8,11,15,20
```

## Вывод

В ходе выполнения данной лабораторной работы я выпустил цепочку сертификатов с расширениями, настроил HTTPS-сервер, проверил цепочку доверия и отзыв, захватил рукопожатие, а также разобрал его в Wireshark.
