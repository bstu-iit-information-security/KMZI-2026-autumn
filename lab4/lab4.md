# МИНИСТЕРСТВО ОБРАЗОВАНИЯ РЕСПУБЛИКИ БЕЛАРУСЬ

## УЧРЕЖДЕНИЕ ОБРАЗОВАНИЯ

# «БРЕСТСКИЙ ГОСУДАРСТВЕННЫЙ ТЕХНИЧЕСКИЙ УНИВЕРСИТЕТ»

Кафедра «Интеллектуальные информационные технологии»

# ЛАБОРАТОРНАЯ РАБОТА №4

по дисциплине «Криптографические методы защиты информации» за 4 семестр

**Тема:** «PKI, HTTPS и TLS 1.3. Развертывание тестового Удостоверяющего Центра (CA), выпуск сертификатов X.509, настройка HTTPS-сервера и анализ рукопожатия TLS 1.3 в Wireshark»

**Вариант 5**

**Выполнил:**
студент 3 курса  
группы ИИ-28  
(1 подгруппа)  
Деркач Е. В.

**Проверил:**  
Хацкевич А.С.

Брест 2026

---

Цель работы: на собственном тестовом CA выпустить цепочку сертификатов X.509 с расширениями, настроить HTTPS-сервер, принимающий только TLS 1.3, проверить цепочку доверия и отзыв, захватить рукопожатие TLS 1.3 и разобрать его в Wireshark, в том числе после расшифровки через журнал ключей (SSLKEYLOGFILE).

# Ход работы

## Задания

| № | Ключ корня / промежуточного CA | Ключ сервера | Группа ECDHE | Набор шифров TLS 1.3 | Задача варианта |
|---|---|---|---|---|---|
| 5 | RSA-2048 | RSA-2048 | X25519 | TLS_AES_128_GCM_SHA256 | Соответствие имени: подключение по адресу, которого нет в SAN (127.0.0.2). Объясните, почему CN не помогает. Найдите SNI в ClientHello |

## Задачи

1. Подготовить рабочую среду.
2. Создать корневой удостоверяющий центр (Root CA).
3. Создать промежуточный удостоверяющий центр (Intermediate CA).
4. Настроить базу промежуточного CA.
5. Создать серверный сертификат с SAN.
6. Проверить цепочку сертификатов.
7. Настроить HTTPS-сервер nginx.
8. Проверить работу HTTPS.
9. Захват рукопожатия TLS 1.3.
10. Проанализировать TLS 1.3 в Wireshark.
11. Выполнить индивидуальное задание варианта №5.

## Решение

## Задача 1. Подготовить рабочую среду

### 1.1. Установить WSL на Windows.

```bash
wsl --install
wsl --install -d Ubuntu
```

### 1.2. Установить необходимые программы:

```bash
sudo apt update
sudo apt install openssl curl nginx-light tshark tcpdump libnss3-tools -y
```

### 1.3. Создать рабочие каталоги:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ mkdir -p ~/lab4/root ~/lab4/inter ~/lab4/server ~/lab4/client
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ cd ~/lab4
```

## Задача 2. Создать корневой удостоверяющий центр (Root CA)

### 2.1. Генерация закрытого RSA-ключа размером 2048 бит:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out root/root.key
......+.+++++++++++++++++++++++++++++++++++++++*....+..+.....................
.+...+..+......+.+++++++++++++++++++++++++++++++++++++++*...+......+.+.......
..+.....+.+......+.....+.......+..+...+......+.+......+...+..+...+.........+.
+..+...............+....+...+.....+...+...+....+.....+.......+..............+
.+........+...+....+...+........+.........+....+.........+..+...+...+.......+
...+........+.+........................+..+....+......+..............+.+.....
...+....+.....+...............+...+...+.+......+.........+......+........+.+.
.......+.......+.....+.........+....+........+...+....+...+.........+........
.+.........+........+............+......+.......+...+.....+.......+..+......+
...................+..+....+......+........+.+............+...+......+...+...
.................+.++++++
...+++++++++++++++++++++++++++++++++++++++*.....+..+...+.........+.+...+.....
+++++++++++++++++++++++++++++++++++++++*.......+.+.........+.....+.+......+..
+...+...+......+.+...............+.....+.........+...+.......+...+...+..+....
..+......+.........+.+.........+..+...+.+...........+....+.........+.........
+...+...+.................+....+......+..............+...+.+.....+.........+.
+.....+...................+...........+....+............+...+.....+......+...
.........+...+................+.....+.+..+............+.+.....+.............
..+...+.......+...++++++
```

### 2.2. Ограничение доступа к закрытому ключу:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ chmod 600 root/root.key
```

### 2.3. Создание самоподписанного корневого сертификата:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl req -new -x509 -key root/root.key -sha256 -days 3650 -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'subjectKeyIdentifier=hash' -out root/root.crt
ewwwgeny@DESKTOP-9DNP85E:~/lab4$
```

## Задача 3. Создать промежуточный удостоверяющий центр (Intermediate CA)

### 3.1. Создание файла расширений:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ cat > inter/inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF
ewwwgeny@DESKTOP-9DNP85E:~/lab4$
```

### 3.2. Генерация RSA-ключа промежуточного центра:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out inter/inter.key
.......+......+...+++++++++++++++++++++++++++++++++++++++*.+..+++++++++++++++
++++++++++++++++++++++++*......+............+......+...+.........+..+........
.+....+...+...+..+.........+...++++++
.+....+++++++++++++++++++++++++++++++++++++++*.....+.........+.....+.+.......
.....+..+...............+++++++++++++++++++++++++++++++++++++++*....+...+.+..
..........+....................+...+.+......+..............+....+.........+..
.............+.....+.+.....+....+..+.........+.+.....+.+...+......++++++
```

### 3.3. Ограничение доступа к ключу:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ chmod 600 inter/inter.key
```

### 3.4. Создание запроса на сертификат:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl req -new -key inter/inter.key -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' -out inter/inter.csr
```

### 3.5. Подписание сертификата промежуточного CA корневым центром:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl x509 -req -in inter/inter.csr -CA root/root.crt -CAkey root/root.key -CAcreateserial -sha256 -days 1825 -extfile inter/inter.ext -out inter/inter.crt
Certificate request self-signature ok
subject=C=BY, O=Lab PKI, CN=Lab Intermediate CA
ewwwgeny@DESKTOP-9DNP85E:~/lab4$
```

## Задача 4. Настроить базу промежуточного CA

### 4.1. Создание необходимых файлов:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ cd ~/lab4/inter
ewwwgeny@DESKTOP-9DNP85E:~/lab4/inter$ touch index.txt
ewwwgeny@DESKTOP-9DNP85E:~/lab4/inter$ echo 01 > crlnumber
ewwwgeny@DESKTOP-9DNP85E:~/lab4/inter$ echo 1000 > serial
ewwwgeny@DESKTOP-9DNP85E:~/lab4/inter$ cd ~/lab4
```

### 4.2. Полный путь к каталогу:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ echo $HOME/lab4/inter
/home/ewwwgeny/lab4/inter
```

### 4.3. Создание конфигурационного файла:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ nano inter/ca.cnf
```

```ini
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = /home/ewwwgeny/lab4/inter
database = $dir/index.txt
new_certs_dir = $dir
serial = $dir/serial
crlnumber = $dir/crlnumber
certificate = $dir/inter.crt
private_key = $dir/inter.key
default_md = sha256
default_days = 365
default_crl_days = 30
unique_subject = no
copy_extensions = none
policy = policy_any

[ policy_any ]
commonName = supplied
```

## Задача 5. Создать серверный сертификат с SAN

### 5.1. Создание файла расширений:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ cat > server/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
```

### 5.2. Генерация серверного RSA-ключа размером 2048 бит:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server/server.key
.....+......+...+.+.....+.+.....+...............+......+...+....+...+..+.....
.......+...+.+..+++++++++++++++++++++++++++++++++++++++*.+..............+++++
++++++++++++++++++++++++++++++++++*.........+...+........+...+....+...+..+.+.
....+.+...+..+...................+..+...+....+...............+..+......+.....
....+...+.+..+.........+....+......+..............+.+.....+...+......+.......
+..+......+.+......+..+...+....+.....+.+.....+..........+....................
+..........+...+.........+.....+.+...............+.........+..+.+........+...
.+........+.......+......+..............+...+...+..........+.....+.+........+
+++++
....+......+..+......+.+...+...+..............+++++++++++++++++++++++++++++++++++++++*.....++
+++++++++++++++++++++++++++++++++++++*...+.....+.+.....+...................+...+......+..+........
.+....+......+...+.....++++++
```

### 5.3. Ограничение доступа к ключу:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ chmod 600 server/server.key
```

### 5.4. Создание запроса на сертификат:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl req -new -key server/server.key -subj '/C=BY/O=Lab PKI/CN=localhost' -out server/server.csr
```

### 5.5. Серверный сертификат через промежуточный CA:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl ca -config inter/ca.cnf -batch -in server/server.csr -extfile server/server.ext -notext -out server/server.crt
Using configuration from inter/ca.cnf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'BY'
organizationName      :ASN.1 12:'Lab PKI'
commonName            :ASN.1 12:'localhost'
Certificate is to be certified until Nov 9 07:47:02 2027 GMT (365 days)
Write out database with 1 new entries
Database updated
ewwwgeny@DESKTOP-9DNP85E:~/lab4$
```

## Задача 6. Проверить цепочку сертификатов

### 6.1. Проверка цепочки доверия:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
server/server.crt: OK
```

### 6.2. Проверкацепочки без промежуточного сертификата:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl verify -CAfile root/root.crt server/server.crt
CN=localhost
error 20 at 0 depth lookup: unable to get local issuer certificate
error server/server.crt: verification failed
```

Является негативным тестом, так как отсутствует промежуточный сертификат в цепочке. Утилита openssl verify не может найти издателя (issuer) для server.crt и достроить путь до корневого сертификата, указанного в -CAfile.

### 6.3. Посмотр расширения серверного сертификата:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl x509 -in server/server.crt -noout -ext subjectAltName,extendedKeyUsage,basicConstraints
X509v3 Basic Constraints: critical
    CA:FALSE
X509v3 Extended Key Usage:
    TLS Web Server Authentication
X509v3 Subject Alternative Name:
    DNS:localhost, IP Address:127.0.0.1
ewwwgeny@DESKTOP-9DNP85E:~/lab4$
```

## Задача 7. Настроить HTTPS-сервер nginx

### 7.1. Создание полной цепочки сертификатов:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ cat server/server.crt inter/inter.crt > server/fullchain.pem
```

### 7.2. Открытие конфигурации nginx:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ sudo nano /etc/nginx/conf.d/lab4.conf
[sudo: authenticate] Password:
```

### 7.3. Добавление конфигурации:

```nginx
server {
listen 8443 ssl;
server_name localhost;

ssl_certificate /home/ewwwgeny/lab4/server/fullchain.pem;
ssl_certificate_key /home/ewwwgeny/lab4/server/server.key;

ssl_protocols TLSv1.3;
ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256;
ssl_ecdh_curve X25519;

ssl_session_tickets on;

location / {
return 200 'tls13 ok';
}
}
```

### 7.4. Проверкаконфигурации:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ sudo nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

### 7.5. Перезапуск nginx:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ sudo service nginx restart
ewwwgeny@DESKTOP-9DNP85E:~/lab4$
```

## Задача 8. Проверить работу HTTPS

### 8.1. Выполнение подключения с проверкой корневого сертификата:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ curl -v --cacert root/root.crt https://localhost:8443/
* Host localhost:8443 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8443...
* connect to ::1 port 8443 from ::1 port 35124 failed: Connection refused
*   Trying 127.0.0.1:8443...
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* SSL Trust Anchors:
*   CAfile: root/root.crt
*   CApath: /etc/ssl/certs
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256 / x25519 / RSASSA-PSS
* ALPN: server accepted http/1.1
* Server certificate:
*   subject: CN=localhost
*   start date: Nov 9 07:47:02 2026 GMT
*   expire date: Nov 9 07:47:02 2027 GMT
*   issuer: C=BY; O=Lab PKI; CN=Lab Intermediate CA
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed
using sha256WithRSAEncryption
*   Certificate level 1: Public key type RSA (2048/112 Bits/secBits), signed
using sha256WithRSAEncryption
*   Certificate level 2: Public key type RSA (2048/112 Bits/secBits), signed
using sha256WithRSAEncryption
*   subjectAltName: "localhost" matches cert's "localhost"
* SSL certificate verified via OpenSSL.
* Established connection to localhost (127.0.0.1 port 8443) from 127.0.0.1
port 37148
* using HTTP/1.x
> GET / HTTP/1.1
> Host: localhost:8443
> User-Agent: curl/8.18.0
> Accept: */*
>
* Request completely sent off
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
< HTTP/1.1 200 OK
< Server: nginx/1.28.3 (Ubuntu)
< Date: Mon, 09 Nov 2026 07:59:16 GMT
< Content-Type: application/octet-stream
< Content-Length: 8
< Connection: keep-alive
<
* Connection #0 to host localhost:8443 left intact
tls13 ok
```

Соединение установлено успешно:

- TLS 1.3;
- HTTP 200;
- ответ tls13 ok.

### 8.2. Проверка подключения без указания доверенного корневого сертификата:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ curl https://localhost:8443/
curl: (60) SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the webpage mentioned above.
```

Является негативным тестом. Ошибка unable to get local issuer certificate возникает потому, что утилита curl не получила корневой сертификат через флаг --cacert root/root.crt. Без доверенного корня клиент не может построить цепочку сертификатов до известного ему центра, поэтому соединение прерывается.

### 8.3. Проверить подключение по адресу, которого нет в SAN:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ curl --cacert root/root.crt https://127.0.0.2:8443/
curl: (60) SSL: no alternative certificate subject name matches target ipv4 address '127.0.0.2'
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the webpage mentioned above.
```

Является негативным тестом. Ошибка no alternative certificate subject name matches target ipv4 address '127.0.0.2' возникает потому, что в сертификате сервера в расширении Subject Alternative Name (SAN) указаны только DNS:localhost и IP:127.0.0.1. Адреса 127.0.0.2 там нет, поэтому curl отказывается доверять серверу.

### 8.4. Создание чужого сертификата:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/other.key
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ openssl req -new -x509 -key /tmp/other.key -subj '/CN=Other Root' -days 1 -out /tmp/other.crt
```

### 8.5. Подключение с чужим сертификатом:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ curl --cacert /tmp/other.crt https://localhost:8443/
curl: (60) SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the webpage mentioned above.
```

Является негативным тестом. Мы попытались подключиться к серверу, указав в качестве доверенного корня «чужой» самоподписанный сертификат /tmp/other.crt. Поскольку серверный сертификат подписан нашим промежуточным CA, а не этим «чужим» корнем, утилита curl не смогла построить цепочку доверия и выдала ошибку unable to get local issuer certificate.

### 8.6. Проверка отказ TLS 1.2:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ ( sleep 1 ) | openssl s_client -connect localhost:8443 -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'
40B7A42CEC790000:error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version:../ssl/record/rec_layer_s3.c:918:SSL alert number 70
Protocol: TLSv1.2
    Protocol : TLSv1.2
ewwwgeny@DESKTOP-9DNP85E:~/lab4$
```

## Задача 9. Захват рукопожатия TLS 1.3

**Терминал 1 (захват):**

```console
ewwwgeny@DESKTOP-9DNP85E:~$ sudo tcpdump -i lo -w ~/lab4/client/handshake.pcap 'tcp port 8443'
[sudo: authenticate] Password:
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
^C19 packets captured
38 packets received by filter
0 packets dropped by kernel
```

**Терминал 2 (клиент):**

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4$ cd ~/lab4/client
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$
SSLKEYLOGFILE=$HOME/lab4/client/keys.log curl -sS --cacert ../root/root.crt https://localhost:8443/
tls13 ok
```

Возвращение прав на файл захвата:

```console
ewwwgeny@DESKTOP-9DNP85E:~$ sudo chown $USER ~/lab4/client/handshake.pcap
ewwwgeny@DESKTOP-9DNP85E:~$
```

Проверка наличия журнала ключей:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$ wc -l ~/lab4/client/keys.log
5 /home/ewwwgeny/lab4/client/keys.log
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$
```

В файле keys.log присутствуют пять строк с секретами TLS, необходимых для расшифровки захваченного сеанса

## Задача 10. Проанализировать TLS 1.3 в Wireshark

### 10.1. Посмотр рукопожатия без журнала ключей:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$ tshark -r handshake.pcap -Y tls -T fields -e frame.number -e tls.record.content_type -e tls.handshake.type
6       22      1
8       22,20   2
10      20
11
12
13
15
16
```

Подтверждение свойства конфиденциальности протокола TLS 1.3. В TLS 1.3 сообщения после ServerHello зашифрованы, поэтому без ключей их содержимое нельзя прочитать.

### 10.2. Посмотр рукопожатия с журналом ключей:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$ tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y tls.handshake -T fields -e frame.number -e tls.handshake.type
6       1
8       2,8,11,15,20
10      20
12      4
13      4
```

Зафиксировать сообщения:

- ClientHello – приветствие клиента
- ServerHello – приветствие сервера
- EncryptedExtensions – зашифрованные расширения
- Certificate цепочка – сертификатов сервера
- CertificateVerify – подпись транскрипта, подтверждающая владение ключом
- Finished – завершение рукопожатия со стороны сервера

### 10.3. Определение согласованного набора шифров и группу ECDHE:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$ tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group
0x1301 29
```

- Шифр: 0x1301 – TLS_AES_128_GCM_SHA256.
- Группа: 29 – X25519.

### 10.4. Нахождение SNI в ClientHello:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$ tshark -r handshake.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name
localhost
```

### 10.5. Посмотр SAN серверного сертификата в захвате:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$ tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 11' -V | grep -E 'dNSName|iPAddress'
                                    GeneralName: dNSName (2)
                                        dNSName: localhost
                                    GeneralName: iPAddress (7)
                                        iPAddress: 127.0.0.1
```

### 10.6. Посмотр алгоритма подписи CertificateVerify:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$ tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 15' -T fields -e tls.handshake.sig_hash_alg
0x0804
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$
```

- Алгоритм подписи: 0x0804 – rsa_pss_rsae_sha256.

## Задача 11. Вариант №5

### 11.1. Посмотр имён, указанные в SAN сертификата:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$ openssl x509 -in ~/lab4/server/server.crt -noout -ext subjectAltName
X509v3 Subject Alternative Name:
    DNS:localhost, IP Address:127.0.0.1
```

### 11.2. Посмотр CN серверного сертификата:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$ openssl x509 -in ~/lab4/server/server.crt -noout -subject
subject=CN=localhost
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$
```

CN не помогает, потому что современные клиенты при проверке имени сервера используют расширение Subject Alternative Name (SAN), а не поле Common Name (CN). В сертификате указаны DNS-имя localhost и IP-адрес 127.0.0.1. Адрес 127.0.0.2 в SAN отсутствует, поэтому при подключении к нему проверка имени завершается ошибкой.

Значение CN=localhost не помогает, поскольку современные клиенты не используют CN для такой проверки.

### 11.3. Нахождение SNI в ClientHello

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$
SSLKEYLOGFILE=$HOME/lab4/client/keys.log curl -v --cacert ~/lab4/root/root.crt https://localhost:8443/
* Host localhost:8443 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8443...
* connect to ::1 port 8443 from ::1 port 60920 failed: Connection refused
*   Trying 127.0.0.1:8443...
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* SSL Trust Anchors:
*   CAfile: /home/ewwwgeny/lab4/root/root.crt
*   CApath: /etc/ssl/certs
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256 / x25519 / RSASSA-PSS
* ALPN: server accepted http/1.1
* Server certificate:
*   subject: CN=localhost
*   start date: Nov 9 07:47:02 2026 GMT
*   expire date: Nov 9 07:47:02 2027 GMT
*   issuer: C=BY; O=Lab PKI; CN=Lab Intermediate CA
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed
using sha256WithRSAEncryption
*   Certificate level 1: Public key type RSA (2048/112 Bits/secBits), signed
using sha256WithRSAEncryption
*   Certificate level 2: Public key type RSA (2048/112 Bits/secBits), signed
using sha256WithRSAEncryption
*   subjectAltName: "localhost" matches cert's "localhost"
* SSL certificate verified via OpenSSL.
* Established connection to localhost (127.0.0.1 port 8443) from 127.0.0.1
port 36884
* using HTTP/1.x
> GET / HTTP/1.1
> Host: localhost:8443
> User-Agent: curl/8.18.0
> Accept: */*
>
* Request completely sent off
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
< HTTP/1.1 200 OK
< Server: nginx/1.28.3 (Ubuntu)
< Date: Mon, 09 Nov 2026 10:36:22 GMT
< Content-Type: application/octet-stream
< Content-Length: 8
< Connection: keep-alive
<
* Connection #0 to host localhost:8443 left intact
tls13 ok
```

SNI в захвате:

```console
ewwwgeny@DESKTOP-9DNP85E:~/lab4/client$ tshark -r ~/lab4/client/handshake.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name

localhost
```

SNI (Server Name Indication) в сообщении ClientHello равен localhost. Это расширение TLS, в котором клиент указывает имя сервера, к которому хочет подключиться, и передается оно в открытом виде до установления шифрования. При подключении по IP-адресу (127.0.0.2) клиент обычно не отправляет SNI, поэтому для его демонстрации использовалось отдельное подключение по имени localhost.

## Вывод

Вывод: в ходе лабораторной работы был развернут собственный Удостоверяющий Центр (CA) с трехзвенной цепочкой сертификатов X.509 и настроен веб-сервер Nginx, принимающий соединения строго по протоколу TLS 1.3 с заданными параметрами. С помощью tcpdump и tshark было перехвачено рукопожатие TLS 1.3, а журнал ключей (SSLKEYLOGFILE) позволил расшифровать трафик и детально проанализировать все этапы установления защищенного соединения. В рамках индивидуального задания варианта №5 было доказано, что клиенты проверяют имя только по SAN (отклоняя подключение к 127.0.0.2), а также успешно найдено расширение SNI в сообщении ClientHello.
