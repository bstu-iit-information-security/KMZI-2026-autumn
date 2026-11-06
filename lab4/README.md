<p align="center">Министерство образования Республики Беларусь</p>
<p align="center">Учреждение образования</p>
<p align="center">“Брестский Государственный технический университет”</p>
<p align="center">Кафедра ИИТ</p>
<br><br><br><br><br><br><br>
<p align="center">Лабораторная работа №4</p>
<p align="center">По дисциплине “Криптографические методы защиты информации”</p>
<p align="center">Тема: “PKI, HTTPS и TLS 1.3. Развертывание тестового Удостоверяющего Центра (CA), выпуск сертификатов X.509, настройка HTTPS-сервера и анализ рукопожатия TLS 1.3 в Wireshark”</p>
<p align="center">Вариант: 11</p>
<br><br><br><br><br>
<p align="right">Выполнил:</p>
<p align="right">Студент 3 курса</p>
<p align="right">Группы ИИ-28</p>
<p align="right">Цибульскас В.С.</p>
<p align="right">Проверил:</p>
<p align="right">Хацкевич А.С.</p>
<br><br><br><br><br>
<p align="center">Брест 2026</p>

---

# Цель

На собственном тестовом CA выпустить цепочку сертификатов X.509 с расширениями, настроить HTTPS-сервер, принимающий только TLS 1.3, проверить цепочку доверия и отзыв, захватить рукопожатие TLS 1.3 и разобрать его в Wireshark, в том числе после расшифровки через журнал ключей (`SSLKEYLOGFILE`).

# Вариант 11

![Вариант 11](img/variant.png)

Параметры варианта:

| Параметр | Значение |
|---|---|
| Ключ корневого CA | ECDSA P-256 |
| Ключ промежуточного CA | ECDSA P-256 |
| Ключ сервера | ECDSA P-384 |
| Группа ECDHE | P-384 |
| Набор шифров TLS 1.3 | `TLS_AES_128_GCM_SHA256` (`0x1301`) |
| Задача варианта | OCSP: `good` → `revoked`, сравнение с CRL |

# Ход работы

## 0. Окружение

Работа выполнялась на macOS 27.2 (Darwin 27.2.0, arm64). Использовались OpenSSL 3.6.5 (Homebrew), nginx 1.31.8 (Homebrew), tshark 4.6.9 и curl 8.7.1. Системный `/usr/bin/openssl` в macOS — это LibreSSL, поэтому для всех команд явно используется OpenSSL 3.x из Homebrew.

![Окружение](img/environment.png)

Каталог работы — `~/lab4`:

```bash
mkdir -p ~/lab4/{root,inter,server,client,revoked,expired,nginx}
cd ~/lab4
```

## 1. Корневой CA

Корневой CA создаётся на ECDSA P-256. В сертификате задаются `basicConstraints=critical,CA:TRUE,pathlen:1`, `keyUsage=critical,keyCertSign,cRLSign` и `subjectKeyIdentifier`.

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root/root.key
chmod 600 root/root.key

openssl req -new -x509 -key root/root.key -sha256 -days 3650 \
  -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -out root/root.crt
```

Проверка полей:

```bash
openssl x509 -in root/root.crt -noout -subject -issuer -dates \
  -ext basicConstraints,keyUsage
```

![Корневой CA](img/root_ca.png)

`pathlen:1` разрешает корню выпустить один промежуточный CA, но не больше.

## 2. Промежуточный CA

Промежуточный CA тоже на ECDSA P-256. Для него задаётся `pathlen:0`: он может выпускать конечные сертификаты, но не другие CA.

```bash
cat > inter/inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
chmod 600 inter/inter.key

openssl req -new -key inter/inter.key \
  -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' \
  -out inter/inter.csr

openssl x509 -req -in inter/inter.csr \
  -CA root/root.crt -CAkey root/root.key -CAcreateserial \
  -sha256 -days 1825 -extfile inter/inter.ext \
  -out inter/inter.crt
```

![Промежуточный CA](img/intermediate_ca.png)

В выводе видны `CA:TRUE, pathlen:0`, `keyCertSign`, `cRLSign`, Subject Key Identifier и Authority Key Identifier.

## 3. База промежуточного CA

Сертификаты и CRL выпускаются через `openssl ca`, поэтому нужна база `index.txt`, счётчик серийных номеров и счётчик CRL.

```bash
cd inter
touch index.txt
echo 01 > crlnumber
echo 1000 > serial
cd ..
```

![База промежуточного CA](img/ca_database.png)

Конфигурация `inter/ca.cnf`:

```ini
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = /Users/viktar/lab4/inter
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
```

![Конфигурация промежуточного CA](img/ca_config.png)

`unique_subject = no` позволяет повторно выпускать сертификаты с тем же Subject, а `copy_extensions = none` означает, что расширения берутся из отдельного `-extfile`, а не из CSR.

## 4. Серверный сертификат с SAN

Серверный ключ — ECDSA P-384. В сертификате заданы SAN `DNS:localhost,IP:127.0.0.1`, EKU `serverAuth`, `keyUsage=digitalSignature`, `CA:FALSE` и AIA с адресом OCSP-responder.

```bash
cat > server/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:localhost,IP:127.0.0.1
authorityInfoAccess=OCSP;URI:http://127.0.0.1:2560
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out server/server.key
chmod 600 server/server.key

openssl req -new -key server/server.key \
  -subj '/C=BY/O=Lab PKI/CN=localhost' \
  -out server/server.csr

openssl ca -config inter/ca.cnf -batch \
  -in server/server.csr -extfile server/server.ext \
  -notext -out server/server.crt
```

![Серверный сертификат](img/server_cert.png)

Проверка расширений и сборка полной цепочки:

```bash
openssl x509 -in server/server.crt -noout -subject -issuer \
  -ext basicConstraints,keyUsage,extendedKeyUsage,subjectAltName,authorityInfoAccess

cat server/server.crt inter/inter.crt > server/fullchain.pem
grep -c 'BEGIN CERTIFICATE' server/fullchain.pem
```

![Расширения серверного сертификата](img/server_ext.png)

`fullchain.pem` содержит два сертификата: сначала лист `localhost`, затем промежуточный CA. Именно этот файл отдаёт nginx, иначе клиент не построит цепочку до корня.

## 5. Тестовые сертификаты для отзыва и истечения

Серверный сертификат отзывать нельзя: после отзыва придётся перевыпускать его и перезапускать nginx. Поэтому для варианта 11 выпускается отдельный тестовый лист `revoked.localhost` на ECDSA P-384.

```bash
cat > revoked/revoked.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:revoked.localhost
authorityInfoAccess=OCSP;URI:http://127.0.0.1:2560
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out revoked/revoked.key
chmod 600 revoked/revoked.key

openssl req -new -key revoked/revoked.key \
  -subj '/C=BY/O=Lab PKI/CN=revoked.localhost' \
  -out revoked/revoked.csr

openssl ca -config inter/ca.cnf -batch \
  -in revoked/revoked.csr -extfile revoked/revoked.ext \
  -notext -out revoked/revoked.crt
```

![Тестовый сертификат для отзыва](img/revoked_cert.png)

Для негативной проверки срока действия выпускается отдельный лист с датами в прошлом:

```bash
cat > expired/expired.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:expired.localhost
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out expired/expired.key
chmod 600 expired/expired.key

openssl req -new -key expired/expired.key \
  -subj '/C=BY/O=Lab PKI/CN=expired.localhost' \
  -out expired/expired.csr

openssl ca -config inter/ca.cnf -batch \
  -in expired/expired.csr -extfile expired/expired.ext \
  -startdate 20200101000000Z -enddate 20210101000000Z \
  -notext -out expired/expired.crt
```

![Сертификат с истёкшим сроком](img/expired_cert.png)

## 6. Проверка цепочки

Положительная проверка: клиент доверяет только корню, а промежуточный сертификат получает как untrusted.

```bash
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt \
  -verify_hostname localhost server/server.crt
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt \
  -verify_ip 127.0.0.1 server/server.crt
```

![Положительная проверка цепочки](img/chain_positive.png)

Негативные проверки:

* без промежуточного сертификата — `unable to get local issuer certificate`;
* с чужим корнем — `unable to get local issuer certificate`;
* имя вне SAN — `hostname mismatch` (код 62);
* IP вне SAN — `IP address mismatch` (код 64);
* истёкший сертификат — `certificate has expired` (код 10).

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/other.key
openssl req -new -x509 -key /tmp/other.key -subj '/CN=Other Root' -days 1 -out /tmp/other.crt

openssl verify -CAfile root/root.crt server/server.crt
openssl verify -CAfile /tmp/other.crt -untrusted inter/inter.crt server/server.crt
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt \
  -verify_hostname wrong.localhost server/server.crt
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt \
  -verify_ip 127.0.0.2 server/server.crt
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt expired/expired.crt
```

![Негативные проверки цепочки](img/chain_negative.png)

## 7. nginx: HTTPS только по TLS 1.3

Для варианта 11 в nginx заданы только TLS 1.3, один шифр `TLS_AES_128_GCM_SHA256` и группа `P-384`. В TLS 1.3 набор задаётся не через `ssl_ciphers`, а через `ssl_conf_command Ciphersuites`.

```nginx
server {
    listen 8443 ssl;
    server_name localhost;

    ssl_certificate     /Users/viktar/lab4/server/fullchain.pem;
    ssl_certificate_key /Users/viktar/lab4/server/server.key;

    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256;
    ssl_ecdh_curve P-384;
    ssl_session_tickets on;

    location / { return 200 'tls13 ok'; }
}
```

На macOS nginx запускался без `sudo` на непривилегированном порту 8443 через локальную обёртку `nginx/nginx.conf`, которая подключает `lab4.conf`. На Linux этот же `lab4.conf` можно скопировать в `/etc/nginx/conf.d/`.

```bash
nginx -t -c /Users/viktar/lab4/nginx/nginx.conf
nginx -c /Users/viktar/lab4/nginx/nginx.conf
```

![Конфигурация nginx](img/nginx_config.png)

После запуска nginx слушает `*:8443`:

![Запуск nginx](img/nginx_start.png)

## 8. Проверка клиентом

Положительный тест: `curl` получает корень через `--cacert`, проверяет цепочку, SAN `localhost` и договаривается на TLS 1.3.

```bash
curl -v --cacert root/root.crt https://localhost:8443/
```

![Положительная проверка curl](img/curl_positive.png)

В выводе видны `SSL connection using TLSv1.3 / AEAD-AES128-GCM-SHA256`, `HTTP/1.1 200 OK` и тело `tls13 ok`.

Негативные тесты:

```bash
curl https://localhost:8443/
curl --cacert root/root.crt \
  --connect-to wrong.localhost:8443:127.0.0.1:8443 \
  https://wrong.localhost:8443/
curl --cacert /tmp/other.crt https://localhost:8443/
( sleep 1 ) | openssl s_client -connect localhost:8443 -tls1_2 \
  -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'
```

![Негативные проверки curl](img/curl_negative.png)

Ожидаемые результаты: без `--cacert` — exit 60 `unable to get local issuer certificate`; с именем вне SAN — exit 60 `no alternative certificate subject name matches target host name`; с чужим корнем — exit 60 `unable to get local issuer certificate`; TLS 1.2 — `alert protocol version`, код 70.

В macOS адрес `127.0.0.2` не был доступен для подключения, поэтому для проверки имени использован `--connect-to` на `127.0.0.1` с сохранением имени `wrong.localhost`; проверка IP вне SAN отдельно выполнена через `openssl verify -verify_ip 127.0.0.2`.

## 9. Захват рукопожатия и журнал ключей

Захват выполняется на loopback-интерфейсе. В macOS это `lo0`, в Linux — `lo`. `tcpdump` писал пакеты порта 8443 в `client/handshake.pcap`.

```bash
tcpdump -i lo0 -U -w client/handshake.pcap 'tcp port 8443' &
```

Клиент `openssl s_client` записывает секреты сессии в `client/keys.log` через `-keylogfile`. Переменная `SSLKEYLOGFILE` для `s_client` не работает; в macOS curl собран с SecureTransport и журнал ключей также не пишет.

```bash
openssl s_client -connect localhost:8443 -servername localhost \
  -CAfile root/root.crt -tls1_3 -groups P-384 \
  -keylogfile client/keys.log -brief
```

![Захват рукопожатия](img/capture_handshake.png)

В журнале шесть строк: заголовок и пять секретов. Список меток:

```bash
cut -d' ' -f1 client/keys.log | sort -u
```

![Журнал ключей](img/keys_log.png)

## 10. Анализ в tshark

Без журнала ключей видны только `ClientHello` (тип 1) и `ServerHello` (тип 2). Остальные сообщения TLS 1.3 находятся внутри записей `application_data`; в tshark 4.6 фактический тип записи удобно смотреть через `tls.record.opaque_type` (23), потому что `tls.record.content_type` для зашифрованных записей может быть пустым.

```bash
tshark -r client/handshake.pcap -Y tls -T fields \
  -e frame.number -e tls.record.content_type \
  -e tls.record.opaque_type -e tls.handshake.type
```

![tshark без ключей](img/tshark_no_keys.png)

С журналом ключей видны `EncryptedExtensions` (8), `Certificate` (11), `CertificateVerify` (15), `Finished` (20) и `NewSessionTicket` (4).

```bash
tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
  -Y tls.handshake -T fields -e frame.number -e tls.handshake.type
```

![tshark с ключами](img/tshark_with_keys.png)

Параметры рукопожатия:

```bash
tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
  -Y 'tls.handshake.type == 2' -T fields \
  -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group

tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
  -Y 'tls.handshake.type == 1' -T fields \
  -e tls.handshake.extensions_server_name

tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
  -Y 'tls.handshake.type == 11' -V | grep -E 'dNSName|iPAddress'

tshark -r client/handshake.pcap -o tls.keylog_file:client/keys.log \
  -Y 'tls.handshake.type == 15' -T fields \
  -e tls.handshake.sig_hash_alg
```

![Поля рукопожатия](img/handshake_fields.png)

Полученные значения:

| Поле | Значение |
|---|---|
| Шифр | `0x1301` — `TLS_AES_128_GCM_SHA256` |
| Группа `key_share` | `24` — P-384 (`secp384r1`) |
| SNI | `localhost` |
| SAN сертификата | `dNSName: localhost`, `iPAddress: 127.0.0.1` |
| Подпись `CertificateVerify` | `0x0503` — `ecdsa_secp384r1_sha384` |

## 11. Индивидуальное задание: OCSP

Для варианта 11 поднимается OCSP-responder на порту 2560. Он подписывает ответы ключом промежуточного CA и читает базу `inter/index.txt` при старте.

```bash
openssl ocsp -index inter/index.txt -port 2560 \
  -rsigner inter/inter.crt -rkey inter/inter.key \
  -CA inter/inter.crt -text
```

Запрос статуса серверного и ещё не отозванного тестового сертификата:

```bash
openssl ocsp -issuer inter/inter.crt -cert server/server.crt \
  -url http://127.0.0.1:2560 -CAfile root/root.crt -no_nonce

openssl ocsp -issuer inter/inter.crt -cert revoked/revoked.crt \
  -url http://127.0.0.1:2560 -CAfile root/root.crt -no_nonce
```

![OCSP: сертификаты действительны](img/ocsp_good.png)

Оба ответа — `good`, подпись ответа проверяется (`Response verify OK`).

Теперь отзывается только тестовый лист `revoked.crt`, а не серверный сертификат:

```bash
openssl ca -config inter/ca.cnf -batch -revoke revoked/revoked.crt
openssl ca -config inter/ca.cnf -batch -gencrl -out inter/inter.crl
```

Responder читает `index.txt` при старте, поэтому после отзыва его нужно перезапустить. После перезапуска:

```bash
openssl ocsp -issuer inter/inter.crt -cert server/server.crt \
  -url http://127.0.0.1:2560 -CAfile root/root.crt -no_nonce
# server.crt: good

openssl ocsp -issuer inter/inter.crt -cert revoked/revoked.crt \
  -url http://127.0.0.1:2560 -CAfile root/root.crt -no_nonce
# revoked.crt: revoked
```

![OCSP: revoked после отзыва](img/ocsp_revoked.png)

Серверный сертификат остаётся `good`, отозванный тестовый — `revoked`.

### Сравнение с CRL

Тот же отзыв можно проверить по CRL. В CRL попадает серийный номер `1001` (revoked.crt), а серийного номера `1000` (server.crt) там нет.

```bash
openssl crl -in inter/inter.crl -noout -text
openssl verify -crl_check -CAfile root/root.crt \
  -untrusted inter/inter.crt -CRLfile inter/inter.crl server/server.crt
openssl verify -crl_check -CAfile root/root.crt \
  -untrusted inter/inter.crt -CRLfile inter/inter.crl revoked/revoked.crt
```

![Проверка по CRL](img/crl_check.png)

Результат:

| Сертификат | OCSP | CRL |
|---|---|---|
| `server.crt` | `good` | `OK` (не отозван) |
| `revoked.crt` | `revoked` | `error 23: certificate revoked` |

OCSP отвечает про один сертификат онлайн и позволяет получить статус без скачивания всего списка. CRL — это подписанный CA список всех отозванных сертификатов; клиент скачивает его целиком, и со временем список растёт. В работе оба механизма дали согласованный результат: `server.crt` действителен, `revoked.crt` отозван.

# Вывод

В ходе работы был развёрнут тестовый удостоверяющий центр с корневым и промежуточным CA, выпущена цепочка X.509 с `pathlen`, `keyUsage`, `extendedKeyUsage`, SAN и AIA. Проверка `openssl verify` подтвердила, что цепочка строится только при наличии промежуточного сертификата, а неверное имя, IP, чужой корень и истёкший срок корректно отвергаются.

nginx был настроен на TLS 1.3 с `TLS_AES_128_GCM_SHA256` и группой P-384; `curl` получил `HTTP 200` и тело `tls13 ok`, а TLS 1.2 был отвергнут alert-ом `protocol version` (70). В захвате `tls.handshake.ciphersuite` равен `0x1301`, группа `key_share` — `24` (P-384), SNI — `localhost`, подпись `CertificateVerify` — `0x0503`.

В индивидуальном задании был поднят OCSP-responder: серверный сертификат получил статус `good`, тестовый лист после отзыва — `revoked`. Повторный запрос после перезапуска responder подтвердил, что он перечитывает `index.txt`. CRL для того же отзыва содержит серийный номер `1001` и не содержит `1000`; `openssl verify -crl_check` даёт `certificate revoked` для отозванного листа и `OK` для серверного. Это показывает разницу между онлайн-проверкой отдельного сертификата через OCSP и офлайн-списком CRL.

# Использованные источники

1. Методические указания к лабораторной работе №4 «PKI, HTTPS и TLS 1.3».
2. RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and CRL Profile.
3. RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3.
4. RFC 6960 — Online Certificate Status Protocol (OCSP).
