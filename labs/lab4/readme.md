# Отчёт по Лабораторной работе №4. Вариант 2

**Студент:** Литвинчук Илья Витальевич
**Стенд:** Ubuntu 24.04, OpenSSL 3.0.13, nginx 1.24.0, curl 8.5.0, tshark 4.2.2

**Параметры варианта 2**

| Параметр | Значение |
|---|---|
| Ключ корневого и промежуточного CA | RSA-3072 |
| Ключ сервера | RSA-2048 |
| Группа ECDHE | P-256 (secp256r1, код `23`) |
| Набор шифров TLS 1.3 | `TLS_AES_256_GCM_SHA384` (`0x1302`) |
| Протокол | только TLS 1.3 |
| mTLS | нет |
| Порт | 8443 |
| Задача варианта | ограничение `pathlen` |

**Запуск.** Вся работа автоматизирована скриптом `lab4_var2.sh`:

```bash
chmod +x lab4_var2.sh
./lab4_var2.sh all      # полный цикл: CA → nginx → проверки → pathlen → захват → tshark
```

Артефакты складываются в `~/lab4/structure/`. Отдельные шаги доступны командами
`ca`, `leaf`, `nginx`, `chain`, `https`, `negatives`, `pathlen`, `capture`,
`analyze`, `collect`, `clean`.

---

## 1. Удостоверяющий центр и сертификаты X.509

Значения серийных номеров, SKI и отпечатков ниже приведены для одного прогона
скрипта; при повторном запуске они будут другими, структура и расширения — те же.

### Корневой CA (`root.crt`)

```
Subject: C = BY, O = Lab PKI, CN = Lab Root CA RSA3072
Public Key Algorithm: rsaEncryption
    Public-Key: (3072 bit)
X509v3 Basic Constraints: critical
    CA:TRUE, pathlen:1
X509v3 Key Usage: critical
    Certificate Sign, CRL Sign
X509v3 Subject Key Identifier:
    D2:4C:CA:32:EE:0A:F6:7D:34:F3:A2:12:E2:29:3B:D1:C2:93:4E:01
Signature Algorithm: sha256WithRSAEncryption
```

**Ожидается:** `CA:TRUE, pathlen:1`, `Certificate Sign, CRL Sign`, ключ RSA-3072.
**Совпадает.**

### Промежуточный CA (`inter.crt`)

```
Subject: C = BY, O = Lab PKI, CN = Lab Intermediate CA RSA
Issuer:  C = BY, O = Lab PKI, CN = Lab Root CA RSA3072
Public Key Algorithm: rsaEncryption
    Public-Key: (3072 bit)
X509v3 Basic Constraints: critical
    CA:TRUE, pathlen:0
X509v3 Key Usage: critical
    Certificate Sign, CRL Sign
X509v3 Subject Key Identifier:
    45:90:22:35:C9:2A:C0:CB:B3:95:E4:1B:71:AA:60:16:98:13:C0:F2
X509v3 Authority Key Identifier:
    D2:4C:CA:32:EE:0A:F6:7D:34:F3:A2:12:E2:29:3B:D1:C2:93:4E:01
Signature Algorithm: sha256WithRSAEncryption
```

**Ожидается:** `CA:TRUE, pathlen:0` (запрещает выпуск других CA), `Certificate Sign,
CRL Sign`, RSA-3072, AKI совпадает с SKI корня. **Совпадает.**

### Серверный сертификат (`server.crt`)

```
Subject: CN = localhost
Issuer:  C = BY, O = Lab PKI, CN = Lab Intermediate CA RSA
Public Key Algorithm: rsaEncryption
    Public-Key: (2048 bit)
X509v3 Basic Constraints: critical
    CA:FALSE
X509v3 Key Usage: critical
    Digital Signature
X509v3 Extended Key Usage:
    TLS Web Server Authentication
X509v3 Subject Alternative Name:
    DNS:localhost, IP Address:127.0.0.1
X509v3 Subject Key Identifier:
    FB:CE:20:3B:04:76:98:90:BA:7E:B5:B5:3A:E4:EA:2E:C4:37:EA:07
X509v3 Authority Key Identifier:
    45:90:22:35:C9:2A:C0:CB:B3:95:E4:1B:71:AA:60:16:98:13:C0:F2
Signature Algorithm: sha256WithRSAEncryption
```

**Ожидается:** `CA:FALSE`, `Digital Signature`, `TLS Web Server Authentication`,
SAN `localhost` и `127.0.0.1`, ключ RSA-2048. **Совпадает.**

Срок действия листа — 365 дней (`default_days = 365` в `inter/ca.cnf`):

```
Not Before: Nov 25 14:19:54 2026 GMT
Not After : Nov 25 14:19:54 2027 GMT
```

## 2. Конфигурация HTTPS-сервера (nginx)

Файл `/etc/nginx/conf.d/lab4.conf` (порт 8443 — 443 привилегированный и не требуется):

```
server {
    listen 8443 ssl;
    server_name localhost;

    ssl_certificate     /home/us230/lab4/server/fullchain.pem;
    ssl_certificate_key /home/us230/lab4/server/server.key;

    # Вариант 2: только TLS 1.3, AES-256-GCM, P-256
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;
    ssl_ecdh_curve P-256;

    ssl_session_tickets on;

    location / { return 200 'tls13 variant2 ok\n'; }
}
```

Сервер отдаёт `fullchain.pem` (лист + промежуточный CA), иначе клиент не построит
путь до корня. Вывод `sudo nginx -t`:

```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

## 3. Проверка цепочки и негативные тесты

### Позитивная проверка цепочки

```
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
```

Вывод:

```
server/server.crt: OK
```

### Позитивный запрос

```
curl -v --cacert root/root.crt https://localhost:8443/
```

Ключевые строки:

```
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / prime256v1 / RSASSA-PSS
*  subjectAltName: host "localhost" matched cert's "localhost"
*  SSL certificate verify ok.
< HTTP/1.1 200 OK
tls13 variant2 ok
```

### Негативный тест 1: без `--cacert`

```
curl https://localhost:8443/
```

```
curl: (60) SSL certificate problem: unable to get local issuer certificate
```

### Негативный тест 2: чужой корень

```
curl --cacert /tmp/other.crt https://localhost:8443/
```

```
curl: (60) SSL certificate problem: unable to get local issuer certificate
```

### Негативный тест 3: имя хоста вне SAN

```
curl --cacert root/root.crt https://127.0.0.2:8443/
```

```
curl: (60) SSL: no alternative certificate subject name matches target host name '127.0.0.2'
```

### Негативный тест 4: TLS 1.2

```
( sleep 1 ) | openssl s_client -connect localhost:8443 -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'
```

```
tlsv1 alert protocol version:...SSL alert number 70
Protocol  : TLSv1.2
```

Сервер принимает только TLS 1.3 — клиент получает `alert protocol version (70)`.

### Негативный тест 5: без промежуточного сертификата

```
openssl verify -CAfile root/root.crt server/server.crt
```

```
CN = localhost
error 20 at 0 depth lookup: unable to get local issuer certificate
error server/server.crt: verification failed
```

## 4. Анализ рукопожатия в tshark

### Без журнала ключей

```
tshark -r ~/lab4/client/handshake.pcap -Y tls -T fields -e frame.number -e tls.record.content_type -e tls.handshake.type
```

**Вывод:** видны только `1` (ClientHello) и `2` (ServerHello). Остальные сообщения
скрыты внутри записей с `content_type 23` (application_data) и `content_type 20`
(change_cipher_spec, режим совместимости).

### С журналом ключей (`keys.log`)

```
tshark -r ~/lab4/client/handshake.pcap -o tls.keylog_file:$HOME/lab4/client/keys.log \
  -Y tls.handshake -T fields -e frame.number -e tls.handshake.type
```

**Вывод:** `1` (ClientHello), `2` (ServerHello), `8` (EncryptedExtensions),
`11` (Certificate), `15` (CertificateVerify), `20` (Finished),
`4` (NewSessionTicket). Сообщения `Certificate`, `CertificateVerify`, `Finished`
расшифрованы благодаря журналу ключей.

### Детальные поля из расшифрованного захвата

```
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 2' \
  -T fields -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group
0x1302	23
```

```
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 1' \
  -T fields -e tls.handshake.extensions_server_name
localhost
```

```
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 11' -V | grep -E 'dNSName|iPAddress'
dNSName: localhost
iPAddress: 127.0.0.1
```

```
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 15' \
  -T fields -e tls.handshake.sig_hash_alg
0x0804
```

- Шифр и группа: `0x1302` (`TLS_AES_256_GCM_SHA384`), `23` (secp256r1 / P-256) —
  соответствуют варианту 2.
- SNI: `localhost`.
- SAN в сертификате: `dNSName: localhost`, `iPAddress: 127.0.0.1`.
- Подпись CertificateVerify: `0x0804` (`rsa_pss_rsae_sha256`) — серверный ключ
  RSA, в TLS 1.3 подпись только RSA-PSS.

### Уникальные метки из `keys.log`

```
cut -d' ' -f1 keys.log | sort -u
```

- `CLIENT_HANDSHAKE_TRAFFIC_SECRET`
- `CLIENT_TRAFFIC_SECRET_0`
- `EXPORTER_SECRET`
- `SERVER_HANDSHAKE_TRAFFIC_SECRET`
- `SERVER_TRAFFIC_SECRET_0`

## 5. Решение задачи Варианта 2 — ограничение `pathlen`

**Требование:** корень с `pathlen:0` и промежуточный CA под ним; проверка должна
дать `path length constraint exceeded`. Нужно объяснить, что именно ограничивает
`pathlen`.

Скрипт строит отдельную ветку `~/lab4/pathlen/`: корень `root_pl.crt`
(`pathlen:0`) → промежуточный CA `inter_pl.crt` (`CA:TRUE`) → лист `leaf.crt`.

```
openssl x509 -in pathlen/root_pl.crt -noout -ext basicConstraints
```

```
X509v3 Basic Constraints: critical
    CA:TRUE, pathlen:0
```

**Команда проверки:**

```
openssl verify -CAfile pathlen/root_pl.crt -untrusted pathlen/inter_pl.crt pathlen/leaf.crt
```

**Фактический вывод:**

```
C = BY, O = Lab PKI, CN = Lab Root Pathlen0
error 25 at 2 depth lookup: path length constraint exceeded
error pathlen/leaf.crt: verification failed
```

**Контроль 1** — тот же корень подписывает лист напрямую (промежуточного CA нет):

```
openssl x509 -req -in pathlen/leaf.csr -CA pathlen/root_pl.crt \
  -CAkey pathlen/root_pl.key -CAcreateserial -days 365 \
  -extfile pathlen/leaf.ext -out pathlen/leaf_direct.crt

openssl verify -CAfile pathlen/root_pl.crt pathlen/leaf_direct.crt
```

```
pathlen/leaf_direct.crt: OK
```

**Контроль 2** — основная цепочка лабораторной, у корня `pathlen:1`:

```
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
server/server.crt: OK
```

**Объяснение.** `pathLenConstraint` (RFC 5280, п. 4.2.1.9) задаёт максимальное
число **не-self-issued промежуточных CA-сертификатов**, которые могут находиться
ниже данного сертификата в пути сертификации. Правила подсчёта:

* считаются только CA-сертификаты; листовые сертификаты не считаются;
* сам сертификат, в котором записано ограничение, не считается;
* self-issued сертификаты (Subject = Issuer) не считаются;
* ограничение не запрещает листья — оно ограничивает глубину иерархии CA.

Отсюда:

| Сертификат | `pathlen` | Что разрешено ниже |
|---|---|---|
| корень основного стенда | `1` | один промежуточный CA: `root → inter → leaf` |
| промежуточный CA | `0` | только листья, выпускать CA нельзя |
| корень в задаче | `0` | ни одного промежуточного CA |

В задаче под корнем с `pathlen:0` стоит промежуточный CA, то есть ниже корня
оказался один промежуточный CA при разрешённых нулю. Проверка падает с
`error 25` (`X509_V_ERR_PATH_LENGTH_EXCEEDED`).

Глубина в сообщении OpenSSL: `0` — лист, `1` — промежуточный CA, `2` — корень.
Ошибка приписывается сертификату, чьё ограничение нарушено, поэтому в выводе
стоит `at 2 depth` и Subject корня, а не листа. OpenSSL проверяет `pathlen` и у
корня, хотя корень является точкой доверия.

Контроль 1 показывает, что `pathlen:0` не запрещает выпуск листовых
сертификатов: цепочка `root(pathlen:0) → leaf` проходит. Значит, ограничение
касается именно промежуточных CA, а не длины цепочки вообще.

## 6. Сводка

| Проверка | Результат |
|---|---|
| Корень RSA-3072, `CA:TRUE,pathlen:1` | да |
| Промежуточный RSA-3072, `CA:TRUE,pathlen:0` | да |
| Лист RSA-2048, `CA:FALSE`, `serverAuth`, SAN `localhost,127.0.0.1` | да |
| Цепочка с intermediate | `OK` |
| Цепочка без intermediate (негативный) | `unable to get local issuer certificate` |
| nginx TLS 1.3 + AES-256-GCM (`0x1302`) + P-256 (`23`) | да |
| `curl` позитив | HTTP 200, TLSv1.3 / AES-256-GCM / P-256 |
| TLS 1.2 (негативный) | `alert protocol version (70)` |
| Wireshark: cipher `0x1302`, group `23`, SNI `localhost`, sig `0x0804` | да |
| Задача 2: `root(pathlen:0) → inter → leaf` | `error 25 at 2 depth: path length constraint exceeded` |
| Задача 2, контроль: `root(pathlen:0) → leaf` | `OK` |
