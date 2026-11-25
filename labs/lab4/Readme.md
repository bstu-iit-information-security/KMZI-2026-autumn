
# Отчёт по Лабораторной работе №4. Вариант 8

**Студент:**Олексюк Илья Витальевич 
**Стенд:** Ubuntu 24.04, OpenSSL 3.0.13, nginx 1.24.0, curl 8.5.0, tshark 4.2.2

## 1. Удостоверяющий центр и сертификаты X.509

### Корневой CA (`root.crt`)

```
X509v3 Basic Constraints: critical
    CA:TRUE, pathlen:1
X509v3 Key Usage: critical
    Certificate Sign, CRL Sign
X509v3 Subject Key Identifier:
    A0:06:D2:F1:93:35:E3:26:C1:56:09:20:B9:55:64:7C:E5:C2:FA:1C
Signature Algorithm: ED25519
```

**Ожидается:** `CA:TRUE, pathlen:1`, `Certificate Sign, CRL Sign`, ключ Ed25519. **Совпадает.**

### Промежуточный CA (`inter.crt`)

```
X509v3 Basic Constraints: critical
    CA:TRUE, pathlen:0
X509v3 Key Usage: critical
    Certificate Sign, CRL Sign
X509v3 Subject Key Identifier:
    B3:14:2A:17:27:94:D2:4E:96:36:F4:6A:A0:96:84:59:7B:B9:27:9D
X509v3 Authority Key Identifier:
    A0:06:D2:F1:93:35:E3:26:C1:56:09:20:B9:55:64:7C:E5:C2:FA:1C
Signature Algorithm: ED25519
```

**Ожидается:** `CA:TRUE, pathlen:0` (запрещает выпуск других CA), `Certificate Sign, CRL Sign`, Ed25519. **Совпадает.**

### Серверный сертификат (`server.crt`)

```
X509v3 Basic Constraints: critical
    CA:FALSE
X509v3 Key Usage: critical
    Digital Signature
X509v3 Extended Key Usage:
    TLS Web Server Authentication
X509v3 Subject Alternative Name:
    DNS:localhost, IP Address:127.0.0.1
Signature Algorithm: ED25519
```

**Ожидается:** `CA:FALSE`, `Digital Signature`, `TLS Web Server Authentication`, SAN `localhost` и `127.0.0.1`, ключ Ed25519. **Совпадает.**

## 2. Конфигурация HTTPS-сервера (nginx)

Файл `/etc/nginx/conf.d/lab4.conf` (порт 8443 — 443 привилегированный и не требуется):

```
server {
    listen 8443 ssl;
    server_name localhost;

    ssl_certificate     /home/us230/lab4/server/fullchain.pem;
    ssl_certificate_key /home/us230/lab4/server/server.key;

    # Вариант 8: только TLS 1.3, ChaCha20, X25519
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_CHACHA20_POLY1305_SHA256;
    ssl_ecdh_curve X25519;
    ssl_session_tickets on;

    location / { return 200 'tls13 variant8 ok\n'; }
}
```

Вывод `sudo nginx -t`:

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
* SSL connection using TLSv1.3 / TLS_CHACHA20_POLY1305_SHA256 / X25519
*  subjectAltName: host "localhost" matched cert's "localhost"
*  SSL certificate verify ok.
< HTTP/1.1 200 OK
tls13 variant8 ok
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

### Негативный тест 5 (задача варианта 8): срок действия

```
ATTIME=$(( $(date +%s) + 400*24*3600 ))
openssl verify -attime $ATTIME -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
```

```
attime = 1790000000 (Thu Sep 24 00:53:20 2026)
CN = localhost
error 10 at 0 depth lookup: certificate has expired
error server/server.crt: verification failed
```

**Контроль** — через 100 дней:

```
openssl verify -attime $(( $(date +%s) + 100*24*3600 )) -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
```

```
server/server.crt: OK
```

**Вывод:** лист на 365 дней (`default_days = 365`) через 400 дней просрочен (`error 10`), через 100 дней — валиден. Это подтверждает, что ошибка именно из-за срока, а не поломки цепочки.

## 4. Анализ рукопожатия в tshark

### Без журнала ключей

```
tshark -r ~/lab4/client/handshake.pcap -Y tls -T fields -e frame.number -e tls.record.content_type -e tls.handshake.type
```

**Вывод:** видны только `1` (ClientHello) и `2` (ServerHello). Остальные сообщения скрыты внутри записей с `content_type 23` (application_data) и `content_type 20` (change_cipher_spec, режим совместимости).

### С журналом ключей (`keys.log`)

```
tshark -r ~/lab4/client/handshake.pcap -o tls.keylog_file:$HOME/lab4/client/keys.log \
  -Y tls.handshake -T fields -e frame.number -e tls.handshake.type
```

**Вывод:** `1` (ClientHello), `2` (ServerHello), `8` (EncryptedExtensions), `11` (Certificate), `15` (CertificateVerify), `20` (Finished), `4` (NewSessionTicket). Сообщения `Certificate`, `CertificateVerify`, `Finished` расшифрованы благодаря журналу ключей.

### Детальные поля из расшифрованного захвата

```
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 2' \
  -T fields -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group
0x1303	29
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
0x0807
```

- Шифр и группа: `0x1303` (`TLS_CHACHA20_POLY1305_SHA256`), `29` (X25519) — соответствуют варианту 8.
- SNI: `localhost`.
- SAN в сертификате: `dNSName: localhost`, `iPAddress: 127.0.0.1`.
- Подпись CertificateVerify: `0x0807` (ed25519) — ключ сервера Ed25519.

### Уникальные метки из `keys.log`

```
cut -d' ' -f1 keys.log | sort -u
```

- `CLIENT_HANDSHAKE_TRAFFIC_SECRET`
- `CLIENT_TRAFFIC_SECRET_0`
- `EXPORTER_SECRET`
- `SERVER_HANDSHAKE_TRAFFIC_SECRET`
- `SERVER_TRAFFIC_SECRET_0`

## 5. Решение задачи Варианта 8

**Требование:** срок действия — `openssl verify -attime` на дату через 400 дней даёт `certificate has expired`; обосновать срок листа (CA/Browser Forum — 398 дней).

**Команда:**

```
ATTIME=$(( $(date +%s) + 400*24*3600 ))
openssl verify -attime $ATTIME -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
```

**Фактический вывод:**

```
CN = localhost
error 10 at 0 depth lookup: certificate has expired
error server/server.crt: verification failed
```

**Контроль (через 100 дней):**

```
server/server.crt: OK
```

**Наблюдение в Wireshark:** в расшифрованном `Certificate` (type 11) видны `validity.notBefore = Nov 10 20:12:01 2026 GMT` и `validity.notAfter = Nov 10 20:12:01 2027 GMT` — ровно 365 дней.

**Объяснение:** `openssl verify -attime` проверяет `NotBefore ≤ attime ≤ NotAfter`. Лист выпущен на 365 дней (`default_days = 365` в `inter/ca.cnf`). Дата +400 дней (`Sep 24 2027`) выходит за `NotAfter` → `error 10: certificate has expired`. Контроль +100 дней даёт `OK` — значит, причина именно в сроке, а не в цепочке.

**Обоснование срока:** CA/Browser Forum Baseline Requirements с 1 сентября 2020 г. ограничивают максимальный срок TLS-сертификатов публичных CA **398 днями**. Причина — сократить окно, в котором скомпрометированный ключ остаётся валидным, и заставить владельцев регулярно перевыпускать сертификаты (автоматизация через ACME). В работе лист на 365 дней — удовлетворяет требованию; +400 дней демонстрирует истечение.

## 6. Сводка

| Проверка | Результат |
|---|---|
| Корень Ed25519, `CA:TRUE,pathlen:1` | да |
| Промежуточный Ed25519, `CA:TRUE,pathlen:0` | да |
| Лист Ed25519, `CA:FALSE`, `serverAuth`, SAN `localhost,127.0.0.1` | да |
| Цепочка с intermediate | `OK` |
| Цепочка без intermediate (негативный) | `unable to get local issuer certificate` |
| nginx TLS 1.3 + ChaCha20 (`0x1303`) + X25519 | да |
| `curl` позитив | HTTP 200, TLSv1.3 / CHACHA20 / X25519 |
| TLS 1.2 (негативный) | `alert protocol version (70)` |
| Wireshark: cipher `0x1303`, group `29`, SNI `localhost`, sig `0x0807` | да |
| `-attime` +400 дней (задача 8) | `certificate has expired` (error 10) |
| `-attime` +100 дней (контроль) | `OK` |
