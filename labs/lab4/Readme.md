# Отчёт по Лабораторной работе №4. Вариант 12

## 1. Удостоверяющий центр и сертификаты X.509

### Фрагменты вывода `openssl x509 -noout -text`

**Корневой CA (`root.crt`):**
```
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                87:90:E7:B8:DE:A8:BC:BA:A5:9A:EB:53:55:41:ED:32:24:29:2F:C9
```
*Ожидается:* `CA:TRUE, pathlen:1` и `Key Usage: Certificate Sign, CRL Sign`. **Совпадает.**

**Промежуточный CA (`inter.crt`):**
```
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                FB:1F:B6:8F:1A:C0:EF:48:8D:C4:2E:31:B0:63:78:DE:FC:E3:94:7C
            X509v3 Authority Key Identifier:
                87:90:E7:B8:DE:A8:BC:BA:A5:9A:EB:53:55:41:ED:32:24:29:2F:C9
```
*Ожидается:* `CA:TRUE, pathlen:0` (запрещает выпуск других CA) и `Key Usage: Certificate Sign, CRL Sign`. **Совпадает.**

**Серверный сертификат (`server.crt`):**
```
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Alternative Name:
                DNS:localhost, IP Address:127.0.0.1
```
*Ожидается:* `CA:FALSE`, `Digital Signature`, `TLS Web Server Authentication` и SAN с `localhost` и `127.0.0.1`. **Совпадает.**

---

## 2. Конфигурация HTTPS-сервера (nginx)

Файл `/etc/nginx/conf.d/lab4.conf` (порт изменён на 8443, так как 443 привилегированный и не требуется по заданию):
```nginx
server {
    listen 8443 ssl;
    server_name localhost;

    ssl_certificate     /home/user1/lab4/server/fullchain.pem;
    ssl_certificate_key /home/user1/lab4/server/server.key;

    # Вариант 12: только TLS 1.3, конкретный шифр и группа
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;
    ssl_ecdh_curve X25519;
    ssl_session_tickets on;

    # Настройки mTLS
    ssl_verify_client on;
    ssl_client_certificate /home/user1/lab4/server/client_ca_chain.pem;

    location / { return 200 'tls13 ok'; }
}
```
**Вывод `sudo nginx -t`:**
```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

---

## 3. Проверка цепочки и негативные тесты

**Позитивная проверка цепочки:**
```bash
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
```
*Вывод:* `server/server.crt: OK`

**Негативный тест 1: Отсутствие клиентского сертификата (Задача варианта 12)**
```bash
curl -v --cacert root/root.crt https://localhost:8443/
```
*Вывод:* `HTTP/1.1 400 Bad Request`, `<h1>400 No required SSL certificate was sent</h1>`. Соединение не прерывается TLS-алертом.

**Негативный тест 2: Чужой корневой сертификат**
```bash
curl -v --cacert /tmp/other.crt --cert client/client.crt --key client/client.key https://localhost:8443/
```
*Вывод:* `curl: (60) SSL certificate problem: unable to get local issuer certificate`

**Негативный тест 3: Имя хоста вне SAN**
```bash
curl -v --cacert root/root.crt --cert client/client.crt --key client/client.key https://127.0.0.2:8443/
```
*Вывод:* `curl: (60) SSL: no alternative certificate subject name matches target host name '127.0.0.2'`

**Негативный тест 4: Попытка использования TLS 1.2**
```bash
( sleep 1 ) | openssl s_client -connect localhost:8443 -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'
```
*Вывод:* `tlsv1 alert protocol version:../ssl/record/rec_layer_s3.c:1599:SSL alert number 70` и `Protocol : TLSv1.2`

---

## 4. Анализ рукопожатия в tshark

**Без журнала ключей:**
```bash
tshark -r ~/lab4/client/handshake.pcap -Y tls -T fields -e frame.number -e tls.record.content_type -e tls.handshake.type
```
*Вывод:* Видны только `1` (ClientHello) и `2` (ServerHello). Остальные сообщения скрыты внутри записей с `content_type` 23 (application_data).

**С журналом ключей (`keys.log`):**
```bash
tshark -r ~/lab4/client/handshake.pcap -o tls.keylog_file:$HOME/lab4/client/keys.log -Y 'tls.handshake.type == 13' -T fields -e tls.handshake.type
```
*Вывод:* `2,8,13,11,15,20` (в одном зашифрованном TLS-записи от сервера расшифровываются ServerHello, EncryptedExtensions, **CertificateRequest**, Certificate, CertificateVerify, Finished). Наличие типа `13` подтверждает запрос mTLS.

**Детальные поля из расшифрованного захвата:**
*   **Шифр и группа:** `0x1302` (TLS_AES_256_GCM_SHA384), `29` (X25519)
*   **SNI:** `localhost`
*   **SAN в сертификате:** `dNSName: localhost`, `iPAddress: 127.0.0.1`
*   **Уникальные метки из `keys.log`:**
    ```
    CLIENT_HANDSHAKE_TRAFFIC_SECRET
    CLIENT_TRAFFIC_SECRET_0
    EXPORTER_SECRET
    SERVER_HANDSHAKE_TRAFFIC_SECRET
    SERVER_TRAFFIC_SECRET_0
    ```

---

## 5. Решение задачи Варианта 12

**Требование:** mTLS с клиентским сертификатом Ed25519: без сертификата соединение отвергается, с сертификатом проходит. Для nginx без клиентского сертификата ответ — HTTP 400, а не TLS-alert. Объясните разницу.

**Команда позитивного теста:**
```bash
curl -v --cacert root/root.crt --cert client/client.crt --key client/client.key https://localhost:8443/
```
*Фактический вывод:* `HTTP/1.1 200 OK`, тело ответа `tls13 ok`.

**Команда негативного теста:**
```bash
curl -v --cacert root/root.crt https://localhost:8443/
```
*Фактический вывод:* `HTTP/1.1 400 Bad Request`, `<h1>400 No required SSL certificate was sent</h1>`.

**Наблюдение в Wireshark:** При использовании `keys.log` в захвате видно, что сервер отправляет сообщение `CertificateRequest` (type 13) в зашифрованной части рукопожатия.

**Объяснение разницы:** 
Спецификация TLS 1.3 делает предоставление клиентского сертификата в ответ на `CertificateRequest` опциональным на уровне протокола. Клиент имеет право отправить пустой список сертификатов, при этом криптографическое рукопожатие успешно завершится (будут вычислены ключи и отправлены сообщения `Finished`). После установки зашифрованного канала nginx расшифровывает HTTP-запрос и, обнаружив отсутствие валидного клиентского сертификата, самостоятельно формирует ответ на уровне приложения: `HTTP 400 Bad Request`. Это принципиально отличается от TLS-alert (например, `certificate_required` с кодом 116), который принудительно и немедленно разорвал бы TLS-сессию на транспортном уровне до передачи каких-либо HTTP-данных. Такое поведение nginx реализовано для гибкости, позволяя обрабатывать отсутствие сертификата на уровне веб-приложения.