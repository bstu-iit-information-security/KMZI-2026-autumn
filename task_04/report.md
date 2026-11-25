Министерство образования Республики Беларусь

Учреждение образования
«Брестский Государственный технический университет»

Кафедра ИИТ

**Лабораторная работа №4**

По дисциплине «КМЗИ»

Тема: «PKI, HTTPS и TLS 1.3. Тестовый Удостоверяющий Центр, сертификаты X.509 и анализ рукопожатия TLS 1.3»

> **Выполнил:** Студент 3 курса, группы ИИ-27/24, Ханцевич Г.С.
>
> **Проверил:** Хацкевич А.С.

Брест 2026

---

**Цель работы:** на собственном тестовом CA выпустить цепочку X.509 с расширениями, проверить цепочку доверия и выполнить задачу индивидуального варианта — взаимную аутентификацию (mTLS).

**Индивидуальный вариант — №4:**

| Параметр | Значение |
|---|---|
| Ключ корня / промежуточного CA | Ed25519 |
| Ключ сервера | ECDSA P-384 |
| Группа ECDHE | P-384 |
| Набор шифров TLS 1.3 | TLS_AES_256_GCM_SHA384 |
| Задача варианта | mTLS: сервер требует клиентский сертификат (в nginx — `ssl_verify_client on` + `ssl_client_certificate` с корнем и intermediate); в захвате показать CertificateRequest (type 13) и клиентский Certificate; без сертификата соединение отвергается |

**Отличия от методички.** Задача проверялась на `openssl s_server` (`-Verify 1 -CAfile server/client-ca.pem` — аналог `ssl_verify_client on` и `ssl_client_certificate`), а не на nginx: nginx на машине не был установлен. Поэтому поведение nginx (HTTP 400) в этом архиве **не наблюдалось**, оно описано по методичке. Захват `tcpdump`/`tshark` не выполнялся (на `lo0` нужен root); сообщения рукопожатия разобраны через `s_client -msg`/`-trace`, журнал ключей записан (`-keylogfile`). Проверка сертификатов нигде не отключалась; негативные тесты помечены. Среда: macOS, OpenSSL 3.6.3. Ключи в `pki/` одноразовые.

## 1. Центр сертификации и сертификаты

Генератор — `gen_pki.sh` (в архиве): `./gen_pki.sh pki ED25519 P-384 P-384`. Он выпускает корень (`pathlen:1`), промежуточный CA (`pathlen:0`), серверный и клиентский сертификаты через `openssl ca` (`Write out database with 1 new entries`, `Database updated`). `-sha256` не указывается: Ed25519 использует собственную схему подписи. Для сервера собираются `fullchain.pem` (лист + intermediate) и `client-ca.pem` (корень + intermediate) — список доверенных CA для проверки клиента.

Расширения серверного сертификата: `CA:FALSE`, `digitalSignature`, EKU `serverAuth`, SAN `DNS:localhost, IP:127.0.0.1`. Клиентского: `CA:FALSE`, `digitalSignature`, EKU **`clientAuth`**, без SAN (`CN=lab-client`).

```
$ openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt client/client.crt
server/server.crt: OK
client/client.crt: OK
[НЕГАТИВНЫЙ] без промежуточного сертификата:
$ openssl verify -CAfile root/root.crt server/server.crt
error 20 at 0 depth lookup: unable to get local issuer certificate
```

| Сертификат | Basic Constraints | Key Usage | EKU | SAN | Ключ / подпись |
|---|---|---|---|---|---|
| root.crt | critical, CA:TRUE, pathlen:1 | Certificate Sign, CRL Sign | – | – | ED25519 / ED25519 |
| inter.crt | critical, CA:TRUE, **pathlen:0** | Certificate Sign, CRL Sign | – | – | ED25519 / ED25519 |
| server.crt | critical, CA:FALSE | Digital Signature | TLS Web Server Authentication | DNS:localhost, IP:127.0.0.1 | id-ecPublicKey (secp384r1) / ED25519 |
| client.crt | critical, CA:FALSE | Digital Signature | TLS Web Client Authentication | – | id-ecPublicKey (secp384r1) / ED25519 |

## 2. Сервер с обязательной аутентификацией клиента

```bash
openssl s_server -accept 8453 -cert server/server.crt -key server/server.key -cert_chain inter/inter.crt \
  -CAfile server/client-ca.pem -Verify 1 -verify_return_error \
  -tls1_3 -groups P-384 -ciphersuites TLS_AES_256_GCM_SHA384 -www
```

`-Verify 1` (заглавная V) делает клиентский сертификат обязательным; строчная `-verify` его бы только запрашивала. Эквивалент nginx:

```nginx
ssl_verify_client on;
ssl_client_certificate /path/pki/server/client-ca.pem;
ssl_protocols TLSv1.3;
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;
ssl_ecdh_curve secp384r1;
```

## 3. Результаты

**[НЕГАТИВНЫЙ] Клиент без сертификата:**

```
<<< TLS 1.3, Handshake [length 00b5], CertificateRequest
<<< TLS 1.3, Alert [length 0002], fatal certificate_required
error:0A00045C:SSL routines:ssl3_read_bytes:tlsv13 alert certificate required ... SSL alert number 116
```

Сервер запросил сертификат (CertificateRequest), клиент отправил пустое сообщение Certificate, сервер прервал соединение alert-ом `certificate_required` (116).

**Клиент с сертификатом `client.crt` (ECDSA P-384):**

```
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=localhost
Signature type: ecdsa_secp384r1_sha384
Verification: OK
Peer Temp Key: ECDH, secp384r1, 384 bits
```

Запрос `GET /` возвращает `HTTP/1.0 200 ok`, `Verify return code: 0 (ok)`.

### Рукопожатие (`s_client -trace`, `logs/with_cert_trace.log`)

| Шаг | Сообщение | Длина | Кто |
|---|---|---|---|
| 1 | ClientHello | 285 | клиент |
| 2 | ServerHello | 183 | сервер |
| 3 | EncryptedExtensions | 2 | сервер |
| 4 | **CertificateRequest (type 13)** | 177 | сервер |
| 5 | Certificate (цепочка сервера) | 912 | сервер |
| 6 | CertificateVerify | 106 | сервер |
| 7 | Finished | 48 | сервер |
| 8 | **Certificate (клиентский)** | 464 | клиент |
| 9 | CertificateVerify | 106 | клиент |
| 10 | Finished | 48 | клиент |
| – | NewSessionTicket (×2) | – | сервер |

Без клиентского сертификата (`logs/no_cert.log`) клиент после CertificateRequest присылает пустой Certificate без CertificateVerify, и сервер отвечает alert 116. Серверный CertificateVerify и Finished при этом уже отправлены.

CertificateRequest содержит расширение `signature_algorithms` — список схем, которыми сервер примет подпись клиента. В TLS 1.3 после ServerHello всё шифруется, поэтому в `tshark` без журнала ключей CertificateRequest и клиентский Certificate не видны: нужен `keys.log` (метки `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET`; 6 строк с комментарием). Команда для Wireshark/`tshark`: `tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 13 || tls.handshake.type == 11'`; в этой работе она не запускалась.

### Почему TLS-alert, а у nginx — HTTP 400

* **OpenSSL `s_server`** (наблюдалось) отвергает клиента на уровне TLS: fatal alert `certificate_required` (116). Приложение (HTTP) не начинает работу.
* **nginx** с `ssl_verify_client on` по методичке завершает TLS-рукопожатие и отвечает на уровне HTTP: `400 Bad Request — No required SSL certificate was sent`. Решение принимает уже HTTP-слой, поэтому клиент получает страницу с ошибкой, а не alert. Это различие реализации, а не протокола: RFC 8446 допускает оба поведения. Для клиента практический вывод: `curl` с alert получит ошибку TLS (exit 56/35), с nginx — код 400.

Клиентский сертификат Ed25519 из текста методички (вариант 12) здесь не используется: по варианту 4 ключи листьев ECDSA P-384, поэтому клиентский сертификат также P-384.

## 4. Что не выполнено

nginx и `curl` (ответ HTTP 400), захват и разбор в `tshark`, CRL/OCSP, `-attime` и TLS 1.2 с alert 70 в этот архив не входят.
