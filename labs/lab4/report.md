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

**Цель работы:** на собственном тестовом CA выпустить цепочку X.509 с расширениями, проверить цепочку доверия и показать возобновление сессии TLS 1.3 по PSK.

**Индивидуальный вариант — №7:**

| Параметр | Значение |
|---|---|
| Ключ корня / промежуточного CA | ECDSA P-256 |
| Ключ сервера | Ed25519 |
| Группа ECDHE | X25519 |
| Набор шифров TLS 1.3 | TLS_AES_128_GCM_SHA256 |
| Задача варианта | Возобновление сессии: `-sess_out` в первом соединении, `-sess_in` во втором; сравнить Certificate и pre_shared_key |

**Что отличается от методички.** Задача варианта 7 проверялась на `openssl s_server` (методичка рекомендует его для PSK-вариантов), а не на nginx. Захват `tcpdump`/`tshark` не выполнялся: `tcpdump -i lo0` требует root. Вместо него рукопожатие разобрано клиентскими `s_client -msg` и `-trace`; журнал ключей записан через `-keylogfile` (`logs/keys.log`) и пригоден для расшифровки в Wireshark. Ключи в `pki/` одноразовые, тестовые. Проверка отключена нигде не была.

Среда: macOS, OpenSSL 3.6.3. Все команды — в `run_resumption.sh` и ниже.

## 1. Корневой и промежуточный CA (ECDSA P-256)

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root/root.key
openssl req -new -x509 -key root/root.key -sha256 -days 3650 -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' -out root/root.crt
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
openssl req -new -key inter/inter.key -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' -out inter/inter.csr
openssl x509 -req -in inter/inter.csr -CA root/root.crt -CAkey root/root.key -CAcreateserial -sha256 -days 1825 -extfile inter/inter.ext -out inter/inter.crt
```

`inter.ext`: `basicConstraints=critical,CA:TRUE,pathlen:0`, `keyUsage=critical,keyCertSign,cRLSign`, SKI/AKI.

## 2. Серверный сертификат Ed25519 с SAN (через `openssl ca`, запись в базу)

```bash
openssl genpkey -algorithm ED25519 -out server/server.key
openssl req -new -key server/server.key -subj '/C=BY/O=Lab PKI/CN=localhost' -out server/server.csr
openssl ca -config inter/ca.cnf -batch -in server/server.csr -extfile server/server.ext -notext -out server/server.crt
cat server/server.crt inter/inter.crt > server/fullchain.pem
```

Вывод: `Write out database with 1 new entries`, `Database updated`.

## 3. Поля сертификатов (`openssl x509 -noout -ext ...`)

| Сертификат | Basic Constraints | Key Usage | EKU | SAN | Ключ / подпись |
|---|---|---|---|---|---|
| root.crt | critical, CA:TRUE, pathlen:1 | Certificate Sign, CRL Sign | – | – | id-ecPublicKey / ecdsa-with-SHA256 |
| inter.crt | critical, CA:TRUE, **pathlen:0** | Certificate Sign, CRL Sign | – | – | id-ecPublicKey / ecdsa-with-SHA256 |
| server.crt | critical, CA:FALSE | Digital Signature | TLS Web Server Authentication | DNS:localhost, IP:127.0.0.1 | ED25519 / ecdsa-with-SHA256 (подписан P-256 CA) |

## 4. Проверка цепочки

```
$ openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
server/server.crt: OK

[НЕГАТИВНЫЙ ТЕСТ] без промежуточного сертификата:
$ openssl verify -CAfile root/root.crt server/server.crt
error 20 at 0 depth lookup: unable to get local issuer certificate
error server/server.crt: verification failed
```

Путь без intermediate не строится — ожидаемо.

## 5. Задача варианта: возобновление сессии

Сервер (X25519 и AES-128-GCM, как по варианту):

```bash
openssl s_server -accept 8453 -cert server/server.crt -key server/server.key -cert_chain inter/inter.crt \
  -tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 -www
```

Клиент (`( sleep 1 ) |` держит stdin открытым):

```bash
# соединение 1: полное рукопожатие, сохраняем сессию (тикет)
( sleep 1 ) | openssl s_client -connect localhost:8453 -servername localhost -CAfile root/root.crt \
  -tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 -sess_out client/sess.pem -keylogfile client/keys.log
# соединение 2: возобновление
( sleep 1 ) | openssl s_client ... -sess_in client/sess.pem
```

Вывод (`-brief`) в обоих случаях: `Protocol version: TLSv1.3`, `Ciphersuite: TLS_AES_128_GCM_SHA256`, `Peer Temp Key: X25519, 253 bits`, `Verification: OK`. Итоговая строка сессии: соединение 1 — `New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256`, соединение 2 — **`Reused`**, `TLS_AES_128_GCM_SHA256`.

### Сравнение соединений (`s_client -msg` / `-trace`, файлы `logs/`)

| Сообщение | Соединение 1 (полное) | Соединение 2 (PSK) |
|---|---|---|
| ClientHello | 1, длина 220 (0xdc) | 1, длина 459; добавлено расширение **psk(41), length=235** (тикет и binder) |
| ServerHello | 1, длина 118 | 1, длина 124; расширение **psk(41), length=2** (выбран идентификатор PSK) |
| EncryptedExtensions | 1 | 1 |
| **Certificate** | **1** (917 байт, лист и intermediate) | **0** |
| **CertificateVerify** | **1** (Ed25519, 68 байт) | **0** |
| Finished | сервер + клиент | сервер + клиент |
| NewSessionTicket | от сервера после Finished | от сервера после Finished (выдан новый) |
| psk_key_exchange_modes | в ClientHello | в ClientHello |

Расширения `key_share` (X25519) и `server_name` (localhost, 14 байт) присутствуют в обоих ClientHello.

Число ClientHello и ServerHello в обоих соединениях по 1 (HelloRetryRequest нет: группа X25519 принята сразу). Certificate есть только в соединении 1.

### Выводы

* Во втором соединении сервер доказывает владение секретом через PSK и Finished, а не подписью, поэтому Certificate и CertificateVerify не отправляются. Рукопожатие короче: нет цепочки и проверки подписи Ed25519.
* Клиент отправил psk(41) с тикетом и binder; сервер подтвердил выбор PSK. Рукопожатие остаётся 1-RTT.
* Тикет — не ключ: это зашифрованное сервером состояние сессии (resumption secret), из него клиент выводит PSK через HKDF от `resumption_master_secret`; binder в ClientHello доказывает владение этим секретом. Сам тикет по сети не даёт доступа к трафику, а каждое новое соединение смешивается с новыми значениями из ClientHello и ServerHello.
* В данном режиме (`psk_dhe_ke`) возобновление сохраняет прямую секретность только при новом key_share ECDHE; `s_client` в этом прогоне отправил key_share X25519 (в обоих ClientHello присутствует `key_share`).

### Журнал ключей

`wc -l logs/keys.log` — 6 строк (комментарий + 5 меток). Уникальные метки: `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET`. Журнал записан только для соединения 1. С ним в Wireshark становятся видны EncryptedExtensions, Certificate, CertificateVerify и Finished, зашифрованные handshake-ключами.

## 6. Что не выполнено

* Части 2–3 методички для nginx (HTTPS-сервер, `curl`), негативные тесты CRL/OCSP/`-attime`, TLS 1.2 alert 70 и захват в `tshark` в этот архив не входят.
