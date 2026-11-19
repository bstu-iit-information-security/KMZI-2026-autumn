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

**Цель работы:** на собственном тестовом CA выпустить цепочку X.509 с расширениями, проверить цепочку доверия и выполнить задачу индивидуального варианта.

**Индивидуальный вариант — №8:**

| Параметр | Значение |
|---|---|
| Ключ корня / промежуточного CA | Ed25519 |
| Ключ сервера | Ed25519 |
| Группа ECDHE | X25519 |
| Набор шифров TLS 1.3 | TLS_CHACHA20_POLY1305_SHA256 |
| Задача варианта | Срок действия: `openssl verify -attime` на дату через 400 дней, ожидаемо `certificate has expired`; обосновать срок листа (398 дней у CA/Browser Forum) |

**Отличия от методички.** Задача проверялась на `openssl s_server`/`s_client` (macOS, OpenSSL 3.6.3), а не на nginx: nginx на машине не был установлен. Захват `tcpdump`/`tshark` не выполнялся (на `lo0` нужен root); вместо него рукопожатие разобрано через `s_client -msg`/`-trace`. Проверка сертификатов нигде не отключалась; негативные тесты помечены. Ключи в `pki/` одноразовые.

## 1. Центр сертификации и серверный сертификат

Генератор — `gen_pki.sh` (в архиве). Он выполняет шаги методички: корень (`openssl req -new -x509`, `pathlen:1`), промежуточный CA (`openssl x509 -req`, `pathlen:0`), серверный сертификат через `openssl ca` с записью в базу (`Write out database with 1 new entries`, `Database updated`), затем `fullchain.pem` (лист + intermediate). Флаг `-sha256` не указывается: для Ed25519 он не нужен, для остальных ключей применяется дайджест по умолчанию (SHA-256).

Расширения серверного сертификата: `basicConstraints=critical,CA:FALSE`, `keyUsage=critical,digitalSignature`, `extendedKeyUsage=serverAuth`, SKI/AKI, `subjectAltName=DNS:localhost,IP:127.0.0.1`.

Генерация: `./gen_pki.sh pki ED25519 ED25519`. Цепочка:

```
$ openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
server/server.crt: OK
[НЕГАТИВНЫЙ] без промежуточного сертификата:
$ openssl verify -CAfile root/root.crt server/server.crt
error 20 at 0 depth lookup: unable to get local issuer certificate
```

### Поля сертификатов

| Сертификат | Basic Constraints | Key Usage | EKU | SAN | Ключ / подпись |
|---|---|---|---|---|---|
| root.crt | critical, CA:TRUE, pathlen:1 | Certificate Sign, CRL Sign | – | – | ED25519 / ED25519 |
| inter.crt | critical, CA:TRUE, **pathlen:0** | Certificate Sign, CRL Sign | – | – | ED25519 / ED25519 |
| server.crt | critical, CA:FALSE | Digital Signature | TLS Web Server Authentication | DNS:localhost, IP:127.0.0.1 | ED25519 / ED25519 |

## 2. Рукопожатие TLS 1.3 с ChaCha20-Poly1305

```bash
openssl s_server -accept 8453 -cert server/server.crt -key server/server.key -cert_chain inter/inter.crt \
  -tls1_3 -groups X25519 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -www
( sleep 1 ) | openssl s_client -connect localhost:8453 -servername localhost -CAfile root/root.crt \
  -tls1_3 -groups X25519 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -brief
```

Фактический вывод: `Protocol version: TLSv1.3`, `Ciphersuite: TLS_CHACHA20_POLY1305_SHA256`, `Signature type: ed25519`, `Verification: OK`, `Peer Temp Key: X25519, 253 bits`.

## 3. Задача варианта: срок действия

Сроки (`openssl x509 -noout -startdate -enddate`):

| Сертификат | notBefore | notAfter |
|---|---|---|
| root | 10.11.2026 | 07.11.2036 (3650 дней) |
| inter | 10.11.2026 | 09.11.2031 (1825 дней) |
| server | 10.11.2026 | 10.11.2027 (365 дней, `default_days` в `ca.cnf`) |

Проверка на разные даты (`-attime` принимает Unix-время; `T N` = `date -j -v+Nd +%s`):

| Команда | Результат |
|---|---|
| `openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt` | `OK` |
| то же с `-attime` через 364 дня | `OK` |
| **[НЕГАТИВНЫЙ]** `-attime` через 366 дней | `error 10 at 0 depth lookup: certificate has expired` |
| **[НЕГАТИВНЫЙ]** `-attime` через **400 дней** (задача варианта) | `error 10 at 0 depth lookup: certificate has expired`, `verification failed` |
| `-attime` через 400 дней для `inter.crt` | `OK` (промежуточный CA действует до 2031) |
| **[НЕГАТИВНЫЙ]** `s_client -attime` +400 дней | `verify error:num=10:certificate has expired` |

Через 400 дней истекает только лист (`depth 0`): корень и intermediate выпущены на 10 и 5 лет. Ошибка `error 10` — это `X509_V_ERR_CERT_HAS_EXPIRED`. Примечание: без `-verify_return_error` `s_client` всё равно открывает соединение и лишь печатает `Verification error`, поэтому в рабочей проверке нужен этот флаг (в нём клиент прерывает рукопожатие).

### Обоснование срока листа

Лист выпущен на 365 дней: это меньше 398 дней, предельного срока для публично доверенных TLS-сертификатов по Baseline Requirements CA/Browser Forum (действует для выдачи с сентября 2020 года, браузеры отвергают более длинные). Короткий срок листа ограничивает ущерб от утечки ключа: отзыв (CRL/OCSP) работает ненадёжно, и истечение срока — последняя гарантия. Он же вынуждает автоматизировать перевыпуск и ускоряет смену алгоритмов. Корень и intermediate живут дольше, потому что их ключи хранятся офлайн или в HSM, а доверие к ним нужно распространять заранее; это не противоречит правилам, так как 398 дней относится только к конечным TLS-сертификатам. По данным CA/B Forum (ballot SC-081), предельный срок дальше сокращается (200 дней с марта 2026 года, затем 100 и 47); эти цифры в работе не проверялись, их стоит сверить с актуальной редакцией BR. Для тестового CA такого ограничения нет, но 365 дней укладывается в 398.

## 4. Что не выполнено

nginx, `curl`, захват `tshark`, CRL/OCSP и TLS 1.2 с alert 70 в этот архив не входят.
