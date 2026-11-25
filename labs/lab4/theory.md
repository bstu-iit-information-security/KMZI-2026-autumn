### Лабораторная работа №4. PKI, HTTPS и TLS 1.3. Развертывание тестового Удостоверяющего Центра (CA), выпуск сертификатов X.509, настройка HTTPS-сервера и анализ рукопожатия TLS 1.3 в Wireshark

**Команды и варианты проверены на стенде:** Ubuntu 24.04, OpenSSL 3.0.13, curl 8.5.0, nginx 1.24.0, tshark 4.2.2

**Средства:** OpenSSL (CLI), nginx, curl, tcpdump, Wireshark/tshark. Запрещено реализовывать X.509, ASN.1 или TLS самостоятельно и отключать проверку сертификатов (curl -k, --insecure, verify=False). Единственное исключение – негативный тест, который в отчёте помечается явно.

**Цель работы:** на собственном тестовом CA выпустить цепочку сертификатов X.509 с расширениями, настроить HTTPS-сервер, принимающий только TLS 1.3, проверить цепочку доверия и отзыв, захватить рукопожатие TLS 1.3 и разобрать его в Wireshark, в том числе после расшифровки через журнал ключей (```SSLKEYLOGFILE```).

Обязательный теоретический минимум для всех вариантов:
* иерархия доверия PKI: корневой CA, промежуточный CA, конечный сертификат;
* подпись CA над TBSCertificate;
* расширения X.509 v3, влияющие на проверку: basicConstraints (с pathlen), keyUsage, extendedKeyUsage, subjectAltName, nameConstraints, SubjectKeyIdentifier/AuthorityKeyIdentifier;
* путь сертификации по RFC 5280 и проверка имени хоста по SAN;
* отзыв сертификатов: CRL и OCSP;
* рукопожатие TLS 1.3 по RFC 8446: 1-RTT, ECDHE, HKDF, HelloRetryRequest, возобновление по PSK, взаимная аутентификация (mTLS);
* наблюдаемость: какие сообщения рукопожатия видны без ключей, а какие только с журналом ключей.

Части работы:
1. Удостоверяющий центр: корневой и промежуточный CA, серверный сертификат с SAN, проверка цепочки, отзыв.
2. HTTPS-сервер на nginx: только TLS 1.3, передача полной цепочки, набор шифров и группа ECDHE по варианту.
3. Анализ: захват рукопожатия, расшифровка через журнал ключей, разбор в Wireshark, задача варианта.

Пререквизиты:

| Компонент                             | Команда проверки  | Команды проверены для      |
|---------------------------------------|-------------------|----------------------------|
| OpenSSL 3.x (не LibreSSL)             | openssl version   | 3.0.13                     | 
| curl с OpenSSL-сборкой                | curl --version    | 8.5.0                      | 
| nginx                                 | nginx -v          | 1.24.0 (пакет nginx-light) | 
| tshark (Wireshark 4.x)                | tshark --version  | 4.2.2                      |
| tcpdump                               | tcpdump --version | из репозитория Ubuntu      |
| certutil (только для браузерной части)| certutil -H       | пакет libnss3-tools        |


* Операционная система – Linux. Проверено на Ubuntu 24.04. Windows – через WSL2 или виртуальную машину (не проверено), macOS: системный openssl – это LibreSSL, поставьте openssl@3 через Homebrew;
* Установка: ```sudo apt install openssl curl nginx-light tshark tcpdump libnss3-tools```;
* Права: захват пакетов и управление ```nginx``` требуют ```sudo```. Порты ```8443```, ```8453``` и ```9443``` непривилегированные; порт ```443``` в работе не нужен;
* Изоляция: работайте в отдельной ВМ или тестовой учётной записи. Закрытые ключи CA хранятся только в ```~/lab4``` с правами ```600```. Ключ корня не копируйте на другие машины;
* Журнал ключей: файл ```SSLKEYLOGFILE``` позволяет расшифровать трафик любому, кто его получит. Не включайте его на рабочих машинах и не используйте с реальными учётными записями.
* Браузер (некритично): Chromium на Linux доверяет корню из базы ```~/.pki/nssdb```. Без импорта корня – ```ERR_CERT_AUTHORITY_INVALID```; после импорта – ```HTTP 200``` и записанный журнал ключей.
Команды:
  * ```certutil -d sql:$HOME/.pki/nssdb -N --empty-password```
  * ```certutil -d sql:$HOME/.pki/nssdb -A -t 'C,,' -n 'Lab Root CA' -i $HOME/lab4/root/root.crt```
  
  Первую команду выполняйте, только если базы ещё нет. Браузер запускается из терминала с переменной окружения, например ```SSLKEYLOGFILE=$HOME/lab4/client/chrome_keys.log chromium```.

---

**Теоретическая база**

#### 1. Зачем нужен TLS и откуда берётся доверие

Сетевой трафик можно перехватить, прочитать и подменить. TLS (Transport Layer Security) закрывает это тремя свойствами:

* **конфиденциальность**: посторонний видит только зашифрованные байты;
* **целостность**: изменение данных в пути обнаруживается;
* **аутентичность**: клиент уверен, что говорит с нужным сервером, а не с посредником.

Первые два свойства дают ключи шифрования, которые стороны вычисляют в рукопожатии. Третье даёт сертификат сервера.

**Сертификат** – документ, в котором удостоверяющий центр (CA, Certificate Authority) подтверждает: открытый ключ принадлежит данному имени, например localhost. Клиент доверяет сертификату сервера, если может построить **цепочку** от него до **корневого сертификата** из своего хранилища доверия.

**Подпись** – ключевая пара состоит из открытого ключа (его можно публиковать) и закрытого (его никому нельзя отдавать). Подпись – хэш данных, зашифрованный закрытым ключом; проверяется она открытым. Издатель подписывает сертификат по формуле $Signature = Sign(K_{издателя}, H(TBSCertificate))$, где $TBSCertificate$ – тело сертификата.

Корневой CA (root) выпускает промежуточный CA (intermediate), а тот выпускает сертификат сервера (leaf, «лист»). Ключ корня самый ценный: тот, кто его получит, сможет выпустить сертификат для любого имени. Поэтому в реальных системах корневой ключ хранят оффлайн, а повседневную выдачу делает промежуточный CA. В работе всё лежит на одной машине, но порядок действий тот же.

#### 2. Сертификат X.509: поля и расширения

Сертификат X.509 – структура с полями. Их можно увидеть командой `openssl x509 -noout -text`.

| Поле                    | Что означает                                                        | Где в выводе op enssl                |
|-------------------------|---------------------------------------------------------------------|--------------------------------------|
| Version                 | версия формата; расширения появились в версии 3                     | Version: 3 (0x2)                     |
| Serial Number           | номер, назначенный издателем; openssl ca записывает его в index.txt | Serial Number                        |
| Signature Algorithm     | алгоритм, которым издатель подписал сертификат                      | встречается дважды: внутри и в конце |
| Issuer                  | имя издателя                                                        | Issuer                               |
| Validity                | Not Before и Not After: срок действия                               | Validity                             |
| Subject                 | имя владельца; для проверки имени хоста TLS использует SAN          | Subject                              |
| Subject Public Key Info | алгоритм и открытый ключ владельца                                  | Subject Public Key Info              |
| X509v3 extensions       | правила использования сертификата                                   | блок X509v3 extensions               |
| Signature Value         | подпись издателя над телом сертификата                              | в самом конце вывода                 |

**Расширения** задают правила использования сертификата. В работе важны такие:

- **basicConstraints** отвечает на вопрос, можно ли этим сертификатом выпускать другие сертификаты. `CA:TRUE` – да, `CA:FALSE` – нет, `pathlen` – сколько промежуточных CA может стоять ниже. Промежуточный CA в работе выпускается с `pathlen:0`, то есть не может выпускать другие CA. Лист всегда `CA:FALSE`;
- **keyUsage** перечисляет допустимые действия ключа: `keyCertSign` – подписывать сертификаты, `cRLSign` – подписывать списки отзыва, `digitalSignature` – подписывать данные, в том числе сообщения TLS;
- **extendedKeyUsage (EKU)** задаёт назначение: `serverAuth` (`1.3.6.1.5.5.7.3.1`) для сервера, `clientAuth` (`1.3.6.1.5.5.7.3.2`) для клиента. openssl и браузеры отвергают сертификат, если назначение не совпадает;
- **subjectAltName (SAN)** содержит имена, для которых действителен сертификат: DNS-имена и IP-адреса. Клиент сверяет с SAN имя, к которому подключился. Поле CN (Common Name) современные клиенты для этого не используют;
- **nameConstraints** ограничивает имена, которые CA вправе выпускать. В работе не используется, но встречается в корпоративных CA;
- **SubjectKeyIdentifier и AuthorityKeyIdentifier** — идентификаторы ключей. Помогают найти сертификат издателя при сборке цепочки.

Сертификат действителен между `Not Before` и `Not After`. Публичные CA по правилам CA/Browser Forum с 2020 года выпускают TLS-сертификаты не более чем на 398 дней. В варианте 8 вы проверяете дату через 400 дней: сертификат должен считаться просроченным.

### 3. Проверка цепочки доверия

Клиент проверяет путь сертификации (RFC 5280) по шагам:

1. Подпись каждого сертификата проверяется открытым ключом его издателя.
2. Текущее время попадает в интервал `Not Before` – `Not After`.
3. У каждого CA в цепочке `basicConstraints` разрешает роль CA, `pathlen` не нарушен, `keyUsage` содержит `keyCertSign`.
4. EKU подходит для назначения: для сервера нужен `serverAuth`.
5. Сертификат не отозван.
6. Имя хоста, к которому подключился клиент, есть в SAN листа.

Если хотя бы один шаг не проходит, соединение прерывается.

**Зачем сервер присылает промежуточный сертификат**

Лист клиент получает в сообщении Certificate сервера, а корень берёт из своего хранилища. Промежуточный CA клиент может получить только от сервера. Если его не прислать, путь не строится, и `curl` выдаёт `unable to get local issuer certificate`. Поэтому в шаге 6 nginx отдаёт `fullchain.pem` (лист и промежуточный CA), а не один `server.crt`.

**Где клиент берёт корень**

`curl` в работе получает корень через `--cacert root/root.crt`. Chromium на Linux читает корни из базы NSS (`\~/.pki/nssdb`), которую вы настраиваете в пререквизитах.

### 4. Отзыв сертификатов

Сертификат можно отозвать до конца срока, например если его ключ попал к посторонним. Клиент узнаёт об отзыве одним из двух способов:

* **CRL (Certificate Revocation List)** – список серийных номеров отозванных сертификатов, подписанный CA. Список публикуется с номером версии и сроком следующего обновления. Клиент скачивает его целиком, и со временем он растёт.
* **OCSP (Online Certificate Status Protocol)** – клиент спрашивает статус одного сертификата. Ответ бывает `good`, `revoked` или `unknown` и подписывается responder-ом. В работе responder – промежуточный CA.

Отзыв необратим, поэтому в работе отзывается отдельный тестовый сертификат (например, `revoked.crt`), а не серверный.

### 5. Рукопожатие TLS 1.3

**Рукопожатие** (handshake) – обмен служебными сообщениями до передачи данных. В TLS 1.3 полное рукопожатие занимает один обмен (1-RTT): клиент отправляет одно сообщение, сервер отвечает, и дальше сразу идёт зашифрованный HTTP.

Для шифрования нужен общий секрет, но передавать его по сети нельзя. Поэтому используется ECDHE (эфемерный Диффи–Хеллман на эллиптических кривых). Каждая сторона создаёт временную пару ключей, отправляет публичную часть (**key\_share**) и сама вычисляет общий секрет из своего закрытого ключа и чужого публичного. Обе стороны получают одно и то же значение, а по сети оно не передаётся. Ключи временные, поэтому утечка ключа сертификата не раскрывает прошлые сеансы. Это называется прямой секретностью (forward secrecy). В TLS 1.3 ECDHE обязателен. Группы, которые используются в работе: X25519 (код `29`), secp256r1 (P-256, код `23`) и secp384r1 (P-384, код `24`).

**Ход обмена.**

Сообщения в фигурных скобках шифруются ключами рукопожатия.

1. **ClientHello** (клиент → сервер): поддерживаемые версии, список шифровых наборов, группы ECDHE, `key\_share`, `signature\_algorithms` и `SNI` (имя хоста, к которому клиент подключается).
2. **ServerHello** (сервер → клиент): выбранный шифровой набор и `key_share` сервера. Теперь обе стороны могут вычислить общий секрет.
3. Из общего секрета и транскрипта (хэша переданных сообщений) по HKDF выводятся ключи рукопожатия. Всё дальше шифруется ими.
4. **{EncryptedExtensions}**: прочие параметры, например ALPN.
5. **{Certificate}**: цепочка сертификатов сервера.
6. **{CertificateVerify}**: подпись транскрипта закрытым ключом сервера. Она доказывает, что сервер владеет ключом сертификата. Сам сертификат можно скопировать, а ключа у копирующего нет.
7. **{Finished}**: HMAC над транскриптом. Подтверждает, что обе стороны вычислили одни и те же ключи и видели одни и те же сообщения.
8. Клиент проверяет цепочку, SAN, подпись `CertificateVerify` и `Finished`, затем отправляет свой `{Finished}`. Дальше идёт **Application Data**: зашифрованный HTTP.

**Шифровой набор (cipher suite).** В TLS 1.3 три варианта, и все они AEAD, то есть шифрование, которое одновременно проверяет целостность:

* `TLS_AES_128_GCM_SHA256` (`0x1301`);
* `TLS_AES_256_GCM_SHA384` (`0x1302`);
* `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`).

Часть после GCM или POLY1305 задаёт хэш для HKDF.

CertificateVerify подписывается алгоритмом, который клиент перечислил в `signature_algorithms` и который подходит к ключу сертификата. Коды: `ecdsa_secp256r1_sha256 = 0x0403`, `ecdsa_secp384r1_sha384 = 0x0503`, `rsa_pss_rsae_sha256 = 0x0804`, `ed25519 = 0x0807`. Для RSA в TLS 1.3 используется RSA-PSS.

**HelloRetryRequest (HRR).** Если в `key_share` клиента нет группы, которую сервер готов принять, сервер не продолжает обмен, а отвечает особым ServerHello (HRR) с нужной группой. Клиент повторяет ClientHello с `key_share` для неё. Итог: лишний обмен. Варианты 6 и 13 показывают HRR в захвате.

### 6. Как появился TLS 1.3

TLS – преемник SSL, который разработала Netscape.

Версии:
* **SSL 2.0** (1995) признан небезопасным; RFC 6176 (2011) запрещает его использование.
* **SSL 3.0** (1996, RFC 6101) уязвим к атаке POODLE (2014); RFC 7568 (2015) запрещает его.
* **TLS 1.0** (1999, RFC 2246) и **TLS 1.1** (2006, RFC 4346) устарели; RFC 8996 (2021) предписывает их не использовать.
* **TLS 1.2** (2008, RFC 5246) допустим, но разрешает RSA-обмен ключами без прямой секретности и шифры CBC, которых в TLS 1.3 нет.
* **TLS 1.3** (2018, RFC 8446) переработан: удалены RSA-обмен ключами, статический DH, сжатие, ренегоциация и шифры без AEAD. ECDHE обязателен, большая часть рукопожатия шифруется.

В ClientHello поле `legacy_version` фиксировано как `0x0303`, а настоящие версии клиент перечисляет в расширении `supported_versions`. Сервер отвечает ServerHello с `supported_versions = 0x0304`. Поэтому `openssl s_client -tls1_2` против сервера, который принимает только TLS 1.3, получает `alert protocol version (70)`.

Сервер, который знает TLS 1.3, но согласует TLS 1.2 или более раннюю версию, записывает маркер DOWNGRD в последние 8 байт поля random в ServerHello: `44 4F 57 4E 47 52 44 01` для TLS 1.2 и `44 4F 57 4E 47 52 44 00` для TLS 1.1 и ниже. Клиент, который знает TLS 1.3, видит маркер и обязан прервать соединение.

### 7. Возобновление по PSK

Повторное подключение не всегда требует полного рукопожатия с сертификатами. TLS 1.3 позволяет возобновить сеанс по **PSK** (pre-shared key, общий ключ, полученный заранее). Ключ получается в первом соединении:

1. После Finished сервер присылает **NewSessionTicket** (тип 4). Тикет содержит данные, зашифрованные ключом сервера. Клиент его не расшифровывает.
2. Клиент выводит PSK из секрета первого сеанса (`resumption_master_secret`) и номера тикета (`ticket_nonce`): PSK = HKDF-Expand-Label(`resumption_master_secret`, "resumption", `ticket_nonce`, Hash.length).
3. ClientHello содержит расширение `pre_shared_key`: тикет как идентификатор, `obfuscated_ticket_age` и binder. Binder – HMAC над ClientHello с ключом PSK; он доказывает, что клиент знает PSK.
4. Сервер расшифровывает тикет, проверяет binder и отвечает ServerHello с `pre_shared_key`, где указан принятый тикет. Certificate и CertificateVerify не передаются: сервер уже аутентифицирован в первом соединении.
5. Расширение `psk_key_exchange_modes` задаёт режим: `psk_ke` — только PSK, без нового ECDHE, поэтому прямой секретности нет, `psk_dhe_ke` — PSK вместе с ECDHE, тогда в ClientHello есть `key_share`. Какой режим выбран, видно в захвате.

Тикет непрозрачен: открыть его может только сервер. Клиент не знает ключа тикетов и выводит из PSK ключи для данных. Если ключ тикетов на сервере утёк, злоумышленник может получить resumption secret и расшифровать сеансы, возобновлённые по этим тикетам, поэтому серверы регулярно меняют этот ключ.

0-RTT (ранние данные) в работе не используется. Такие данные можно повторить, поэтому сервер их ограничивает (`max_early_data_size`).

### 8. Аутентификация клиента (mTLS)

В обычном TLS аутентифицируется только сервер. При mTLS (взаимный TLS) сервер требует сертификат и от клиента:

1. Сервер присылает **CertificateRequest** (тип 13) в зашифрованной части, после EncryptedExtensions. В нём перечислены допустимые `signature_algorithms` и, при необходимости, список CA.
2. Клиент присылает **Certificate** со своей цепочкой, **CertificateVerify** (подпись закрытым ключом клиента) и Finished. Если подходящего сертификата нет, клиент присылает Certificate с пустым списком.
3. Сервер проверяет цепочку клиента по своим доверенным CA, срок действия, EKU clientAuth и отзыв, если он настроен.
4. При пустом Certificate сервер может продолжить без аутентификации клиента или прервать рукопожатие alert-ом `certificate_required (116)`. В варианте 12 nginx в этой работе отвечает `HTTP 400 No required SSL certificate was sent`, а не `alert`.

Certificate клиента зашифрован, поэтому без журнала ключей его не видно, как и сертификат сервера. Для nginx в вариантах 4 и 12 доверенные CA указываются в директиве `ssl_client_certificate`.

### 9. Что видно в захвате и журнал ключей

Без ключей видны ClientHello (тип 1) и ServerHello (тип 2): они не шифруются. Всё после ServerHello в TLS 1.3 передаётся записями `application_data` (content type 23). Внутри зашифрованы EncryptedExtensions (8), Certificate (11), CertificateVerify (15) и Finished (20). Без ключей вы видите только число и размер таких записей.

Клиент может записывать секреты сеанса в файл формата NSS Key Log. В нём строки с метками `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0` и `EXPORTER_SECRET`. Wireshark и tshark читают этот файл и расшифровывают захват.
* Журнал пишет клиент. `curl` и Chromium используют переменную `SSLKEYLOGFILE`; `openssl s_client` использует опцию `-keylogfile`, переменная для него не работает.
* Сервер nginx журнал не пишет.
* Журнал позволяет расшифровать трафик, поэтому его включают только на тестовом стенде, а не на рабочих машинах.

--- 

**Архитектура**

1. Корневой CA (```root.key```) – верхний уровень доверия. Подписывает промежуточный CA и хранится оффлайн, на рабочих машинах его нет.
2. Промежуточный CA (```inter.key```, ```pathlen:0```) подписан корневым сертификатом. Выпускает серверные сертификаты через ```openssl ca```, что записывает их в базу ```index.txt```. Ограничение ```pathlen:0``` может запрещать ему выпускать другие CA.
3. Серверный сертификат (```server.key```, ```SAN: localhost```, ```127.0.0.1```) подписан промежуточным CA. По его именам клиент проверяет, что отвечает нужный сервер.
4. ```fullchain.pem``` – файл из сертификата сервера и промежуточного сертификата. ```Nginx``` отдаёт клиенту именно его: без промежуточного сертификата клиент не сможет построить цепочку до корня.
5. Клиент (```curl --cacert root.crt```) доверяет только корню. Проверяет подписи от сервера вверх до корня и сверяет имя с SAN. Переменная ```SSLKEYLOGFILE``` заставляет клиента записывать секреты сессии в ```keys.log```.
6. ```Nginx``` на порту ```8443``` принимает соединение TLS 1.3, отдаёт ```fullchain.pem``` и проводит рукопожатие.
7. ```tcpdump -i lo``` записывает пакеты между клиентом и сервером в ```handshake.pcap```.
8. ```tshark``` разбирает ```pcap```. Без ```keys.log``` видны только ```ClientHello``` и ```ServerHello```; с ```keys.log``` видны ```Certificate```, ```CertificateVerify``` и ```Finished```.

Жизненный цикл:
1. Генерация ключа корня и самоподписанного корневого сертификата.
2. Корень выпускает промежуточный CA (```pathlen:0```).
3. Промежуточный CA выпускает серверный сертификат через ```openssl ca``` (с записью в базу).
4. Проверка цепочки командой ```openssl verify```.
5. Сборка ```fullchain.pem```, настройка ```nginx```, перезапуск.
6. Клиентский запрос с ```--cacert root.crt``` и ```SSLKEYLOGFILE``` при работающем ```tcpdump```.
7. Анализ в ```tshark``` и задача варианта.

---

**Ход работы**

Все команды выполняйте в каталоге ```~/lab4```. Команды проверены на стенде; в каждом шаге указан ожидаемый результат.

#### 1. Корневой CA

```bash
mkdir -p ~/lab4/root ~/lab4/inter ~/lab4/server ~/lab4/client && cd ~/lab4
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root/root.key && chmod 600 root/root.key
openssl req -new -x509 -key root/root.key -sha256 -days 3650 -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'subjectKeyIdentifier=hash' -out root/root.crt
```

Ключ меняйте по варианту: RSA – ```openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ...```; Ed25519 – ```openssl genpkey -algorithm ED25519 -out ....``` Для Ed25519 флаг ```-sha256``` не нужен (он игнорируется без ошибки, но лучше его не писать).

#### 2. Промежуточный CA

``` bash
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

```pathlen:0``` запрещает промежуточному CA выпускать другие CA.

#### 3. База промежуточного CA

Выпускать и отзывать сертификаты нужно через ```openssl ca```. Команда ```openssl x509 -req``` базу не пишет, и отозвать такой сертификат нельзя.

```bash
cd ~/lab4/inter && touch index.txt && echo 01 > crlnumber && echo 1000 > serial && cd ~/lab4
cat > inter/ca.cnf <<'EOF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir              = ПОЛНЫЙ_ПУТЬ/lab4/inter
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

Полный путь выведите командой ```echo $HOME/lab4/inter``` и подставьте вместо ```ПОЛНЫЙ_ПУТЬ/lab4/inter```. Строка ```unique_subject = no``` разрешает повторный выпуск с тем же ```Subject```; она нужна в вариантах, где сертификат перевыпускается.

#### 4. Серверный сертификат с SAN

``` bash
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

Ожидается: ```Write out database with 1 new entries``` и ```Data Base Updated```.

#### 5. Проверка цепочки

``` bash
openssl verify -CAfile root/root.crt -untrusted inter/inter.crt server/server.crt
openssl verify -CAfile root/root.crt server/server.crt
openssl x509 -in server/server.crt -noout -ext subjectAltName,extendedKeyUsage,basicConstraints
```

Ожидается: первая команда выводит ```server/server.crt: OK```. Вторая, без промежуточного сертификата, выводит ```unable to get local issuer certificate```: путь без ```intermediate``` не строится, это нормально.

#### 6. nginx: HTTPS только по TLS 1.3

``` bash
cat server/server.crt inter/inter.crt > server/fullchain.pem
```

Листовой сертификат идёт первым, промежуточный сертификат вторым. Директива ```ssl_certificate``` в ```nginx``` принимает весь файл, поэтому указывайте ```fullchain.pem```, а не ```server.crt```.

Создайте файл ```/etc/nginx/conf.d/lab4.conf```, подставив свой логин вместо ```ВАШ_ЛОГИН```:

``` bash
server {
    listen 8443 ssl;
    server_name localhost;
    ssl_certificate     /home/ВАШ_ЛОГИН/lab4/server/fullchain.pem;
    ssl_certificate_key /home/ВАШ_ЛОГИН/lab4/server/server.key;
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;
    ssl_ecdh_curve X25519:P-256;
    ssl_session_tickets on;
    location / { return 200 'tls13 ok'; }
}
```

Набор шифров и группы меняйте по варианту. Затем проверьте конфигурацию и примените её:

``` bash
sudo nginx -t && sudo systemctl restart nginx
```

Ожидается: ```syntax is ok``` и ```test is successful```.

#### 7. Проверка клиентом

```curl -v --cacert root/root.crt https://localhost:8443/```

Ожидается: тело ответа ```tls13 ok```, код ```HTTP 200```, в подробном выводе видна версия ```TLSv1.3```.

Обязательные негативные тесты. Каждый отметьте в отчёте как негативный:

``` bash
curl https://localhost:8443/
curl --cacert root/root.crt https://127.0.0.2:8443/
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/other.key
openssl req -new -x509 -key /tmp/other.key -subj '/CN=Other Root' -days 1 -out /tmp/other.crt
curl --cacert /tmp/other.crt https://localhost:8443/
( sleep 1 ) | openssl s_client -connect localhost:8443 -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'
```

Ожидается:
* первый запрос: ```exit 60```, ```unable to get local issuer certificate```;
* второй: ```exit 60```, ```no alternative certificate subject name matches target host name '127.0.0.2'```;
* третий: ```exit 60```, ```unable to get local issuer certificate```;
* последний: ```alert protocol version``` (код ```70```), TLS 1.2 отвергается.

В командах ```openssl s_client``` держите ```stdin``` открытым через ```( sleep 1 ) |```. При ```</dev/null``` алерт сервера иногда не выводится.

#### 8. Захват рукопожатия и журнал ключей

Терминал 1 (захват):

``` bash
sudo tcpdump -i lo -w ~/lab4/client/handshake.pcap 'tcp port 8443'
```

Терминал 2 (клиент):

``` bash
cd ~/lab4/client
SSLKEYLOGFILE=$HOME/lab4/client/keys.log curl -sS --cacert ../root/root.crt https://localhost:8443/
```

Остановите tcpdump (```Ctrl+C```) и верните владельца файлу: ```sudo chown $USER ~/lab4/client/handshake.pcap```. Проверка: ```wc -l keys.log``` должен показать не меньше 5 строк.

#### 9. Анализ в Wireshark (```tshark```)

Без журнала ключей:

``` bash
tshark -r handshake.pcap -Y tls -T fields -e frame.number -e tls.record.content_type -e tls.handshake.type
```

Ожидается: ```ClientHello (handshake type 1)``` и ```ServerHello (type 2)```. Дальше идут записи ```content type 23 (application data)``` и, в режиме совместимости, ```change_cipher_spec (20)```. Сообщения рукопожатия после ```ServerHello``` не видны.

С журналом ключей:

``` bash
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y tls.handshake -T fields -e frame.number -e tls.handshake.type
```

Ожидается: сервер присылает ```2 (ServerHello)```, ```8 (EncryptedExtensions)```, ```11 (Certificate)```, ```15 (CertificateVerify)```, ```20 (Finished)```; клиент присылает ```20 (Finished)```. При выдаче тикетов встречается ```4 (NewSessionTicket)```.

Поля, которые нужны в отчёте:

``` bash
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 11' -V | grep -E 'dNSName|iPAddress'
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 15' -T fields -e tls.handshake.sig_hash_alg
```

Ожидается для шагов 1–8 с настройками из шага 6: шифр ```0x1302```, группа ```29 (x25519)```; SNI – ```localhost```; в сертификате dNSName: ```localhost```, iPAddress: ```127.0.0.1```; подпись ```CertificateVerify 0x0403``` для ECDSA P-256.

В графическом Wireshark то же самое: ```Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename = путь к keys.log```; фильтр ```tls.handshake```. Путь в меню взят из документации; проверено только через ```tshark```.

#### 10. Индивидуальные варианты заданий

Выполните задачу своего варианта (таблица ниже). В отчёте приведите команду, ожидаемый и фактический вывод.

Варианты 6 и 13 (HelloRetryRequest) и 7 и 14 (PSK) удобнее проверять на тестовом ```openssl s_server```, который принимает группы напрямую. Пример для варианта 6 (запускайте сервер в отдельном терминале):

``` bash
openssl s_server -accept 8453 -cert server/server.crt -key server/server.key -cert_chain inter/inter.crt -tls1_3 -groups P-384 -ciphersuites TLS_AES_256_GCM_SHA384 -www
( sleep 1 ) | openssl s_client -connect localhost:8453 -servername localhost -CAfile root/root.crt -tls1_3 -groups X25519:P-384 -brief
```

Ожидается: ```Server Temp Key: ECDH```, ```secp384r1``` и ```Verification: OK```. Клиент первым указал ```X25519```, сервер принял только ```P-384```, поэтому рукопожатие прошло через ```HRR```.


| №  | Ключ корня / промежуточного CA | Ключ сервера | Группа ECDHE | Набор шифров TLS 1.3         | Задача варианта                                                                                                                                                                                                                                                                                                                                                |
|----|--------------------------------|--------------|--------------|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | ECDSA P-256                    | ECDSA P-256  | X25519       | TLS_AES_128_GCM_SHA256       | Name Constraints: промежуточный CA разрешает только поддерево DNS:.lab.local. Промежуточный CA выпускается через openssl x509 -req с расширением nameConstraints. Лист для localhost: ожидаемо permitted subtree violation; лист для app.lab.local: OK.                                                                                                        |
| 2  | RSA-3072                       | RSA-2048     | P-256        | TLS_AES_256_GCM_SHA384       | pathlen: корень с pathlen:0 и промежуточный CA под ним. Проверка даёт path length constraint exceeded. Объясните, что именно ограничивает pathlen                                                                                                                                                                                                              |
| 3  | ECDSA P-384                    | Ed25519      | X25519       | TLS_CHACHA20_POLY1305_SHA256 | Отзыв через CRL: отзовите тестовый лист, выпустите CRL, проверьте openssl verify -crl_check и curl --crlfile. Ожидается: certificate revoked                                                                                                                                                                                                                   |
| 4  | Ed25519                        | ECDSA P-384  | P-384        | TLS_AES_256_GCM_SHA384       | mTLS: nginx с ssl_verify_client on и ssl_client_certificate (файл с корнем и промежуточным CA). В захвате покажите CertificateRequest (type 13) и клиентский Certificate. Без клиентского сертификата соединение отвергается                                                                                                                                   |
| 5  | RSA-2048                       | RSA-2048     | X25519       | TLS_AES_128_GCM_SHA256       | Соответствие имени: подключение по адресу, которого нет в SAN (127.0.0.2). Объясните, почему CN не помогает. Найдите SNI в ClientHello                                                                                                                                                                                                                         |
| 6  | ECDSA P-384                    | ECDSA P-256  | P-384        | TLS_AES_256_GCM_SHA384       | HelloRetryRequest: клиент первым присылает key_share для X25519, сервер принимает только P-384. Найдите HRR в захвате (Hello Retry Request, Selected Group). Сервер — openssl s_server, пример в шаге 10                                                                                                                                                       |
| 7  | ECDSA P-256                    | Ed25519      | X25519       | TLS_AES_128_GCM_SHA256       | Возобновление сессии: первое соединение с -sess_out, второе с -sess_in, оба с `( sleep 1 )                                                                                                                                                                                                                                                                     |
| 8  | Ed25519                        | Ed25519      | X25519       | TLS_CHACHA20_POLY1305_SHA256 | Срок действия: openssl verify -attime на дату через 400 дней, ожидаемо certificate has expired. Обоснуйте срок листа: для публичных CA правила CA/Browser Forum ограничивают срок TLS-сертификатов 398 днями                                                                                                                                                   |
| 9  | RSA-3072                       | ECDSA P-256  | P-256        | TLS_CHACHA20_POLY1305_SHA256 | Неполная цепочка: nginx отдаёт только server.crt вместо fullchain.pem. curl выдаёт unable to get local issuer certificate. Исправьте конфиг и сравните число сертификатов в сообщении Certificate                                                                                                                                                              |
| 10 | ECDSA P-384                    | RSA-2048     | X25519       | TLS_AES_256_GCM_SHA384       | EKU: лист только с clientAuth. Попытка использовать его как серверный даёт unsuitable certificate purpose (openssl verify -purpose sslserver). Объясните разницу EKU                                                                                                                                                                                           |
| 11 | ECDSA P-256                    | ECDSA P-384  | P-384        | TLS_AES_128_GCM_SHA256       | OCSP: поднимите responder openssl ocsp -index inter/index.txt -port 2560 -rsigner inter/inter.crt -rkey inter/inter.key -CA inter/inter.crt. Запрос openssl ocsp -issuer inter/inter.crt -cert server/server.crt -url http://127.0.0.1:2560 -CAfile root/root.crt -no_nonce даёт good. После отзыва перезапустите responder и получите revoked. Сравните с CRL |
| 12 | RSA-2048                       | Ed25519      | X25519       | TLS_AES_256_GCM_SHA384       | mTLS с клиентским сертификатом Ed25519: без сертификата соединение отвергается, с сертификатом проходит. Для nginx без клиентского сертификата ответ — HTTP 400 No required SSL certificate was sent, а не TLS-alert. Объясните разницу                                                                                                                        |
| 13 | Ed25519                        | ECDSA P-256  | X25519       | TLS_AES_128_GCM_SHA256       | HelloRetryRequest в обратной паре: клиент первым присылает P-256, сервер выбирает X25519. Сравните число ClientHello и ServerHello с обычным рукопожатием                                                                                                                                                                                                      |
| 14 | ECDSA P-384                    | ECDSA P-384  | P-256        | TLS_CHACHA20_POLY1305_SHA256 | PSK на P-256 с ChaCha20: сравните первое и второе соединения по наличию Certificate и pre_shared_key. Объясните, почему тикет нельзя использовать как обычный ключ                                                                                                                                                                                             |
| 15 | RSA-3072                       | RSA-3072     | X25519       | TLS_AES_256_GCM_SHA384       | Версия TLS: nginx с ssl_protocols TLSv1.3. Клиент openssl s_client -tls1_2 получает alert protocol version (70). Объясните риски TLS 1.0–1.2: downgrade-атаки и устаревшие шифры                                                                                                                                                                               |

**Замечания по вариантам:**
* Варианты с ```Ed25519``` в корневом или листовом сертификате проверяются через ```curl``` и ```openssl```. В Chromium ```Ed25519``` не проверялся. Если браузер отвергнет сертификат, это наблюдение фиксируется в отчёте.
* Отзыв необратим. Отзывайте отдельный тестовый сертификат (например, ```revoked.crt```), а не ```server.crt```, иначе придётся перевыпускать серверный сертификат и перезапускать ```nginx```.
* Вариант 4 и вариант 12 требуют в ```nginx``` ```ssl_client_certificate``` с файлом, где лежат корень и промежуточный CA.

**Требования к структуре и содержанию отчёта**

Отчёт должен содержать:
1. Команды, которые вы ввели, и фактический вывод каждой. Сверяйте вывод с полем «Ожидается». Если меняли пути, порты, логин или набор шифров, укажите, что и почему.
2. Фрагменты вывода ```openssl x509 -noout -text``` для ```root.crt```, ```inter.crt``` и ```server.crt``` с полями ```Basic Constraints``` (у промежуточного CA – ```pathlen```), ```Key Usage```, ```Extended Key Usage``` и ```Subject Alternative Name```.
3. Конфигурация nginx. Строки ```ssl_protocols```, ```ssl_conf_command Ciphersuites```, ```ssl_ecdh_curve``` и ```ssl_certificate``` из вашего ```lab4.conf``` и вывод ```nginx -t```.
4. Проверка цепочки и отзыва: ```openssl verify``` для цепочки; ```curl``` с ```root.crt``` (```HTTP 200```, ```TLSv1.3```); негативные тесты: неполная цепочка, чужой корень, имя вне SAN (```127.0.0.2```), истёкший сертификат через ```openssl verify -attime```, отозванный сертификат (CRL или OCSP), TLS 1.2 с alert protocol version (```70```). Каждый негативный тест помечайте в отчёте как негативный.
5. Wireshark без ключей и с ключами: номера и типы сообщений рукопожатия, которые вы видите в tshark, а также шифр, группа ```key_share```, ```SNI``` и ```dNSName```. Отдельно: что добавил журнал ключей и список уникальных меток из ```keys.log``` (```cut -d' ' -f1 keys.log | sort -u```).
6. Задача варианта: команда, ожидаемый и фактический вывод, наблюдение в Wireshark. Для вариантов с ```HelloRetryRequest``` или PSK укажите число ClientHello и ServerHello и наличие Certificate.

**Типичные ошибки**:
* ```openssl s_server -cert fullchain.pem``` отдаёт клиенту только лист. Для цепочки в ```s_server``` нужна опция ```-cert_chain```;
* ```openssl x509 -req``` не пишет базу, поэтому отзыв невозможен. Подписывайте через ```openssl ca```;
* ```openssl s_client``` игнорирует переменную ```SSLKEYLOGFILE```. Используйте опцию ```-keylogfile```;
* ```</dev/null``` в ```s_client``` может проглотить предупреждение сервера. Используйте ```( sleep 1 ) | openssl s_client ...```;
* OCSP-responder читает ```index.txt``` при старте. После ```openssl ca -revoke``` перезапустите responder, иначе он продолжит отвечать ```good```;
* текст ошибки ```EKU: unsuitable certificate purpose```, а не ```unsupported```;
* ```nginx``` с ```ssl_verify_client on``` без клиентского сертификата отвечает ```HTTP 400 No required SSL certificate was sent```, а не TLS-alert;
* отзыв необратим: отзывайте отдельный тестовый сертификат, а не серверный;
* порт ```443``` в работе не используется. Если ```8443``` или ```8453``` заняты, поменяйте номер в конфиге nginx и в командах.