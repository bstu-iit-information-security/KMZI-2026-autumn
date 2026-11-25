# Лабораторная работа №4. PKI, HTTPS и TLS 1.3
**Вариант 9:** Неполная цепочка (отсутствие промежуточного сертификата)

В ходе выполнения работы мы использовали три окна терминала (WSL Ubuntu), чтобы разделить процессы настройки сервера, захвата трафика и генерации клиентских запросов. 

---

## 🖥️ Терминал 1 (Левый): Создание PKI, настройка сервера и анализ

В этом терминале мы выполняли основную работу: создавали сертификаты, настраивали Nginx и анализировали перехваченный трафик.

### 1. Создание Удостоверяющего Центра (CA)
Наша первая задача — создать инфраструктуру открытых ключей (PKI), включающую корневой CA, промежуточный CA и серверный сертификат.

*   **Для создания Корневого CA (RSA-3072):** мы использовали команду 
    ```bash
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root/root.key

которая сгенерировала закрытый ключ. Затем команда:
"openssl req -new -x509 -key root/root.key -sha256 -days 3650 -subj '/C=BY/O=Lab PKI/CN=Lab Root CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'subjectKeyIdentifier=hash' -out root/root.crt"
создала самоподписанный корневой сертификат (root.crt) с необходимыми расширениями (basicConstraints, keyUsage).

Для создания Промежуточного CA: мы создали файл с расширениями:
"cat > inter/inter.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF"

Затем сгенерировали ключ:
"openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out inter/inter.key && chmod 600 inter/inter.key"

Создали запрос на подпись:
"openssl req -new -key inter/inter.key -subj '/C=BY/O=Lab PKI/CN=Lab Intermediate CA' -out inter/inter.csr"

И подписали его корневым ключом:
"openssl x509 -req -in inter/inter.csr -CA root/root.crt -CAkey root/root.key -CAcreateserial -sha256 -days 1825 -extfile inter/inter.ext -out inter/inter.crt"

Для создания Серверного сертификата (ECDSA P-256): мы создали файл с расширениями для сервера:

"cat > server/server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF"

Сгенерировали ключ на эллиптической кривой:
"openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server/server.key && chmod 600 server/server.key"

Создали запрос:
"openssl req -new -key server/server.key -subj '/C=BY/O=Lab PKI/CN=localhost' -out server/server.csr"

И выпустили сертификат через базу промежуточного CA:
"openssl ca -config inter/ca.cnf -batch -in server/server.csr -extfile server/server.ext -notext -out server/server.crt"

Затем мы проверили, что цепочка выстраивается правильно:
"openssl verify -CAfile root/root.crt -untrusted inter/inter.crt -verify_hostname localhost server/server.crt"

И посмотрели сроки действия:
"openssl x509 -in server/server.crt -noout -dates"
https://img/verify_chain.png
https://img/cert_dates.png

2. Настройка Nginx (HTTPS только TLS 1.3)
Следующая задача — заставить Nginx отдавать наш сертификат по TLS 1.3.
Сборка полной цепочки: мы объединили серверный и промежуточный сертификаты в один файл:
"cat server/server.crt inter/inter.crt > server/fullchain.pem"

Создание конфига: мы использовали команду для записи настроек в файл:
"sudo tee /etc/nginx/conf.d/lab4.conf <<EOF
server {
    listen 8443 ssl;
    server_name localhost;
    ssl_certificate     $HOME/lab4/server/fullchain.pem;
    ssl_certificate_key $HOME/lab4/server/server.key;
    ssl_protocols TLSv1.3;
    ssl_conf_command Ciphersuites TLS_CHACHA20_POLY1305_SHA256;
    ssl_ecdh_curve P-256;
    location / { return 200 'tls13 ok'; }
}
EOF"

Перезапуск:
"sudo nginx -t && sudo service nginx restart"
проверила синтаксис и применила настройки.
https://img/nginx_9.png

3. Проверка работы и негативные тесты
Успешное подключение:
"curl -v --cacert root/root.crt https://localhost:8443/"
В выводе мы увидели tls13 ok и SSL connection using TLSv1.3 / TLS_CHACHA20_POLY1305_SHA256.
https://img/curl_check_9.png

Задача варианта 9 (Неполная цепочка): мы специально изменили конфиг Nginx, чтобы он отдавал только server.crt (без промежуточного). Запрос:
"curl --cacert root/root.crt https://localhost:8443/
выдал ошибку unable to get local issuer certificate, что доказывает важность передачи полной цепочки.
https://img/negative_test_1_9.png

Неверный хост: мы обратились по адресу https://127.0.0.2:8443/, которого нет в SAN сертификата:
"curl --cacert root/root.crt https://127.0.0.2:8443/"
и получили ожидаемую ошибку.
https://img/negative_test_2_9.png

Попытка TLS 1.2: команда
"( sleep 1 ) | openssl s_client -connect localhost:8443 -tls1_2 -CAfile root/root.crt 2>&1 | grep -E 'alert|Protocol'"
принудительно пыталась установить старое соединение, но сервер отверг его с ошибкой alert protocol version.
https://img/negative_test_3_9.png

4. Анализ в Wireshark (tshark)
После захвата трафика мы анализировали его в этом же терминале.
Без ключей: команда
"tshark -r handshake.pcap -Y tls -T fields -e frame.number -e tls.record.content_type -e tls.handshake.type"
показала только ClientHello и ServerHello. Остальное — зашифрованные данные.
https://img/tshark_no_key_9.png

С ключами: добавив
"tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y tls.handshake -T fields -e frame.number -e tls.handshake.type"
мы увидели расшифрованные Encrypted Extensions, Certificate, CertificateVerify и Finished.
https://img/tshark_key_9.png

Параметры: мы вытащили шифр, группу и подпись:
"tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group
tshark -r handshake.pcap -o tls.keylog_file:keys.log -Y 'tls.handshake.type == 15' -T fields -e tls.handshake.sig_hash_alg"

Получили 0x1303, 23 (P-256) и 0x0403, подтвердив соответствие варианту.
https://img/tshark_extra_9.png

Терминал 2 (Средний): Захват трафика (tcpdump)

Здесь мы стояли задачу поймать сетевые пакеты во время подключения клиента.
Запуск захвата: мы выполнили:
"sudo tcpdump -i lo -w ~/lab4/client/handshake.pcap 'tcp port 8443'"
Эта команда начала слушать интерфейс lo (loopback) и записывать все пакеты, идущие через порт 8443, в файл handshake.pcap. Терминал «завис» в ожидании трафика.
Остановка: после того как клиент сделал запрос, мы нажали Ctrl+C. В выводе отобразилось, что было захвачено 42 пакета (21 captured).
https://img/tcpdump_serv_9.png

Терминал 3 (Правый): Клиент (Генерация трафика)
В этом терминале мы стояли задачу сделать запрос к серверу так, чтобы сохранились ключи для расшифровки.
Запрос с журналом ключей: мы выполнили команду:
"SSLKEYLOGFILE=$HOME/lab4/client/keys.log curl -sS --cacert root/root.crt https://localhost:8443/"
Переменная SSLKEYLOGFILE заставила curl записать секретные ключи сессии в файл keys.log. Запрос успешно вернул tls13 ok.

Проверка файла: командой:
"wc -l client/keys.log && ls -l client/keys.log"
мы убедились, что файл создан (5 строк, 778 байт). Именно этот файл позволил нам расшифровать трафик в Wireshark.
https://img/keys_log_9.png

Графический Wireshark:
В конце мы открыли файл handshake.pcap в GUI Wireshark и указали путь к keys.log в настройках TLS. Трафик успешно расшифровался, что видно на скриншоте.
https://img/wireshark_gui_9.png
