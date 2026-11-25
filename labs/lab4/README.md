### 1. Корневой сертификат root/root.crt
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            36:32:06:73:1a:03:83:1b:ae:78:de:a5:79:12:4e:d6:0d:22:0c:b6
        Signature Algorithm: ED25519
        Issuer: C = BY, O = Lab PKI, CN = Lab Root CA
        Validity
            Not Before: Nov 10 20:09:06 2026 GMT
            Not After : Nov  7 20:09:06 2036 GMT
        Subject: C = BY, O = Lab PKI, CN = Lab Root CA
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    24:57:ac:4a:af:ac:d5:0d:91:7f:a3:cb:e1:50:56:
                    24:da:37:3f:f3:87:87:e4:9e:29:04:e1:95:1c:c1:
                    a2:27
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                A0:06:D2:F1:93:35:E3:26:C1:56:09:20:B9:55:64:7C:E5:C2:FA:1C
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                A0:06:D2:F1:93:35:E3:26:C1:56:09:20:B9:55:64:7C:E5:C2:FA:1C
    Signature Algorithm: ED25519
    Signature Value:
        10:39:77:fa:e3:9d:74:69:2e:60:da:67:d5:b2:10:60:0f:eb:
        a2:10:ad:8e:6b:b0:ec:a8:3f:bd:7d:13:77:1c:fd:5e:8f:ac:
        39:90:1b:f7:04:cc:12:ad:a4:dc:8a:c2:97:69:2e:dd:81:fc:
        1c:de:e4:20:f4:f8:6c:08:1c:0f

```
Комментарий к root.crt. Самоподписанный (Issuer = Subject = Lab Root CA), подпись проверяется собственным открытым ключом. basicConstraints: CA:TRUE, pathlen:1 разрешает одному промежуточному CA стоять ниже. keyUsage: keyCertSign, cRLSign — только подпись сертификатов и CRL, ничего больше. SKI = AKI = A0:06:D2:… — OpenSSL 3.x автоматически проставляет AKI для самоподписанных (RFC 5280 это рекомендует), не дубль-ошибка.

### 2. Промежуточный сертификат inter/inter.crt
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3f:10:03:50:2f:99:21:74:cd:af:e8:90:f6:b8:9a:f6:48:99:ab:60
        Signature Algorithm: ED25519
        Issuer: C = BY, O = Lab PKI, CN = Lab Root CA
        Validity
            Not Before: Nov 10 20:10:02 2026 GMT
            Not After : Nov  9 20:10:02 2031 GMT
        Subject: C = BY, O = Lab PKI, CN = Lab Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    c3:47:f5:9f:40:df:ce:4b:40:1e:f4:62:7c:30:75:
                    47:db:7d:91:bd:50:58:d9:51:fa:ed:c1:17:22:6b:
                    29:46
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                B3:14:2A:17:27:94:D2:4E:96:36:F4:6A:A0:96:84:59:7B:B9:27:9D
            X509v3 Authority Key Identifier:
                A0:06:D2:F1:93:35:E3:26:C1:56:09:20:B9:55:64:7C:E5:C2:FA:1C
    Signature Algorithm: ED25519
    Signature Value:
        b0:82:1d:fc:81:31:cb:eb:cd:c1:99:37:75:05:c1:74:c6:2a:
        0b:7e:6d:f2:16:c1:58:46:67:29:d1:9f:5a:7a:a0:52:8c:eb:
        1e:b0:b6:e2:6e:34:b9:a0:38:af:3f:77:23:68:f8:43:f2:0c:
        77:12:ec:58:a5:61:50:87:e9:01
```
Комментарий к inter.crt. Issuer = Lab Root CA, Subject = Lab Intermediate CA — подписан корнем. pathlen:0 запрещает выпускать под собой другие CA (листовые — можно). AKI = A0:06:D2:… = SKI корня — связка цепочки сходится. Этим сертификатом подписаны server.crt, client.crt и revoked.crt.

### 3. Серверный сертификат server/server.crt
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4096 (0x1000)
        Signature Algorithm: ED25519
        Issuer: C = BY, O = Lab PKI, CN = Lab Intermediate CA
        Validity
            Not Before: Nov 10 20:12:01 2026 GMT
            Not After : Nov 10 20:12:01 2027 GMT
        Subject: CN = localhost
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:69:92:3e:c5:31:f3:54:c1:35:53:c2:8a:81:0f:
                    20:26:cc:0a:bd:2d:90:98:b9:97:a7:50:57:7a:1b:
                    0a:09:e3:e7:c2:4b:c9:8c:01:e7:4b:6e:f5:cf:bd:
                    83:c5:a6:7c:ff:6e:61:42:ea:a6:e2:84:ec:08:c9:
                    7b:64:98:00:13:97:e1:31:93:85:82:fb:8f:c0:36:
                    57:b4:60:3b:1f:01:92:7c:c2:24:bd:fc:7c:51:1f:
                    5a:0e:eb:e5:c2:bf:f3
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Key Identifier:
                46:99:9D:CD:39:9F:F8:2C:3E:96:56:6C:68:EB:E9:C4:B6:00:A1:4C
            X509v3 Authority Key Identifier:
                B3:14:2A:17:27:94:D2:4E:96:36:F4:6A:A0:96:84:59:7B:B9:27:9D
            X509v3 Subject Alternative Name:
                DNS:localhost, IP Address:127.0.0.1
    Signature Algorithm: ED25519
    Signature Value:
        49:53:f6:40:e5:cb:d0:b0:21:d4:73:96:3c:d4:7f:80:11:29:
        c6:1a:92:26:5c:2d:6f:72:e5:84:05:c9:64:6c:6d:fe:f2:86:
        f9:0c:70:2d:ef:07:01:15:3b:90:86:f2:5c:11:c8:8d:d2:95:
        b4:b9:f0:5a:be:80:70:1a:71:06
```
Комментарий к server.crt. Ключ — ECDSA P-384 (secp384r1), подпись — Ed25519 (издатель — промежуточный CA). CA:FALSE — не CA. EKU: serverAuth — только для сервера. SAN = DNS:localhost, IP:127.0.0.1 — по нему curl/браузер сверяют имя хоста (CN для TLS игнорируется). AKI = B3:14:2A:… = SKI промежуточного — цепочка сходится. Subject: CN=localhost без C=BY/O=Lab PKI — фильтр policy_any в inter/ca.cnf (только commonName = supplied); на проверку TLS не влияет, поэтому оставлено как есть.

### 4. Клиентский сертификат client/client.crt
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4097 (0x1001)
        Signature Algorithm: ED25519
        Issuer: C = BY, O = Lab PKI, CN = Lab Intermediate CA
        Validity
            Not Before: Nov 10 20:12:31 2026 GMT
            Not After : Nov 10 20:12:31 2027 GMT
        Subject: CN = client.lab.local
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:9b:5e:d4:9c:57:f2:da:1b:3e:20:fd:4b:65:46:
                    f0:0e:51:6f:c0:56:3b:0e:3f:c4:09:c8:fd:02:b1:
                    f0:4a:c3:54:fa:5a:f3:b9:88:20:d0:3a:05:42:f6:
                    cc:d3:47:71:50:40:5b:e2:72:7b:83:56:b3:f6:e6:
                    cd:8b:1a:d8:77
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
            X509v3 Subject Key Identifier:
                D0:F0:AE:2C:61:F0:31:EE:6E:CF:F5:C9:A8:77:6F:5A:4C:28:D7:D7
            X509v3 Authority Key Identifier:
                B3:14:2A:17:27:94:D2:4E:96:36:F4:6A:A0:96:84:59:7B:B9:27:9D
            X509v3 Subject Alternative Name:
                DNS:client.lab.local
    Signature Algorithm: ED25519
    Signature Value:
        eb:48:19:72:44:ba:14:8d:b9:91:d1:64:54:a9:75:e3:cc:8e:
        e3:e8:47:9c:c1:73:cf:62:98:5d:b7:ba:1a:bf:56:2b:d5:af:
        12:da:b1:f1:d2:1f:8c:ed:bb:65:3c:d1:66:60:a8:ee:b0:a4:
        92:07:fb:99:e3:24:de:e8:ed:01
```
Комментарий к client.crt. Ключ — ECDSA P-256 (prime256v1), подпись — Ed25519. EKU: clientAuth — ключевое отличие от серверного; nginx при ssl_verify_client on требует именно этот EKU. SAN: DNS:client.lab.local — для консистентности. AKI = B3:14:2A:… = SKI промежуточного — цепочка сходится. Subject без C/O — та же причина (политика policy_any).

### 5. Тестовый отозванный сертификат server/revoked.crt
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4098 (0x1002)
        Signature Algorithm: ED25519
        Issuer: C = BY, O = Lab PKI, CN = Lab Intermediate CA
        Validity
            Not Before: Nov 24 17:37:06 2026 GMT
            Not After : Nov 24 17:37:06 2027 GMT
        Subject: CN = revoked.local
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:11:77:79:20:e5:1b:8f:8a:93:96:d0:05:75:74:
                    f5:52:51:17:28:6f:7a:c3:0f:d1:37:69:4d:0b:fc:
                    bb:9b:89:ba:8d:89:2f:77:a2:43:2e:4d:1c:17:4f:
                    54:bf:a5:2c:c2:bb:5e:88:db:18:f0:29:5a:65:cf:
                    6f:54:36:66:4e
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Key Identifier:
                2F:F6:3C:FC:6C:3F:91:C9:3C:47:EB:A0:00:0B:C8:3C:A5:57:CF:2A
            X509v3 Authority Key Identifier:
                B3:14:2A:17:27:94:D2:4E:96:36:F4:6A:A0:96:84:59:7B:B9:27:9D
            X509v3 Subject Alternative Name:
                DNS:revoked.local
    Signature Algorithm: ED25519
    Signature Value:
        e7:23:80:9b:ef:e8:45:3c:c2:d4:85:6f:03:91:dc:63:87:a6:
        bc:66:bd:a6:f3:ec:c5:4b:e7:66:72:a6:85:e7:1e:9c:56:8e:
        8d:05:bd:3a:26:22:f2:d3:01:e3:6f:eb:31:95:d3:6d:6f:3d:
        78:73:da:0f:a4:1c:f6:de:90:0c
```
Комментарий к revoked.crt. Отдельный тестовый лист, не server.crt — чтобы отзыв не сломал рабочий nginx. Серийник 0x1002 — именно он попал в index.txt со статусом R и в crl.pem.

### 6. База удостоверяющего центра (после CRL-теста)
inter/index.txt — реестр выданных сертификатов:

```
V	271110201201Z		1000	unknown	/CN=localhost
V	271110201231Z		1001	unknown	/CN=client.lab.local
R	271124173706Z	261124173706Z	1002	unknown	/CN=revoked.local
```
Расшифровка колонок: статус (V = valid, R = revoked), дата истечения, дата отзыва (пусто для V), серийник, unknown, subject.

inter/serial.txt — следующий свободный серийник:
```
1003
```
inter/crlnumber.txt — номер следующего CRL:
```
02
```
structure/serials.txt — сводка серийник | статус | subject:

```
1000	V	/CN=localhost
1001	V	/CN=client.lab.local
1002	R	/CN=revoked.local
```