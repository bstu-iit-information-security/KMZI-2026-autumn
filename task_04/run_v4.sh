#!/bin/bash
# Вариант 4: mTLS (запуск из каталога pki/). Сервер требует клиентский сертификат (-Verify 1).
mkdir -p ../logs
pkill -f "s_server -accept 8453" 2>/dev/null; sleep 0.5
openssl s_server -accept 8453 -cert server/server.crt -key server/server.key -cert_chain inter/inter.crt \
  -CAfile server/client-ca.pem -Verify 1 -verify_return_error -tls1_3 -groups P-384 -ciphersuites TLS_AES_256_GCM_SHA384 -www -msg > ../logs/server.log 2>&1 & SP=$!; sleep 1
cl() { ( sleep 1 ) | openssl s_client -connect localhost:8453 -servername localhost -CAfile root/root.crt -verify_return_error -tls1_3 -groups P-384 -ciphersuites TLS_AES_256_GCM_SHA384 "$@"; }
echo "== [НЕГАТИВНЫЙ] без клиентского сертификата"
cl -msg > ../logs/no_cert.log 2>&1; grep -E "alert|Alert|error|CertificateRequest|^[0-9]+:error" ../logs/no_cert.log | head -8
echo "== С клиентским сертификатом ECDSA P-384 (-brief)"
cl -cert client/client.crt -key client/client.key -brief 2>&1 | head -10
echo "== С сертификатом: тело ответа сервера"
( printf 'GET / HTTP/1.0\r\n\r\n'; sleep 1 ) | openssl s_client -connect localhost:8453 -servername localhost -CAfile root/root.crt -tls1_3 -groups P-384 -ciphersuites TLS_AES_256_GCM_SHA384 -cert client/client.crt -key client/client.key -ign_eof -quiet 2>&1 | head -4
cl -cert client/client.crt -key client/client.key -msg -keylogfile ../logs/keys.log > ../logs/with_cert.log 2>&1
cl -cert client/client.crt -key client/client.key -trace > ../logs/with_cert_trace.log 2>&1
for n in no_cert with_cert; do echo "-- $n: сообщения (клиент)"; grep -E "^(>>>|<<<) TLS 1.3, Handshake" ../logs/$n.log | sed -E 's/.*\], //' | awk '{c[$0]++} END{for(k in c) print c[k], k}' | sort -k2; done
echo "== CertificateRequest / клиентский Certificate в -trace"
grep -nE "^ +(CertificateRequest|Certificate|CertificateVerify|ClientHello|ServerHello|EncryptedExtensions|Finished)," ../logs/with_cert_trace.log | head -20
grep -nE "^(Sent|Received)|Handshake, Length|extension_type=signature_algorithms" ../logs/with_cert_trace.log | head -0
echo "== keylog"; wc -l < ../logs/keys.log; cut -d' ' -f1 ../logs/keys.log | sort -u
kill $SP
