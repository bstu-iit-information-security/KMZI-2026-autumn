#!/bin/bash
O=openssl
pkill -f "s_server -accept 8453" 2>/dev/null; sleep 0.5
$O s_server -accept 8453 -cert server/server.crt -key server/server.key -cert_chain inter/inter.crt -tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 -www -msg > server.log 2>&1 &
SP=$!; sleep 1
cl() { ( sleep 1 ) | $O s_client -connect localhost:8453 -servername localhost -CAfile root/root.crt -tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 "$@"; }
echo "=== conn1 (full) ==="; cl -sess_out client/sess.pem -msg -keylogfile client/keys.log > conn1.log 2>&1
cl -brief 2>&1 | head -12
echo "=== conn2 (resume, -sess_in) ==="; cl -sess_in client/sess.pem -msg > conn2.log 2>&1
cl -sess_in client/sess.pem -brief 2>&1 | head -12
for n in conn1 conn2; do echo "-- $n: handshake messages"; grep -oE "(ClientHello|ServerHello|EncryptedExtensions|CertificateVerify|Certificate|Finished|NewSessionTicket)," $n.log | sort | uniq -c; echo "pre_shared_key: $(grep -c pre_shared_key $n.log)"; grep -E "Reused|New, TLSv|Cipher is|Server Temp Key|Verification" $n.log; done
echo "== keylog"; wc -l < client/keys.log; cut -d' ' -f1 client/keys.log | sort -u
kill $SP
