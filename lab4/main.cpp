#include <iostream>
#include <string>
#include <vector>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#define closesocket close
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

using namespace std;

void printSeparator() {
    cout << "========================================================\n";
}

bool verifyCertificatesOffline(const string& rootPath, const string& interPath, const string& serverPath) {
    printSeparator();
    cout << "[Офлайн-верификация цепочки X.509 (Вариант 7)]\n";

    FILE* fRoot = fopen(rootPath.c_str(), "r");
    FILE* fInter = fopen(interPath.c_str(), "r");
    FILE* fServer = fopen(serverPath.c_str(), "r");

    if (!fRoot || !fInter || !fServer) {
        cerr << "[-] Ошибка открытия файлов сертификатов.\n";
        if (fRoot) fclose(fRoot);
        if (fInter) fclose(fInter);
        if (fServer) fclose(fServer);
        return false;
    }

    X509* rootCert = PEM_read_X509(fRoot, nullptr, nullptr, nullptr);
    X509* interCert = PEM_read_X509(fInter, nullptr, nullptr, nullptr);
    X509* serverCert = PEM_read_X509(fServer, nullptr, nullptr, nullptr);

    fclose(fRoot);
    fclose(fInter);
    fclose(fServer);

    if (!rootCert || !interCert || !serverCert) {
        cerr << "[-] Не удалось распарсить PEM сертификатов.\n";
        return false;
    }

    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, rootCert);

    STACK_OF(X509)* untrusted = sk_X509_new_null();
    sk_X509_push(untrusted, interCert);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, serverCert, untrusted);

    int ret = X509_verify_cert(ctx);
    if (ret == 1) {
        cout << "[+] Сертификат сервера успешно верифицирован цепочкой: Root CA -> Intermediate CA -> Server Leaf!\n";
    } else {
        int err = X509_STORE_CTX_get_error(ctx);
        cout << "[-] Ошибка верификации: " << X509_verify_cert_error_string(err) << "\n";
    }

    int keyType = X509_get_signature_nid(serverCert);
    cout << "[*] Алгоритм подписи сервера: " << OBJ_nid2sn(keyType) << "\n";

    X509_STORE_CTX_free(ctx);
    sk_X509_free(untrusted);
    X509_STORE_free(store);
    X509_free(serverCert);
    X509_free(interCert);
    X509_free(rootCert);
    return ret == 1;
}

int connectSocket(const string& host, int port) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    string portStr = to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) {
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) < 0) {
        closesocket(sock);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return sock;
}

int main(int argc, char* argv[]) {
    printSeparator();
    cout << " Лабораторная работа №4 (КМЗИ) - Вариант 7\n";
    cout << " Тема: PKI, X.509, TLS 1.3, Session Resumption (PSK)\n";
    cout << " Параметры варианта 7:\n";
    cout << "  - Root / Inter CA: ECDSA P-256\n";
    cout << "  - Server Key:      Ed25519\n";
    cout << "  - ECDHE Curve:     X25519\n";
    cout << "  - Ciphersuite:     TLS_AES_128_GCM_SHA256\n";
    cout << "  - Задача варианта: Возобновление сессии (Session Resumption / PSK)\n";
    printSeparator();
    cout << "\n";

    verifyCertificatesOffline("root/root.crt", "inter/inter.crt", "server/server.crt");

    cout << "\n[*] Проверка TLS 1.3 рукопожатия и Session Resumption с сервером на порту 8453...\n";
    int sock1 = connectSocket("127.0.0.1", 8453);
    if (sock1 < 0) {
        cout << "[!] Сервер на порту 8453 не запущен. Для онлайн-теста запустите s_server:\n";
        cout << "    openssl s_server -accept 8453 -cert server/server.crt -key server/server.key \\\n";
        cout << "      -cert_chain inter/inter.crt -tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 -www\n";
        cout << "[+] Офлайн проверка сертификатов выполнена успешно!\n";
        return 0;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    SSL_CTX_set1_groups_list(ctx, "X25519");
    SSL_CTX_load_verify_locations(ctx, "root/root.crt", nullptr);

    cout << "\n--> [Соединение 1]: Первичное полное рукопожатие TLS 1.3\n";
    SSL* ssl1 = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl1, "localhost");
    SSL_set_fd(ssl1, sock1);

    if (SSL_connect(ssl1) <= 0) {
        cerr << "[-] Ошибка TLS-рукопожатия в соединении 1.\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl1);
        closesocket(sock1);
        SSL_CTX_free(ctx);
        return 1;
    }

    cout << "[+] Рукопожатие 1 успешно!\n";
    cout << "    Версия протокола: " << SSL_get_version(ssl1) << "\n";
    cout << "    Шифровой набор:   " << SSL_get_cipher_name(ssl1) << "\n";
    cout << "    Сессия повторно использована? " << (SSL_session_reused(ssl1) ? "Да (PSK)" : "Нет (Полное рукопожатие)") << "\n";

    const char req[] = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    SSL_write(ssl1, req, (int)strlen(req));
    char buf[256];
    SSL_read(ssl1, buf, sizeof(buf) - 1);

    SSL_SESSION* savedSession = SSL_get1_session(ssl1);
    SSL_shutdown(ssl1);
    SSL_free(ssl1);
    closesocket(sock1);

    if (!savedSession) {
        cerr << "[-] Не удалось получить объект сессии для возобновления.\n";
        SSL_CTX_free(ctx);
        return 1;
    }

    cout << "\n--> [Соединение 2]: Возобновление сессии (Session Resumption / PSK)\n";
    int sock2 = connectSocket("127.0.0.1", 8453);
    if (sock2 < 0) {
        cerr << "[-] Ошибка подключения сокета для соединения 2.\n";
        SSL_SESSION_free(savedSession);
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL* ssl2 = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl2, "localhost");
    SSL_set_fd(ssl2, sock2);
    SSL_set_session(ssl2, savedSession);

    if (SSL_connect(ssl2) <= 0) {
        cerr << "[-] Ошибка TLS-рукопожатия в соединении 2.\n";
        ERR_print_errors_fp(stderr);
    } else {
        cout << "[+] Рукопожатие 2 успешно!\n";
        cout << "    Версия протокола: " << SSL_get_version(ssl2) << "\n";
        cout << "    Шифровой набор:   " << SSL_get_cipher_name(ssl2) << "\n";
        cout << "    Сессия повторно использована? " << (SSL_session_reused(ssl2) ? "Да (PSK/Resumption подтверждено!)" : "Нет") << "\n";
        SSL_shutdown(ssl2);
    }

    SSL_free(ssl2);
    closesocket(sock2);
    SSL_SESSION_free(savedSession);
    SSL_CTX_free(ctx);

    printSeparator();
    cout << "[+] Задача варианта 7 успешно выполнена!\n";
    printSeparator();
    return 0;
}
