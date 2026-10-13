#pragma once

#include "rsa_math.hpp"

// Модуль 2. Вычислительное ядро RSA.
// Шифрование: c = m^e mod n.
// Расшифрование: алгоритм Гарнера (CRT) по заранее посчитанным dp, dq, qinv.
class RsaCore {
public:
    struct GarnerTrace {
        Bn m1;
        Bn m2;
        Bn diff;
        Bn h;
        Bn message;
        bool diff_was_negative = false;
    };

    static bool encrypt(Bn& cipher, const Bn& message, const Bn& e, const Bn& n);
    static bool decrypt_naive(Bn& message, const Bn& cipher, const Bn& d, const Bn& n);
    static bool decrypt_crt(Bn& message, const Bn& cipher, const RsaPrivateKey& key);
    static bool decrypt_crt_trace(Bn& message, GarnerTrace& trace, const Bn& cipher,
                                  const RsaPrivateKey& key);
};
