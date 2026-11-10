// Верхний слой: склейка модулей 2 и 3.
//   шифрование:   M -> OAEP-encode -> EM -> (os2ip) -> RSA(e) -> (i2osp) -> C
//   расшифрование: C -> (os2ip) -> RSA-CRT(d) -> (i2osp) -> EM -> OAEP-decode -> M
#pragma once
#include <cstddef>
#include <cstdint>

#include "oaep.hpp"
#include "rsa_core.hpp"

namespace rsa {

// ct -- буфер oaep::K байт. Возврат: 0 -- ок, -1 -- сообщение слишком длинное.
int oaep_encrypt(const PublicKey& pub, const uint8_t* msg, size_t msg_len,
                 const uint8_t* label, size_t label_len, uint8_t ct[oaep::K]);

// Для тестов: шифрование с заданным seed.
int oaep_encrypt_with_seed(const PublicKey& pub, const uint8_t* msg, size_t msg_len,
                           const uint8_t* label, size_t label_len,
                           const uint8_t seed[oaep::HLEN], uint8_t ct[oaep::K]);

// Шифрование уже готового блока EM (нужно для тестов "битых" EM).
void rsa_encrypt_em(const PublicKey& pub, const uint8_t em[oaep::K], uint8_t ct[oaep::K]);

// out -- буфер минимум oaep::MAX_MSG байт. Возврат: 0 -- ок, -1 -- любая ошибка.
int oaep_decrypt(const PrivateKey& priv, const uint8_t ct[oaep::K],
                 const uint8_t* label, size_t label_len,
                 uint8_t* out, size_t* out_len);

}  // namespace rsa
