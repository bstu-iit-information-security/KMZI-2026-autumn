#include "rsa_lab.h"

#include <iomanip>
#include <iostream>
#include <string>

void printHex(const RSABytes& data) {
    for (Byte byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(byte);
    }
    std::cout << std::dec << '\n';
}

int main() {
    std::cout << "RSA-4096, variant 6\n";
    std::cout << "Generating keys...\n";
    RSAKey key = generateRSAKey();

    std::string text = "Hello RSA!";
    std::vector<Byte> message(text.begin(), text.end());
    std::cout << "Original: " << text << "\n\n";

    // 1. OAEP prepares the message for RSA.
    RSABytes encoded{};
    if (!oaepEncode(message, encoded)) {
        std::cout << "OAEP encoding error\n";
        return 1;
    }

    // 2. RSA encryption: c = m^e mod N.
    BigInt m = bytesToBigInt(encoded.data(), encoded.size());
    BigInt c = rsaEncrypt(m, key);
    RSABytes cipher = bigIntToBytes(c);

    std::cout << "Encrypted (HEX):\n";
    printHex(cipher);

    // 3. RSA-CRT decryption + variant 6 check: m^e mod N == c.
    BigInt decryptedNumber;
    if (!rsaDecryptCRT(c, key, decryptedNumber)) {
        std::cout << "Fault Injection detected\n";
        return 1;
    }

    // 4. Remove OAEP and restore the text.
    RSABytes decryptedBlock = bigIntToBytes(decryptedNumber);
    std::vector<Byte> decryptedMessage;
    if (!oaepDecode(decryptedBlock, decryptedMessage)) {
        std::cout << "OAEP decoding error\n";
        return 1;
    }

    std::string result(decryptedMessage.begin(), decryptedMessage.end());
    std::cout << "\nDecrypted: " << result << '\n';

    // Small demonstration of the individual task.
    BigInt damagedResult;
    bool faultPassed = rsaDecryptCRT(c, key, damagedResult, true);
    std::cout << "Fault test: "
              << (faultPassed ? "ERROR" : "fault was blocked") << '\n';

    return 0;
}
