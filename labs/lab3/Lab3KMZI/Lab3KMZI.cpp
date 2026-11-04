#include "Curves.h"
#include "CryptoProtocols.h"
#include <iostream>
#include <iomanip>

using u64 = Curves::u64;
using Point = Curves::Point;

// Вспомогательная функция для красивого вывода точки
void printPoint(const std::string& label, const Point& P) {
    std::cout << label << " = ";
    if (P.infinity) {
        std::cout << "O (infinity)\n";
    }
    else {
        std::cout << "(" << P.x << ", " << P.y << ")\n";
    }
}

int main() {
    setlocale(LC_ALL, "Russian");

    // 1. Инициализация кривой (y² = x³ + 2x + 3 mod 97, q=5)
    Curves E(97, 2, 3, 3, 6, 5);
    CryptoProtocols proto(E);

    std::cout << "[Параметры кривой]\n";
    std::cout << "p = " << E.p() << ", a = " << E.a() << ", b = " << E.b()
        << ", q = " << E.q() << "\n";
    printPoint("G", E.G());
    std::cout << "Инварианты (p!=0, неособая, G на кривой, q*G=O): "
        << (E.validateInvariants() ? "OK" : "FAIL") << "\n\n";

    // 2. Генерация ключей для Алисы и Боба
    std::cout << "[Генерация ключей]\n";
    auto alice = proto.generateKeyPair();
    auto bob = proto.generateKeyPair();

    std::cout << "Alice (d, Q):\n";
    std::cout << "  d = " << alice.d << "\n";
    printPoint("  Q", alice.Q);

    std::cout << "Bob (d, Q):\n";
    std::cout << "  d = " << bob.d << "\n";
    printPoint("  Q", bob.Q);

    // Проверка валидности ключей
    bool aliceValid = proto.isValidPrivateKey(alice.d) && E.isOnCurve(alice.Q);
    bool bobValid = proto.isValidPrivateKey(bob.d) && E.isOnCurve(bob.Q);
    std::cout << "Валидация ключей: Alice=" << (aliceValid ? "OK" : "FAIL")
        << ", Bob=" << (bobValid ? "OK" : "FAIL") << "\n\n";

    // 3. ECDH
    std::cout << "[ECDH: Выработка общего секрета]\n";
    u64 secretA = proto.ecdhSharedSecret(alice.d, bob.Q);
    u64 secretB = proto.ecdhSharedSecret(bob.d, alice.Q);
    std::cout << "Alice secret: " << secretA << "\n";
    std::cout << "Bob secret:   " << secretB << "\n";
    std::cout << "Секреты совпадают: " << (secretA == secretB ? "YES" : "NO") << "\n\n";

    // 4. Подпись ГОСТ Р 34.10-2012 и проверка
    std::cout << "[ЭЦП ГОСТ Р 34.10-2012]\n";
    u64 hash_e = 0xABCDEF % E.q(); // Имитация хэша
    std::cout << "Хэш (e) = " << hash_e << "\n";

    auto sig = proto.sign(alice.d, alice.Q, hash_e);
    std::cout << "Подпись: r = " << sig.r << ", s = " << sig.s << "\n";

    bool verifyOk = proto.verify(alice.Q, hash_e, sig);
    std::cout << "Проверка подписи (валидная): " << (verifyOk ? "OK" : "FAIL") << "\n";

    // Проверка с неверным хэшем
    bool verifyBadHash = proto.verify(alice.Q, (hash_e + 1) % E.q(), sig);
    std::cout << "Проверка подписи (изменен хэш): " << (verifyBadHash ? "FAIL (плохо)" : "OK (отклонено)") << "\n";

    // Проверка с подделанной подписью
    CryptoProtocols::Signature fakeSig = { sig.r, (sig.s + 1) % E.q() };
    bool verifyFake = proto.verify(alice.Q, hash_e, fakeSig);
    std::cout << "Проверка подписи (подделана s): " << (verifyFake ? "FAIL (плохо)" : "OK (отклонено)") << "\n\n";

    // 5. Защита от Fault Injection
    std::cout << "[Защита от Fault Injection]\n";
    std::cout << "1. Пробуем подписать с неверным публичным ключом Q_pub.\n";
    Point badQ = alice.Q;
    badQ.x ^= 1; // "Инъекция ошибки" в координату x

    try {
        proto.sign(alice.d, badQ, hash_e);
        std::cout << "   Результат: FAIL (защита не сработала!)\n";
    }
    catch (const std::exception& e) {
        std::cout << "   Результат: OK (защита сработала: " << e.what() << ")\n";
    }

    std::cout << "2. Пробуем подписать с ключом, вышедшим за диапазон (d = q).\n";
    try {
        proto.sign(E.q(), alice.Q, hash_e);
        std::cout << "   Результат: FAIL (защита не сработала!)\n";
    }
    catch (const std::exception& e) {
        std::cout << "   Результат: OK (защита сработала: " << e.what() << ")\n";
    }

    std::cout << "\nВсе проверки завершены.\n";
    return 0;
}
