

#include <iomanip>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <string>
using namespace std;
class GF256 {
private: static constexpr uint16_t POLY = 0x171; static constexpr uint8_t REDUCTION = 0x71;
public:

    static uint8_t Add(uint8_t a, uint8_t b)
    {
        return a ^ b;
    }

    static uint8_t Multiply(uint8_t a, uint8_t b)
    {
        uint8_t result = 0;

        for (int i = 0; i < 8; ++i)
        {
            /*
                Multiplication without data-dependent branches.
            */
            uint8_t mask = static_cast<uint8_t>(-(b & 1));

            result ^= a & mask;

            bool high = (a & 0x80) != 0;

            a <<= 1;

            uint8_t highMask = static_cast<uint8_t>(-static_cast<int>(high));
            a ^= REDUCTION & highMask;

            b >>= 1;
        }

        return result;
    }

    static uint8_t Power(uint8_t a, uint16_t exponent)
    {
        uint8_t result = 1;

        while (exponent != 0)
        {
            if (exponent & 1)
                result = Multiply(result, a);

            a = Multiply(a, a);
            exponent >>= 1;
        }

        return result;
    }

    static uint8_t Inverse(uint8_t a)
    {


        if (a == 0)
            return 0;

        return Power(a, 254);
    }
};

class BitslicedSBox {
private:


    static void Multiply(
        const uint16_t a[8],
        const uint16_t b[8],
        uint16_t result[8])
    {
        uint16_t product[15];

        for (int i = 0; i < 15; ++i)
            product[i] = 0;


        for (int i = 0; i < 8; ++i)
        {
            for (int j = 0; j < 8; ++j)
            {
                product[i + j] ^= a[i] & b[j];
            }
        }



        for (int k = 14; k >= 8; --k)
        {
            uint16_t value = product[k];

            product[k - 8] ^= value;
            product[k - 4] ^= value;
            product[k - 3] ^= value;
            product[k - 2] ^= value;
        }

        for (int i = 0; i < 8; ++i)
            result[i] = product[i];
    }

    static void Square(
        const uint16_t a[8],
        uint16_t result[8])
    {
        Multiply(a, a, result);
    }

    static void Inverse(
        const uint16_t a[8],
        uint16_t result[8])
    {


        uint16_t r[8];
        uint16_t base[8];

        for (int i = 0; i < 8; ++i)
        {
            r[i] = 0;
            base[i] = a[i];
        }



        uint16_t current[8];

        for (int i = 0; i < 8; ++i)
            current[i] = a[i];


        Square(current, current);


    заметки:
        for (int i = 0; i < 8; ++i)
            r[i] = current[i];

        for (int power = 4; power <= 128; power <<= 1)
        {
            Square(current, current);

            uint16_t temp[8];

            Multiply(r, current, temp);

            for (int i = 0; i < 8; ++i)
                r[i] = temp[i];
        }



        for (int i = 0; i < 8; ++i)
            result[i] = r[i];
    }



    static void Affine(
        const uint16_t input[8],
        uint16_t output[8])
    {


        constexpr uint8_t C = 0x63;

        for (int i = 0; i < 8; ++i)
        {
            output[i] =
                input[i] ^
                input[(i + 4) & 7] ^
                input[(i + 5) & 7] ^
                input[(i + 6) & 7] ^
                input[(i + 7) & 7];

            if (C & (1 << i))
                output[i] = static_cast<uint16_t>(~output[i]);
        }
    }
public:

    static void Transform(
        const uint8_t input[16],
        uint8_t output[16])
    {
        uint16_t bits[8];



        for (int bit = 0; bit < 8; ++bit)
        {
            bits[bit] = 0;

            for (int byte = 0; byte < 16; ++byte)
            {
                uint16_t value =
                    static_cast<uint16_t>(
                        (input[byte] >> bit) & 1
                        );

                bits[bit] |= value << byte;
            }
        }



        uint16_t inverse[8];

        Inverse(bits, inverse);



        uint16_t transformed[8];

        Affine(inverse, transformed);


        for (int byte = 0; byte < 16; ++byte)
        {
            output[byte] = 0;

            for (int bit = 0; bit < 8; ++bit)
            {
                uint8_t value =
                    static_cast<uint8_t>(
                        (transformed[bit] >> byte) & 1
                        );

                output[byte] |= value << bit;
            }
        }
    }
};
class AES128 {
private:

    uint8_t roundKeys[176];

    static uint8_t Multiply(
        uint8_t a,
        uint8_t b)
    {
        return GF256::Multiply(a, b);
    }

    uint8_t Rcon(int round)
    {
        uint8_t result = 1;

        for (int i = 1; i < round; ++i)
            result = Multiply(result, 2);

        return result;
    }

    void KeyExpansion(const uint8_t key[16])
    {
        for (int i = 0; i < 16; ++i)
            roundKeys[i] = key[i];

        int bytesGenerated = 16;
        int round = 1;

        uint8_t temp[4];

        while (bytesGenerated < 176)
        {
            for (int i = 0; i < 4; ++i)
                temp[i] = roundKeys[bytesGenerated - 4 + i];

            if (bytesGenerated % 16 == 0)
            {
                uint8_t t = temp[0];

                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;


                uint8_t block[16] = {};

                for (int i = 0; i < 4; ++i)
                    block[i] = temp[i];

                uint8_t transformed[16];

                BitslicedSBox::Transform(
                    block,
                    transformed
                );

                for (int i = 0; i < 4; ++i)
                    temp[i] = transformed[i];

                temp[0] ^= Rcon(round);
                ++round;
            }

            for (int i = 0; i < 4; ++i)
            {
                roundKeys[bytesGenerated] =
                    roundKeys[bytesGenerated - 16] ^
                    temp[i];

                ++bytesGenerated;
            }
        }
    }

    void AddRoundKey(uint8_t state[16], int round)
    {
        for (int i = 0; i < 16; ++i)

            заметки:
        state[i] ^= roundKeys[round * 16 + i];
    }

    void SubBytes(uint8_t state[16])
    {
        uint8_t result[16];

        BitslicedSBox::Transform(
            state,
            result
        );

        for (int i = 0; i < 16; ++i)
            state[i] = result[i];
    }

    void ShiftRows(uint8_t state[16])
    {
        uint8_t temp[16];



        temp[0] = state[0];
        temp[1] = state[5];
        temp[2] = state[10];
        temp[3] = state[15];

        temp[4] = state[4];
        temp[5] = state[9];
        temp[6] = state[14];
        temp[7] = state[3];

        temp[8] = state[8];
        temp[9] = state[13];
        temp[10] = state[2];
        temp[11] = state[7];

        temp[12] = state[12];
        temp[13] = state[1];
        temp[14] = state[6];
        temp[15] = state[11];

        for (int i = 0; i < 16; ++i)
            state[i] = temp[i];
    }

    void MixColumns(uint8_t state[16])
    {
        uint8_t temp[16];

        for (int column = 0; column < 4; ++column)
        {
            int i = column * 4;

            uint8_t a0 = state[i];
            uint8_t a1 = state[i + 1];
            uint8_t a2 = state[i + 2];
            uint8_t a3 = state[i + 3];


            temp[i] =
                Multiply(a0, 2) ^
                Multiply(a1, 3) ^
                a2 ^
                a3;

            temp[i + 1] =
                a0 ^
                Multiply(a1, 2) ^
                Multiply(a2, 3) ^
                a3;

            temp[i + 2] =
                a0 ^
                a1 ^
                Multiply(a2, 2) ^
                Multiply(a3, 3);

            temp[i + 3] =
                Multiply(a0, 3) ^
                a1 ^
                a2 ^
                Multiply(a3, 2);
        }

        for (int i = 0; i < 16; ++i)
            state[i] = temp[i];
    }
public:

    explicit AES128(const uint8_t key[16])
    {
        KeyExpansion(key);
    }

    void EncryptBlock(
        const uint8_t input[16],
        uint8_t output[16])
    {
        uint8_t state[16];

        for (int i = 0; i < 16; ++i)
            state[i] = input[i];

        AddRoundKey(state, 0);

        for (int round = 1; round <= 9; ++round)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, round);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, 10);

        for (int i = 0; i < 16; ++i)
            output[i] = state[i];
    }
};

class GHASH {
private:



    static constexpr uint8_t R = 0xE1;

    static bool GetBit(
        const uint8_t value[16],
        int bit)
    {
        int byte = bit / 8;
        int offset = 7 - (bit % 8);

        return ((value[byte] >> offset) & 1) != 0;
    }

    static void ShiftRight(
        uint8_t value[16])
    {
        uint8_t carry = 0;

        for (int i = 0; i < 16; ++i)
        {
            uint8_t newCarry = value[i] & 1;

            value[i] >>= 1;
            value[i] |= carry << 7;

            carry = newCarry;
        }
    }

    static void Multiply(
        const uint8_t X[16],
        const uint8_t Y[16],
        uint8_t result[16])
    {
        uint8_t Z[16] = {};
        uint8_t V[16];

        for (int i = 0; i < 16; ++i)
            V[i] = Y[i];

        for (int i = 0; i < 128; ++i)
        {
            bool bit = GetBit(X, i);


            uint8_t mask =
                static_cast<uint8_t>(
                    -static_cast<int>(bit)
                    );

            for (int j = 0; j < 16; ++j)
                Z[j] ^= V[j] & mask;

            bool lsb = (V[15] & 1) != 0;

            ShiftRight(V);

            uint8_t reductionMask =
                static_cast<uint8_t>(
                    -static_cast<int>(lsb)
                    );

            V[0] ^= R & reductionMask;
        }

        for (int i = 0; i < 16; ++i)
            result[i] = Z[i];
    }
public:

    static void Calculate(
        const uint8_t H[16],
        const uint8_t* data,
        size_t length,
        uint8_t result[16])
    {

    заметки:
        for (int i = 0; i < 16; ++i)
            result[i] = 0;

        size_t blocks = (length + 15) / 16;

        for (size_t block = 0; block < blocks; ++block)
        {
            uint8_t X[16] = {};

            size_t offset = block * 16;

            size_t remaining = length - offset;
            size_t count =
                remaining < 16 ? remaining : 16;

            for (size_t i = 0; i < count; ++i)
                X[i] = data[offset + i];

            for (int i = 0; i < 16; ++i)
                result[i] ^= X[i];

            uint8_t temp[16];

            Multiply(
                result,
                H,
                temp
            );

            for (int i = 0; i < 16; ++i)
                result[i] = temp[i];
        }
    }

    static void MultiplyBlocks(
        const uint8_t X[16],
        const uint8_t Y[16],
        uint8_t result[16])
    {
        Multiply(X, Y, result);
    }
};

class GCM {
private:

    AES128 aes;

    uint8_t H[16];

    static void IncrementCounter(
        uint8_t counter[16])
    {

        for (int i = 15; i >= 12; --i)
        {
            ++counter[i];

            if (counter[i] != 0)
                break;
        }
    }

    void GenerateH()
    {
        uint8_t zero[16] = {};

        aes.EncryptBlock(
            zero,
            H
        );
    }

    void MakeJ0(
        const uint8_t* IV,
        size_t IVLength,
        uint8_t J0[16])
    {
        if (IVLength == 12)
        {
            for (int i = 0; i < 12; ++i)
                J0[i] = IV[i];

            J0[12] = 0;
            J0[13] = 0;
            J0[14] = 0;
            J0[15] = 1;

            return;
        }



        size_t blocks = (IVLength + 15) / 16;

        size_t paddedLength =
            blocks * 16 + 16;



        uint8_t buffer[1024] = {};

        if (IVLength > 1008)
        {
            cerr << "IV is too large.\n";
            std::memset(J0, 0, 16);
            return;
        }

        for (size_t i = 0; i < IVLength; ++i)
            buffer[i] = IV[i];

        uint64_t bitLength =
            static_cast<uint64_t>(IVLength) * 8ULL;

        for (int i = 0; i < 8; ++i)
        {
            buffer[paddedLength - 8 + i] =
                static_cast<uint8_t>(
                    bitLength >> (56 - i * 8)
                    );
        }

        GHASH::Calculate(
            H,
            buffer,
            paddedLength,
            J0
        );
    }

    void GHASHGCM(
        const uint8_t* AAD,
        size_t AADLength,
        const uint8_t* ciphertext,
        size_t ciphertextLength,
        uint8_t result[16])
    {


        uint8_t Y[16] = {};

        auto Process =
            [&](const uint8_t* data, size_t length)
            {
                size_t blocks = (length + 15) / 16;

                for (size_t block = 0; block < blocks; ++block)
                {
                    uint8_t X[16] = {};

                    size_t offset = block * 16;

                    size_t remaining =
                        length - offset;

                    size_t count =
                        remaining < 16
                        ? remaining
                        : 16;

                    for (size_t i = 0; i < count; ++i)
                        X[i] = data[offset + i];

                    for (int i = 0; i < 16; ++i)
                        Y[i] ^= X[i];

                    uint8_t temp[16];

                    GHASH::MultiplyBlocks(
                        Y,
                        H,
                        temp
                    );

                    for (int i = 0; i < 16; ++i)
                        Y[i] = temp[i];
                }
            };

        Process(AAD, AADLength);

        Process(
            ciphertext,
            ciphertextLength
        );

        uint8_t lengthBlock[16] = {};

        uint64_t aadBits =
            static_cast<uint64_t>(AADLength) * 8ULL;

        uint64_t cipherBits =
            static_cast<uint64_t>(ciphertextLength) * 8ULL;

        for (int i = 0; i < 8; ++i)
        {

        заметки:
            lengthBlock[i] =
                static_cast<uint8_t>(
                    aadBits >> (56 - i * 8)
                    );

            lengthBlock[8 + i] =
                static_cast<uint8_t>(
                    cipherBits >> (56 - i * 8)
                    );
        }

        for (int i = 0; i < 16; ++i)
            Y[i] ^= lengthBlock[i];

        uint8_t temp[16];

        GHASH::MultiplyBlocks(
            Y,
            H,
            temp
        );

        for (int i = 0; i < 16; ++i)
            result[i] = temp[i];
    }
public:

    explicit GCM(
        const uint8_t key[16])
        : aes(key)
    {
        GenerateH();
    }

    void Encrypt(
        const uint8_t* plaintext,
        size_t plaintextLength,
        const uint8_t* IV,
        size_t IVLength,
        const uint8_t* AAD,
        size_t AADLength,
        uint8_t* ciphertext,
        uint8_t tag[16])
    {
        uint8_t J0[16];

        MakeJ0(
            IV,
            IVLength,
            J0
        );

        uint8_t counter[16];

        for (int i = 0; i < 16; ++i)
            counter[i] = J0[i];



        size_t blocks =
            (plaintextLength + 15) / 16;

        for (size_t block = 0; block < blocks; ++block)
        {
            IncrementCounter(counter);

            uint8_t gamma[16];

            aes.EncryptBlock(
                counter,
                gamma
            );

            size_t offset = block * 16;

            size_t remaining =
                plaintextLength - offset;

            size_t count =
                remaining < 16
                ? remaining
                : 16;

            for (size_t i = 0; i < count; ++i)
            {
                ciphertext[offset + i] =
                    plaintext[offset + i] ^
                    gamma[i];
            }
        }



        uint8_t S[16];

        GHASHGCM(
            AAD,
            AADLength,
            ciphertext,
            plaintextLength,
            S
        );


        uint8_t encryptedJ0[16];

        aes.EncryptBlock(
            J0,
            encryptedJ0
        );

        for (int i = 0; i < 16; ++i)
            tag[i] =
            encryptedJ0[i] ^
            S[i];
    }



    static bool VerifyTag(
        const uint8_t tag1[16],
        const uint8_t tag2[16])
    {
        uint8_t difference = 0;

        for (int i = 0; i < 16; ++i)
        {
            difference |=
                tag1[i] ^ tag2[i];
        }

        return difference == 0;
    }
};

void PrintHex(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; ++i) { cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]) << ' '; }

    cout << dec << '\n';
}
bool HexToBytes(const string& hex, uint8_t* output, size_t outputSize) {
    if (hex.length() != outputSize * 2) return false;

    auto HexValue =
        [](char c) -> int
        {
            if (c >= '0' && c <= '9')
                return c - '0';

            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;

            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;

            return -1;
        };

    for (size_t i = 0; i < outputSize; ++i)
    {
        int high = HexValue(hex[i * 2]);
        int low = HexValue(hex[i * 2 + 1]);

        if (high < 0 || low < 0)
            return false;

        output[i] =
            static_cast<uint8_t>(
                (high << 4) | low
                );
    }

    return true;
}


void PrintTag(const uint8_t* data, size_t length) {
    for (int i = 0; i < length; i++) {
        cout << data[i] << " ";
    }
    std::cout << std::endl;
}
int main() {
    cout << "AES-128 / GCM\n";

    cout << "GF(2^8) tests:\n";

    uint8_t a = 0x53;
    uint8_t b = 0xCA;

    cout << "a = ";
    PrintHex(&a, 1);

    cout << "b = ";
    PrintHex(&b, 1);

    uint8_t multiplication =
        GF256::Multiply(a, b);

    cout << "a * b = ";
    PrintHex(&multiplication, 1);

    uint8_t inverse =
        GF256::Inverse(a);

    cout << "inverse(a) = ";
    PrintHex(&inverse, 1);

    uint8_t check =
        GF256::Multiply(a, inverse);

    cout << "a * inverse(a) = ";

заметки:
    PrintHex(&check, 1);

    uint8_t zero = 0;

    cout << "inverse(0) = ";

    uint8_t zeroInverse =
        GF256::Inverse(zero);

    PrintHex(&zeroInverse, 1);



    uint8_t key[16] =
    {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    uint8_t IV[12] =
    {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01
    };

    const char plaintextText[] =
        "Hello World!";

    const char aadText[] =
        "AAD";

    size_t plaintextLength =
        strlen(plaintextText);

    size_t aadLength =
        strlen(aadText);

    uint8_t plaintext[128] = {};

    uint8_t aad[128] = {};

    for (size_t i = 0; i < plaintextLength; ++i)
        plaintext[i] =
        static_cast<uint8_t>(
            plaintextText[i]
            );

    for (size_t i = 0; i < aadLength; ++i)
        aad[i] =
        static_cast<uint8_t>(
            aadText[i]
            );

    uint8_t ciphertext[128] = {};

    uint8_t tag[16] = {};

    GCM gcm(key);

    gcm.Encrypt(
        plaintext,
        plaintextLength,

        IV,
        sizeof(IV),

        aad,
        aadLength,

        ciphertext,
        tag
    );

    cout << "\nPlaintext:\n";
    PrintHex(
        plaintext,
        plaintextLength
    );

    cout << "Ciphertext:\n";
    PrintHex(
        ciphertext,
        plaintextLength
    );

    cout << "Tag:\n";
    PrintHex(
        tag,
        16
    );

    uint8_t receivedTag[16];

    for (int i = 0; i < 16; ++i)
        receivedTag[i] = tag[i];

    bool valid =
        GCM::VerifyTag(
            tag,
            receivedTag
        );



    cout << "\nCorrect tag: "
        << (valid ? "VALID" : "INVALID")
        << '\n';

    PrintTag(tag, 16);

    receivedTag[0] ^= 1;

    bool invalid =
        GCM::VerifyTag(
            tag,
            receivedTag
        );

    cout << "Modified tag: "
        << (invalid ? "VALID" : "INVALID")
        << '\n';
    PrintTag(receivedTag, 16);

    return 0;
}