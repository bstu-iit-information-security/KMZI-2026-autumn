class RSA_OAEP {
private:
    static constexpr size_t k = 384;
    static constexpr size_t hLen = 32;
    static constexpr size_t maxMsgLen = k - 2 * hLen - 2;

    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
        return std::vector<uint8_t>(hLen, 0xAA);
    }

    static std::vector<uint8_t> MGF1(const std::vector<uint8_t>& seed, size_t maskLen) {
        std::vector<uint8_t> mask;
        mask.reserve(maskLen + hLen);
        uint32_t counter = 0;
        
        while (mask.size() < maskLen) {
            std::vector<uint8_t> C(4);
            C[0] = (counter >> 24) & 0xFF;
            C[1] = (counter >> 16) & 0xFF;
            C[2] = (counter >> 8) & 0xFF;
            C[3] = counter & 0xFF;
            
            std::vector<uint8_t> Z = seed;
            Z.insert(Z.end(), C.begin(), C.end());
            
            std::vector<uint8_t> hash = sha256(Z);
            mask.insert(mask.end(), hash.begin(), hash.end());
            counter++;
        }
        mask.resize(maskLen);
        return mask;
    }

    static void xorArrays(std::vector<uint8_t>& dest, const std::vector<uint8_t>& src) {
        for (size_t i = 0; i < dest.size(); ++i) dest[i] ^= src[i];
    }

public:
    static std::vector<uint8_t> encodeOAEP(const std::vector<uint8_t>& M) {
        if (M.size() > maxMsgLen) throw std::runtime_error("Message too long");

        std::vector<uint8_t> lHash = sha256({});
        size_t psLen = k - M.size() - 2 * hLen - 2;
        
        std::vector<uint8_t> DB = lHash;
        DB.insert(DB.end(), psLen, 0x00);
        DB.push_back(0x01);
        DB.insert(DB.end(), M.begin(), M.end());

        std::vector<uint8_t> seed(hLen, 0xBB);
        
        std::vector<uint8_t> dbMask = MGF1(seed, k - hLen - 1);
        std::vector<uint8_t> maskedDB = DB;
        xorArrays(maskedDB, dbMask);

        std::vector<uint8_t> seedMask = MGF1(maskedDB, hLen);
        std::vector<uint8_t> maskedSeed = seed;
        xorArrays(maskedSeed, seedMask);

        std::vector<uint8_t> EM;
        EM.reserve(k);
        EM.push_back(0x00);
        EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
        EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());

        return EM;
    }

    static std::vector<uint8_t> decodeOAEP(const std::vector<uint8_t>& EM) {
        if (EM.size() != k || EM[0] != 0x00) {
            throw std::runtime_error("Ошибка деинкапсуляции: неверный размер или первый байт");
        }

        std::vector<uint8_t> maskedSeed(EM.begin() + 1, EM.begin() + 1 + hLen);
        std::vector<uint8_t> maskedDB(EM.begin() + 1 + hLen, EM.end());

        std::vector<uint8_t> seedMask = MGF1(maskedDB, hLen);
        std::vector<uint8_t> seed = maskedSeed;
        xorArrays(seed, seedMask);

        std::vector<uint8_t> dbMask = MGF1(seed, k - hLen - 1);
        std::vector<uint8_t> DB = maskedDB;
        xorArrays(DB, dbMask);

        size_t separator_index = 0;
        for (size_t i = hLen; i < DB.size(); ++i) {
            if (DB[i] == 0x01) {
                separator_index = i;
                break;
            }
        }

        if (separator_index == 0) throw std::runtime_error("Разделитель 0x01 не найден");
        return std::vector<uint8_t>(DB.begin() + separator_index + 1, DB.end());
    }
};