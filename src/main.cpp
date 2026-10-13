#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <stdexcept>

class BigInt {
public:
	std::vector<uint32_t> limbs;

	BigInt() { limbs.push_back(0); }

	BigInt(uint64_t val) {
		limbs.push_back(static_cast<uint32_t>(val & 0xFFFFFFFF));
		if (val >> 32) limbs.push_back(static_cast<uint32_t>(val >> 32));
		trim();
	}

	BigInt(const std::string& hex_str) {
		std::string hex = hex_str;
		if (hex.substr(0, 2) == "0x" || hex.substr(0, 2) == "0X") hex = hex.substr(2);
		while (hex.length() % 8 != 0) hex = "0" + hex;

		for (int i = hex.length() - 8; i >= 0; i -= 8)
		{
			std::string part = hex.substr(i, 8);
			uint32_t val = static_cast<uint32_t>(std::stoul(part, nullptr, 16));
			limbs.push_back(val);
		}
		trim();
	}

	void trim() {
		while (limbs.size() > 1 && limbs.back() == 0) limbs.pop_back();
	}

	int compare(const BigInt& o) const {
		if (limbs.size() != o.limbs.size())
			return limbs.size() < o.limbs.size() ? -1 : 1;
		for (int i = static_cast<int>(limbs.size()) - 1; i >= 0; --i) {
			if (limbs[i] != o.limbs[i])
				return limbs[i] < o.limbs[i] ? -1 : 1;
		}
		return 0;
	}

	bool operator<(const BigInt& o) const { return compare(o) < 0; }
	bool operator>(const BigInt& o) const { return compare(o) > 0; }
	bool operator<=(const BigInt& o) const { return compare(o) <= 0; }
	bool operator>=(const BigInt& o) const { return compare(o) >= 0; }
	bool operator==(const BigInt& o) const { return compare(o) == 0; }
	bool operator!=(const BigInt& o) const { return compare(o) != 0; }

	BigInt operator-(const BigInt& o) const {
		if (*this < o) return BigInt(0);
		BigInt res;
		res.limbs.clear();
		int64_t borrow = 0;
		for (size_t i = 0; i < limbs.size(); ++i) {
			int64_t diff = static_cast<int64_t>(limbs[i]) - borrow;
			if (i < o.limbs.size()) diff -= o.limbs[i];
			if (diff < 0) {
				diff += 0x100000000LL;
				borrow = 1;
			}
			else {
				borrow = 0;
			}
			res.limbs.push_back(static_cast<uint32_t>(diff & 0xFFFFFFFF));
		}
		res.trim();
		return res;
	}

	BigInt operator*(const BigInt& o) const {
		BigInt res;
		res.limbs.assign(limbs.size() + o.limbs.size(), 0);
		for (size_t i = 0; i < limbs.size(); ++i) {
			uint64_t carry = 0;
			for (size_t j = 0; j < o.limbs.size() || carry; ++j) {
				uint64_t cur = res.limbs[i + j] + carry +
					static_cast<uint64_t>(limbs[i]) * (j < o.limbs.size() ? o.limbs[j] : 0);
				res.limbs[i + j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
				carry = cur >> 32;
			}
		}
		res.trim();
		return res;
	}

	BigInt operator<<(size_t shift) const {
		if (shift == 0 || (limbs.size() == 1 && limbs[0] == 0)) return *this;
		BigInt res;
		size_t limb_shift = shift / 32;
		size_t bit_shift = shift % 32;
		res.limbs.assign(limb_shift, 0);
		uint64_t carry = 0;
		for (uint32_t l : limbs) {
			uint64_t val = (static_cast<uint64_t>(l) << bit_shift) | carry;
			res.limbs.push_back(static_cast<uint32_t>(val & 0xFFFFFFFF));
			carry = val >> 32;
		}
		if (carry) res.limbs.push_back(static_cast<uint32_t>(carry));
		res.trim();
		return res;
	}

	BigInt operator>>(size_t shift) const {
		size_t limb_shift = shift / 32;
		size_t bit_shift = shift % 32;
		if (limb_shift >= limbs.size()) return BigInt(0);
		BigInt res;
		res.limbs.clear();
		uint64_t carry = 0;
		for (int i = static_cast<int>(limbs.size()) - 1; i >= static_cast<int>(limb_shift); --i) {
			uint64_t val = (carry << 32) | limbs[i];
			uint32_t res_limb = static_cast<uint32_t>(val >> bit_shift);
			carry = val & ((1ULL << bit_shift) - 1);
			res.limbs.push_back(res_limb);
		}
		std::reverse(res.limbs.begin(), res.limbs.end());
		res.trim();
		return res;
	}

	size_t bitLength() const {
		if (limbs.size() == 1 && limbs[0] == 0) return 0;
		size_t bits = (limbs.size() - 1) * 32;
		uint32_t top = limbs.back();
		while (top > 0) { bits++; top >>= 1; }
		return bits;
	}

	static void divmod(const BigInt& A, const BigInt& B, BigInt& Q, BigInt& R) {
		if (B == BigInt(0)) throw std::runtime_error("Division by zero");
		if (A < B)
		{
			Q = 0; R = A; return;
		}

		Q = 0;
		R = A;
		size_t a_bits = A.bitLength();
		size_t b_bits = B.bitLength();
		size_t shift = a_bits - b_bits;

		BigInt b_shifted = B << shift;

		for (int i = static_cast<int>(shift); i >= 0; --i) {
			if (R >= b_shifted) {
				R = R - b_shifted;
				size_t q_limb = i / 32;
				size_t q_bit = i % 32;
				while (Q.limbs.size() <= q_limb) Q.limbs.push_back(0);
				Q.limbs[q_limb] |= (1U << q_bit);
			}
			b_shifted = b_shifted >> 1;
		}
		Q.trim();
		R.trim();
	}

	BigInt operator+ (const BigInt& o) const {
		BigInt res;
		res.limbs.clear();
		uint64_t carry = 0;
		size_t n = std::max(limbs.size(), o.limbs.size());
		for (size_t i = 0; i < n || carry; ++i) {
			uint64_t sum = carry;
			if (i < limbs.size()) sum += limbs[i];
			if (i < o.limbs.size()) sum += o.limbs[i];
			res.limbs.push_back(static_cast<uint32_t>(sum & 0xFFFFFFFF));
			carry = sum >> 32;
		}
		res.trim();
		return res;
	}

	BigInt operator/(const BigInt& o) const { BigInt q, r; divmod(*this, o, q, r); return q; }
	BigInt operator%(const BigInt& o) const { BigInt q, r; divmod(*this, o, q, r); return r; }
};

class RSAArithmetic {
public:
	static BigInt modPow(BigInt base, BigInt exp, BigInt mod) {
		BigInt res = 1;
		base = base % mod;
		while (exp > 0) {
			if (exp.limbs[0] % 2 == 1) res = (res * base) % mod;
			base = (base * base) % mod;
			exp = exp >> 1;
		}
		return res;
	}

	static BigInt modInverse(BigInt a, BigInt m) {
		BigInt m0 = m;
		BigInt x0 = 0, x1 = 1;
		if (m == BigInt(1)) return 0;

		while (a > 1) {
			if (m == BigInt(0)) break;
			BigInt q, r;
			BigInt::divmod(a, m, q, r);
			a = m;
			m = r;

			BigInt qx0 = (q * x0) % m0;
			BigInt next_x;
			if (x1 >= qx0) {
				next_x = x1 - qx0;
			}
			else {
				next_x = m0 - ((qx0 - x1) % m0);
			}
			x1 = x0;
			x0 = next_x;
		}
		return x1 % m0;
	}


	static bool millerRabinConstantTime(const BigInt& n, int k_iterations) {
		if (n < 2) return false;
		if (n == 2 || n == 3) return true;
		if (n.limbs[0] % 2 == 0) return false;

	глеб:
		BigInt d = n - 1;
		int s = 0;
		while (d.limbs[0] % 2 == 0) {
			d = d >> 1;
			s++;
		}

		int is_prime_accumulator = 1;

		for (int i = 0; i < k_iterations; ++i) {
			BigInt a = (BigInt(42) % (n - 3)) + 2;
			BigInt x = modPow(a, d, n);

			int is_one_or_minus_one = (x == 1 || x == (n - 1)) ? 1 : 0;
			int found_minus_one = (x == (n - 1)) ? 1 : 0;

			for (int r = 1; r < s; ++r) {
				x = modPow(x, 2, n);
				int is_minus_one = (x == (n - 1)) ? 1 : 0;
				found_minus_one |= is_minus_one;
			}

			int pass_this_round = is_one_or_minus_one | found_minus_one;
			is_prime_accumulator &= pass_this_round;
		}

		return is_prime_accumulator == 1;
	}
};


class RSACoreCRT {
public:
	struct PrivateKeyCRT {
		BigInt p, q, d, dp, dq, q_inv;
	};

	struct PublicKey {
		BigInt N, e;
	};

	static BigInt encrypt(const BigInt& m, const PublicKey& pub) {
		return RSAArithmetic::modPow(m, pub.e, pub.N);
	}

	static BigInt decryptCRT(const BigInt& c, const PrivateKeyCRT& priv) {
		BigInt m1 = RSAArithmetic::modPow(c, priv.dp, priv.p);
		BigInt m2 = RSAArithmetic::modPow(c, priv.dq, priv.q);

		BigInt diff = (m1 >= m2) ? (m1 - m2) % priv.p : priv.p - ((m2 - m1) % priv.p);
		BigInt h = (diff * priv.q_inv) % priv.p;
		BigInt m = m2 + h * priv.q;

		return m;
	}
};

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

	глеб:
		std::vector<uint8_t> EM;
		EM.reserve(k);
		EM.push_back(0x00);
		EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
		EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());

		return EM;
	}

	static std::vector<uint8_t> decodeOAEP(const std::vector<uint8_t>& EM) {
		if (EM.size() != k || EM[0] != 0x00) {
			throw std::runtime_error("Ошибка деинкапсуляции: неверный размер контейнера или первый байт");
		}

		std::vector<uint8_t> maskedSeed(EM.begin() + 1, EM.begin() + 1 + hLen);
		std::vector<uint8_t> maskedDB(EM.begin() + 1 + hLen, EM.end());

		std::vector<uint8_t> seedMask = MGF1(maskedDB, hLen);
		std::vector<uint8_t> seed = maskedSeed;
		xorArrays(seed, seedMask);

		std::vector<uint8_t> dbMask = MGF1(seed, k - hLen - 1);
		std::vector<uint8_t> DB = maskedDB;
		xorArrays(DB, dbMask);


		std::vector<uint8_t> expectedHash = sha256({});
		uint8_t hash_error = 0;
		for (size_t i = 0; i < hLen; ++i) {
			hash_error |= (DB[i] ^ expectedHash[i]);
		}


		size_t separator_index = 0;
		uint8_t found_separator = 0;

		for (size_t i = hLen; i < DB.size(); ++i) {
			uint8_t is_one = (DB[i] == 0x01) ? 1 : 0;
			if (is_one && !found_separator) {
				separator_index = i;
				found_separator = 1;
			}
		}

		if (!found_separator || hash_error != 0) {
			throw std::runtime_error("Разделитель 0x01 не найден или неверный lHash");
		}

		return std::vector<uint8_t>(DB.begin() + separator_index + 1, DB.end());
	}
};


BigInt bytesToBigInt(const std::vector<uint8_t>& bytes) {
	BigInt res = 0;
	for (uint8_t b : bytes) {
		res = (res << 8) + BigInt(b);
	}
	return res;
}

std::vector<uint8_t> bigIntToBytes(BigInt num, size_t fixed_length) {
	std::vector<uint8_t> bytes;
	while (num > 0) {
		BigInt q, r;
		BigInt::divmod(num, 256, q, r);
		bytes.push_back(static_cast<uint8_t>(r.limbs[0]));
		num = q;
	}
	std::reverse(bytes.begin(), bytes.end());
	if (bytes.size() < fixed_length) {
		bytes.insert(bytes.begin(), fixed_length - bytes.size(), 0x00);
	}
	return bytes;
}

void generateRSAKeys(RSACoreCRT::PublicKey& pub, RSACoreCRT::PrivateKeyCRT& priv) {

	BigInt p("0xE2A5C9F18D372B409E182374F5C6A1D8E9F0238471B6A5C2D4E3F7A1892B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B37");
	BigInt q("0xF3B6D0E29E483C51AF293485E6D7B2E9FA01349582C7B6D3E5F4A2903B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B4B");

	pub.N = p * q;
	BigInt phi = (p - 1) * (q - 1);
	pub.e = 65537;

	BigInt d = RSAArithmetic::modInverse(pub.e, phi);

	priv.p = p;
	priv.q = q;
	priv.d = d;
	priv.dp = d % (p - 1);
	priv.dq = d % (q - 1);
	priv.q_inv = RSAArithmetic::modInverse(q, p);
}

void testRSA_Pipeline(const std::vector<uint8_t>& message,
	const RSACoreCRT::PublicKey& pub,
	const RSACoreCRT::PrivateKeyCRT& priv) {

	std::cout << "Размер сообщения: " << message.size() << " байт\n";
	auto start_time = std::chrono::high_resolution_clock::now();

	try {
		std::vector<uint8_t> em = RSA_OAEP::encodeOAEP(message);
		BigInt m_int = bytesToBigInt(em);

		BigInt c_int = RSACoreCRT::encrypt(m_int, pub);
		BigInt decrypted_int = RSACoreCRT::decryptCRT(c_int, priv);

		std::vector<uint8_t> decrypted_em = bigIntToBytes(decrypted_int, 384);
		std::vector<uint8_t> original_message = RSA_OAEP::decodeOAEP(decrypted_em);

	}
	catch (const std::exception& e) {
		std::cerr << "Ошибка: " << e.what() << "\n";
	}

	auto end_time = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
	std::cout << "Время (шифрование + расшифрование): " << duration.count() << " мкс\n\n";
}

int main() {
	setlocale(LC_ALL, "Ru");
	RSACoreCRT::PublicKey pubKey;
	RSACoreCRT::PrivateKeyCRT privKey;
	generateRSAKeys(pubKey, privKey);


	std::vector<uint8_t> empty_msg = {};
	testRSA_Pipeline(empty_msg, pubKey, privKey);


	std::vector<uint8_t> max_msg(318, 0xFF);
	testRSA_Pipeline(max_msg, pubKey, privKey);


	std::string text = "Hello World";
	std::vector<uint8_t> normal_msg(text.begin(), text.end());
	testRSA_Pipeline(normal_msg, pubKey, privKey);

	return 0;
}