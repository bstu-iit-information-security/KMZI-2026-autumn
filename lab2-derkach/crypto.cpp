#include "common.hpp"


namespace rsa
{
	namespace
	{

		const unsigned kSmallPrimes[] = {
			 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
			 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
			 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
			 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389,
			 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
			 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631,
			 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757,
			 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883,
			 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997};

		bool trial_division(const BigInt &n)
		{
			for (unsigned p : kSmallPrimes)
			{
				BigInt pr(p);
				if (n.cmp(pr) == 0)
				{
					return true;
				}
				if (n.mod(pr).is_zero())
				{
					return false;
				}
			}
			return true;
		}

	} 

	bool random_bytes(uint8_t *buf, std::size_t n)
	{
		if (n == 0)
		{
			return true;
		}
		return RAND_bytes(buf, static_cast<int>(n)) == 1;
	}

	BigInt gcd(const BigInt &a, const BigInt &b)
	{
		BigInt x = a;
		BigInt y = b;
		while (!y.is_zero())
		{
			BigInt t = y;
			y = x.mod(y);
			x = t;
		}
		return x;
	}

	void egcd(const BigInt &a, const BigInt &b, BigInt &g, BigInt &x, BigInt &y)
	{
		BigInt old_r = a;
		BigInt r = b;
		BigInt old_s(1);
		BigInt s(0);
		BigInt old_t(0);
		BigInt t(1);

		while (!r.is_zero())
		{
			BigInt q = old_r.div(r);
			BigInt tmp = r;
			r = old_r.sub(q.mul(r));
			old_r = tmp;

			tmp = s;
			s = old_s.sub(q.mul(s));
			old_s = tmp;

			tmp = t;
			t = old_t.sub(q.mul(t));
			old_t = tmp;
		}
		g = old_r;
		x = old_s;
		y = old_t;
	}

	BigInt mod_inverse(const BigInt &a, const BigInt &m)
	{
		BigInt g, x, y;
		egcd(a, m, g, x, y);
		if (g.cmp(BigInt(1)) != 0)
		{
			throw BnError("modular inverse does not exist");
		}
		return x.mod(m);
	}

	BigInt lcm(const BigInt &a, const BigInt &b)
	{
		if (a.is_zero() || b.is_zero())
		{
			return BigInt(0);
		}
		return a.div(gcd(a, b)).mul(b);
	}

	BigInt mod_exp_binary(const BigInt &base, const BigInt &exp, const BigInt &mod)
	{
		BigInt result(1);
		BigInt cur = base.mod(mod);
		const int bits = exp.bit_length();
		for (int i = 0; i < bits; ++i)
		{
			if (exp.bit_set(i))
			{
				result = result.mod_mul(cur, mod);
			}
			cur = cur.mod_mul(cur, mod);
		}
		return result;
	}

	BigInt mod_exp(const BigInt &base, const BigInt &exp, const BigInt &mod)
	{
		thread_local BN_CTX *c = BN_CTX_new();
		if (!c)
		{
			throw BnError("BN_CTX_new failed");
		}
		BigInt r;
		if (BN_mod_exp(r.raw(), base.raw(), exp.raw(), mod.raw(), c) != 1)
		{
			throw BnError("BN_mod_exp failed");
		}
		return r;
	}

	bool miller_rabin(const BigInt &n, int rounds)
	{
		if (n.cmp(BigInt(2)) < 0)
		{
			return false;
		}
		if (n.cmp(BigInt(2)) == 0)
		{
			return true;
		}
		if (!n.is_odd())
		{
			return false;
		}
		if (!trial_division(n))
		{
			return false;
		}

		BigInt n_minus_1 = n.sub(BigInt(1));
		BigInt d = n_minus_1;
		int s = 0;
		while (!d.is_odd())
		{
			d = d.div(BigInt(2));
			++s;
		}

		BigInt two(2);
		for (int round = 0; round < rounds; ++round)
		{
			BigInt a = BigInt::random_bits(n.bit_length(), false);
			a = a.mod(n.sub(BigInt(3))).add(two);
			BigInt x = mod_exp(a, d, n);
			if (x.cmp(BigInt(1)) == 0 || x.cmp(n_minus_1) == 0)
			{
				continue;
			}
			bool witness = true;
			for (int j = 1; j < s; ++j)
			{
				x = x.mod_mul(x, n);
				if (x.cmp(n_minus_1) == 0)
				{
					witness = false;
					break;
				}
			}
			if (witness)
			{
				return false;
			}
		}
		return true;
	}

	BigInt generate_prime(int bits, ProgressFn progress)
	{
		int attempts = 0;
		for (;;)
		{
			BigInt cand = BigInt::random_bits(bits, true);
			++attempts;
			if (progress && (attempts % 64 == 0))
			{
				progress("prime search: testing candidate");
			}
			if (!trial_division(cand))
			{
				continue;
			}
			if (miller_rabin(cand, kMillerRabinRounds))
			{
				return cand;
			}
		}
	}

	KeyPair generate_keypair(int bits, ProgressFn progress)
	{
		if (bits < 16 || (bits % 2) != 0)
		{
			throw BnError("modulus bit length must be even and >= 16");
		}
		const int pbits = bits / 2;
		KeyPair kp;
		kp.e = BigInt(static_cast<unsigned long>(kPublicExponent));

		for (;;)
		{
			if (progress)
			{
				progress("generating prime p");
			}
			kp.p = generate_prime(pbits, progress);
			if (progress)
			{
				progress("generating prime q");
			}
			kp.q = generate_prime(pbits, progress);
			if (kp.p.cmp(kp.q) == 0)
			{
				continue;
			}
			if (kp.p.cmp(kp.q) < 0)
			{
				std::swap(kp.p, kp.q);
			}

			BigInt pm1 = kp.p.sub(BigInt(1));
			BigInt qm1 = kp.q.sub(BigInt(1));
			kp.lambda = lcm(pm1, qm1);
			if (gcd(kp.e, kp.lambda).cmp(BigInt(1)) != 0)
			{
				continue;
			}

			kp.n = kp.p.mul(kp.q);
			if (kp.n.bit_length() != bits)
			{
				continue;
			}
			kp.d = mod_inverse(kp.e, kp.lambda);
			kp.dp = kp.d.mod(pm1);
			kp.dq = kp.d.mod(qm1);
			kp.qinv = mod_inverse(kp.q, kp.p);
			return kp;
		}
	}

	 

	BigInt rsa_encrypt_raw(const BigInt &m, const KeyPair &kp)
	{
		if (m.cmp(kp.n) >= 0)
		{
			throw BnError("message representative >= modulus");
		}
		return mod_exp(m, kp.e, kp.n);
	}

	BigInt rsa_decrypt_crt(const BigInt &c, const KeyPair &kp)
	{
		if (c.cmp(kp.n) >= 0)
		{
			throw BnError("ciphertext representative >= modulus");
		}
		BigInt m1 = mod_exp(c, kp.dp, kp.p);
		BigInt m2 = mod_exp(c, kp.dq, kp.q);
		BigInt h = kp.qinv.mod_mul(m1.mod_sub(m2, kp.p), kp.p);
		return m2.add(h.mul(kp.q));
	}

	GarnerDemo garner_demo_small()
	{
		GarnerDemo d;
		d.p = BigInt(61);
		d.q = BigInt(53);
		d.n = d.p.mul(d.q);
		d.e = BigInt(17);
		BigInt lambda = lcm(d.p.sub(BigInt(1)), d.q.sub(BigInt(1)));
		d.d = mod_inverse(d.e, lambda);
		d.dp = d.d.mod(d.p.sub(BigInt(1)));
		d.dq = d.d.mod(d.q.sub(BigInt(1)));
		d.qinv = mod_inverse(d.q, d.p);
		d.m = BigInt(65);
		d.c = mod_exp_binary(d.m, d.e, d.n);

		KeyPair kp;
		kp.n = d.n;
		kp.e = d.e;
		kp.d = d.d;
		kp.p = d.p;
		kp.q = d.q;
		kp.dp = d.dp;
		kp.dq = d.dq;
		kp.qinv = d.qinv;
		d.m1 = mod_exp_binary(d.c, d.dp, d.p);
		d.m2 = mod_exp_binary(d.c, d.dq, d.q);
		d.h = d.qinv.mod_mul(d.m1.mod_sub(d.m2, d.p), d.p);
		d.recovered = d.m2.add(d.h.mul(d.q));
		return d;
	}

	 
	namespace
	{

		constexpr std::size_t kDbLen = kModulusBytes - kHashLen - 1;

	} 

	void OaepEngine::hash(const uint8_t *data, std::size_t len, uint8_t out[kHashLen])
	{
		sha256(data, len, out);
	}

	void OaepEngine::mgf1(const uint8_t *seed, std::size_t seed_len, uint8_t *mask, std::size_t mask_len)
	{
		std::size_t offset = 0;
		uint32_t counter = 0;
		while (offset < mask_len)
		{
			std::memcpy(mgf_block_, seed, seed_len);
			mgf_block_[seed_len] = static_cast<uint8_t>(counter >> 24);
			mgf_block_[seed_len + 1] = static_cast<uint8_t>(counter >> 16);
			mgf_block_[seed_len + 2] = static_cast<uint8_t>(counter >> 8);
			mgf_block_[seed_len + 3] = static_cast<uint8_t>(counter);
			hash(mgf_block_, seed_len + 4, mgf_hash_);
			std::size_t take = kHashLen;
			if (take > mask_len - offset)
			{
				take = mask_len - offset;
			}
			std::memcpy(mask + offset, mgf_hash_, take);
			offset += take;
			++counter;
		}
	}

	uint8_t OaepEngine::lhash_xor_accum(const uint8_t *a, const uint8_t *b)
	{
		return ct::xor_accum(a, b, kHashLen);
	}

	bool OaepEngine::encode(const uint8_t *msg, std::size_t msg_len, uint8_t em[kModulusBytes])
	{
		if (msg_len > kMaxMessage)
		{
			return false;
		}

		const uint8_t empty_label = 0;
		hash(&empty_label, 0, lhash_);

		std::memset(db_, 0, kDbLen);
		std::memcpy(db_, lhash_, kHashLen);
		const std::size_t ps_len = kDbLen - kHashLen - 1 - msg_len;
		db_[kHashLen + ps_len] = 0x01;
		if (msg_len != 0)
		{
			std::memcpy(db_ + kHashLen + ps_len + 1, msg, msg_len);
		}

		if (!random_bytes(seed_, kHashLen))
		{
			return false;
		}

		mgf1(seed_, kHashLen, db_mask_, kDbLen);
		for (std::size_t i = 0; i < kDbLen; ++i)
		{
			masked_db_[i] = static_cast<uint8_t>(db_[i] ^ db_mask_[i]);
		}
		mgf1(masked_db_, kDbLen, seed_mask_, kHashLen);
		for (std::size_t i = 0; i < kHashLen; ++i)
		{
			seed_[i] = static_cast<uint8_t>(seed_[i] ^ seed_mask_[i]);
		}

		em[0] = 0x00;
		std::memcpy(em + 1, seed_, kHashLen);
		std::memcpy(em + 1 + kHashLen, masked_db_, kDbLen);
		return true;
	}

	OaepResult OaepEngine::decode(const uint8_t em[kModulusBytes])
	{
		OaepResult r{};
		r.ok = false;
		r.len = 0;
		std::memset(r.msg, 0, sizeof(r.msg));

		const uint8_t empty_label = 0;
		hash(&empty_label, 0, lhash_);

		const uint8_t *masked_seed = em + 1;
		const uint8_t *masked_db = em + 1 + kHashLen;
		std::memcpy(masked_db_, masked_db, kDbLen);

		mgf1(masked_db_, kDbLen, seed_mask_, kHashLen);
		for (std::size_t i = 0; i < kHashLen; ++i)
		{
			seed_[i] = static_cast<uint8_t>(masked_seed[i] ^ seed_mask_[i]);
		}
		mgf1(seed_, kHashLen, db_mask_, kDbLen);
		for (std::size_t i = 0; i < kDbLen; ++i)
		{
			db_[i] = static_cast<uint8_t>(masked_db_[i] ^ db_mask_[i]);
		}

		uint32_t good = ct::eq_u8(em[0], 0x00);

		const uint8_t hash_diff = lhash_xor_accum(db_, lhash_);
		good &= ct::eq_u8(hash_diff, 0);

		uint32_t still_ps = 0xffffffffu;
		uint32_t found_one = 0;
		uint32_t one_pos = 0;
		uint32_t ps_ok = 0xffffffffu;

		for (std::size_t i = kHashLen; i < kDbLen; ++i)
		{
			const uint32_t is_zero = ct::eq_u8(db_[i], 0x00);
			const uint32_t is_one = ct::eq_u8(db_[i], 0x01);
			const uint32_t invalid = still_ps & ~is_zero & ~is_one;
			ps_ok &= ~invalid;
			const uint32_t take = still_ps & is_one;
			one_pos = ct::select(take, static_cast<uint32_t>(i), one_pos);
			found_one |= take;
			still_ps &= ~is_one;
		}
		good &= ps_ok;
		good &= found_one;

		const uint32_t mlen = static_cast<uint32_t>(kDbLen) - one_pos - 1u;

		for (std::size_t j = 0; j < kMaxMessage; ++j)
		{
			uint8_t v = 0;
			const uint32_t src = one_pos + 1u + static_cast<uint32_t>(j);
			for (std::size_t i = kHashLen; i < kDbLen; ++i)
			{
				const uint32_t match = ct::eq(static_cast<uint32_t>(i), src);
				v = static_cast<uint8_t>(v | (match & db_[i]));
			}
			const uint32_t in_range = ct::lt(static_cast<uint32_t>(j), mlen);
			r.msg[j] = ct::select_u8(in_range & good, v, 0);
		}

		r.len = ct::select(good, mlen, 0);
		r.ok = good == 0xffffffffu;
		return r;
	}

	bool rsa_oaep_encrypt(const uint8_t *msg, std::size_t msg_len, const KeyPair &kp,
								 uint8_t ct[kModulusBytes])
	{
		OaepEngine eng;
		uint8_t em[kModulusBytes];
		if (!eng.encode(msg, msg_len, em))
		{
			return false;
		}
		BigInt m = BigInt::from_bytes_be(em, kModulusBytes);
		BigInt c = rsa_encrypt_raw(m, kp);
		c.to_bytes_be(ct, kModulusBytes);
		return true;
	}

	OaepResult rsa_oaep_decrypt(const uint8_t ct[kModulusBytes], const KeyPair &kp)
	{
		BigInt c = BigInt::from_bytes_be(ct, kModulusBytes);
		BigInt m = rsa_decrypt_crt(c, kp);
		uint8_t em[kModulusBytes];
		m.to_bytes_be(em, kModulusBytes);
		OaepEngine eng;
		return eng.decode(em);
	}

}  