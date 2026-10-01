#include <iostream>
#include <string>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <random>
#include <cstring>

namespace RSA9 {

    static const size_t MAX_WORDS = 256;

    class BigNum {
    public:
        uint32_t words[MAX_WORDS];
        size_t len;

        BigNum() : len(1) { words[0] = 0; }

        BigNum(uint64_t v) {
            if (v == 0) { len = 1; words[0] = 0; }
            else {
                len = 0;
                words[len++] = (uint32_t)(v & 0xFFFFFFFF);
                if (v >> 32) words[len++] = (uint32_t)(v >> 32);
            }
            norm();
        }

        BigNum(const std::string& s) {
            std::string h = s;
            if (h.rfind("0x", 0) == 0 || h.rfind("0X", 0) == 0) h = h.substr(2);
            while (h.length() % 8) h = "0" + h;
            len = 0;
            for (int i = (int)h.length() - 8; i >= 0; i -= 8)
                words[len++] = (uint32_t)std::stoul(h.substr(i, 8), nullptr, 16);
            norm();
        }

        void norm() { while (len > 1 && words[len - 1] == 0) --len; }

        int cmp(const BigNum& o) const {
            if (len != o.len) return len < o.len ? -1 : 1;
            for (int i = (int)len - 1; i >= 0; --i) if (words[i] != o.words[i]) return words[i] < o.words[i] ? -1 : 1;
            return 0;
        }

        bool operator< (const BigNum& o) const { return cmp(o) < 0; }
        bool operator> (const BigNum& o) const { return cmp(o) > 0; }
        bool operator<=(const BigNum& o) const { return cmp(o) <= 0; }
        bool operator>=(const BigNum& o) const { return cmp(o) >= 0; }
        bool operator==(const BigNum& o) const { return cmp(o) == 0; }
        bool operator!=(const BigNum& o) const { return cmp(o) != 0; }

        void shr1() {
            uint32_t c = 0;
            for (int i = (int)len - 1; i >= 0; --i) {
                uint64_t t = ((uint64_t)c << 32) | words[i];
                words[i] = (uint32_t)(t >> 1);
                c = (uint32_t)(t & 1);
            }
            norm();
        }

        void subInPlace(const BigNum& o) {
            int64_t b = 0;
            for (size_t i = 0; i < len; ++i) {
                int64_t d = (int64_t)words[i] - b - (i < o.len ? o.words[i] : 0);
                if (d < 0) { d += 0x100000000LL; b = 1; }
                else b = 0;
                words[i] = (uint32_t)(d & 0xFFFFFFFF);
            }
            norm();
        }

        bool bit(size_t i) const {
            size_t w = i / 32, b = i % 32;
            if (w >= len) return false;
            return (words[w] >> b) & 1;
        }

        BigNum operator+(const BigNum& o) const {
            BigNum r;
            r.len = 0;
            uint64_t c = 0;
            size_t n = std::max(len, o.len);
            for (size_t i = 0; i < n || c; ++i) {
                uint64_t s = c + (i < len ? words[i] : 0) + (i < o.len ? o.words[i] : 0);
                r.words[r.len++] = (uint32_t)(s & 0xFFFFFFFF);
                c = s >> 32;
            }
            r.norm();
            return r;
        }

        BigNum operator-(const BigNum& o) const {
            if (*this < o) return BigNum(0);
            BigNum r = *this;
            r.subInPlace(o);
            return r;
        }

        BigNum operator*(const BigNum& o) const {
            BigNum r;
            r.len = len + o.len;
            for (size_t i = 0; i < r.len; ++i) r.words[i] = 0;
            for (size_t i = 0; i < len; ++i) {
                uint64_t c = 0;
                for (size_t j = 0; j < o.len || c; ++j) {
                    uint64_t t = r.words[i + j] + c + (uint64_t)words[i] * (j < o.len ? o.words[j] : 0);
                    r.words[i + j] = (uint32_t)(t & 0xFFFFFFFF);
                    c = t >> 32;
                }
            }
            r.norm();
            return r;
        }

        BigNum operator<<(size_t s) const {
            if (s == 0 || (len == 1 && words[0] == 0)) return *this;
            BigNum r;
            size_t ws = s / 32, bs = s % 32;
            r.len = 0;
            for (size_t i = 0; i < ws; ++i) r.words[r.len++] = 0;
            uint64_t c = 0;
            for (size_t i = 0; i < len; ++i) {
                uint64_t t = ((uint64_t)words[i] << bs) | c;
                r.words[r.len++] = (uint32_t)(t & 0xFFFFFFFF);
                c = t >> 32;
            }
            if (c) r.words[r.len++] = (uint32_t)c;
            r.norm();
            return r;
        }

        BigNum operator>>(size_t s) const {
            size_t ws = s / 32, bs = s % 32;
            if (ws >= len) return BigNum(0);
            BigNum r;
            r.len = 0;
            uint64_t c = 0;
            for (int i = (int)len - 1; i >= (int)ws; --i) {
                uint64_t t = (c << 32) | words[i];
                r.words[r.len++] = (uint32_t)(t >> bs);
                c = t & ((1ULL << bs) - 1);
            }
            std::reverse(r.words, r.words + r.len);
            r.norm();
            return r;
        }

        size_t bits() const {
            if (len == 1 && words[0] == 0) return 0;
            size_t b = (len - 1) * 32;
            uint32_t t = words[len - 1];
            while (t) { b++; t >>= 1; }
            return b;
        }

        static void divmod(const BigNum& a, const BigNum& b, BigNum& q, BigNum& r) {
            if (b == BigNum(0)) throw std::runtime_error("div by 0");
            if (a < b) { q = 0; r = a; return; }
            r = a;
            size_t sh = a.bits() - b.bits();
            BigNum sb = b << sh;
            q.len = (sh / 32) + 1;
            for (size_t i = 0; i < q.len; ++i) q.words[i] = 0;
            for (int i = (int)sh; i >= 0; --i) {
                if (r >= sb) {
                    r.subInPlace(sb);
                    q.words[i / 32] |= (1U << (i % 32));
                }
                sb.shr1();
            }
            q.norm();
            r.norm();
        }

        BigNum operator/(const BigNum& o) const { BigNum q, r; divmod(*this, o, q, r); return q; }
        BigNum operator%(const BigNum& o) const { BigNum q, r; divmod(*this, o, q, r); return r; }

        static void cmov(BigNum& d, const BigNum& s, uint32_t m) {
            size_t n = std::max(d.len, s.len);
            for (size_t i = d.len; i < n; ++i) d.words[i] = 0;
            d.len = n;
            for (size_t i = 0; i < n; ++i) {
                uint32_t x = (i < s.len) ? s.words[i] : 0;
                d.words[i] = (d.words[i] & ~m) | (x & m);
            }
            d.norm();
        }

        static uint32_t zeroMask(const BigNum& a) {
            uint32_t x = 0;
            for (size_t i = 0; i < a.len; ++i) x |= a.words[i];
            return x == 0 ? 0xFFFFFFFFu : 0u;
        }

        static uint32_t evenMask(const BigNum& a) {
            return ((a.words[0] & 1) == 0) ? 0xFFFFFFFFu : 0u;
        }
    };

    namespace CM {
        BigNum powMod(const BigNum& bIn, const BigNum& e, const BigNum& m) {
            if (m == BigNum(1)) return BigNum(0);
            BigNum r = 1, b = bIn % m;
            size_t n = e.bits();
            for (size_t i = 0; i < n; ++i) {
                if (e.bit(i)) r = (r * b) % m;
                if (i + 1 < n) b = (b * b) % m;
            }
            return r;
        }

        BigNum invMod(BigNum a, BigNum m) {
            BigNum m0 = m, x0 = 0, x1 = 1;
            if (m == BigNum(1)) return 0;
            while (a > BigNum(1)) {
                if (m == BigNum(0)) break;
                BigNum q, r;
                BigNum::divmod(a, m, q, r);
                a = m;
                m = r;
                BigNum qx0 = (q * x0) % m0;
                BigNum nx = (x1 >= qx0) ? (x1 - qx0) : (m0 - ((qx0 - x1) % m0));
                x1 = x0;
                x0 = nx;
            }
            return x1 % m0;
        }

        BigNum ctBinaryInv(BigNum a, const BigNum& mod) {
            if (mod == BigNum(1)) return BigNum(0);
            BigNum u = a % mod, v = mod, x1 = 1, x2 = 0;
            size_t N = 2 * mod.bits() + 2;
            for (size_t i = 0; i < N; ++i) {
                uint32_t ue = BigNum::evenMask(u);
                {
                    BigNum us = u; us.shr1();
                    BigNum xp = x1 + mod;
                    uint32_t xo = (x1.words[0] & 1) ? 0xFFFFFFFFu : 0u;
                    BigNum::cmov(x1, xp, ue & xo);
                    BigNum xs = x1; xs.shr1();
                    BigNum::cmov(u, us, ue);
                    BigNum::cmov(x1, xs, ue);
                }
                uint32_t ve = BigNum::evenMask(v);
                {
                    BigNum vs = v; vs.shr1();
                    BigNum xp = x2 + mod;
                    uint32_t xo = (x2.words[0] & 1) ? 0xFFFFFFFFu : 0u;
                    BigNum::cmov(x2, xp, ve & xo);
                    BigNum xs = x2; xs.shr1();
                    BigNum::cmov(v, vs, ve);
                    BigNum::cmov(x2, xs, ve);
                }
                int c = u.cmp(v);
                uint32_t ge = (c >= 0) ? 0xFFFFFFFFu : 0u;
                BigNum um = (u >= v) ? (u - v) : BigNum(0);
                BigNum vm = (v >= u) ? (v - u) : BigNum(0);
                BigNum x12 = (x1 >= x2) ? (x1 - x2) : (mod - ((x2 - x1) % mod));
                BigNum x21 = (x2 >= x1) ? (x2 - x1) : (mod - ((x1 - x2) % mod));
                BigNum::cmov(u, um, ge);
                BigNum::cmov(x1, x12, ge);
                BigNum::cmov(v, vm, ~ge);
                BigNum::cmov(x2, x21, ~ge);
                if (BigNum::zeroMask(u)) break;
            }
            return x2 % mod;
        }
    }

    namespace SHA384 {
        static const uint64_t K[80] = {
            0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
            0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
            0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
            0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
            0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
            0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
            0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
            0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
            0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
            0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
            0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
            0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
            0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
            0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
            0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
            0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
        };

        static inline uint64_t rr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

        struct Hash48 { uint8_t b[48]; };

        Hash48 hash(const uint8_t* m, size_t mlen) {
            uint64_t h[8] = {
                0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,0x9159015a3070dd17ULL,0x152fecd8f70e5939ULL,
                0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL
            };

            size_t total = mlen + 1;
            while (total % 128 != 112) total++;
            total += 16;

            uint8_t* d = new uint8_t[total];
            for (size_t i = 0; i < mlen; ++i) d[i] = m[i];
            d[mlen] = 0x80;
            for (size_t i = mlen + 1; i < total - 16; ++i) d[i] = 0;
            uint64_t bl = (uint64_t)mlen * 8;
            for (int i = 0; i < 8; ++i) d[total - 16 + i] = 0;
            for (int i = 7; i >= 0; --i) d[total - 8 + i] = (uint8_t)((bl >> ((7 - i) * 8)) & 0xFF);

            for (size_t off = 0; off < total; off += 128) {
                uint64_t w[80];
                for (int i = 0; i < 16; ++i) {
                    w[i] = 0;
                    for (int j = 0; j < 8; ++j) w[i] = (w[i] << 8) | d[off + i * 8 + j];
                }
                for (int i = 16; i < 80; ++i) {
                    uint64_t s0 = rr(w[i - 15], 1) ^ rr(w[i - 15], 8) ^ (w[i - 15] >> 7);
                    uint64_t s1 = rr(w[i - 2], 19) ^ rr(w[i - 2], 61) ^ (w[i - 2] >> 6);
                    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }
                uint64_t a = h[0], b = h[1], c = h[2], d4 = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
                for (int i = 0; i < 80; ++i) {
                    uint64_t S1 = rr(e, 14) ^ rr(e, 18) ^ rr(e, 41);
                    uint64_t ch = (e & f) ^ (~e & g);
                    uint64_t t1 = hh + S1 + ch + K[i] + w[i];
                    uint64_t S0 = rr(a, 28) ^ rr(a, 34) ^ rr(a, 39);
                    uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
                    uint64_t t2 = S0 + mj;
                    hh = g; g = f; f = e; e = d4 + t1; d4 = c; c = b; b = a; a = t1 + t2;
                }
                h[0] += a; h[1] += b; h[2] += c; h[3] += d4; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
            }

            delete[] d;

            Hash48 out;
            for (int i = 0; i < 6; ++i)
                for (int j = 0; j < 8; ++j)
                    out.b[i * 8 + j] = (uint8_t)((h[i] >> (56 - j * 8)) & 0xFF);
            return out;
        }
    }

    namespace OAEP {
        constexpr size_t RSA = 512, SH = 48, MAX = RSA - 2 * SH - 2;

        struct Buf { uint8_t b[512]; size_t n; };

        void mgf(const uint8_t* s, size_t slen, uint8_t* out, size_t n) {
            size_t pos = 0;
            uint32_t c = 0;
            uint8_t in[512 + 4];
            while (pos < n) {
                for (size_t i = 0; i < slen; ++i) in[i] = s[i];
                in[slen] = (uint8_t)((c >> 24) & 0xFF);
                in[slen + 1] = (uint8_t)((c >> 16) & 0xFF);
                in[slen + 2] = (uint8_t)((c >> 8) & 0xFF);
                in[slen + 3] = (uint8_t)(c & 0xFF);
                auto h = SHA384::hash(in, slen + 4);
                size_t take = (n - pos < 48) ? (n - pos) : 48;
                for (size_t i = 0; i < take; ++i) out[pos + i] = h.b[i];
                pos += take;
                c++;
            }
        }

        Buf pad(const uint8_t* in, size_t inlen) {
            if (inlen > MAX) throw std::runtime_error("payload too large");
            auto lh = SHA384::hash(nullptr, 0);
            size_t pl = RSA - inlen - 2 * SH - 2;

            uint8_t db[512];
            for (size_t i = 0; i < SH; ++i) db[i] = lh.b[i];
            for (size_t i = 0; i < pl; ++i) db[SH + i] = 0;
            db[SH + pl] = 1;
            for (size_t i = 0; i < inlen; ++i) db[SH + pl + 1 + i] = in[i];

            uint8_t sd[48];
            std::random_device rd;
            for (size_t i = 0; i < SH; i += 4) {
                uint32_t r = rd();
                sd[i] = r & 0xFF;
                if (i + 1 < SH) sd[i + 1] = (r >> 8) & 0xFF;
                if (i + 2 < SH) sd[i + 2] = (r >> 16) & 0xFF;
                if (i + 3 < SH) sd[i + 3] = (r >> 24) & 0xFF;
            }

            uint8_t mdb[512];
            size_t mdblen = RSA - SH - 1;
            for (size_t i = 0; i < mdblen; ++i) mdb[i] = db[i];
            mgf(sd, SH, mdb, mdblen);
            for (size_t i = 0; i < mdblen; ++i) mdb[i] ^= db[i];

            uint8_t msd[48];
            for (size_t i = 0; i < SH; ++i) msd[i] = sd[i];
            mgf(mdb, mdblen, msd, SH);
            for (size_t i = 0; i < SH; ++i) msd[i] ^= sd[i];

            Buf out;
            out.n = RSA;
            out.b[0] = 0;
            for (size_t i = 0; i < SH; ++i) out.b[1 + i] = msd[i];
            for (size_t i = 0; i < mdblen; ++i) out.b[1 + SH + i] = mdb[i];
            return out;
        }

        Buf unpad(const uint8_t* eb, size_t eblen) {
            if (eblen != RSA || eb[0] != 0) throw std::runtime_error("OAEP: bad framing");
            uint8_t msd[48], mdb[512];
            size_t mdblen = RSA - SH - 1;
            for (size_t i = 0; i < SH; ++i) msd[i] = eb[1 + i];
            for (size_t i = 0; i < mdblen; ++i) mdb[i] = eb[1 + SH + i];

            uint8_t sd[48];
            mgf(mdb, mdblen, sd, SH);
            for (size_t i = 0; i < SH; ++i) sd[i] ^= msd[i];

            uint8_t db[512];
            mgf(sd, SH, db, mdblen);
            for (size_t i = 0; i < mdblen; ++i) db[i] ^= mdb[i];

            auto eh = SHA384::hash(nullptr, 0);
            uint8_t bad = 0;
            for (size_t i = 0; i < SH; ++i) bad |= db[i] ^ eh.b[i];

            size_t sp = 0;
            uint8_t sf = 0;
            for (size_t i = SH; i < mdblen; ++i) {
                if (db[i] == 1 && !sf) { sp = i; sf = 1; }
            }
            if (!sf || bad) throw std::runtime_error("OAEP: invalid padding");

            Buf out;
            out.n = mdblen - sp - 1;
            for (size_t i = 0; i < out.n; ++i) out.b[i] = db[sp + 1 + i];
            return out;
        }
    }

    namespace U {
        BigNum pack(const uint8_t* b, size_t n) {
            BigNum r;
            r.len = 0;
            if (n == 0) { r.words[r.len++] = 0; return r; }
            size_t p = (4 - (n % 4)) % 4;
            uint8_t buf[520];
            for (size_t i = 0; i < p; ++i) buf[i] = 0;
            for (size_t i = 0; i < n; ++i) buf[p + i] = b[i];
            size_t total = p + n;
            for (size_t i = 0; i < total; i += 4) {
                uint32_t w = ((uint32_t)buf[i] << 24) | ((uint32_t)buf[i + 1] << 16) | ((uint32_t)buf[i + 2] << 8) | (uint32_t)buf[i + 3];
                r.words[r.len++] = w;
            }
            std::reverse(r.words, r.words + r.len);
            r.norm();
            return r;
        }

        void unpack(const BigNum& v, uint8_t* out, size_t t) {
            uint8_t o[520];
            size_t olen = 0;
            for (int i = (int)v.len - 1; i >= 0; --i) {
                uint32_t w = v.words[i];
                o[olen++] = (uint8_t)((w >> 24) & 0xFF);
                o[olen++] = (uint8_t)((w >> 16) & 0xFF);
                o[olen++] = (uint8_t)((w >> 8) & 0xFF);
                o[olen++] = (uint8_t)(w & 0xFF);
            }
            size_t s = 0;
            while (s + 1 < olen && o[s] == 0) s++;
            size_t cnt = olen - s;
            if (cnt < t) {
                size_t pad = t - cnt;
                for (size_t i = 0; i < pad; ++i) out[i] = 0;
                for (size_t i = 0; i < cnt; ++i) out[pad + i] = o[s + i];
            }
            else {
                for (size_t i = 0; i < t; ++i) out[i] = o[s + (cnt - t) + i];
            }
        }
    }

    struct Pub { BigNum N, e; };
    struct Priv { BigNum p, q, d, dP, dQ, qInv; };

    static const char* P_HEX = "C972F29015EBD19724D2C4F867F212FEE1E0C96087B2623FC9F694729C83B73A2F7F58855677DFCC3EA6BAD8A4CD1F3AF4962F5DE1EAEA26BCB682FAD4A1B1EA084981BA8E904523DF65B0BA587BE40FDD482E2A1DC98A39F61CF42134D9C566C433B87FA7EAE18EFF538B442A7B8BFDBEDAF33633897B6EA4028F522D78E759872CC1E7BDF76358D81BD3B07EF8CB54992FAB704166D975A8868B9C8F84EB71EFF75A123313326D0F5B92006608B803EA44D67DAF3FC228A823F3EF7FBF14B35A0F5954D092DA168E440746DB7A89A7EA7B88212E217D478878401873549C6130CCC51F58D4A12683E4BB37070816F8338B18ECE0C1A950620334E51F06F179";
    static const char* Q_HEX = "C19712B9FE8CECE2DAE3671547AAD8645806020046CAE3E079208050CFE7EC7F0279FF355F4BC49C94FF17DFF8EA35EDBC75DF8EE8306BB9C599B250B9AE5BB12CECF14483836BA0787BFBD3420DF151CFF422E6F8B5C7E912D07E5680A1A8D3C67797C63ECC64A1FE2021E45681A5A48539308F4D5A2326EEB3572B1D49141DCAADDD3669A170F47482DFB231E19B9B8798E5836E9BC26CCF1052A622FA381FD43AB06E66DCE4594599D9ECAC83AB41BED10F1E5E2F050FAB13F557322BEC3949AB45277D73E81F5B6147B4BABBEA737D223FCD623D8AF06ACA56D7330673E93535EA850A0B1D756D2AD85C7093C502FFBB6880EC7A5B8CB44489807092610A";

    void setup(Pub& pub, Priv& priv) {
        BigNum p(P_HEX), q(Q_HEX);
        pub.N = p * q;
        pub.e = 65537;
        BigNum phi = (p - 1) * (q - 1);
        BigNum d = CM::invMod(pub.e, phi);
        priv.p = p;
        priv.q = q;
        priv.d = d;
        priv.dP = d % (p - 1);
        priv.dQ = d % (q - 1);
        priv.qInv = CM::ctBinaryInv(q, p);
        if ((q * priv.qInv) % p != BigNum(1)) throw std::runtime_error("qInv self-test failed");
    }

    BigNum encrypt(const BigNum& m, const Pub& k) { return CM::powMod(m, k.e, k.N); }

    BigNum decrypt(const BigNum& c, const Priv& k) {
        BigNum m1 = CM::powMod(c, k.dP, k.p), m2 = CM::powMod(c, k.dQ, k.q);
        BigNum diff = (m1 >= m2) ? (m1 - m2) : (k.p - (m2 - m1));
        BigNum h = (diff * k.qInv) % k.p;
        return m2 + h * k.q;
    }

    void test(const uint8_t* payload, size_t plen, const Pub& pub, const Priv& priv) {
        std::cout << "Вход: " << plen << " байт. ";
        auto t0 = std::chrono::high_resolution_clock::now();
        try {
            auto padded = OAEP::pad(payload, plen);
            BigNum m = U::pack(padded.b, padded.n);
            BigNum c = encrypt(m, pub);
            BigNum dec = decrypt(c, priv);
            uint8_t dp[512];
            U::unpack(dec, dp, OAEP::RSA);
            auto out = OAEP::unpad(dp, OAEP::RSA);
            if (out.n != plen) throw std::runtime_error("mismatch");
            for (size_t i = 0; i < plen; ++i) if (out.b[i] != payload[i]) throw std::runtime_error("mismatch");
            std::cout << "OK (" << out.n << " байт)\n";
        }
        catch (const std::exception& e) {
            std::cout << "Ошибка: " << e.what() << "\n";
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        std::cout << "    Время: " << ms << " мс\n";
    }

}

int main() {
    setlocale(LC_ALL, "rus");
    RSA9::Pub pub;
    RSA9::Priv priv;
    try { RSA9::setup(pub, priv); }
    catch (const std::exception& e) { std::cerr << "setup error: " << e.what() << "\n"; return 1; }

    RSA9::test(nullptr, 0, pub, priv);

    uint8_t big[414];
    for (size_t i = 0; i < 414; ++i) big[i] = 0xAB;
    RSA9::test(big, 414, pub, priv);

    const char* s = "Refactored Variant 9 Test";
    RSA9::test((const uint8_t*)s, strlen(s), pub, priv);

    return 0;
}//e