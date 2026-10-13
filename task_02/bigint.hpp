#pragma once
#include <cstdint>
#include <cstring>

namespace bn {

constexpr int CAP = 100;
using u64 = std::uint64_t;
using u128 = unsigned __int128;

struct Big {
    u64 w[CAP];
};

inline void set_zero(Big& a) {
    std::memset(a.w, 0, sizeof(a.w));
}

inline void set_u64(Big& a, u64 v) {
    set_zero(a);
    a.w[0] = v;
}

inline Big from_u64(u64 v) {
    Big a;
    set_u64(a, v);
    return a;
}

inline int used(const Big& a) {
    int n = CAP;
    while (n > 0 && a.w[n - 1] == 0) --n;
    return n;
}

inline bool is_zero(const Big& a) {
    return used(a) == 0;
}

inline int bitlen(const Big& a) {
    int n = used(a);
    if (n == 0) return 0;
    return 64 * (n - 1) + 64 - __builtin_clzll(a.w[n - 1]);
}

inline int get_bit(const Big& a, int i) {
    return (int)((a.w[i >> 6] >> (i & 63)) & 1);
}

inline void set_bit(Big& a, int i) {
    a.w[i >> 6] |= (u64)1 << (i & 63);
}

inline int cmp(const Big& a, const Big& b) {
    for (int i = CAP - 1; i >= 0; --i) {
        if (a.w[i] != b.w[i]) return a.w[i] > b.w[i] ? 1 : -1;
    }
    return 0;
}

inline bool eq_u64(const Big& a, u64 v) {
    if (a.w[0] != v) return false;
    for (int i = 1; i < CAP; ++i) {
        if (a.w[i] != 0) return false;
    }
    return true;
}

inline void add(Big& r, const Big& a, const Big& b) {
    u64 carry = 0;
    for (int i = 0; i < CAP; ++i) {
        u128 s = (u128)a.w[i] + b.w[i] + carry;
        r.w[i] = (u64)s;
        carry = (u64)(s >> 64);
    }
}

inline void sub(Big& r, const Big& a, const Big& b) {
    u64 borrow = 0;
    for (int i = 0; i < CAP; ++i) {
        u64 x = a.w[i];
        u64 y = b.w[i];
        r.w[i] = x - y - borrow;
        borrow = (u64)((x < y) | ((x == y) & borrow));
    }
}

inline void shl(Big& r, const Big& a, int s) {
    int ws = s >> 6;
    int bs = s & 63;
    Big t;
    set_zero(t);
    for (int i = CAP - 1; i >= ws; --i) {
        u64 v = a.w[i - ws] << bs;
        if (bs != 0 && i - ws - 1 >= 0) v |= a.w[i - ws - 1] >> (64 - bs);
        t.w[i] = v;
    }
    r = t;
}

inline void shr1(Big& a) {
    for (int i = 0; i < CAP - 1; ++i) {
        a.w[i] = (a.w[i] >> 1) | (a.w[i + 1] << 63);
    }
    a.w[CAP - 1] >>= 1;
}

inline void mul(Big& r, const Big& a, const Big& b) {
    int la = used(a);
    int lb = used(b);
    Big t;
    set_zero(t);
    for (int i = 0; i < la; ++i) {
        u64 carry = 0;
        u64 ai = a.w[i];
        for (int j = 0; j < lb; ++j) {
            u128 s = (u128)ai * b.w[j] + t.w[i + j] + carry;
            t.w[i + j] = (u64)s;
            carry = (u64)(s >> 64);
        }
        t.w[i + lb] = carry;
    }
    r = t;
}

inline void divmod(Big& q, Big& r, const Big& a, const Big& b) {
    Big rem = a;
    Big qq;
    set_zero(qq);
    int sh = bitlen(a) - bitlen(b);
    if (sh >= 0) {
        Big d;
        shl(d, b, sh);
        for (int s = sh; s >= 0; --s) {
            if (cmp(rem, d) >= 0) {
                sub(rem, rem, d);
                set_bit(qq, s);
            }
            shr1(d);
        }
    }
    q = qq;
    r = rem;
}

inline u64 mod_small(const Big& a, u64 m) {
    u128 rem = 0;
    for (int i = used(a) - 1; i >= 0; --i) {
        rem = ((rem << 64) | a.w[i]) % m;
    }
    return (u64)rem;
}

inline void from_bytes_be(Big& a, const std::uint8_t* in, std::size_t n) {
    set_zero(a);
    for (std::size_t i = 0; i < n; ++i) {
        a.w[i / 8] |= (u64)in[n - 1 - i] << (8 * (i % 8));
    }
}

inline void to_bytes_be(const Big& a, std::uint8_t* out, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        out[n - 1 - i] = (std::uint8_t)((a.w[i / 8] >> (8 * (i % 8))) & 0xff);
    }
}

struct Mont {
    Big n;
    Big rr;
    Big one;
    int k;
    u64 ninv;
};

inline void mont_init(Mont& m, const Big& n) {
    m.n = n;
    m.k = used(n);
    u64 n0 = n.w[0];
    u64 inv = n0;
    for (int i = 0; i < 6; ++i) inv *= 2 - n0 * inv;
    m.ninv = (u64)0 - inv;
    Big x;
    set_zero(x);
    set_bit(x, 64 * m.k);
    Big q;
    divmod(q, m.one, x, n);
    m.rr = m.one;
    for (int i = 0; i < 64 * m.k; ++i) {
        add(m.rr, m.rr, m.rr);
        if (cmp(m.rr, n) >= 0) sub(m.rr, m.rr, n);
    }
}

inline void mont_mul(Big& r, const Big& a, const Big& b, const Mont& m) {
    const int k = m.k;
    u64 t[CAP / 2 + 4];
    for (int i = 0; i < k + 2; ++i) t[i] = 0;
    for (int i = 0; i < k; ++i) {
        u64 c = 0;
        u64 bi = b.w[i];
        for (int j = 0; j < k; ++j) {
            u128 s = (u128)a.w[j] * bi + t[j] + c;
            t[j] = (u64)s;
            c = (u64)(s >> 64);
        }
        u128 s = (u128)t[k] + c;
        t[k] = (u64)s;
        t[k + 1] = (u64)(s >> 64);
        u64 mq = t[0] * m.ninv;
        s = (u128)mq * m.n.w[0] + t[0];
        c = (u64)(s >> 64);
        for (int j = 1; j < k; ++j) {
            s = (u128)mq * m.n.w[j] + t[j] + c;
            t[j - 1] = (u64)s;
            c = (u64)(s >> 64);
        }
        s = (u128)t[k] + c;
        t[k - 1] = (u64)s;
        t[k] = t[k + 1] + (u64)(s >> 64);
    }
    bool ge = t[k] != 0;
    if (!ge) {
        ge = true;
        for (int j = k - 1; j >= 0; --j) {
            if (t[j] != m.n.w[j]) {
                ge = t[j] > m.n.w[j];
                break;
            }
        }
    }
    Big out;
    set_zero(out);
    if (ge) {
        u64 borrow = 0;
        for (int j = 0; j < k; ++j) {
            u64 x = t[j];
            u64 y = m.n.w[j];
            out.w[j] = x - y - borrow;
            borrow = (u64)((x < y) | ((x == y) & borrow));
        }
    } else {
        for (int j = 0; j < k; ++j) out.w[j] = t[j];
    }
    r = out;
}

}
