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
        
        BigInt diff = m1 - m2;
        if (diff < 0) {
            diff += priv.p;
        }
        BigInt h = (priv.q_inv * diff) % priv.p;
        BigInt m = m2 + h * priv.q; // m = m2 + h * q[cite: 1]
        
        return m;
    }
};