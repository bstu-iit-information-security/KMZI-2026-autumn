
#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;

class RSAArithmetic {
public:
    static BigInt modPow(BigInt base, BigInt exp, BigInt mod) {
        BigInt res = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 == 1) res = (res * base) % mod;
            base = (base * base) % mod;
            exp /= 2;
        }
        return res;
    }

    static BigInt modInverse(BigInt a, BigInt m) {
        BigInt m0 = m, t, q;
        BigInt x0 = 0, x1 = 1;
        if (m == 1) return 0;
        while (a > 1) {
            q = a / m;
            t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0) x1 += m0;
        return x1;
    }

    static bool millerRabinConstantTime(const BigInt& n, int k_iterations) {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;

        BigInt d = n - 1;
        int s = 0;
        while (d % 2 == 0) {
            d /= 2;
            s++;
        }

        int is_prime_accumulator = 1; 

        for (int i = 0; i < k_iterations; ++i) {
            BigInt a = 2 + (BigInt(42) % (n - 3)); // Заглушка: здесь нужен нормальный ГПСЧ
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