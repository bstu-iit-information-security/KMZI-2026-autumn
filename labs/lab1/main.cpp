#include <array>
#include <cmath>
#include <iostream>
#include <string_view>
#include <bitset>
#include <vector>
using namespace std;

class Galois{

    public:

        unsigned int add(unsigned int a, unsigned int b){
            return a ^ b;
        }

        unsigned int multiply(unsigned int a, unsigned int b, unsigned int poly) {
                unsigned int result = 0;

                for (int i = 0; i < 8; i++) {
                    unsigned int take = -(unsigned int)(b & 1);
                    result ^= a & take;

                    unsigned int hi_bit = -(unsigned int)((a >> 7) & 1);
                    a = ((a << 1) & 0xFF) ^ (hi_bit & (poly & 0xFF));
                    b >>= 1;
                }

                return result;
            }

            unsigned int inverse(unsigned int a, unsigned int poly) {
                if (a == 0)
                    return 0;

                unsigned int exponent = 254;
                unsigned int result = 1;
                unsigned int base = a;

                while (exponent > 0) {
                    if (exponent & 1) {
                        result = multiply(result, base, poly);
                    }

                    base = multiply(base, base, poly);
                    exponent >>= 1;
                }

                return result;
            }
};

class BelT{
    private:
        Galois field;
        unsigned int sbox[256];
        unsigned int poly;

        static unsigned int rotl(unsigned int val, unsigned int shift){
            return (val << shift) | (val >> (32u - shift));
        }

        unsigned int hbox(unsigned int x){
            unsigned int inv = field.inverse(x, poly);
            unsigned int s = 0;

            for(int b = 0; b<8;b++){
                unsigned int bit = ((inv >> b) & 1)
                ^ ((inv >> ((b + 2) % 8)) & 1)
                ^ ((inv >> ((b + 5) % 8)) & 1)
                ^ ((inv >> ((b + 6) % 8)) & 1)
                ^ ((inv >> ((b + 7) % 8)) & 1);
                s |= bit << b;
            }

            return s ^ 0xB1;
        }

        unsigned int div(unsigned int w){
            return hbox((w >> 24) & 0xFF) << 24
                    | hbox((w >> 16) & 0xFF) << 16
                    | hbox((w >>  8) & 0xFF) <<  8
                    | hbox( w & 0xFF);
        }

        unsigned int G(unsigned int w, unsigned int r){
            return rotl(div(w), r);
        }

    public:
        BelT(unsigned int x): poly(x){
            for(int i = 0; i<256;i++){
                unsigned int inv = field.inverse(i, poly);

                unsigned int s = 0;
                for(int b = 0; b < 8;b++){
                    unsigned int bit = ((inv >> b) & 1) ^
                                                  ((inv >> ((b + 2) % 8)) & 1) ^
                                                  ((inv >> ((b + 5) % 8)) & 1) ^
                                                  ((inv >> ((b + 6) % 8)) & 1) ^
                                                  ((inv >> ((b + 7) % 8)) & 1);
                    s |= (bit << b);
                }
                sbox [i] = (s ^ 0xB1) & 0xFF;
            }
        }

        array<unsigned int, 57> keySchedule(const std::array<unsigned int, 8>& theta) const {
            
            array<unsigned int, 57> X{};

            for(int i = 1;i<=56;++i){
                X[i] = theta[(i-1) % 8];
            }
            return X;
        }

        void round(std::array<unsigned int, 4>& block,
                       const std::array<unsigned int, 57>& X,
                       unsigned int roundNum){
            unsigned int& a = block[0];
            unsigned int& b = block[1];
            unsigned int& c = block[2];
            unsigned int& d = block[3];

            b ^= G(a + X[7 * roundNum - 6], 5);
            c ^= G(d + X[7 * roundNum - 5], 21);
            a -= G(b + X[7 * roundNum - 4], 13);

            unsigned int temp = G(b + c + X[7 * roundNum -3], 21) ^ roundNum;
            b += temp;
            c -= temp;

            d += G(c + X[7 * roundNum - 2], 13);
            b ^= G(a + X[7 * roundNum - 1], 21);
            c ^= G(d + X[7 * roundNum], 5);

            swap(a,b);
            swap(c,d);
            swap(b,c);
        }

        array<unsigned int, 4> encrypt(array<unsigned int, 4> block,
                                                const array<unsigned int, 8>& key)
        {
            auto X = keySchedule(key);

            for(int i = 1;i<=8;i++)
                round(block, X, i);

            return { block[1], block[3], block[0], block[2] };
        }
};


class GCM{
    BelT& cipher;
    array<unsigned int,8> key;


    array<unsigned int,16> H;

    array<unsigned int, 4> toWords(array<unsigned int, 16>& block){
        array<unsigned int, 4> words{};
        for(int i = 0;i<4;i++){
            words[i] = (block[4 * i] << 24)
                 | (block[4 * i + 1] << 16)
                 | (block[4 * i + 2] <<  8)
                 | (block[4 * i + 3]);
        }
        return words;
    }

    array<unsigned int, 16> toBytes(array<unsigned int, 4> words){
        array<unsigned int, 16> block{};
        for(int i = 0; i<4; i++){
            block[4 * i]     = (words[i] >> 24) & 0xFF;
            block[4 * i + 1] = (words[i] >> 16) & 0xFF;
            block[4 * i + 2] = (words[i] >>  8) & 0xFF;
            block[4 * i + 3] = (words[i]) & 0xFF;
        }
        return block;
    }

    array<unsigned int, 16 > cEncrypt(array<unsigned int, 16>& block){
        return toBytes(cipher.encrypt(toWords(block), key));
    }

    static void xorCharging(array<unsigned int, 16>& a,
                            array<unsigned int, 16>& b){
        for(int i = 0; i<16;i++){
            a[i] ^= b[i];
        }
    }

    static void inc32(array<unsigned int, 16>& cBlock){
        for (int i = 15; i >= 12;i--){
            if(++cBlock[i] != 0)
                break;
        }
    }

    static array<unsigned int, 16> makeCB0(unsigned int* iv){
        array<unsigned int, 16> cb{};
        for(int i = 0; i<12;i++)
            cb[i] = iv[i] & 0xFF;
        cb[15] = 1;
        return cb;
    }

    static array<unsigned int, 16> gf(  array<unsigned int, 16> x,
                                        array<unsigned int, 16> y){
        array<unsigned int, 16> z{};
        array<unsigned int, 16> v = y;

        for(int byte = 0; byte < 16; byte++){
            for(int bit = 7; bit >= 0 ; bit--){
                
                unsigned int mask = -((x[byte] >> bit)& 1);
                for(int i = 0; i<16;i++){
                    z[i] ^= v[i] & mask;
                }

                unsigned int lsb = v[15] & 1;
                for(int i = 15; i>0; i--){
                    v[i] = ((v[i] >> 1) | (v[i - 1] << 7)) & 0xFF;
                }
                v[0] >>= 1;

                unsigned int red = -(lsb);
                v[0] ^= (0xE1 & red);
            }
        }

        return z;     
    }

    void absorb(array<unsigned int, 16>& Y,
                unsigned int* data, int len){
        
        int pauseCondition = 0;
        while(pauseCondition < len){
            array<unsigned int, 16> block{};
            int n = len - pauseCondition;

            if(n > 16)
                n = 16;

            for(int i = 0; i<n; i++){
                block[i] = data[pauseCondition + i] & 0xFF;
            }

            xorCharging(Y, block);
            Y = gf(Y,H);
            pauseCondition += n;
        }
    }

    array<unsigned int, 16> ghash(unsigned int* aad, int aadLen,
                                unsigned int* c, int cLen){
        
        array<unsigned int, 16> Y{};
        absorb(Y, aad, aadLen);
        absorb(Y, c, cLen);
        
        array<unsigned int, 16> lenBlock{};
        unsigned long long aadBits = (unsigned long long)aadLen * 8;
        unsigned long long cBits = (unsigned long long)cLen * 8;

        for(int i = 0; i<8;i++){
            lenBlock[7 - i] = (aadBits >> (8 * i)) & 0xFF;
            lenBlock[15 - i] = (cBits >> (8 * i)) & 0xFF;
        }

        xorCharging(Y, lenBlock);
        Y = gf(Y, H);
        return Y;
    }

public:

    GCM(BelT& belt, const array<unsigned int, 8>& k): cipher(belt), key(k){
        array<unsigned int, 16> zero{};
        H = cEncrypt(zero);
    }

    void seal(unsigned int* iv,
              unsigned int* aad, int aadLen,
              unsigned int* p, int pLen,
              unsigned int* c,
              unsigned int* tag){

        array<unsigned int, 16> cb = makeCB0(iv);
        array<unsigned int, 16> ek0 = cEncrypt(cb);

        inc32(cb);

        int off = 0;
        while(off < pLen){
            array<unsigned int, 16> gamma = cEncrypt(cb);
            inc32(cb);

            int n = pLen - off;
            if(n > 16)
                n = 16;

            for(int i = 0; i<n;i++)
                c[off + i] = (p[off + i] ^ gamma[i]) & 0xFF;

            off += n;
        }

        array<unsigned int, 16> S = ghash(aad, aadLen, c, pLen);
        xorCharging(S, ek0);
        for(int i = 0; i<16;i++)
            tag[i] = S[i] & 0xFF;
    }

    bool open(unsigned int* iv,
              unsigned int* aad, int aadLen,
              unsigned int* c, int cLen,
              unsigned int* tag,
              unsigned int* p){

        array<unsigned int, 16> cb = makeCB0(iv);
        array<unsigned int, 16> ek0 = cEncrypt(cb);

        array<unsigned int, 16> S = ghash(aad, aadLen, c, cLen);
        xorCharging(S, ek0);

        unsigned int delta = 0;
        for(int i = 0; i<16;i++)
            delta |= (S[i] ^ tag[i]);

        bool ok = (delta == 0);

        inc32(cb);
        int off = 0;
        while(off < cLen){
            array<unsigned int, 16> gamma = cEncrypt(cb);
            inc32(cb);

            int n = cLen - off;
            if(n > 16)
                n = 16;

            for(int i = 0; i<n;i++)
                p[off + i] = (c[off + i] ^ gamma[i]) & 0xFF;

            off += n;
        }

        return ok;
    }

};


int main(){

    unsigned int P_X = 0x14D; 
    BelT cipher(P_X);

    array<unsigned int, 8> key{};
    GCM gcm(cipher, key);

    unsigned int iv[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
    unsigned int aad[3] = {'A','A','D'};
    unsigned int p[5] = {'h','e','l','l','o'};
    unsigned int c[5];
    unsigned int tag[16];
    unsigned int back[5];

    gcm.seal(iv, aad, 3, p, 5, c, tag);
    bool ok = gcm.open(iv, aad, 3, c, 5, tag, back);

    cout << ok << "\n";
    for(int i = 0;i<5;i++)
        cout << (char)back[i];
    cout << "\n";

}
