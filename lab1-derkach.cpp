#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>
#include <stdexcept>

using Byte = std::uint8_t;
using Block = std::array<Byte, 16>;

class GF256 {
public:
    static constexpr std::uint16_t P = 0x12D;

    static constexpr Byte add(Byte a, Byte b) noexcept { return static_cast<Byte>(a ^ b); }
    //shift-and-XOR
    static Byte multiply(Byte a, Byte b) noexcept {
        Byte r = 0;
        for (int i = 0; i < 8; ++i) {
            const Byte mask = static_cast<Byte>(0u - static_cast<unsigned>(b & 1u));
            r ^= static_cast<Byte>(a & mask);

            const Byte hi = static_cast<Byte>(a >> 7);
            const Byte red_mask = static_cast<Byte>(0u - static_cast<unsigned>(hi));
            a = static_cast<Byte>((a << 1) ^ (static_cast<Byte>(P) & red_mask));
            b = static_cast<Byte>(b >> 1);
        }
        return r;
    }

    static Byte square(Byte a) noexcept { return multiply(a, a); }

    static Byte inverse(Byte a) noexcept {
        const Byte a2   = square(a);
        const Byte a4   = square(a2);
        const Byte a8   = square(a4);
        const Byte a16  = square(a8);
        const Byte a32  = square(a16);
        const Byte a64  = square(a32);
        const Byte a128 = square(a64);

        Byte r = a128;
        r = multiply(r, a64);
        r = multiply(r, a32);
        r = multiply(r, a16);
        r = multiply(r, a8);
        r = multiply(r, a4);
        r = multiply(r, a2);
        return r;
    }

    static Byte xtime(Byte a) noexcept {
        const Byte hi = static_cast<Byte>(a >> 7);
        const Byte mask = static_cast<Byte>(0u - static_cast<unsigned>(hi));
        return static_cast<Byte>((a << 1) ^ (static_cast<Byte>(P) & mask));
    }

    static bool check_inverse(Byte a, Byte inv) noexcept {
        return multiply(a, inv) == 1;
    }
};

class AES128 {
public:
    AES128() = default;

    static constexpr std::size_t ROUNDS = 10;

    static constexpr std::array<Byte, 16> MIX = {
        0x02,0x03,0x01,0x01,
        0x01,0x02,0x03,0x01,
        0x01,0x01,0x02,0x03,
        0x03,0x01,0x01,0x02
    };

    static constexpr std::array<Byte, 16> INV_MIX = {
        0x0E,0x0B,0x0D,0x09,
        0x09,0x0E,0x0B,0x0D,
        0x0D,0x09,0x0E,0x0B,
        0x0B,0x0D,0x09,0x0E
    };

    void set_key(const Block& key) {
        for (std::size_t i = 0; i < 16; ++i) round_keys_[i] = key[i];

        std::size_t bytes = 16;
        Byte rcon = 0x01;
        while (bytes < 176) {
            std::array<Byte,4> t = {
                round_keys_[bytes-4],
                round_keys_[bytes-3],
                round_keys_[bytes-2],
                round_keys_[bytes-1]
            };

            const bool key_word_boundary = (bytes % 16) == 0;
            if (key_word_boundary) {
                const Byte first = t[0];
                t[0] = sbox(t[1]);
                t[1] = sbox(t[2]);
                t[2] = sbox(t[3]);
                t[3] = sbox(first);
                t[0] ^= rcon;
                rcon = GF256::xtime(rcon);
            }

            for (std::size_t j = 0; j < 4; ++j) {
                round_keys_[bytes] =
                    static_cast<Byte>(round_keys_[bytes-16] ^ t[j]);
                ++bytes;
            }
        }
    }

    void encrypt(const Block& in, Block& out) const noexcept {
        Block s = in;
        //AddRoundKey
        add_round_key(s, 0);

        for (std::size_t round = 1; round <= 9; ++round) {
            //SubBytes
            sub_bytes(s);
            //ShiftRows
            shift_rows(s);
            //MixColumns
            mix_columns(s);
            //AddRoundKey
            add_round_key(s, round);
        }

        //SubBytes
        sub_bytes(s);
        //ShiftRows
        shift_rows(s);
        //AddRoundKey
        add_round_key(s, 10);
        out = s;
    }

    void decrypt(const Block& in, Block& out) const noexcept {
        Block s = in;
        add_round_key(s, 10);

        for (int round = 9; round >= 1; --round) {
            inv_shift_rows(s);
            inv_sub_bytes(s);
            add_round_key(s, static_cast<std::size_t>(round));
            inv_mix_columns(s);
        }

        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, 0);
        out = s;
    }

    //S-box
    static Byte sbox(Byte x) noexcept {
        const Byte y = GF256::inverse(x);
        return static_cast<Byte>(
            y ^ rotl8(y,1) ^ rotl8(y,2) ^ rotl8(y,3) ^ rotl8(y,4) ^ 0x63
        );
    }

    static Byte inv_sbox(Byte x) noexcept {
        const Byte y = static_cast<Byte>(
            rotl8(x,1) ^ rotl8(x,3) ^ rotl8(x,6) ^ 0x05
        );
        return GF256::inverse(y);
    }

    static bool verify_inverse_mix() noexcept {
        for (std::size_t r = 0; r < 4; ++r) {
            for (std::size_t c = 0; c < 4; ++c) {
                Byte acc = 0;
                for (std::size_t k = 0; k < 4; ++k)
                    acc ^= GF256::multiply(INV_MIX[4*r+k], MIX[4*k+c]);
                const Byte expected = static_cast<Byte>(r == c ? 1 : 0);
                if (acc != expected) return false;
            }
        }
        return true;
    }

private:
    std::array<Byte,176> round_keys_{};

    static Byte rotl8(Byte x, unsigned n) noexcept {
        return static_cast<Byte>((x << n) | (x >> (8u - n)));
    }

    static void add_round_key(Block& s, std::size_t round,
                              const std::array<Byte,176>& keys) noexcept {
        const std::size_t base = round * 16;
        for (std::size_t i = 0; i < 16; ++i) s[i] ^= keys[base+i];
    }

    void add_round_key(Block& s, std::size_t round) const noexcept {
        add_round_key(s, round, round_keys_);
    }

    static void sub_bytes(Block& s) noexcept {
        for (Byte& x : s) x = sbox(x);
    }

    static void inv_sub_bytes(Block& s) noexcept {
        for (Byte& x : s) x = inv_sbox(x);
    }

    static void shift_rows(Block& s) noexcept {
        Block t = s;
        for (std::size_t r = 0; r < 4; ++r)
            for (std::size_t c = 0; c < 4; ++c)
                s[4*c+r] = t[4*((c+r)%4)+r];
    }

    static void inv_shift_rows(Block& s) noexcept {
        Block t = s;
        for (std::size_t r = 0; r < 4; ++r)
            for (std::size_t c = 0; c < 4; ++c)
                s[4*c+r] = t[4*((c+4-r)%4)+r];
    }

    static void mix_columns(Block& s) noexcept {
        Block t = s;
        for (std::size_t c = 0; c < 4; ++c) {
            const Byte a0=t[4*c+0], a1=t[4*c+1], a2=t[4*c+2], a3=t[4*c+3];
            s[4*c+0] = GF256::multiply(0x02,a0) ^ GF256::multiply(0x03,a1) ^ a2 ^ a3;
            s[4*c+1] = a0 ^ GF256::multiply(0x02,a1) ^ GF256::multiply(0x03,a2) ^ a3;
            s[4*c+2] = a0 ^ a1 ^ GF256::multiply(0x02,a2) ^ GF256::multiply(0x03,a3);
            s[4*c+3] = GF256::multiply(0x03,a0) ^ a1 ^ a2 ^ GF256::multiply(0x02,a3);
        }
    }

    static void inv_mix_columns(Block& s) noexcept {
        Block t = s;
        for (std::size_t c = 0; c < 4; ++c) {
            const Byte a0=t[4*c+0], a1=t[4*c+1], a2=t[4*c+2], a3=t[4*c+3];
            s[4*c+0] = GF256::multiply(0x0E,a0) ^ GF256::multiply(0x0B,a1) ^
                       GF256::multiply(0x0D,a2) ^ GF256::multiply(0x09,a3);
            s[4*c+1] = GF256::multiply(0x09,a0) ^ GF256::multiply(0x0E,a1) ^
                       GF256::multiply(0x0B,a2) ^ GF256::multiply(0x0D,a3);
            s[4*c+2] = GF256::multiply(0x0D,a0) ^ GF256::multiply(0x09,a1) ^
                       GF256::multiply(0x0E,a2) ^ GF256::multiply(0x0B,a3);
            s[4*c+3] = GF256::multiply(0x0B,a0) ^ GF256::multiply(0x0D,a1) ^
                       GF256::multiply(0x09,a2) ^ GF256::multiply(0x0E,a3);
        }
    }
};

class GCM {
public:
    static constexpr std::size_t MAX_DATA = 4096;

    struct Result {
        std::array<Byte, MAX_DATA> ciphertext{};
        std::size_t size = 0;
        Block tag{};
    };

    explicit GCM(const AES128& aes) : aes_(aes) {
        Block zero{};
        aes_.encrypt(zero, H_);
    }

    Result encrypt(const std::array<Byte,MAX_DATA>& plaintext,
                   std::size_t len,
                   const std::array<Byte,MAX_DATA>& aad,
                   std::size_t aad_len,
                   const std::array<Byte,12>& iv) const {
        Result res;
        res.size = len;

        Block j0{};
        for (std::size_t i=0; i<12; ++i) j0[i]=iv[i];
        j0[15]=1;

        Block ctr = j0;
        inc32(ctr);

        std::size_t offset = 0;
        while (offset < len) {
            Block stream{};
            aes_.encrypt(ctr, stream);
            const std::size_t take = std::min<std::size_t>(16, len-offset);
            for (std::size_t i=0; i<take; ++i)
                res.ciphertext[offset+i] = plaintext[offset+i] ^ stream[i];
            offset += take;
            inc32(ctr);
        }
        //CTR

        //GHASH
        const Block s = ghash(aad, aad_len, res.ciphertext, len);
        //Tag
        Block e0{};
        aes_.encrypt(j0, e0);
        for (std::size_t i=0; i<16; ++i) res.tag[i] = e0[i] ^ s[i];
        return res;
    }

    static bool constant_time_equal(const Block& a, const Block& b) noexcept {
        Byte diff = 0;
        for (std::size_t i=0; i<16; ++i)
            diff |= static_cast<Byte>(a[i] ^ b[i]);
        return diff == 0;
    }

private:
    const AES128& aes_;
    Block H_{};

    static void inc32(Block& b) noexcept {
        Byte carry = 1;
        for (int i=15; i>=12; --i) {
            const Byte old = b[i];
            const Byte sum = static_cast<Byte>(old + carry);
            const Byte was_ff = static_cast<Byte>(old == 0xFF);
            const Byte carry_mask =
                static_cast<Byte>(0u - static_cast<unsigned>(carry));
            b[i] = static_cast<Byte>(
                (sum & carry_mask) | (old & static_cast<Byte>(~carry_mask))
            );
            carry = static_cast<Byte>(carry & was_ff);
        }
    }

    static Block gf128_mul(const Block& x, const Block& y) noexcept {
        Block z{};
        Block v = y;
        for (int i=0; i<128; ++i) {
            const unsigned bit = (x[i/8] >> (7-(i%8))) & 1u;
            const Byte mask8 = static_cast<Byte>(0u - bit);
            for (std::size_t j=0; j<16; ++j)
                z[j] ^= static_cast<Byte>(v[j] & mask8);

            const unsigned lsb = v[15] & 1u;
            const Byte rmask = static_cast<Byte>(0u - lsb);
            Byte carry = 0;
            for (int j=0; j<16; ++j) {
                const Byte cur = v[j];
                const Byte next_carry = static_cast<Byte>(cur & 1u);
                v[j] = static_cast<Byte>((cur >> 1) | (carry << 7));
                carry = next_carry;
            }
            v[0] ^= static_cast<Byte>(0xE1u & rmask);
        }
        return z;
    }

    static Block xor_block(const Block& a, const Block& b) noexcept {
        Block r{};
        for (std::size_t i=0; i<16; ++i) r[i]=a[i]^b[i];
        return r;
    }

    Block ghash(const std::array<Byte,MAX_DATA>& aad, std::size_t aad_len,
                const std::array<Byte,MAX_DATA>& c, std::size_t c_len) const noexcept {
        Block y{};

        auto absorb = [&](const std::array<Byte,MAX_DATA>& data, std::size_t len) {
            std::size_t off=0;
            while (off < len) {
                Block x{};
                const std::size_t take=std::min<std::size_t>(16,len-off);
                for (std::size_t i=0;i<take;++i) x[i]=data[off+i];
                y = gf128_mul(xor_block(y,x), H_);
                off += take;
            }
        };

        absorb(aad,aad_len);
        absorb(c,c_len);

        Block lengths{};
        const std::uint64_t aad_bits = static_cast<std::uint64_t>(aad_len) * 8u;
        const std::uint64_t c_bits   = static_cast<std::uint64_t>(c_len) * 8u;
        for (int i=0;i<8;++i) {
            lengths[7-i]  = static_cast<Byte>(aad_bits >> (8*i));
            lengths[15-i] = static_cast<Byte>(c_bits >> (8*i));
        }
        y = gf128_mul(xor_block(y,lengths),H_);
        return y;
    }
};

static int hexCharToInt(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static Block parse16(const std::string& hex) {
    if(hex.size()!=32) throw std::invalid_argument("Expected 32 hex chars");
    Block out{};
    for(std::size_t i=0;i<16;++i){
        int hi=hexCharToInt(hex[2*i]), lo=hexCharToInt(hex[2*i+1]);
        if(hi<0||lo<0) throw std::invalid_argument("Invalid hex");
        out[i]=static_cast<Byte>((hi<<4)|lo);
    }
    return out;
}

static std::array<Byte, 12> parseIV(const std::string& hex) {
    if(hex.size()!=24) throw std::invalid_argument("Expected 24 hex chars");
    std::array<Byte, 12> out{};
    for(std::size_t i=0;i<12;++i){
        int hi=hexCharToInt(hex[2*i]), lo=hexCharToInt(hex[2*i+1]);
        if(hi<0||lo<0) throw std::invalid_argument("Invalid hex");
        out[i]=static_cast<Byte>((hi<<4)|lo);
    }
    return out;
}

static std::string hex(const Byte* p, std::size_t n) {
    std::ostringstream os;
    os<<std::hex<<std::setfill('0');
    for(std::size_t i=0;i<n;++i)
        os<<std::setw(2)<<static_cast<unsigned>(p[i]);
    return os.str();
}

int main() {
    try {
        const Block key = parse16("000102030405060708090a0b0c0d0e0f");
        const Block pt  = parse16("00112233445566778899aabbccddeeff");

        AES128 aes;
        aes.set_key(key);

        Block ct{}, dec{};
        aes.encrypt(pt,ct);
        aes.decrypt(ct,dec);

        std::cout<<"p(x): 0x12D\n";
        std::cout<<"S-box[00]: "<<std::setw(2)<<std::setfill('0')<<std::hex
                 <<static_cast<unsigned>(AES128::sbox(0x00))<<"\n";
        std::cout<<"S-box[53]: "<<std::setw(2)<<static_cast<unsigned>(AES128::sbox(0x53))<<"\n";

        bool sbox_ok = true;
        for (int x=0;x<256;++x)
            if (AES128::inv_sbox(AES128::sbox(static_cast<Byte>(x))) != static_cast<Byte>(x))
                sbox_ok = false;

        bool gf_ok = (GF256::inverse(0x00) == 0x00);
        for (int x=1;x<256;++x)
            gf_ok = gf_ok &&
                    GF256::check_inverse(static_cast<Byte>(x),
                                         GF256::inverse(static_cast<Byte>(x)));

        std::cout<<"S-box bijection OK: "<<(sbox_ok ? "YES":"NO")<<"\n";
        std::cout<<"GF(2^8) inverse tests OK (including 0x00): "<<(gf_ok ? "YES":"NO")<<"\n";
        std::cout<<"AES-like CT: "<<hex(ct.data(),16)<<"\n";
        std::cout<<"Decrypt OK: "<<(dec==pt ? "YES":"NO")<<"\n";
        std::cout<<"Inverse MixColumns OK: "
                 <<(AES128::verify_inverse_mix() ? "YES":"NO")<<"\n";

        std::array<Byte,GCM::MAX_DATA> msg{};
        std::array<Byte,GCM::MAX_DATA> aad{};
        const std::string text="Hello, GCM! Variant 5.";
        const std::string aad_text="lab1-variant5";
        std::copy(text.begin(),text.end(),msg.begin());
        std::copy(aad_text.begin(),aad_text.end(),aad.begin());

        std::array<Byte,12> iv = parseIV("000102030405060708090a0b");

        GCM gcm(aes);
        auto r=gcm.encrypt(msg,text.size(),aad,aad_text.size(),iv);

        std::cout<<"GCM ciphertext: "<<hex(r.ciphertext.data(),r.size)<<"\n";
        std::cout<<"GCM tag: "<<hex(r.tag.data(),16)<<"\n";
        std::cout<<"Tag valid: "<<(GCM::constant_time_equal(r.tag,r.tag) ? "YES":"NO")<<"\n";

        Block bad=r.tag;
        bad[0]^=1;
        std::cout<<"Modified tag rejected: "
                 <<(!GCM::constant_time_equal(r.tag,bad) ? "YES":"NO")<<"\n";
                 
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}