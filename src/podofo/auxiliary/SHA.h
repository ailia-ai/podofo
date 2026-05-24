/*
 * SHA-256, SHA-384, SHA-512 implementation
 * Based on FIPS 180-4 (Secure Hash Standard)
 *
 * This is a standalone implementation with no external dependencies.
 */

#ifndef _PODOFO_SHA_H_
#define _PODOFO_SHA_H_

#include <cstdint>
#include <cstring>

// SHA-256

class SHA256 {
public:
    static constexpr unsigned DIGEST_SIZE = 32;
    static constexpr unsigned BLOCK_SIZE = 64;

    SHA256() { reset(); }

    void reset() {
        m_totalLen = 0;
        m_bufLen = 0;
        m_h[0] = 0x6a09e667; m_h[1] = 0xbb67ae85;
        m_h[2] = 0x3c6ef372; m_h[3] = 0xa54ff53a;
        m_h[4] = 0x510e527f; m_h[5] = 0x9b05688c;
        m_h[6] = 0x1f83d9ab; m_h[7] = 0x5be0cd19;
    }

    void update(const unsigned char* data, size_t len) {
        m_totalLen += len;
        while (len > 0) {
            size_t toCopy = BLOCK_SIZE - m_bufLen;
            if (toCopy > len) toCopy = len;
            std::memcpy(m_buf + m_bufLen, data, toCopy);
            m_bufLen += toCopy;
            data += toCopy;
            len -= toCopy;
            if (m_bufLen == BLOCK_SIZE) {
                processBlock(m_buf);
                m_bufLen = 0;
            }
        }
    }

    void final(unsigned char digest[DIGEST_SIZE]) {
        uint64_t totalBits = m_totalLen * 8;
        unsigned char pad = 0x80;
        update(&pad, 1);
        pad = 0;
        while (m_bufLen != 56)
            update(&pad, 1);
        unsigned char lenBytes[8];
        for (int i = 7; i >= 0; i--) {
            lenBytes[i] = (unsigned char)(totalBits & 0xff);
            totalBits >>= 8;
        }
        update(lenBytes, 8);
        for (int i = 0; i < 8; i++) {
            digest[i*4+0] = (unsigned char)(m_h[i] >> 24);
            digest[i*4+1] = (unsigned char)(m_h[i] >> 16);
            digest[i*4+2] = (unsigned char)(m_h[i] >> 8);
            digest[i*4+3] = (unsigned char)(m_h[i]);
        }
    }

    static void hash(const unsigned char* data, size_t len, unsigned char digest[DIGEST_SIZE]) {
        SHA256 ctx;
        ctx.update(data, len);
        ctx.final(digest);
    }

private:
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t Sigma0(uint32_t x) { return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }
    static uint32_t Sigma1(uint32_t x) { return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }
    static uint32_t sigma0(uint32_t x) { return rotr(x,7) ^ rotr(x,18) ^ (x >> 3); }
    static uint32_t sigma1(uint32_t x) { return rotr(x,17) ^ rotr(x,19) ^ (x >> 10); }

    void processBlock(const unsigned char block[BLOCK_SIZE]) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)block[i*4]<<24) | ((uint32_t)block[i*4+1]<<16) |
                   ((uint32_t)block[i*4+2]<<8) | (uint32_t)block[i*4+3];
        for (int i = 16; i < 64; i++)
            w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];

        uint32_t a=m_h[0], b=m_h[1], c=m_h[2], d=m_h[3];
        uint32_t e=m_h[4], f=m_h[5], g=m_h[6], h=m_h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + w[i];
            uint32_t t2 = Sigma0(a) + Maj(a,b,c);
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        m_h[0]+=a; m_h[1]+=b; m_h[2]+=c; m_h[3]+=d;
        m_h[4]+=e; m_h[5]+=f; m_h[6]+=g; m_h[7]+=h;
    }

    uint32_t m_h[8];
    unsigned char m_buf[BLOCK_SIZE];
    size_t m_bufLen;
    uint64_t m_totalLen;
};

// SHA-512 (also used as base for SHA-384)

class SHA512Base {
public:
    static constexpr unsigned BLOCK_SIZE = 128;

    void update(const unsigned char* data, size_t len) {
        m_totalLen += len;
        while (len > 0) {
            size_t toCopy = BLOCK_SIZE - m_bufLen;
            if (toCopy > len) toCopy = len;
            std::memcpy(m_buf + m_bufLen, data, toCopy);
            m_bufLen += toCopy;
            data += toCopy;
            len -= toCopy;
            if (m_bufLen == BLOCK_SIZE) {
                processBlock(m_buf);
                m_bufLen = 0;
            }
        }
    }

protected:
    void initState(const uint64_t iv[8]) {
        m_totalLen = 0;
        m_bufLen = 0;
        std::memcpy(m_h, iv, sizeof(m_h));
    }

    void finalImpl(unsigned char* digest, unsigned digestLen) {
        uint64_t totalBits = m_totalLen * 8;
        unsigned char pad = 0x80;
        update(&pad, 1);
        pad = 0;
        while (m_bufLen != 112)
            update(&pad, 1);
        unsigned char lenBytes[16];
        std::memset(lenBytes, 0, 8); // high 64 bits = 0
        for (int i = 15; i >= 8; i--) {
            lenBytes[i] = (unsigned char)(totalBits & 0xff);
            totalBits >>= 8;
        }
        update(lenBytes, 16);
        for (unsigned i = 0; i < digestLen / 8; i++) {
            digest[i*8+0] = (unsigned char)(m_h[i] >> 56);
            digest[i*8+1] = (unsigned char)(m_h[i] >> 48);
            digest[i*8+2] = (unsigned char)(m_h[i] >> 40);
            digest[i*8+3] = (unsigned char)(m_h[i] >> 32);
            digest[i*8+4] = (unsigned char)(m_h[i] >> 24);
            digest[i*8+5] = (unsigned char)(m_h[i] >> 16);
            digest[i*8+6] = (unsigned char)(m_h[i] >> 8);
            digest[i*8+7] = (unsigned char)(m_h[i]);
        }
    }

private:
    static uint64_t rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
    static uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
    static uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint64_t Sigma0(uint64_t x) { return rotr(x,28) ^ rotr(x,34) ^ rotr(x,39); }
    static uint64_t Sigma1(uint64_t x) { return rotr(x,14) ^ rotr(x,18) ^ rotr(x,41); }
    static uint64_t sigma0(uint64_t x) { return rotr(x,1) ^ rotr(x,8) ^ (x >> 7); }
    static uint64_t sigma1(uint64_t x) { return rotr(x,19) ^ rotr(x,61) ^ (x >> 6); }

    void processBlock(const unsigned char block[BLOCK_SIZE]) {
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
        uint64_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint64_t)block[i*8]<<56) | ((uint64_t)block[i*8+1]<<48) |
                   ((uint64_t)block[i*8+2]<<40) | ((uint64_t)block[i*8+3]<<32) |
                   ((uint64_t)block[i*8+4]<<24) | ((uint64_t)block[i*8+5]<<16) |
                   ((uint64_t)block[i*8+6]<<8) | (uint64_t)block[i*8+7];
        for (int i = 16; i < 80; i++)
            w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];

        uint64_t a=m_h[0], b=m_h[1], c=m_h[2], d=m_h[3];
        uint64_t e=m_h[4], f=m_h[5], g=m_h[6], h=m_h[7];
        for (int i = 0; i < 80; i++) {
            uint64_t t1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + w[i];
            uint64_t t2 = Sigma0(a) + Maj(a,b,c);
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        m_h[0]+=a; m_h[1]+=b; m_h[2]+=c; m_h[3]+=d;
        m_h[4]+=e; m_h[5]+=f; m_h[6]+=g; m_h[7]+=h;
    }

    uint64_t m_h[8];
    unsigned char m_buf[BLOCK_SIZE];
    size_t m_bufLen;
    uint64_t m_totalLen;
};

class SHA384 : public SHA512Base {
public:
    static constexpr unsigned DIGEST_SIZE = 48;

    SHA384() { reset(); }

    void reset() {
        static const uint64_t IV[8] = {
            0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
            0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
            0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
            0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
        };
        initState(IV);
    }

    void final(unsigned char digest[DIGEST_SIZE]) {
        finalImpl(digest, DIGEST_SIZE);
    }

    static void hash(const unsigned char* data, size_t len, unsigned char digest[DIGEST_SIZE]) {
        SHA384 ctx;
        ctx.update(data, len);
        ctx.final(digest);
    }
};

class SHA512 : public SHA512Base {
public:
    static constexpr unsigned DIGEST_SIZE = 64;

    SHA512() { reset(); }

    void reset() {
        static const uint64_t IV[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        initState(IV);
    }

    void final(unsigned char digest[DIGEST_SIZE]) {
        finalImpl(digest, DIGEST_SIZE);
    }

    static void hash(const unsigned char* data, size_t len, unsigned char digest[DIGEST_SIZE]) {
        SHA512 ctx;
        ctx.update(data, len);
        ctx.final(digest);
    }
};

#endif // _PODOFO_SHA_H_
