#include "zk_blake2s_mac.h"

#include <string.h>

#define BLAKE2S_BLOCKBYTES 64u
#define BLAKE2S_OUTBYTES 32u
#define BLAKE2S_KEYBYTES 32u
#define BLAKE2S_CHAIN_WORDS 8u
#define BLAKE2S_MSG_WORDS 16u

typedef struct
{
    uint32_t h[BLAKE2S_CHAIN_WORDS];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[BLAKE2S_BLOCKBYTES];
    size_t buflen;
    size_t outlen;
} blake2s_state;

static const uint32_t blake2s_iv[BLAKE2S_CHAIN_WORDS] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

static const uint8_t blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 4, 7, 15, 14, 1, 13, 3, 9, 8, 11, 5, 0 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
};

static uint32_t load32(const void *src)
{
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)p[0]) | (((uint32_t)p[1]) << 8) | (((uint32_t)p[2]) << 16) | (((uint32_t)p[3]) << 24);
}

static void store32(void *dst, uint32_t w)
{
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w & 0xFFu);
    p[1] = (uint8_t)((w >> 8) & 0xFFu);
    p[2] = (uint8_t)((w >> 16) & 0xFFu);
    p[3] = (uint8_t)((w >> 24) & 0xFFu);
}

static uint32_t rotr32(uint32_t w, uint32_t c)
{
    return (w >> c) | (w << (32u - c));
}

static void blake2s_init_state(blake2s_state *S, size_t outlen, size_t keylen)
{
    for (size_t i = 0; i < BLAKE2S_CHAIN_WORDS; i++)
    {
        S->h[i] = blake2s_iv[i];
    }

    S->h[0] ^= 0x01010000u ^ ((uint32_t)keylen << 8) ^ (uint32_t)outlen;
    S->t[0] = 0u;
    S->t[1] = 0u;
    S->f[0] = 0u;
    S->f[1] = 0u;
    S->buflen = 0u;
    S->outlen = outlen;
    memset(S->buf, 0, sizeof(S->buf));
}

static void blake2s_increment_counter(blake2s_state *S, uint32_t inc)
{
    S->t[0] += inc;
    if (S->t[0] < inc)
    {
        S->t[1]++;
    }
}

static void blake2s_compress(blake2s_state *S, const uint8_t block[BLAKE2S_BLOCKBYTES], int last)
{
    uint32_t m[BLAKE2S_MSG_WORDS];
    uint32_t v[16];

    for (size_t i = 0; i < BLAKE2S_MSG_WORDS; i++)
    {
        m[i] = load32(block + (i * 4u));
    }

    for (size_t i = 0; i < BLAKE2S_CHAIN_WORDS; i++)
    {
        v[i] = S->h[i];
    }

    v[8] = blake2s_iv[0];
    v[9] = blake2s_iv[1];
    v[10] = blake2s_iv[2];
    v[11] = blake2s_iv[3];
    v[12] = blake2s_iv[4] ^ S->t[0];
    v[13] = blake2s_iv[5] ^ S->t[1];
    v[14] = blake2s_iv[6] ^ S->f[0];
    v[15] = blake2s_iv[7] ^ S->f[1];

    if (last)
    {
        v[14] ^= 0xFFFFFFFFu;
    }

    for (size_t round = 0; round < 10u; round++)
    {
        const uint8_t *s = blake2s_sigma[round];

        #define G(r, i, a, b, c, d)                                     \
            do                                                            \
            {                                                             \
                a = a + b + m[s[2 * i + 0]];                              \
                d = rotr32(d ^ a, 16u);                                   \
                c = c + d;                                                \
                b = rotr32(b ^ c, 12u);                                   \
                a = a + b + m[s[2 * i + 1]];                              \
                d = rotr32(d ^ a, 8u);                                    \
                c = c + d;                                                \
                b = rotr32(b ^ c, 7u);                                    \
            } while (0)

        G(round, 0, v[0], v[4], v[8], v[12]);
        G(round, 1, v[1], v[5], v[9], v[13]);
        G(round, 2, v[2], v[6], v[10], v[14]);
        G(round, 3, v[3], v[7], v[11], v[15]);
        G(round, 4, v[0], v[5], v[10], v[15]);
        G(round, 5, v[1], v[6], v[11], v[12]);
        G(round, 6, v[2], v[7], v[8], v[13]);
        G(round, 7, v[3], v[4], v[9], v[14]);

        #undef G
    }

    for (size_t i = 0; i < BLAKE2S_CHAIN_WORDS; i++)
    {
        S->h[i] ^= v[i] ^ v[i + 8];
    }
}

static void blake2s_update_internal(blake2s_state *S, const uint8_t *in, size_t inlen)
{
    size_t left = S->buflen;
    size_t fill = BLAKE2S_BLOCKBYTES - left;

    if (inlen > 0u)
    {
        if (inlen > fill)
        {
            memcpy(S->buf + left, in, fill);
            blake2s_increment_counter(S, (uint32_t)BLAKE2S_BLOCKBYTES);
            blake2s_compress(S, S->buf, 0);
            in += fill;
            inlen -= fill;
            left = 0u;

            while (inlen > BLAKE2S_BLOCKBYTES)
            {
                blake2s_increment_counter(S, (uint32_t)BLAKE2S_BLOCKBYTES);
                blake2s_compress(S, in, 0);
                in += BLAKE2S_BLOCKBYTES;
                inlen -= BLAKE2S_BLOCKBYTES;
            }
        }

        memcpy(S->buf + left, in, inlen);
        S->buflen = left + inlen;
    }
}

static void blake2s_final_internal(blake2s_state *S, uint8_t *out)
{
    if (S->f[0] != 0u)
    {
        return;
    }

    blake2s_increment_counter(S, (uint32_t)S->buflen);
    S->f[0] = 0xFFFFFFFFu;
    while (S->buflen < BLAKE2S_BLOCKBYTES)
    {
        S->buf[S->buflen++] = 0u;
    }
    blake2s_compress(S, S->buf, 1);

    for (size_t i = 0; i < BLAKE2S_CHAIN_WORDS; i++)
    {
        store32(out + (i * 4u), S->h[i]);
    }
}

void blake2s_mac(uint8_t *out, const void *data, size_t len, const void *key, size_t keylen)
{
    if (out == NULL)
    {
        return;
    }

    if (keylen == 0u || keylen > BLAKE2S_KEYBYTES)
    {
        return;
    }

    blake2s_state S;
    blake2s_init_state(&S, BLAKE2S_MAC_LEN, keylen);

    uint8_t block[BLAKE2S_BLOCKBYTES];
    memset(block, 0, sizeof(block));
    memcpy(block, key, keylen);
    blake2s_update_internal(&S, block, sizeof(block));
    memset(block, 0, sizeof(block));

    blake2s_update_internal(&S, (const uint8_t *)data, len);

    uint8_t full_out[BLAKE2S_OUTBYTES];
    blake2s_final_internal(&S, full_out);
    memcpy(out, full_out, BLAKE2S_MAC_LEN);
    memset(full_out, 0, sizeof(full_out));
    memset(&S, 0, sizeof(S));
}
