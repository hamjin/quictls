/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* chacha20_d_poly1305 cipher implementation */

#include <internal/endian.h>
#include "cipher_chacha20_d_poly1305.h"

static int chacha20_d_poly1305_tls_init(PROV_CIPHER_CTX *bctx,
                                    unsigned char *aad, size_t alen)
{
    unsigned int len;
    PROV_CHACHA20_D_POLY1305_CTX *ctx = (PROV_CHACHA20_D_POLY1305_CTX *)bctx;

    if (alen != EVP_AEAD_TLS1_AAD_LEN)
        return 0;

    memcpy(ctx->tls_aad, aad, EVP_AEAD_TLS1_AAD_LEN);
    len = aad[EVP_AEAD_TLS1_AAD_LEN - 2] << 8 | aad[EVP_AEAD_TLS1_AAD_LEN - 1];
    aad = ctx->tls_aad;
    if (!bctx->enc) {
        if (len < POLY1305_BLOCK_SIZE)
            return 0;
        len -= POLY1305_BLOCK_SIZE; /* discount attached tag */
        aad[EVP_AEAD_TLS1_AAD_LEN - 2] = (unsigned char)(len >> 8);
        aad[EVP_AEAD_TLS1_AAD_LEN - 1] = (unsigned char)len;
    }
    ctx->tls_payload_length = len;

    /* merge record sequence number as per RFC7905 */
    ctx->chacha.counter[1] = ctx->nonce[0];
    ctx->chacha.counter[2] = ctx->nonce[1] ^ CHACHA_U8TOU32(aad);
    ctx->chacha.counter[3] = ctx->nonce[2] ^ CHACHA_U8TOU32(aad+4);
    ctx->mac_inited = 0;

    return POLY1305_BLOCK_SIZE;         /* tag length */
}

static int chacha20_d_poly1305_initkey(PROV_CIPHER_CTX *bctx,
                                     const unsigned char *key, size_t keylen)
{
    PROV_CHACHA20_D_POLY1305_CTX *ctx = (PROV_CHACHA20_D_POLY1305_CTX *)bctx;

    ctx->len.aad = 0;
    ctx->len.text = 0;
    ctx->aad = 0;
    ctx->mac_inited = 0;
    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

    if (bctx->enc)
        return ossl_chacha20_einit(&ctx->chacha, key, keylen, NULL, 0, NULL);
    else
        return ossl_chacha20_dinit(&ctx->chacha, key, keylen, NULL, 0, NULL);
}

#if !defined(OPENSSL_SMALL_FOOTPRINT)

# if defined(POLY1305_ASM) && (defined(__x86_64) || defined(__x86_64__) \
     || defined(_M_AMD64) || defined(_M_X64))
#  define XOR128_HELPERS
static const unsigned char zero[4 * CHACHA_BLK_SIZE] = { 0 };
# else
static const unsigned char zero[2 * CHACHA_BLK_SIZE] = { 0 };
# endif

#else
static const unsigned char zero[CHACHA_BLK_SIZE] = { 0 };
#endif /* OPENSSL_SMALL_FOOTPRINT */

static int chacha20_d_poly1305_aead_cipher(PROV_CIPHER_CTX *bctx,
                                         unsigned char *out, size_t *outl,
                                         const unsigned char *in, size_t inl)
{
    PROV_CHACHA20_D_POLY1305_CTX *ctx = (PROV_CHACHA20_D_POLY1305_CTX *)bctx;
    POLY1305 *poly = &ctx->poly1305;
    size_t rem, plen = ctx->tls_payload_length;
    size_t olen = 0;
    int rv = 0;
    uint64_t thirteen = EVP_AEAD_TLS1_AAD_LEN;

    DECLARE_IS_ENDIAN;

    if (!ctx->mac_inited) {
        ctx->chacha.counter[0] = 0;
        ChaCha20_ctr32(ctx->chacha.buf, zero, CHACHA_BLK_SIZE,
                       ctx->chacha.key.d, ctx->chacha.counter);
        Poly1305_Init(poly, ctx->chacha.buf);
        ctx->chacha.counter[0] = 1;
        ctx->chacha.partial_len = 0;
        ctx->len.aad = ctx->len.text = 0;
        ctx->mac_inited = 1;
        if (plen != NO_TLS_PAYLOAD_LENGTH) {
            Poly1305_Update(poly, ctx->tls_aad, EVP_AEAD_TLS1_AAD_LEN);
            ctx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
            ctx->aad = 1;
        }
    }

    if (in != NULL) { /* aad or text */
        if (out == NULL) { /* aad */
            Poly1305_Update(poly, in, inl);
            ctx->len.aad += inl;
            ctx->aad = 1;
            goto finish;
        } else { /* plain- or ciphertext */
            if (ctx->aad) { /* wrap up aad */
                thirteen = ctx->len.aad;
                Poly1305_Update(poly, (const unsigned char *)&thirteen, sizeof(thirteen));
                ctx->aad = 0;
            }

            ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
            if (plen == NO_TLS_PAYLOAD_LENGTH)
                plen = inl;
            else if (inl != plen + POLY1305_BLOCK_SIZE)
                goto err;

            if (bctx->enc) { /* plaintext */
                ctx->chacha.base.hw->cipher(&ctx->chacha.base, out, in, plen);
                Poly1305_Update(poly, out, plen);
                in += plen;
                out += plen;
                ctx->len.text += plen;
            } else { /* ciphertext */
                Poly1305_Update(poly, in, plen);
                ctx->chacha.base.hw->cipher(&ctx->chacha.base, out, in, plen);
                in += plen;
                out += plen;
                ctx->len.text += plen;
            }
        }
    }
    /* explicit final, or tls mode */
    if (in == NULL || inl != plen) {

        unsigned char temp[POLY1305_BLOCK_SIZE];

        thirteen = ctx->len.text;
        Poly1305_Update(poly, (const unsigned char *)&thirteen, sizeof(thirteen));


        if (ctx->aad) {                        /* wrap up aad */
            thirteen = ctx->len.aad;
            Poly1305_Update(poly, (const unsigned char *)&thirteen, sizeof(thirteen));
            ctx->aad = 0;
        }

        Poly1305_Final(poly, bctx->enc ? ctx->tag : temp);
        ctx->mac_inited = 0;

        if (in != NULL && inl != plen) {
            if (bctx->enc) {
                memcpy(out, ctx->tag, POLY1305_BLOCK_SIZE);
            } else {
                if (CRYPTO_memcmp(temp, in, POLY1305_BLOCK_SIZE)) {
                    memset(out - plen, 0, plen);
                    goto err;
                }
                /* Strip the tag */
                inl -= POLY1305_BLOCK_SIZE;
            }
        }
        else if (!bctx->enc) {
            if (CRYPTO_memcmp(temp, ctx->tag, ctx->tag_len))
                goto err;
        }
    }
finish:
    olen = inl;
    rv = 1;
err:
    *outl = olen;
    return rv;
}

static const PROV_CIPHER_HW_CHACHA20_D_POLY1305 chacha20poly1305_hw =
{
    { chacha20_d_poly1305_initkey, NULL },
    chacha20_d_poly1305_aead_cipher,
    chacha20_d_poly1305_tls_init,
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_chacha20_d_poly1305(size_t keybits)
{
    return (PROV_CIPHER_HW *)&chacha20poly1305_hw;
}
