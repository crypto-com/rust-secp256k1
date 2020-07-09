/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_SCHNORRSIG_MAIN_
#define _SECP256K1_MODULE_SCHNORRSIG_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_schnorrsig.h"
#include "hash.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP340/nonce")||SHA256("BIP340/nonce"). */
static void rustsecp256k1_v0_1_2_nonce_function_bip340_sha256_tagged(rustsecp256k1_v0_1_2_sha256 *sha) {
    rustsecp256k1_v0_1_2_sha256_initialize(sha);
    sha->s[0] = 0xa96e75cbul;
    sha->s[1] = 0x74f9f0acul;
    sha->s[2] = 0xc49e3c98ul;
    sha->s[3] = 0x202f99baul;
    sha->s[4] = 0x8946a616ul;
    sha->s[5] = 0x4accf415ul;
    sha->s[6] = 0x86e335c3ul;
    sha->s[7] = 0x48d0a072ul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP340/aux")||SHA256("BIP340/aux"). */
static void rustsecp256k1_v0_1_2_nonce_function_bip340_sha256_tagged_aux(rustsecp256k1_v0_1_2_sha256 *sha) {
    rustsecp256k1_v0_1_2_sha256_initialize(sha);
    sha->s[0] = 0x5d74a872ul;
    sha->s[1] = 0xd57064d4ul;
    sha->s[2] = 0x89495becul;
    sha->s[3] = 0x910f46f5ul;
    sha->s[4] = 0xcbc6fd3eul;
    sha->s[5] = 0xaf05d9d0ul;
    sha->s[6] = 0xcb781ce6ul;
    sha->s[7] = 0x062930acul;

    sha->bytes = 64;
}

/* algo16 argument for nonce_function_bip340 to derive the nonce exactly as stated in BIP-340
 * by using the correct tagged hash function. */
static const unsigned char bip340_algo16[16] = "BIP340/nonce\0\0\0\0";

static int nonce_function_bip340(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo16, void *data, unsigned int counter) {
    rustsecp256k1_v0_1_2_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (counter != 0) {
        return 0;
    }
    if (algo16 == NULL) {
        return 0;
    }

    if (data != NULL) {
        rustsecp256k1_v0_1_2_nonce_function_bip340_sha256_tagged_aux(&sha);
        rustsecp256k1_v0_1_2_sha256_write(&sha, data, 32);
        rustsecp256k1_v0_1_2_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    }

    /* Tag the hash with algo16 which is important to avoid nonce reuse across
     * algorithms. If this nonce function is used in BIP-340 signing as defined
     * in the spec, an optimized tagging implementation is used. */
    if (memcmp(algo16, bip340_algo16, 16) == 0) {
        rustsecp256k1_v0_1_2_nonce_function_bip340_sha256_tagged(&sha);
    } else {
        int algo16_len;
        /* Remove terminating null bytes */
        algo16_len = 16;
        while (algo16_len > 0 && !algo16[algo16_len - 1]) {
            algo16_len--;
        }
        rustsecp256k1_v0_1_2_sha256_initialize_tagged(&sha, algo16, algo16_len);
    }

    /* Hash (masked-)key||pk||msg using the tagged hash as per the spec */
    if (data != NULL) {
        rustsecp256k1_v0_1_2_sha256_write(&sha, masked_key, 32);
    } else {
        rustsecp256k1_v0_1_2_sha256_write(&sha, key32, 32);
    }
    rustsecp256k1_v0_1_2_sha256_write(&sha, xonly_pk32, 32);
    rustsecp256k1_v0_1_2_sha256_write(&sha, msg32, 32);
    rustsecp256k1_v0_1_2_sha256_finalize(&sha, nonce32);
    return 1;
}

const rustsecp256k1_v0_1_2_nonce_function_hardened rustsecp256k1_v0_1_2_nonce_function_bip340 = nonce_function_bip340;

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP340/challenge")||SHA256("BIP340/challenge"). */
static void rustsecp256k1_v0_1_2_schnorrsig_sha256_tagged(rustsecp256k1_v0_1_2_sha256 *sha) {
    rustsecp256k1_v0_1_2_sha256_initialize(sha);
    sha->s[0] = 0x71985ac9ul;
    sha->s[1] = 0x198317a2ul;
    sha->s[2] = 0x60b6e581ul;
    sha->s[3] = 0x54c109b6ul;
    sha->s[4] = 0x64bac2fdul;
    sha->s[5] = 0x91231de2ul;
    sha->s[6] = 0x7301ebdeul;
    sha->s[7] = 0x87635f83ul;
    sha->bytes = 64;
}

int rustsecp256k1_v0_1_2_schnorrsig_sign(const rustsecp256k1_v0_1_2_context* ctx, unsigned char *sig64, const unsigned char *msg32, const rustsecp256k1_v0_1_2_keypair *keypair, rustsecp256k1_v0_1_2_nonce_function_hardened noncefp, void *ndata) {
    rustsecp256k1_v0_1_2_scalar sk;
    rustsecp256k1_v0_1_2_scalar e;
    rustsecp256k1_v0_1_2_scalar k;
    rustsecp256k1_v0_1_2_gej rj;
    rustsecp256k1_v0_1_2_ge pk;
    rustsecp256k1_v0_1_2_ge r;
    rustsecp256k1_v0_1_2_sha256 sha;
    unsigned char buf[32] = { 0 };
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_1_2_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(keypair != NULL);

    if (noncefp == NULL) {
        noncefp = rustsecp256k1_v0_1_2_nonce_function_bip340;
    }

    ret &= rustsecp256k1_v0_1_2_keypair_load(ctx, &sk, &pk, keypair);
    /* Because we are signing for a x-only pubkey, the secret key is negated
     * before signing if the point corresponding to the secret key does not
     * have an even Y. */
    if (rustsecp256k1_v0_1_2_fe_is_odd(&pk.y)) {
        rustsecp256k1_v0_1_2_scalar_negate(&sk, &sk);
    }

    rustsecp256k1_v0_1_2_scalar_get_b32(seckey, &sk);
    rustsecp256k1_v0_1_2_fe_get_b32(pk_buf, &pk.x);
    ret &= !!noncefp(buf, msg32, seckey, pk_buf, bip340_algo16, (void*)ndata, 0);
    rustsecp256k1_v0_1_2_scalar_set_b32(&k, buf, NULL);
    ret &= !rustsecp256k1_v0_1_2_scalar_is_zero(&k);
    rustsecp256k1_v0_1_2_scalar_cmov(&k, &rustsecp256k1_v0_1_2_scalar_one, !ret);

    rustsecp256k1_v0_1_2_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    rustsecp256k1_v0_1_2_ge_set_gej(&r, &rj);

    /* We declassify r to allow using it as a branch point. This is fine
     * because r is not a secret. */
    rustsecp256k1_v0_1_2_declassify(ctx, &r, sizeof(r));
    if (!rustsecp256k1_v0_1_2_fe_is_quad_var(&r.y)) {
        rustsecp256k1_v0_1_2_scalar_negate(&k, &k);
    }
    rustsecp256k1_v0_1_2_fe_normalize_var(&r.x);
    rustsecp256k1_v0_1_2_fe_get_b32(&sig64[0], &r.x);

    /* tagged hash(r.x, pk.x, msg32) */
    rustsecp256k1_v0_1_2_schnorrsig_sha256_tagged(&sha);
    rustsecp256k1_v0_1_2_sha256_write(&sha, &sig64[0], 32);
    rustsecp256k1_v0_1_2_sha256_write(&sha, pk_buf, sizeof(pk_buf));
    rustsecp256k1_v0_1_2_sha256_write(&sha, msg32, 32);
    rustsecp256k1_v0_1_2_sha256_finalize(&sha, buf);

    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    rustsecp256k1_v0_1_2_scalar_set_b32(&e, buf, NULL);
    rustsecp256k1_v0_1_2_scalar_mul(&e, &e, &sk);
    rustsecp256k1_v0_1_2_scalar_add(&e, &e, &k);
    rustsecp256k1_v0_1_2_scalar_get_b32(&sig64[32], &e);

    memczero(sig64, 64, !ret);
    rustsecp256k1_v0_1_2_scalar_clear(&k);
    rustsecp256k1_v0_1_2_scalar_clear(&sk);
    memset(seckey, 0, sizeof(seckey));

    return ret;
}

int rustsecp256k1_v0_1_2_schnorrsig_verify(const rustsecp256k1_v0_1_2_context* ctx, const unsigned char *sig64, const unsigned char *msg32, const rustsecp256k1_v0_1_2_xonly_pubkey *pubkey) {
    rustsecp256k1_v0_1_2_scalar s;
    rustsecp256k1_v0_1_2_scalar e;
    rustsecp256k1_v0_1_2_gej rj;
    rustsecp256k1_v0_1_2_ge pk;
    rustsecp256k1_v0_1_2_gej pkj;
    rustsecp256k1_v0_1_2_fe rx;
    rustsecp256k1_v0_1_2_sha256 sha;
    unsigned char buf[32];
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_1_2_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);

    if (!rustsecp256k1_v0_1_2_fe_set_b32(&rx, &sig64[0])) {
        return 0;
    }

    rustsecp256k1_v0_1_2_scalar_set_b32(&s, &sig64[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!rustsecp256k1_v0_1_2_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    rustsecp256k1_v0_1_2_schnorrsig_sha256_tagged(&sha);
    rustsecp256k1_v0_1_2_sha256_write(&sha, &sig64[0], 32);
    rustsecp256k1_v0_1_2_fe_get_b32(buf, &pk.x);
    rustsecp256k1_v0_1_2_sha256_write(&sha, buf, sizeof(buf));
    rustsecp256k1_v0_1_2_sha256_write(&sha, msg32, 32);
    rustsecp256k1_v0_1_2_sha256_finalize(&sha, buf);
    rustsecp256k1_v0_1_2_scalar_set_b32(&e, buf, NULL);

    /* Compute rj =  s*G + (-e)*pkj */
    rustsecp256k1_v0_1_2_scalar_negate(&e, &e);
    rustsecp256k1_v0_1_2_gej_set_ge(&pkj, &pk);
    rustsecp256k1_v0_1_2_ecmult(&ctx->ecmult_ctx, &rj, &pkj, &e, &s);

    return rustsecp256k1_v0_1_2_gej_has_quad_y_var(&rj) /* fails if rj is infinity */
            && rustsecp256k1_v0_1_2_gej_eq_x_var(&rx, &rj);
}

#endif
