/**********************************************************************
 * Copyright (c) 2020 Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_EXTRAKEYS_MAIN_
#define _SECP256K1_MODULE_EXTRAKEYS_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_extrakeys.h"

static SECP256K1_INLINE int rustsecp256k1_v0_1_2_xonly_pubkey_load(const rustsecp256k1_v0_1_2_context* ctx, rustsecp256k1_v0_1_2_ge *ge, const rustsecp256k1_v0_1_2_xonly_pubkey *pubkey) {
    return rustsecp256k1_v0_1_2_pubkey_load(ctx, ge, (const rustsecp256k1_v0_1_2_pubkey *) pubkey);
}

static SECP256K1_INLINE void rustsecp256k1_v0_1_2_xonly_pubkey_save(rustsecp256k1_v0_1_2_xonly_pubkey *pubkey, rustsecp256k1_v0_1_2_ge *ge) {
    rustsecp256k1_v0_1_2_pubkey_save((rustsecp256k1_v0_1_2_pubkey *) pubkey, ge);
}

int rustsecp256k1_v0_1_2_xonly_pubkey_parse(const rustsecp256k1_v0_1_2_context* ctx, rustsecp256k1_v0_1_2_xonly_pubkey *pubkey, const unsigned char *input32) {
    rustsecp256k1_v0_1_2_ge pk;
    rustsecp256k1_v0_1_2_fe x;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input32 != NULL);

    if (!rustsecp256k1_v0_1_2_fe_set_b32(&x, input32)) {
        return 0;
    }
    if (!rustsecp256k1_v0_1_2_ge_set_xo_var(&pk, &x, 0)) {
        return 0;
    }
    rustsecp256k1_v0_1_2_xonly_pubkey_save(pubkey, &pk);
    rustsecp256k1_v0_1_2_ge_clear(&pk);
    return 1;
}

int rustsecp256k1_v0_1_2_xonly_pubkey_serialize(const rustsecp256k1_v0_1_2_context* ctx, unsigned char *output32, const rustsecp256k1_v0_1_2_xonly_pubkey *pubkey) {
    rustsecp256k1_v0_1_2_ge pk;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output32 != NULL);
    memset(output32, 0, 32);
    ARG_CHECK(pubkey != NULL);

    if (!rustsecp256k1_v0_1_2_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }
    rustsecp256k1_v0_1_2_fe_get_b32(output32, &pk.x);
    return 1;
}

int rustsecp256k1_v0_1_2_xonly_pubkey_from_pubkey(const rustsecp256k1_v0_1_2_context* ctx, rustsecp256k1_v0_1_2_xonly_pubkey *xonly_pubkey, int *y_parity, const rustsecp256k1_v0_1_2_pubkey *pubkey) {
    rustsecp256k1_v0_1_2_ge pk;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(xonly_pubkey != NULL);
    ARG_CHECK(pubkey != NULL);

    rustsecp256k1_v0_1_2_pubkey_load(ctx, &pk, pubkey);
    rustsecp256k1_v0_1_2_ge_even_y(&pk, y_parity);
    rustsecp256k1_v0_1_2_xonly_pubkey_save(xonly_pubkey, &pk);
    return 1;
}

int rustsecp256k1_v0_1_2_xonly_pubkey_tweak_add(const rustsecp256k1_v0_1_2_context* ctx, rustsecp256k1_v0_1_2_pubkey *output_pubkey, const rustsecp256k1_v0_1_2_xonly_pubkey *internal_pubkey, const unsigned char *tweak32) {
    rustsecp256k1_v0_1_2_ge pk;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_1_2_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(output_pubkey != NULL);
    ARG_CHECK(internal_pubkey != NULL);
    ARG_CHECK(tweak32 != NULL);

    memset(output_pubkey, 0, sizeof(*output_pubkey));
    if (!rustsecp256k1_v0_1_2_xonly_pubkey_load(ctx, &pk, internal_pubkey)
        || !rustsecp256k1_v0_1_2_ec_pubkey_tweak_add_helper(&ctx->ecmult_ctx, &pk, tweak32)) {
        return 0;
    }
    rustsecp256k1_v0_1_2_pubkey_save(output_pubkey, &pk);
    return 1;
}

int rustsecp256k1_v0_1_2_xonly_pubkey_tweak_add_test(const rustsecp256k1_v0_1_2_context* ctx, const unsigned char *output_pubkey32, int output_pubkey_parity, const rustsecp256k1_v0_1_2_xonly_pubkey *internal_pubkey, const unsigned char *tweak32) {
    rustsecp256k1_v0_1_2_ge pk;
    unsigned char pk_expected32[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_1_2_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(internal_pubkey != NULL);
    ARG_CHECK(output_pubkey32 != NULL);
    ARG_CHECK(tweak32 != NULL);

    if (!rustsecp256k1_v0_1_2_xonly_pubkey_load(ctx, &pk, internal_pubkey)
        || !rustsecp256k1_v0_1_2_ec_pubkey_tweak_add_helper(&ctx->ecmult_ctx, &pk, tweak32)) {
        return 0;
    }
    rustsecp256k1_v0_1_2_fe_normalize_var(&pk.x);
    rustsecp256k1_v0_1_2_fe_normalize_var(&pk.y);
    rustsecp256k1_v0_1_2_fe_get_b32(pk_expected32, &pk.x);

    return memcmp(&pk_expected32, output_pubkey32, 32) == 0
            && rustsecp256k1_v0_1_2_fe_is_odd(&pk.y) == output_pubkey_parity;
}

static void rustsecp256k1_v0_1_2_keypair_save(rustsecp256k1_v0_1_2_keypair *keypair, const rustsecp256k1_v0_1_2_scalar *sk, rustsecp256k1_v0_1_2_ge *pk) {
    rustsecp256k1_v0_1_2_scalar_get_b32(&keypair->data[0], sk);
    rustsecp256k1_v0_1_2_pubkey_save((rustsecp256k1_v0_1_2_pubkey *)&keypair->data[32], pk);
}


static int rustsecp256k1_v0_1_2_keypair_seckey_load(const rustsecp256k1_v0_1_2_context* ctx, rustsecp256k1_v0_1_2_scalar *sk, const rustsecp256k1_v0_1_2_keypair *keypair) {
    int ret;

    rustsecp256k1_v0_1_2_scalar_set_b32(sk, &keypair->data[0], NULL);
    ret = !rustsecp256k1_v0_1_2_scalar_is_zero(sk);
    /* We can declassify ret here because sk is only zero if a keypair function
     * failed (which zeroes the keypair) and its return value is ignored. */
    rustsecp256k1_v0_1_2_declassify(ctx, &ret, sizeof(ret));
    ARG_CHECK(ret);
    return 1;
}

/* Load a keypair into pk and sk (if non-NULL). This function declassifies pk
 * and ARG_CHECKs that the keypair is not invalid. It always initializes sk and
 * pk with dummy values. */
static int rustsecp256k1_v0_1_2_keypair_load(const rustsecp256k1_v0_1_2_context* ctx, rustsecp256k1_v0_1_2_scalar *sk, rustsecp256k1_v0_1_2_ge *pk, const rustsecp256k1_v0_1_2_keypair *keypair) {
    int ret;
    const rustsecp256k1_v0_1_2_pubkey *pubkey = (const rustsecp256k1_v0_1_2_pubkey *)&keypair->data[32];

    /* Need to declassify the pubkey because pubkey_load ARG_CHECKs if it's
     * invalid. */
    rustsecp256k1_v0_1_2_declassify(ctx, pubkey, sizeof(*pubkey));
    ret = rustsecp256k1_v0_1_2_pubkey_load(ctx, pk, pubkey);
    if (sk != NULL) {
        ret = ret && rustsecp256k1_v0_1_2_keypair_seckey_load(ctx, sk, keypair);
    }
    if (!ret) {
        *pk = rustsecp256k1_v0_1_2_ge_const_g;
        if (sk != NULL) {
            *sk = rustsecp256k1_v0_1_2_scalar_one;
        }
    }
    return ret;
}

int rustsecp256k1_v0_1_2_keypair_create(const rustsecp256k1_v0_1_2_context* ctx, rustsecp256k1_v0_1_2_keypair *keypair, const unsigned char *seckey32) {
    rustsecp256k1_v0_1_2_scalar sk;
    rustsecp256k1_v0_1_2_ge pk;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(keypair != NULL);
    memset(keypair, 0, sizeof(*keypair));
    ARG_CHECK(rustsecp256k1_v0_1_2_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(seckey32 != NULL);

    ret = rustsecp256k1_v0_1_2_ec_pubkey_create_helper(&ctx->ecmult_gen_ctx, &sk, &pk, seckey32);
    rustsecp256k1_v0_1_2_keypair_save(keypair, &sk, &pk);
    memczero(keypair, sizeof(*keypair), !ret);

    rustsecp256k1_v0_1_2_scalar_clear(&sk);
    return ret;
}

int rustsecp256k1_v0_1_2_keypair_pub(const rustsecp256k1_v0_1_2_context* ctx, rustsecp256k1_v0_1_2_pubkey *pubkey, const rustsecp256k1_v0_1_2_keypair *keypair) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(keypair != NULL);

    memcpy(pubkey->data, &keypair->data[32], sizeof(*pubkey));
    return 1;
}

int rustsecp256k1_v0_1_2_keypair_xonly_pub(const rustsecp256k1_v0_1_2_context* ctx, rustsecp256k1_v0_1_2_xonly_pubkey *pubkey, int *pubkey_parity, const rustsecp256k1_v0_1_2_keypair *keypair) {
    rustsecp256k1_v0_1_2_ge pk;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(keypair != NULL);

    if (!rustsecp256k1_v0_1_2_keypair_load(ctx, NULL, &pk, keypair)) {
        return 0;
    }
    rustsecp256k1_v0_1_2_ge_even_y(&pk, pubkey_parity);
    rustsecp256k1_v0_1_2_xonly_pubkey_save(pubkey, &pk);

    return 1;
}

int rustsecp256k1_v0_1_2_keypair_xonly_tweak_add(const rustsecp256k1_v0_1_2_context* ctx, rustsecp256k1_v0_1_2_keypair *keypair, const unsigned char *tweak32) {
    rustsecp256k1_v0_1_2_ge pk;
    rustsecp256k1_v0_1_2_scalar sk;
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_1_2_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(tweak32 != NULL);

    ret = rustsecp256k1_v0_1_2_keypair_load(ctx, &sk, &pk, keypair);
    memset(keypair, 0, sizeof(*keypair));

    if (rustsecp256k1_v0_1_2_fe_is_odd(&pk.y)) {
        rustsecp256k1_v0_1_2_scalar_negate(&sk, &sk);
        rustsecp256k1_v0_1_2_ge_neg(&pk, &pk);
    }

    ret &= rustsecp256k1_v0_1_2_ec_seckey_tweak_add_helper(&sk, tweak32);
    rustsecp256k1_v0_1_2_scalar_cmov(&sk, &rustsecp256k1_v0_1_2_scalar_zero, !ret);
    ret &= rustsecp256k1_v0_1_2_ec_pubkey_tweak_add_helper(&ctx->ecmult_ctx, &pk, tweak32);

    rustsecp256k1_v0_1_2_declassify(ctx, &ret, sizeof(ret));
    if (ret) {
        rustsecp256k1_v0_1_2_keypair_save(keypair, &sk, &pk);
    }

    rustsecp256k1_v0_1_2_scalar_clear(&sk);
    return ret;
}

#endif
