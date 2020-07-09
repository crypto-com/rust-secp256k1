/**********************************************************************
 * Copyright (c) 2020 Gregory Maxwell                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <valgrind/memcheck.h>
#include "include/secp256k1.h"
#include "util.h"

#if ENABLE_MODULE_ECDH
# include "include/rustsecp256k1_v0_1_2_ecdh.h"
#endif

#if ENABLE_MODULE_EXTRAKEYS
# include "include/rustsecp256k1_v0_1_2_extrakeys.h"
#endif

#if ENABLE_MODULE_SCHNORRSIG
#include "include/secp256k1_schnorrsig.h"
#endif

int main(void) {
    rustsecp256k1_v0_1_2_context* ctx;
    rustsecp256k1_v0_1_2_ecdsa_signature signature;
    rustsecp256k1_v0_1_2_pubkey pubkey;
    size_t siglen = 74;
    size_t outputlen = 33;
    int i;
    int ret;
    unsigned char msg[32];
    unsigned char key[32];
    unsigned char sig[74];
    unsigned char spubkey[33];
#if ENABLE_MODULE_EXTRAKEYS
    rustsecp256k1_v0_1_2_keypair keypair;
#endif

    if (!RUNNING_ON_VALGRIND) {
        fprintf(stderr, "This test can only usefully be run inside valgrind.\n");
        fprintf(stderr, "Usage: libtool --mode=execute valgrind ./valgrind_ctime_test\n");
        exit(1);
    }

    /** In theory, testing with a single secret input should be sufficient:
     *  If control flow depended on secrets the tool would generate an error.
     */
    for (i = 0; i < 32; i++) {
        key[i] = i + 65;
    }
    for (i = 0; i < 32; i++) {
        msg[i] = i + 1;
    }

    ctx = rustsecp256k1_v0_1_2_context_create(SECP256K1_CONTEXT_SIGN
                                   | SECP256K1_CONTEXT_VERIFY
                                   | SECP256K1_CONTEXT_DECLASSIFY);

    /* Test keygen. */
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = rustsecp256k1_v0_1_2_ec_pubkey_create(ctx, &pubkey, key);
    VALGRIND_MAKE_MEM_DEFINED(&pubkey, sizeof(rustsecp256k1_v0_1_2_pubkey));
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret);
    CHECK(rustsecp256k1_v0_1_2_ec_pubkey_serialize(ctx, spubkey, &outputlen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

    /* Test signing. */
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = rustsecp256k1_v0_1_2_ecdsa_sign(ctx, &signature, msg, key, NULL, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&signature, sizeof(rustsecp256k1_v0_1_2_ecdsa_signature));
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret);
    CHECK(rustsecp256k1_v0_1_2_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature));

#if ENABLE_MODULE_ECDH
    /* Test ECDH. */
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = rustsecp256k1_v0_1_2_ecdh(ctx, msg, &pubkey, key, NULL, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);
#endif

    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = rustsecp256k1_v0_1_2_ec_seckey_verify(ctx, key);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = rustsecp256k1_v0_1_2_ec_seckey_negate(ctx, key);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    VALGRIND_MAKE_MEM_UNDEFINED(msg, 32);
    ret = rustsecp256k1_v0_1_2_ec_seckey_tweak_add(ctx, key, msg);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    VALGRIND_MAKE_MEM_UNDEFINED(msg, 32);
    ret = rustsecp256k1_v0_1_2_ec_seckey_tweak_mul(ctx, key, msg);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    /* Test context randomisation. Do this last because it leaves the context tainted. */
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = rustsecp256k1_v0_1_2_context_randomize(ctx, key);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret);

    /* Test keypair_create and keypair_xonly_tweak_add. */
#if ENABLE_MODULE_EXTRAKEYS
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = rustsecp256k1_v0_1_2_keypair_create(ctx, &keypair, key);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    /* The tweak is not treated as a secret in keypair_tweak_add */
    VALGRIND_MAKE_MEM_DEFINED(msg, 32);
    ret = rustsecp256k1_v0_1_2_keypair_xonly_tweak_add(ctx, &keypair, msg);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);
#endif

#if ENABLE_MODULE_SCHNORRSIG
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = rustsecp256k1_v0_1_2_keypair_create(ctx, &keypair, key);
    ret = rustsecp256k1_v0_1_2_schnorrsig_sign(ctx, sig, msg, &keypair, NULL, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);
#endif

    rustsecp256k1_v0_1_2_context_destroy(ctx);
    return 0;
}