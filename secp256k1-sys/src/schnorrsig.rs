use ::{Context, NonceFn, PublicKey};
use core::hash;
use ::types::{c_int, c_uchar, c_void};

/// Library-internal representation of a Secp256k1 "x-only" public key
#[repr(C)]
pub struct XOnlyPublicKey([c_uchar; 64]);
impl_array_newtype!(XOnlyPublicKey, c_uchar, 64);
impl_raw_debug!(XOnlyPublicKey);

impl XOnlyPublicKey {
    /// Create a new (zeroed) x-only public key usable for the FFI interface
    pub fn new() -> XOnlyPublicKey { XOnlyPublicKey([0; 64]) }
}

impl Default for XOnlyPublicKey {
    fn default() -> Self {
        XOnlyPublicKey::new()
    }
}

impl hash::Hash for XOnlyPublicKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}

/// Library-internal representation of a Secp256k1 keypair
#[repr(C)]
pub struct Secp256k1KeyPair([c_uchar; 96]);
impl_array_newtype!(Secp256k1KeyPair, c_uchar, 96);
impl_raw_debug!(Secp256k1KeyPair);

impl Secp256k1KeyPair {
    /// Create a new (zeroed) keypair usable for the FFI interface
    pub fn new() -> Secp256k1KeyPair { Secp256k1KeyPair([0; 96]) }
}

impl Default for Secp256k1KeyPair {
    fn default() -> Self {
        Secp256k1KeyPair::new()
    }
}

#[cfg(not(feature = "fuzztarget"))]
extern "C" {
    // x-only pubkey
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_1_2_xonly_pubkey_parse")]
    pub fn secp256k1_xonly_pubkey_parse(ctx: *const Context,
                                        pubkey: *mut XOnlyPublicKey,
                                        input32: *const c_uchar)
                                        -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_1_2_xonly_pubkey_serialize")]
    pub fn secp256k1_xonly_pubkey_serialize(ctx: *const Context,
                                            output32: *mut c_uchar,
                                            pubkey: *const XOnlyPublicKey)
                                            -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_1_2_xonly_pubkey_from_pubkey")]
    pub fn secp256k1_xonly_pubkey_from_pubkey(ctx: *const Context,
                                              xonly_pubkey: *mut XOnlyPublicKey,
                                              is_negated: *mut c_int,
                                              pubkey: *const PublicKey)
                                              -> c_int;

    // keypair
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_1_2_keypair_create")]
    pub fn secp256k1_keypair_create(ctx: *const Context,
                                    keypair: *mut Secp256k1KeyPair,
                                    seckey: *const c_uchar)
                                    -> c_int;

    // SchnorrSig
    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_1_2_schnorrsig_verify")]
    pub fn secp256k1_schnorrsig_verify(ctx: *const Context,
                                       sig64: *const c_uchar,
                                       msg32: *const c_uchar,
                                       pk: *const XOnlyPublicKey)
                                       -> c_int;

    #[cfg_attr(not(feature = "external-symbols"), link_name = "rustsecp256k1_v0_1_2_schnorrsig_sign")]
    pub fn secp256k1_schnorrsig_sign(ctx: *const Context,
                                     sig64: *mut c_uchar,
                                     msg32: *const c_uchar,
                                     keypair: *const Secp256k1KeyPair,
                                     noncefn: Option<NonceFn>,
                                     ndata: *const c_void)
                                     -> c_int;
}