//!  Various utilities for building scripts and deriving keys related to channels. These are
//!  largely of interest for those implementing chain::keysinterface::ChannelKeys message signing
//!  by hand.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

///  Build the commitment secret from the seed and the commitment number
#[no_mangle]
pub extern "C" fn build_commitment_secret(commitment_seed: *const [u8; 32], idx: u64) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = lightning::ln::chan_utils::build_commitment_secret(unsafe { &*commitment_seed}, idx);
	crate::c_types::ThirtyTwoBytes { data: ret }
}


use lightning::ln::chan_utils::TxCreationKeys as lnTxCreationKeysImport;
type lnTxCreationKeys = lnTxCreationKeysImport;

///  The set of public keys which are used in the creation of one commitment transaction.
///  These are derived from the channel base keys and per-commitment data.
#[must_use]
#[repr(C)]
pub struct TxCreationKeys {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut lnTxCreationKeys,
	pub _underlying_ref: bool,
}

impl Drop for TxCreationKeys {
	fn drop(&mut self) {
		if !self._underlying_ref && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner as *mut lnTxCreationKeys) };
		}
	}
}
#[no_mangle]
pub extern "C" fn TxCreationKeys_free(this_ptr: TxCreationKeys) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn TxCreationKeys_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut lnTxCreationKeys); }
}
impl Clone for TxCreationKeys {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			_underlying_ref: false,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TxCreationKeys_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut lnTxCreationKeys)).clone() })) as *mut c_void
}
///  The per-commitment public key which was used to derive the other keys.
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_per_commitment_point(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.per_commitment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
///  The per-commitment public key which was used to derive the other keys.
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_per_commitment_point(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.per_commitment_point = val.into_rust();
}
#[no_mangle]
pub extern "C" fn TxCreationKeys_write(obj: *const TxCreationKeys) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn TxCreationKeys_read(ser: crate::c_types::u8slice) -> TxCreationKeys {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		TxCreationKeys { inner: Box::into_raw(Box::new(res)), _underlying_ref: false }
	} else {
		TxCreationKeys { inner: std::ptr::null_mut(), _underlying_ref: false }
	}
}

use lightning::ln::chan_utils::ChannelPublicKeys as lnChannelPublicKeysImport;
type lnChannelPublicKeys = lnChannelPublicKeysImport;

///  One counterparty's public keys which do not change over the life of a channel.
#[must_use]
#[repr(C)]
pub struct ChannelPublicKeys {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut lnChannelPublicKeys,
	pub _underlying_ref: bool,
}

impl Drop for ChannelPublicKeys {
	fn drop(&mut self) {
		if !self._underlying_ref && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner as *mut lnChannelPublicKeys) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_free(this_ptr: ChannelPublicKeys) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelPublicKeys_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut lnChannelPublicKeys); }
}
impl Clone for ChannelPublicKeys {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			_underlying_ref: false,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelPublicKeys_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut lnChannelPublicKeys)).clone() })) as *mut c_void
}
///  The public key which is used to sign all commitment transactions, as it appears in the
///  on-chain channel lock-in 2-of-2 multisig output.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_funding_pubkey(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.funding_pubkey;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
///  The public key which is used to sign all commitment transactions, as it appears in the
///  on-chain channel lock-in 2-of-2 multisig output.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_funding_pubkey(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.funding_pubkey = val.into_rust();
}
///  The base point which is used (with derive_public_revocation_key) to derive per-commitment
///  revocation keys. This is combined with the per-commitment-secret generated by the
///  counterparty to create a secret which the counterparty can reveal to revoke previous
///  states.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_revocation_basepoint(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.revocation_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
///  The base point which is used (with derive_public_revocation_key) to derive per-commitment
///  revocation keys. This is combined with the per-commitment-secret generated by the
///  counterparty to create a secret which the counterparty can reveal to revoke previous
///  states.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_revocation_basepoint(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.revocation_basepoint = val.into_rust();
}
///  The public key which receives our immediately spendable primary channel balance in
///  remote-broadcasted commitment transactions. This key is static across every commitment
///  transaction.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_payment_point(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.payment_point;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
///  The public key which receives our immediately spendable primary channel balance in
///  remote-broadcasted commitment transactions. This key is static across every commitment
///  transaction.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_payment_point(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.payment_point = val.into_rust();
}
///  The base point which is used (with derive_public_key) to derive a per-commitment payment
///  public key which receives non-HTLC-encumbered funds which are only available for spending
///  after some delay (or can be claimed via the revocation path).
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_delayed_payment_basepoint(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.delayed_payment_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
///  The base point which is used (with derive_public_key) to derive a per-commitment payment
///  public key which receives non-HTLC-encumbered funds which are only available for spending
///  after some delay (or can be claimed via the revocation path).
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_delayed_payment_basepoint(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.delayed_payment_basepoint = val.into_rust();
}
///  The base point which is used (with derive_public_key) to derive a per-commitment public key
///  which is used to encumber HTLC-in-flight outputs.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_htlc_basepoint(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.htlc_basepoint;
	crate::c_types::PublicKey::from_rust(&(*inner_val))
}
///  The base point which is used (with derive_public_key) to derive a per-commitment public key
///  which is used to encumber HTLC-in-flight outputs.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_htlc_basepoint(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.htlc_basepoint = val.into_rust();
}
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_new(mut funding_pubkey_arg: crate::c_types::PublicKey, mut revocation_basepoint_arg: crate::c_types::PublicKey, mut payment_point_arg: crate::c_types::PublicKey, mut delayed_payment_basepoint_arg: crate::c_types::PublicKey, mut htlc_basepoint_arg: crate::c_types::PublicKey) -> ChannelPublicKeys {
	ChannelPublicKeys { inner: Box::into_raw(Box::new(lnChannelPublicKeys {
		funding_pubkey: funding_pubkey_arg.into_rust(),
		revocation_basepoint: revocation_basepoint_arg.into_rust(),
		payment_point: payment_point_arg.into_rust(),
		delayed_payment_basepoint: delayed_payment_basepoint_arg.into_rust(),
		htlc_basepoint: htlc_basepoint_arg.into_rust(),
	})), _underlying_ref: false }
}
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_write(obj: *const ChannelPublicKeys) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_read(ser: crate::c_types::u8slice) -> ChannelPublicKeys {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		ChannelPublicKeys { inner: Box::into_raw(Box::new(res)), _underlying_ref: false }
	} else {
		ChannelPublicKeys { inner: std::ptr::null_mut(), _underlying_ref: false }
	}
}
///  A script either spendable by the revocation
///  key or the delayed_payment_key and satisfying the relative-locktime OP_CSV constrain.
///  Encumbering a `to_local` output on a commitment transaction or 2nd-stage HTLC transactions.
#[no_mangle]
pub extern "C" fn get_revokeable_redeemscript(revocation_key: crate::c_types::PublicKey, to_self_delay: u16, delayed_payment_key: crate::c_types::PublicKey) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::get_revokeable_redeemscript(&revocation_key.into_rust(), to_self_delay, &delayed_payment_key.into_rust());
	ret.into_bytes().into()
}


use lightning::ln::chan_utils::HTLCOutputInCommitment as lnHTLCOutputInCommitmentImport;
type lnHTLCOutputInCommitment = lnHTLCOutputInCommitmentImport;

///  Information about an HTLC as it appears in a commitment transaction
#[must_use]
#[repr(C)]
pub struct HTLCOutputInCommitment {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut lnHTLCOutputInCommitment,
	pub _underlying_ref: bool,
}

impl Drop for HTLCOutputInCommitment {
	fn drop(&mut self) {
		if !self._underlying_ref && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner as *mut lnHTLCOutputInCommitment) };
		}
	}
}
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_free(this_ptr: HTLCOutputInCommitment) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn HTLCOutputInCommitment_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut lnHTLCOutputInCommitment); }
}
impl Clone for HTLCOutputInCommitment {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			_underlying_ref: false,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HTLCOutputInCommitment_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut lnHTLCOutputInCommitment)).clone() })) as *mut c_void
}
///  Whether the HTLC was \"offered\" (ie outbound in relation to this commitment transaction).
///  Note that this is not the same as whether it is ountbound *from us*. To determine that you
///  need to compare this value to whether the commitment transaction in question is that of
///  the remote party or our own.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_offered(this_ptr: &HTLCOutputInCommitment) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.offered;
	(*inner_val)
}
///  Whether the HTLC was \"offered\" (ie outbound in relation to this commitment transaction).
///  Note that this is not the same as whether it is ountbound *from us*. To determine that you
///  need to compare this value to whether the commitment transaction in question is that of
///  the remote party or our own.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_offered(this_ptr: &mut HTLCOutputInCommitment, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.offered = val;
}
///  The value, in msat, of the HTLC. The value as it appears in the commitment transaction is
///  this divided by 1000.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_amount_msat(this_ptr: &HTLCOutputInCommitment) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.amount_msat;
	(*inner_val)
}
///  The value, in msat, of the HTLC. The value as it appears in the commitment transaction is
///  this divided by 1000.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_amount_msat(this_ptr: &mut HTLCOutputInCommitment, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.amount_msat = val;
}
///  The CLTV lock-time at which this HTLC expires.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_cltv_expiry(this_ptr: &HTLCOutputInCommitment) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.cltv_expiry;
	(*inner_val)
}
///  The CLTV lock-time at which this HTLC expires.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_cltv_expiry(this_ptr: &mut HTLCOutputInCommitment, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.cltv_expiry = val;
}
///  The hash of the preimage which unlocks this HTLC.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_payment_hash(this_ptr: &HTLCOutputInCommitment) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.payment_hash;
	&(*inner_val).0
}
///  The hash of the preimage which unlocks this HTLC.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_payment_hash(this_ptr: &mut HTLCOutputInCommitment, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.payment_hash = ::lightning::ln::channelmanager::PaymentHash(val.data);
}
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_write(obj: *const HTLCOutputInCommitment) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_read(ser: crate::c_types::u8slice) -> HTLCOutputInCommitment {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		HTLCOutputInCommitment { inner: Box::into_raw(Box::new(res)), _underlying_ref: false }
	} else {
		HTLCOutputInCommitment { inner: std::ptr::null_mut(), _underlying_ref: false }
	}
}
///  note here that 'a_revocation_key' is generated using b_revocation_basepoint and a's
///  commitment secret. 'htlc' does *not* need to have its previous_output_index filled.
#[no_mangle]
pub extern "C" fn get_htlc_redeemscript(htlc: &crate::ln::chan_utils::HTLCOutputInCommitment, keys: &crate::ln::chan_utils::TxCreationKeys) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::get_htlc_redeemscript(unsafe { &mut *htlc.inner }, unsafe { &mut *keys.inner });
	ret.into_bytes().into()
}

///  Gets the redeemscript for a funding output from the two funding public keys.
///  Note that the order of funding public keys does not matter.
#[no_mangle]
pub extern "C" fn make_funding_redeemscript(a: crate::c_types::PublicKey, b: crate::c_types::PublicKey) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::make_funding_redeemscript(&a.into_rust(), &b.into_rust());
	ret.into_bytes().into()
}

///  panics if htlc.transaction_output_index.is_none()!
#[no_mangle]
pub extern "C" fn build_htlc_transaction(prev_hash: *const [u8; 32], feerate_per_kw: u32, to_self_delay: u16, htlc: &crate::ln::chan_utils::HTLCOutputInCommitment, a_delayed_payment_key: crate::c_types::PublicKey, revocation_key: crate::c_types::PublicKey) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::build_htlc_transaction(&::bitcoin::hash_types::Txid::from_slice(&unsafe { &*prev_hash }[..]).unwrap(), feerate_per_kw, to_self_delay, unsafe { &mut *htlc.inner }, &a_delayed_payment_key.into_rust(), &revocation_key.into_rust());
	let mut local_ret = ::bitcoin::consensus::encode::serialize(&ret);
	local_ret.into()
}


use lightning::ln::chan_utils::LocalCommitmentTransaction as lnLocalCommitmentTransactionImport;
type lnLocalCommitmentTransaction = lnLocalCommitmentTransactionImport;

///  We use this to track local commitment transactions and put off signing them until we are ready
///  to broadcast. This class can be used inside a signer implementation to generate a signature
///  given the relevant secret key.
#[must_use]
#[repr(C)]
pub struct LocalCommitmentTransaction {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut lnLocalCommitmentTransaction,
	pub _underlying_ref: bool,
}

impl Drop for LocalCommitmentTransaction {
	fn drop(&mut self) {
		if !self._underlying_ref && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner as *mut lnLocalCommitmentTransaction) };
		}
	}
}
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_free(this_ptr: LocalCommitmentTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn LocalCommitmentTransaction_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut lnLocalCommitmentTransaction); }
}
impl Clone for LocalCommitmentTransaction {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			_underlying_ref: false,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LocalCommitmentTransaction_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut lnLocalCommitmentTransaction)).clone() })) as *mut c_void
}
///  The commitment transaction itself, in unsigned form.
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_get_unsigned_tx(this_ptr: &LocalCommitmentTransaction) -> crate::c_types::derived::CVec_u8Z {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.unsigned_tx;
	let mut local_inner_val = ::bitcoin::consensus::encode::serialize(inner_val);
	local_inner_val.into()
}
///  The commitment transaction itself, in unsigned form.
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_set_unsigned_tx(this_ptr: &mut LocalCommitmentTransaction, mut val: crate::c_types::derived::CVec_u8Z) {
	unsafe { &mut *this_ptr.inner }.unsigned_tx = ::bitcoin::consensus::encode::deserialize(&val.into_rust()[..]).unwrap();
}
///  Our counterparty's signature for the transaction, above.
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_get_their_sig(this_ptr: &LocalCommitmentTransaction) -> crate::c_types::Signature {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.their_sig;
	crate::c_types::Signature::from_rust(&(*inner_val))
}
///  Our counterparty's signature for the transaction, above.
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_set_their_sig(this_ptr: &mut LocalCommitmentTransaction, mut val: crate::c_types::Signature) {
	unsafe { &mut *this_ptr.inner }.their_sig = val.into_rust();
}
///  The key derivation parameters for this commitment transaction
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_get_local_keys(this_ptr: &LocalCommitmentTransaction) -> crate::ln::chan_utils::TxCreationKeys {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.local_keys;
	crate::ln::chan_utils::TxCreationKeys { inner: unsafe { ( (&((*inner_val)) as *const _) as *mut _) }, _underlying_ref: true }
}
///  The key derivation parameters for this commitment transaction
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_set_local_keys(this_ptr: &mut LocalCommitmentTransaction, mut val: crate::ln::chan_utils::TxCreationKeys) {
	unsafe { &mut *this_ptr.inner }.local_keys = *unsafe { Box::from_raw(val.inner.take_ptr() as *mut _) };
}
///  The feerate paid per 1000-weight-unit in this commitment transaction. This value is
///  controlled by the channel initiator.
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_get_feerate_per_kw(this_ptr: &LocalCommitmentTransaction) -> u32 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.feerate_per_kw;
	(*inner_val)
}
///  The feerate paid per 1000-weight-unit in this commitment transaction. This value is
///  controlled by the channel initiator.
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_set_feerate_per_kw(this_ptr: &mut LocalCommitmentTransaction, mut val: u32) {
	unsafe { &mut *this_ptr.inner }.feerate_per_kw = val;
}
///  The HTLCs and remote htlc signatures which were included in this commitment transaction.
/// 
///  Note that this includes all HTLCs, including ones which were considered dust and not
///  actually included in the transaction as it appears on-chain, but who's value is burned as
///  fees and not included in the to_local or to_remote outputs.
/// 
///  The remote HTLC signatures in the second element will always be set for non-dust HTLCs, ie
///  those for which transaction_output_index.is_some().
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_set_per_htlc(this_ptr: &mut LocalCommitmentTransaction, mut val: crate::c_types::derived::CVec_C2Tuple_HTLCOutputInCommitmentSignatureZZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { let (mut orig_val_0_0, mut orig_val_0_1) = item.to_rust(); let mut local_orig_val_0_1 = if orig_val_0_1.is_null() { None } else { Some( { orig_val_0_1.into_rust() }) }; let mut local_val_0 = (*unsafe { Box::from_raw(orig_val_0_0.inner.take_ptr() as *mut _) }, local_orig_val_0_1); local_val_0 }); };
	unsafe { &mut *this_ptr.inner }.per_htlc = local_val;
}
///  Get the txid of the local commitment transaction contained in this
///  LocalCommitmentTransaction
#[must_use]
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_txid(this_arg: &LocalCommitmentTransaction) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*this_arg.inner }.txid();
	crate::c_types::ThirtyTwoBytes { data: ret.into_inner() }
}

///  Gets our signature for the contained commitment transaction given our funding private key.
/// 
///  Funding key is your key included in the 2-2 funding_outpoint lock. Should be provided
///  by your ChannelKeys.
///  Funding redeemscript is script locking funding_outpoint. This is the mutlsig script
///  between your own funding key and your counterparty's. Currently, this is provided in
///  ChannelKeys::sign_local_commitment() calls directly.
///  Channel value is amount locked in funding_outpoint.
#[must_use]
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_get_local_sig(this_arg: &LocalCommitmentTransaction, funding_key: *const [u8; 32], funding_redeemscript: crate::c_types::u8slice, mut channel_value_satoshis: u64) -> crate::c_types::Signature {
	let mut ret = unsafe { &*this_arg.inner }.get_local_sig(&::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *funding_key}[..]).unwrap(), &::bitcoin::blockdata::script::Script::from(Vec::from(funding_redeemscript.to_slice())), channel_value_satoshis, &bitcoin::secp256k1::Secp256k1::new());
	crate::c_types::Signature::from_rust(&ret)
}

///  Get a signature for each HTLC which was included in the commitment transaction (ie for
///  which HTLCOutputInCommitment::transaction_output_index.is_some()).
/// 
///  The returned Vec has one entry for each HTLC, and in the same order. For HTLCs which were
///  considered dust and not included, a None entry exists, for all others a signature is
///  included.
#[must_use]
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_get_htlc_sigs(this_arg: &LocalCommitmentTransaction, htlc_base_key: *const [u8; 32], mut local_csv: u16) -> crate::c_types::derived::CResult_CVec_SignatureZNoneZ {
	let mut ret = unsafe { &*this_arg.inner }.get_htlc_sigs(&::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *htlc_base_key}[..]).unwrap(), local_csv, &bitcoin::secp256k1::Secp256k1::new());
	let mut local_ret = match ret{ Ok(mut o) => crate::c_types::CResultTempl::good( { let mut local_ret_0 = Vec::new(); for item in o.drain(..) { local_ret_0.push( { let mut local_ret_0_0 = if item.is_none() { crate::c_types::Signature::null() } else {  { crate::c_types::Signature::from_rust(&(item.unwrap())) } }; local_ret_0_0 }); }; local_ret_0.into() }), Err(mut e) => crate::c_types::CResultTempl::err( { 0u8 /*e*/ }) };
	local_ret
}

#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_write(obj: *const LocalCommitmentTransaction) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn LocalCommitmentTransaction_read(ser: crate::c_types::u8slice) -> LocalCommitmentTransaction {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		LocalCommitmentTransaction { inner: Box::into_raw(Box::new(res)), _underlying_ref: false }
	} else {
		LocalCommitmentTransaction { inner: std::ptr::null_mut(), _underlying_ref: false }
	}
}