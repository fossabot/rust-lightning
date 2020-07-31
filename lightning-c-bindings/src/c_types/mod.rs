pub mod derived;

use bitcoin::Script as BitcoinScript;
use bitcoin::Transaction as BitcoinTransaction;
use bitcoin::secp256k1::key::PublicKey as SecpPublicKey;
use bitcoin::secp256k1::key::SecretKey as SecpSecretKey;
use bitcoin::secp256k1::Signature as SecpSignature;

#[derive(Clone)]
#[repr(C)]
pub struct PublicKey {
	pub compressed_form: [u8; 33],
}
impl PublicKey {
	pub(crate) fn from_rust(pk: &SecpPublicKey) -> Self {
		Self {
			compressed_form: pk.serialize(),
		}
	}
	pub(crate) fn into_rust(&self) -> SecpPublicKey {
		SecpPublicKey::from_slice(&self.compressed_form).unwrap()
	}
	pub(crate) fn is_null(&self) -> bool { self.compressed_form[..] == [0; 33][..] }
	pub(crate) fn empty() -> Self { Self { compressed_form: [0; 33] } }
}

#[repr(C)]
pub struct SecretKey {
	pub bytes: [u8; 32],
}
impl SecretKey {
	// from_rust isn't implemented since we jsut return byte array refs directly
	pub(crate) fn into_rust(&self) -> SecpSecretKey {
		SecpSecretKey::from_slice(&self.bytes).unwrap()
	}
}

#[repr(C)]
pub struct Signature {
	pub compact_form: [u8; 64],
}
impl Signature {
	pub(crate) fn from_rust(pk: &SecpSignature) -> Self {
		Self {
			compact_form: pk.serialize_compact(),
		}
	}
	pub(crate) fn into_rust(&self) -> SecpSignature {
		SecpSignature::from_compact(&self.compact_form).unwrap()
	}
	pub(crate) fn is_null(&self) -> bool { self.compact_form[..] == [0; 64][..] }
	pub(crate) fn empty() -> Self { Self { compact_form: [0; 64] } }
}

#[repr(C)]
/// A reference to a serialized transaction, in (pointer, length) form.
/// This type does *not* own its own memory, so access to it after, eg, the call in which it was
/// provided to you are invalid.
pub struct Transaction {
	pub data: *const u8,
	pub datalen: usize,
}
impl Transaction {
	pub(crate) fn into_bitcoin(&self) -> BitcoinTransaction {
		::bitcoin::consensus::encode::deserialize(unsafe { std::slice::from_raw_parts(self.data, self.datalen) }).unwrap()
	}
	pub(crate) fn from_slice(s: &[u8]) -> Self {
		Self {
			data: s.as_ptr(),
			datalen: s.len(),
		}
	}
}

#[repr(C)]
#[derive(Clone)]
/// A transaction output including a scriptPubKey and value.
/// This type *does* own its own memory, so must be free'd appropriately.
pub struct TxOut {
	pub script_pubkey: derived::CVec_u8Z,
	pub value: u64,
}

impl TxOut {
	pub(crate) fn into_rust(self) -> ::bitcoin::blockdata::transaction::TxOut {
		::bitcoin::blockdata::transaction::TxOut {
			script_pubkey: self.script_pubkey.into_rust().into(),
			value: self.value,
		}
	}
	pub(crate) fn from_rust(txout: ::bitcoin::blockdata::transaction::TxOut) -> Self {
		Self {
			script_pubkey: CVecTempl::from(txout.script_pubkey.into_bytes()),
			value: txout.value
		}
	}
}
#[no_mangle]
pub extern "C" fn TxOut_free(_res: TxOut) { }

#[repr(C)]
pub struct u8slice {
	pub data: *const u8,
	pub datalen: usize
}
impl u8slice {
	pub(crate) fn from_slice(s: &[u8]) -> Self {
		Self {
			data: s.as_ptr(),
			datalen: s.len(),
		}
	}
	pub(crate) fn to_slice(&self) -> &[u8] {
		unsafe { std::slice::from_raw_parts(self.data, self.datalen) }
	}
}

#[repr(C)]
pub struct usizeslice {
	pub data: *const usize,
	pub datalen: usize
}
impl usizeslice {
	pub(crate) fn from_slice(s: &[usize]) -> Self {
		Self {
			data: s.as_ptr(),
			datalen: s.len(),
		}
	}
	pub(crate) fn to_slice(&self) -> &[usize] {
		unsafe { std::slice::from_raw_parts(self.data, self.datalen) }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Arbitrary 32 bytes, which could represent one of a few different things. You probably want to
/// look up the corresponding function in rust-lightning's docs.
pub struct ThirtyTwoBytes {
	pub data: [u8; 32],
}
impl ThirtyTwoBytes {
	pub(crate) fn empty() -> Self {
		Self { data: [0; 32] }
	}
}

#[repr(C)]
pub struct ThreeBytes { pub data: [u8; 3], }
#[derive(Clone)]
#[repr(C)]
pub struct FourBytes { pub data: [u8; 4], }
#[derive(Clone)]
#[repr(C)]
pub struct TenBytes { pub data: [u8; 10], }
#[derive(Clone)]
#[repr(C)]
pub struct SixteenBytes { pub data: [u8; 16], }

pub(crate) struct VecWriter(pub Vec<u8>);
impl lightning::util::ser::Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
	fn size_hint(&mut self, size: usize) {
		self.0.reserve_exact(size);
	}
}
pub(crate) fn serialize_obj<I: lightning::util::ser::Writeable>(i: &I) -> derived::CVec_u8Z {
	let mut out = VecWriter(Vec::new());
	i.write(&mut out).unwrap();
	CVecTempl::from(out.0)
}
pub(crate) fn deserialize_obj<I: lightning::util::ser::Readable>(s: u8slice) -> Result<I, lightning::ln::msgs::DecodeError> {
	I::read(&mut s.to_slice())
}

#[repr(C)]
#[derive(Copy, Clone)]
/// A Rust str object, ie a reference to a UTF8-valid string.
/// This is *not* null-terminated so cannot be used directly as a C string!
pub struct Str {
	pub chars: *const u8,
	pub len: usize
}
impl Into<Str> for &'static str {
	fn into(self) -> Str {
		Str { chars: self.as_ptr(), len: self.len() }
	}
}
impl Into<&'static str> for Str {
	fn into(self) -> &'static str {
		std::str::from_utf8(unsafe { std::slice::from_raw_parts(self.chars, self.len) }).unwrap()
	}
}

// Note that the C++ headers memset(0) all the Templ types to avoid deallocation!
// Thus, they must gracefully handle being completely null in _free.

#[repr(C)]
pub struct CSliceTempl<T> {
	pub data: *mut T,
	pub datalen: usize
}
// Things derived from CSliceTempl require per-item conversion, so is actually a Box<[]> underneath
// (thus requires a Drop impl)
impl<T> Drop for CSliceTempl<T> {
	fn drop(&mut self) {
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}

// TODO: Integer/bool primitives should avoid the pointer indirection for underlying types
// everywhere in the containers.

#[repr(C)]
pub union CResultPtr<O, E> {
	pub result: *mut O,
	pub err: *mut E,
}
#[repr(C)]
pub struct CResultTempl<O, E> {
	pub contents: CResultPtr<O, E>,
	pub result_good: bool,
}
impl<O, E> CResultTempl<O, E> {
	pub(crate) extern "C" fn good(o: O) -> Self {
		CResultTempl {
			contents: CResultPtr {
				result: Box::into_raw(Box::new(o)),
			},
			result_good: true,
		}
	}
	pub(crate) extern "C" fn err(e: E) -> Self {
		CResultTempl {
			contents: CResultPtr {
				err: Box::into_raw(Box::new(e)),
			},
			result_good: false,
		}
	}
}
pub extern "C" fn CResultTempl_free<O, E>(_res: CResultTempl<O, E>) { }
impl<O, E> Drop for CResultTempl<O, E> {
	fn drop(&mut self) {
		if self.result_good {
			if unsafe { !self.contents.result.is_null() } {
				unsafe { Box::from_raw(self.contents.result) };
			}
		} else if unsafe { !self.contents.err.is_null() } {
			unsafe { Box::from_raw(self.contents.err) };
		}
	}
}

#[repr(C)]
pub struct CVecTempl<T> {
	pub data: *mut T,
	pub datalen: usize
}
impl<T> CVecTempl<T> {
	pub(crate) fn into_rust(mut self) -> Vec<T> {
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
}
impl<T> From<Vec<T>> for CVecTempl<T> {
	fn from(v: Vec<T>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		CVecTempl { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
pub extern "C" fn CVecTempl_free<T>(_res: CVecTempl<T>) { }
impl<T> Drop for CVecTempl<T> {
	fn drop(&mut self) {
		// datalen == 0 is will gracefully be ignored, so we don't have to handle data == null
		// here.
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl<T: Clone> Clone for CVecTempl<T> {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		res.clone_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}

#[repr(C)]
pub struct C2TupleTempl<A, B> {
	pub a: *mut A,
	pub b: *mut B,
}
impl<A, B> From<(A, B)> for C2TupleTempl<A, B> {
	fn from(tup: (A, B)) -> Self {
		Self {
			a: Box::into_raw(Box::new(tup.0)),
			b: Box::into_raw(Box::new(tup.1)),
		}
	}
}
impl<A, B> C2TupleTempl<A, B> {
	pub(crate) fn to_rust(mut self) -> (A, B) {
		let res = (unsafe { *Box::from_raw(self.a) }, unsafe { *Box::from_raw(self.b) });
		self.a = std::ptr::null_mut();
		self.b = std::ptr::null_mut();
		res
	}
}
pub extern "C" fn C2TupleTempl_free<A, B>(_res: C2TupleTempl<A, B>) { }
impl<A, B> Drop for C2TupleTempl<A, B> {
	fn drop(&mut self) {
		if !self.a.is_null() {
			unsafe { Box::from_raw(self.a) };
		}
		if !self.b.is_null() {
			unsafe { Box::from_raw(self.b) };
		}
	}
}
impl <A: Clone, B: Clone> Clone for C2TupleTempl<A, B> {
	fn clone(&self) -> Self {
		Self {
			a: Box::into_raw(Box::new(unsafe { &*self.a }.clone())),
			b: Box::into_raw(Box::new(unsafe { &*self.b }.clone()))
		}
	}
}

#[repr(C)]
pub struct C3TupleTempl<A, B, C> {
	pub a: *mut A,
	pub b: *mut B,
	pub c: *mut C,
}
impl<A, B, C> From<(A, B, C)> for C3TupleTempl<A, B, C> {
	fn from(tup: (A, B, C)) -> Self {
		Self {
			a: Box::into_raw(Box::new(tup.0)),
			b: Box::into_raw(Box::new(tup.1)),
			c: Box::into_raw(Box::new(tup.2)),
		}
	}
}
impl<A, B, C> C3TupleTempl<A, B, C> {
	pub(crate) fn to_rust(mut self) -> (A, B, C) {
		let res = (unsafe { *Box::from_raw(self.a) }, unsafe { *Box::from_raw(self.b) }, unsafe { *Box::from_raw(self.c) });
		self.a = std::ptr::null_mut();
		self.b = std::ptr::null_mut();
		self.c = std::ptr::null_mut();
		res
	}
}
pub extern "C" fn C3TupleTempl_free<A, B, C>(_res: C3TupleTempl<A, B, C>) { }
impl<A, B, C> Drop for C3TupleTempl<A, B, C> {
	fn drop(&mut self) {
		if !self.a.is_null() {
			unsafe { Box::from_raw(self.a) };
		}
		if !self.b.is_null() {
			unsafe { Box::from_raw(self.b) };
		}
		if !self.c.is_null() {
			unsafe { Box::from_raw(self.c) };
		}
	}
}

/// Utility to make it easy to set a pointer to null and get its original value in line.
pub(crate) trait TakePointer<T> {
	fn take_ptr(&mut self) -> T;
}
impl<T> TakePointer<*const T> for *const T {
	fn take_ptr(&mut self) -> *const T {
		let ret = *self;
		*self = std::ptr::null();
		ret
	}
}
impl<T> TakePointer<*mut T> for *mut T {
	fn take_ptr(&mut self) -> *mut T {
		let ret = *self;
		*self = std::ptr::null_mut();
		ret
	}
}