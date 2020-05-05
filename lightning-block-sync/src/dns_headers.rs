//! A headers-only BlockSource which fetches headers by doing AAAA DNS queries. This should provide
//! some additional robustness by being easy to tunnel over other protocols (eg DNS-over-TLS or
//! DNS-over-HTTPS) and simply by nature of being a protocol which is not Bitcoin-specific.
//!
//! 80-byte Bitcoin headers are encoded in six IPv6 addresses as follows:
//! The first two bytes of each address are ignored.
//! The next 4 bits in each address indicate the ordering of the addresses
//! (as DNS resolvers/servers often shuffle the addresses)
//! The first 8 bits (ie the second half of the 3rd byte and first half of the 4th)
//! of the first address are interpreted as a version and must currently be 0.
//! The remaining bits are placed into the 80 byte result in order.
//!
//! Hostnames are height.(height / 10,000).domain_suffix to keep zones at a more manageable size.
//! bitcoinheaders.net can be used as domain_suffic to get a public copy of the header chain.

use crate::{BlockHeaderData, BlockSource, BlockSourceRespErr};

use bitcoin::hash_types::BlockHash;
use bitcoin::util::hash::BitcoinHash;
use bitcoin::util::uint::Uint256;

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::consensus::encode;

use std::future::Future;
use std::pin::Pin;
use std::net::{IpAddr, Ipv6Addr};

#[cfg(not(feature = "tokio"))]
use std::net::ToSocketAddrs;

/// A trait for a barebones version of a BlockSource which only allows queries from height to
/// header hash, eg our headers-over-DNS protocol.
pub trait SimpleHeadersClient {
	/// Gets the header at a given height
	fn get_header<'a>(&'a self, height: u32) -> Pin<Box<dyn Future<Output = Result<BlockHeader, BlockSourceRespErr>> + 'a + Send>>;
}
/// Adapts a SimpleHeadersClient to a BlockSource (which always returns NoResponse for full block
/// requests) by caching headers on difficulty adjustments and a few recent headers.
///
/// Caching should be under 20KB for a million headers on mainnet (though note that every block is
/// a difficulty adjustment block on testnet so the size is much larger).
pub struct CachingHeadersClient<C: SimpleHeadersClient> {
	/// We track only the headers which fall on a retarget, storing only their hash and nBits field
	/// so that we can recalculate the chainwork from any point.
	retarget_headers: Vec<(BlockHash, u32)>,
	/// Cache the last 6 full block headers and their hashes since almost all requests should just
	/// be for the latest one or two.
	recent_headers: [Option<(BlockHash, BlockHeaderData)>; 6],
	mainnet: bool,
	inner: C,
}
impl<C: SimpleHeadersClient + Send + Sync> CachingHeadersClient<C> {
	/// Creates a new CachingHeadersClient with the given SimpleHeadersClient and a flag to
	/// indicate whether reargets happen every 2016 blocks, or every block (eg on testnet3).
	pub fn new(inner: C, mainnet: bool) -> Self {
		Self {
			retarget_headers: Vec::new(),
			recent_headers: [None, None, None, None, None, None],
			mainnet, inner
		}
	}

	fn calculate_chainwork_to(&self, height: u32) -> Uint256 {
		let interval = if self.mainnet { 2016usize } else { 1 };
		if (height as usize) < interval {
			return Uint256::from_u64(4295032833 * height as u64).unwrap();
		}
		// First difficulty adjustment period is always:
		let mut chainwork = Uint256::from_u64(4295032833 * 2015).unwrap();
		for (_, bits) in self.retarget_headers.iter().take((height as usize / interval) - 1) {
			chainwork = chainwork + BlockHeader { version: 0, prev_blockhash: Default::default(), merkle_root: Default::default(),
					time: 0, bits: *bits, nonce: 0 }
				.target().mul_u32(interval as u32);
		}
		chainwork = chainwork + BlockHeader { version: 0, prev_blockhash: Default::default(), merkle_root: Default::default(),
				time: 0, bits: self.retarget_headers[(height as usize / interval) - 1].1, nonce: 0 }
			.target().mul_u32((height % interval as u32) + 1);
		chainwork
	}

	/// Ask inner for the header at the given height, updating relevant caches
	fn fetch_header_at_height<'a>(&'a mut self, height: u32) -> Pin<Box<dyn Future<Output = Result<(BlockHash, BlockHeaderData), BlockSourceRespErr>> + 'a + Send>> {
		Box::pin(async move {
			let header = self.inner.get_header(height).await?;
			let hash = header.bitcoin_hash();

			let interval = if self.mainnet { 2016usize } else { 1 };
			// Make sure our retarget_headers is filled appropriately:
			if height % interval as u32 == 0 {
				// This block has a fresh nBits that the previous did not, update it in
				// retarget_headers (noting that we have a strange - 1 in a few places as we do
				// not store the genesis header, and thus the first header in retarget_headers
				// is block 2016 stored at pos 0).
				if self.retarget_headers.len() < (height as usize / interval) - 1 {
					self.fetch_header_at_height((height - 1) / interval as u32 * interval as u32).await?;
				}
				if self.retarget_headers.len() == (height as usize / interval) - 1 || self.retarget_headers[height as usize / interval - 1].0 != hash {
					self.retarget_headers.resize(height as usize / interval, (hash, header.bits));
					self.retarget_headers[height as usize / interval - 1] = (hash, header.bits);
				}
			} else if height as usize > interval && self.retarget_headers.len() < (height as usize / interval) {
				self.fetch_header_at_height(height / interval as u32 * interval as u32).await?;
			}

			let chainwork = if self.recent_headers[(height as usize - 1) % self.recent_headers.len()]
					.as_ref().map(|(hash, _)| hash) == Some(&header.prev_blockhash) {
				// Prev matches our prev hash, use it to calculate chainwork and return!
				self.recent_headers[(height as usize - 1) % self.recent_headers.len()]
					.as_ref().unwrap().1.chainwork + header.work()
			} else if height as usize > interval {
				// Prev is unrelated to current, fetch the last difficulty adjustment block
				// and recalculate the chainwork.
				self.fetch_header_at_height((height - 1) / interval as u32 * interval as u32).await?;
				self.calculate_chainwork_to(height)
			} else {
				// Prev is unrelated to current but we're in the first difficulty window,
				// so diff must be 1!
				Uint256::from_u64(4295032833 * height as u64).unwrap()
			};
			let headerdata = BlockHeaderData { chainwork, height, header };
			self.recent_headers[height as usize % self.recent_headers.len()] = Some((hash, headerdata.clone()));
			Ok((hash, headerdata))
		})
	}

	/// Load all available difficulty adjustment blocks
	async fn sync_diff_adjustments(&mut self) -> Result<(), BlockSourceRespErr> {
		// Load blocks jumping up 2016 at a time to get the retarget blocks:
		let interval = if self.mainnet { 2016 } else { 1 };
		let mut height = interval;
		loop {
			match self.fetch_header_at_height(height).await {
				Ok(_) => height += interval,
				Err(BlockSourceRespErr::NoResponse) => return Ok(()),
				Err(BlockSourceRespErr::BogusData) => return Err(BlockSourceRespErr::BogusData),
			}
		}
	}
}

impl<C: SimpleHeadersClient + Send + Sync + 'static> BlockSource for CachingHeadersClient<C> {
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, height_hint: Option<u32>) -> Pin<Box<dyn Future<Output = Result<BlockHeaderData, BlockSourceRespErr>> + 'a + Send>> {
		Box::pin(async move {
			if let Some(height) = height_hint {
				if let &Some((ref hash, ref header)) = &self.recent_headers[height as usize % self.recent_headers.len()] {
					if hash == header_hash {
						return Ok(header.clone());
					}
				}
				let (hash, header) = self.fetch_header_at_height(height).await?;
				if hash == *header_hash {
					Ok(header)
				} else {
					Err(BlockSourceRespErr::NoResponse)
				}
			} else {
				Err(BlockSourceRespErr::NoResponse)
			}
		})
	}

	fn get_block<'a>(&'a mut self, _header_hash: &'a BlockHash) -> Pin<Box<dyn Future<Output = Result<Block, BlockSourceRespErr>> + 'a + Send>> {
		Box::pin(async {
			Err(BlockSourceRespErr::NoResponse)
		})
	}

	fn get_best_block<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(BlockHash, Option<u32>), BlockSourceRespErr>> + 'a + Send>> {
		Box::pin(async move {
			let mut highest_height = 0;
			for hdr in self.recent_headers.iter() {
				if let Some(header) = hdr {
					if header.1.height > highest_height {
						highest_height = header.1.height;
					}
				}
			}
			if highest_height == 0 {
				// If we're just starting, load the difficulty adjustment blocks to get us near the
				// tip, then check for the highest header again:
				self.sync_diff_adjustments().await?;
				for hdr in self.recent_headers.iter() {
					if let Some(header) = hdr {
						if header.1.height > highest_height {
							highest_height = header.1.height;
						}
					}
				}
				if highest_height == 0 {
					return Err(BlockSourceRespErr::NoResponse);
				}
			}

			// We only care about finding the highest header, so walk forward until we get
			// NoResponse:
			let mut res = None;
			loop {
				match self.fetch_header_at_height(highest_height + 1).await {
					Ok((hash, _)) => {
						highest_height += 1;
						res = Some((hash, Some(highest_height)));
					},
					Err(BlockSourceRespErr::NoResponse) => {
						if res.is_some() {
							// We previously got a response. Most likely we just found the tip and
							// should return it.
							return Ok(res.unwrap());
						} else {
							// Probably no new headers, check the current tip is the same and
							// return. If we get another NoResponse just give up - while its
							// possible there was a reorg to a lower height, this probably requires
							// a multi-block reorg around a retarget with a huge difference in
							// timestamps between forks....so we can just wait for another block to
							// be mined.
							return self.fetch_header_at_height(highest_height).await.map(|(hash, _)| (hash, Some(highest_height)));
						}
					},
					Err(BlockSourceRespErr::BogusData) => return Err(BlockSourceRespErr::BogusData),
				}
			}
		})
	}
}

/// A client which fetches headers over DNS from a specific provider, implementing
/// SimpleHeadersClient. You probably want to create one of these and then wrap it in a
/// CachingHeadersClient.
pub struct DNSHeadersClient {
	domain_str: String,
}

impl DNSHeadersClient {
	/// Creates a new DNSHeadersClient which fetches headers by doing AAAA (IPv6) DNS queries to
	/// prefixes on a given hostname (see the module documentation for info on the exact format).
	pub fn new(domain_str: String) -> Self {
		Self { domain_str }
	}
}

fn map_addrs_to_header(ips: &mut [Ipv6Addr]) -> Option<[u8; 80]> {
	if ips.len() != 6 { return None; }
	ips.sort_unstable_by(|a, b| {
		// Sort based on the first 4 bits in the 3rd byte...
		(&(a.octets()[2] & 0xf0)).cmp(&(b.octets()[2] & 0xf0))
	});
	if ips.len() != 6 { unreachable!(); }
	let version = (ips[0].octets()[2] & 0x0f) | (ips[0].octets()[3] & 0xf0);
	if version != 0 { return None; }

	let mut header = [0u8; 80];
	let mut offs = 0; // in bytes * 2
	for (idx, ip) in ips.iter().enumerate() {
		for i in if idx == 0 { 3..14*2 } else { 1..14*2 } {
			if i % 2 == 1 {
				header[offs/2] |= (ip.octets()[i/2 + 2] & 0x0f) >> 0;
			} else {
				header[offs/2] |= (ip.octets()[i/2 + 2] & 0xf0) >> 4;
			}
			if offs % 2 == 0 {
				header[offs/2] <<= 4;
			}
			offs += 1;
		}
	}
	Some(header)
}

impl SimpleHeadersClient for DNSHeadersClient {
	fn get_header<'a>(&'a self, height: u32) -> Pin<Box<dyn Future<Output = Result<BlockHeader, BlockSourceRespErr>> + 'a + Send>> {
		Box::pin(async move {
			let domain = format!("{}.{}.{}", height, height / 10000, self.domain_str);
			#[cfg(not(feature = "tokio"))]
			let lookup_res = (domain.as_str(), 0u16).to_socket_addrs();
			#[cfg(feature = "tokio")]
			let lookup_res = tokio::net::lookup_host((domain.as_str(), 0u16)).await;
			let mut ips: Vec<_> = lookup_res.map_err(|_| BlockSourceRespErr::NoResponse)?
				.filter_map(|a| match a.ip() {
					IpAddr::V6(a) => Some(a),
					_ => None,
				}).collect();
			if ips.len() != 6 {
				return Err(BlockSourceRespErr::NoResponse);
			}
			let data = map_addrs_to_header(&mut ips).ok_or(BlockSourceRespErr::NoResponse)?;
			let header: BlockHeader = encode::deserialize(&data).map_err(|_| BlockSourceRespErr::NoResponse)?;
			Ok(header)
		})
	}
}

#[cfg(test)]
#[test]
fn test_map_addrs() {
	use std::str::FromStr;

	let mut ips = Vec::new();
	// The genesis header:
	ips.push(Ipv6Addr::from_str("2001:0000:1000:0000:0000:0000:0000:0000").unwrap());
	ips.push(Ipv6Addr::from_str("2001:1000:0000:0000:0000:0000:0000:0000").unwrap());
	ips.push(Ipv6Addr::from_str("2001:2000:0000:0000:0000:0000:03ba:3edf").unwrap());
	ips.push(Ipv6Addr::from_str("2001:3d7a:7b12:b27a:c72c:3e67:768f:617f").unwrap());
	ips.push(Ipv6Addr::from_str("2001:4c81:bc38:88a5:1323:a9fb:8aa4:b1e5").unwrap());
	ips.push(Ipv6Addr::from_str("2001:5e4a:29ab:5f49:ffff:001d:1dac:2b7c").unwrap());

	assert_eq!(&map_addrs_to_header(&mut ips).unwrap()[..],
		&[0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, 0x29, 0xab, 0x5f, 0x49, 0xff, 0xff, 0x0, 0x1d, 0x1d, 0xac, 0x2b, 0x7c][..]);

	// Block 100,000
	ips.clear();
	ips.push(Ipv6Addr::from_str("2001:2cc1:f1cd:20::665:7a92").unwrap());
	ips.push(Ipv6Addr::from_str("2001:352a:acd5:c0b2:9409:96ec:ff95:2228").unwrap());
	ips.push(Ipv6Addr::from_str("2001:4c30:67cc:38d4:885e:fb5a:4ac4:247e").unwrap());
	ips.push(Ipv6Addr::from_str("2001:0:1000:5:120:1191:72a6:1042").unwrap());
	ips.push(Ipv6Addr::from_str("2001:11a6:c301:1dd3:30d9:df07:b636:16c2").unwrap());
	ips.push(Ipv6Addr::from_str("2001:59f3:3722:1b4d:4c86:41b:f2b:5710").unwrap());

	assert_eq!(&map_addrs_to_header(&mut ips).unwrap()[..],
		&[0x01, 0x00, 0x00, 0x00, 0x50, 0x12, 0x01, 0x19, 0x17, 0x2a, 0x61, 0x04, 0x21, 0xa6, 0xc3, 0x01, 0x1d, 0xd3, 0x30, 0xd9, 0xdf, 0x07, 0xb6, 0x36, 0x16, 0xc2, 0xcc, 0x1f, 0x1c, 0xd0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x57, 0xa9, 0x25, 0x2a, 0xac, 0xd5, 0xc0, 0xb2, 0x94, 0x09, 0x96, 0xec, 0xff, 0x95, 0x22, 0x28, 0xc3, 0x06, 0x7c, 0xc3, 0x8d, 0x48, 0x85, 0xef, 0xb5, 0xa4, 0xac, 0x42, 0x47, 0xe9, 0xf3, 0x37, 0x22, 0x1b, 0x4d, 0x4c, 0x86, 0x04, 0x1b, 0x0f, 0x2b, 0x57, 0x10][..]);
}
