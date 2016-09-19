package inet.ipaddr.ipv6;

import inet.ipaddr.IPAddressTypeNetwork;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.ipv4.IPv4AddressSection;

/**
 * 
 * @author sfoley
 */
public class IPv6AddressNetwork extends IPAddressTypeNetwork<IPv6Address> {
	
	private static final IPv6AddressSegment emptySegments[] = {};
	private static final IPv6AddressSection emptySection[] = {};
	
	public static class IPv6AddressCreator extends IPAddressCreator<IPv6Address, IPv6AddressSection, IPv6AddressSegment> {
		static boolean CACHE_SEGMENTS_BY_PREFIX = true;
		
		//there are 0x10000 (ie 0xffff + 1) possible segment values in IPv6.  We break the cache into 0x100 blocks of size 0x100
		private static IPv6AddressSegment segmentCache[][] = new IPv6AddressSegment[((2 * IPv6Address.MAX_VALUE_PER_SEGMENT) - 1) / 0x100][];
		
		//we maintain a similar cache for each potential prefixed segment.  
		//Note that there are 2 to the n possible values for prefix n
		//We break up that number into blocks of size 0x100
		private static IPv6AddressSegment segmentPrefixCache[][][] = new IPv6AddressSegment[IPv6Address.BITS_PER_SEGMENT][][];
		private static IPv6AddressSegment allPrefixedCache[] = new IPv6AddressSegment[IPv6Address.BITS_PER_SEGMENT];
		
		@Override
		protected IPv6Address createAddressInternal(IPv6AddressSegment segments[], String zone) {
			return super.createAddressInternal(segments, zone);
		}
		
		@Override
		protected IPv6Address createAddressInternal(IPv6AddressSegment segments[]) {
			return super.createAddressInternal(segments, (String) null);
		}
		
		@Override
		protected IPv6AddressSection createSectionInternal(byte[] bytes, Integer prefix) {
			return new IPv6AddressSection(bytes, prefix, false);
		}

		@Override
		protected IPv6AddressSection createSectionInternal(byte[] bytes, String zone) {
			if(zone != null) {
				throw new IllegalArgumentException();
			}
			return createSectionInternal(bytes);
		}

		@Override
		protected IPv6AddressSection createSectionInternal(byte[] bytes) {
			return new IPv6AddressSection(bytes, null, false);
		}
		
		@Override
		protected IPv6AddressSection createSectionInternal(IPv6AddressSegment segments[]) {
			return new IPv6AddressSection(segments, 0, false);
		}
		
		@Override
		protected IPv6AddressSection createSectionInternal(IPv6AddressSegment segments[], IPv4AddressSection mixedSection) {
			IPv6AddressSection result = new IPv6AddressSection(segments, 0, false);
			result.mixedSection = mixedSection;
			return result;
		}
		
		protected IPv6AddressSection createSectionInternal(IPv6AddressSegment segments[], int startIndex) {
			return new IPv6AddressSection(segments, startIndex, false);
		}
		
		@Override
		protected IPv6Address createAddressInternal(IPv6AddressSection section, String zone) {
			return createAddress(section, zone);
		}

		public IPv6Address createAddress(IPv6AddressSection section, String zone) {
			return new IPv6Address(section, zone);
		}
		
		@Override
		public IPv6Address createAddress(IPv6AddressSection section) {
			return new IPv6Address(section);
		}
		
		public IPv6AddressSection createSection(byte bytes[], Integer prefix) {
			return new IPv6AddressSection(bytes, prefix);
		}
		
		public IPv6AddressSection createSection(IPv6AddressSegment segments[]) {
			return new IPv6AddressSection(segments);
		}
		
		public IPv6AddressSection createSection(IPv6AddressSegment segments[], Integer networkPrefixLength) {
			return new IPv6AddressSection(segments, networkPrefixLength);
		}
		
		@Override
		protected IPv6AddressSection[] createAddressSectionArray(int length) {
			if(length == 0) {
				return emptySection;
			}
			return new IPv6AddressSection[length];
		}

		@Override
		public IPv6AddressSegment[] createAddressSegmentArray(int length) {
			if(length == 0) {
				return emptySegments;
			}
			return new IPv6AddressSegment[length];
		}
		
		@Override
		public IPv6AddressSegment createAddressSegment(int value) {
			IPv6AddressSegment cache[][] = segmentCache;
			int blockIndex = value >>> 8; // divide by 0x100
			int resultIndex = value - (blockIndex << 8); // mod 0x100
			IPv6AddressSegment block[] = cache[blockIndex];
			IPv6AddressSegment result;
			if(block == null) {
				cache[blockIndex] = block = new IPv6AddressSegment[0x100];
				result = block[resultIndex] = new IPv6AddressSegment(value);
			} else {
				result = block[resultIndex];
				if(result == null) {
					result = block[resultIndex] = new IPv6AddressSegment(value);
				}
			}
			return result;
		}
		
		@Override
		public IPv6AddressSegment createAddressSegment(int value, Integer segmentPrefixLength) {
			if(segmentPrefixLength == null) {
				return createAddressSegment(value);
			}
			if(segmentPrefixLength == 0) {
				return IPv6AddressSegment.ZERO_PREFIX_SEGMENT;
			}
			if(CACHE_SEGMENTS_BY_PREFIX) {
				int bitsPerSegment = IPv6Address.BITS_PER_SEGMENT;
				if(segmentPrefixLength > bitsPerSegment) {
					segmentPrefixLength = bitsPerSegment;
				}
				int mask = IPv6Address.network().getSegmentNetworkMask(segmentPrefixLength);
				value &= mask;
				int prefixIndex = segmentPrefixLength - 1;
				int valueIndex = value >>> (bitsPerSegment - segmentPrefixLength);
				
				IPv6AddressSegment cache[][][] = segmentPrefixCache;
				IPv6AddressSegment prefixCache[][] = cache[prefixIndex];
				IPv6AddressSegment block[] = null;
				IPv6AddressSegment result = null;
				int blockIndex = valueIndex >>> 8; // divide by 0x100
				int resultIndex = valueIndex - (blockIndex << 8); // mod 0x100
				boolean blockExists = false, resultExists = false;
				if(prefixCache == null) {
					int prefixCacheSize = 1 << segmentPrefixLength;//number of possible values for segmentPrefix
					cache[prefixIndex] = new IPv6AddressSegment[(prefixCacheSize + 0x100 - 1) >>> 8][];
				} else {
					block = cache[prefixIndex][blockIndex];
					blockExists = (block != null);
					if(blockExists) {
						result = block[resultIndex];
						resultExists = (result != null);
					}
				}
				if(!blockExists) {
					int prefixCacheSize = 1 << segmentPrefixLength;
					int highestIndex = prefixCacheSize >>> 8; // divide by 0x100
					if(valueIndex >>> 8 == highestIndex) { //final block: only use an array as large as we need
						block = new IPv6AddressSegment[prefixCacheSize - (highestIndex << 8)]; // mod 0x100
					} else { //all other blocks are size 0x100
						block = new IPv6AddressSegment[0x100];
					}
					cache[prefixIndex][blockIndex] = block;
				}
				if(!resultExists) {
					result = block[resultIndex] = new IPv6AddressSegment(value, segmentPrefixLength);
				}
				return result;
			}
			IPv6AddressSegment result = new IPv6AddressSegment(value, segmentPrefixLength);
			return result;
		}
		
		@Override
		public IPv6AddressSegment createAddressSegment(int lower, int upper, Integer segmentPrefixLength) {
			if(segmentPrefixLength == null) {
				if(lower == upper) {
					return createAddressSegment(lower);
				}
				if(lower == 0 && upper == IPv6Address.MAX_VALUE_PER_SEGMENT) {
					return IPv6AddressSegment.ALL_RANGE_SEGMENT;
				}
			} else {
				if(segmentPrefixLength == 0) {
					return createAddressSegment(0, 0);
				}
				if(CACHE_SEGMENTS_BY_PREFIX) {
					int mask = IPv6Address.network().getSegmentNetworkMask(segmentPrefixLength);
					lower &= mask;
					if((upper & mask) == lower) {
						return createAddressSegment(lower, segmentPrefixLength);
					}
					if(lower == 0 && upper == mask) {
						//cache */26 type segments
						int prefixIndex = segmentPrefixLength - 1;
						IPv6AddressSegment cache[] = allPrefixedCache;
						IPv6AddressSegment result = cache[prefixIndex];
						if(result == null) {
							cache[prefixIndex] = result = new IPv6AddressSegment(0, IPv6Address.MAX_VALUE_PER_SEGMENT, segmentPrefixLength);
						}
						return result;
					}
				}
			}
			IPv6AddressSegment result = new IPv6AddressSegment(lower, upper, segmentPrefixLength);
			return result;
		}
		
	};

	IPv6AddressNetwork() {
		super(IPv6Address.class);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	protected IPv6AddressCreator createAddressCreator() {
		return new IPv6AddressCreator();
	}
	
	@Override
	protected IPv6Address createLoopback() {
		IPv6AddressCreator creator = getAddressCreator();
		IPv6AddressSegment zero = IPv6AddressSegment.ZERO_SEGMENT;
		IPv6AddressSegment segs[] = creator.createAddressSegmentArray(IPv6Address.SEGMENT_COUNT);
		segs[0] = segs[1] = segs[2] = segs[3] = segs[4] = segs[5] = segs[6] = zero;
		segs[7] = creator.createAddressSegment(1);
		return creator.createAddressInternal(segs);
	}
	
	@Override
	public IPv6AddressCreator getAddressCreator() {
		return (IPv6AddressCreator) super.getAddressCreator();
	}
	
	@Override
	public boolean isIPv6() {
		return true;
	}
	
	@Override
	public IPVersion getIPVersion() {
		return IPVersion.IPV6;
	}
}
