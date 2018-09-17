/*
 * Copyright 2016-2018 Sean C Foley
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *     or at
 *     https://github.com/seancfoley/IPAddress/blob/master/LICENSE
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package inet.ipaddr.ipv6;

import java.net.Inet6Address;
import java.util.function.BiFunction;
import java.util.function.Function;

import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressNetwork;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSection.EmbeddedIPv6AddressSection;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressSection;

/**
 * 
 * @author sfoley
 */
public class IPv6AddressNetwork extends IPAddressNetwork<IPv6Address, IPv6AddressSection, IPv4AddressSection, IPv6AddressSegment, Inet6Address> {
	
	private static final long serialVersionUID = 4L;

	private static PrefixConfiguration defaultPrefixConfiguration = AddressNetwork.getDefaultPrefixConfiguration();

	static final IPv6AddressSegment EMPTY_SEGMENTS[] = {};
	private static final IPv6AddressSection EMPTY_SECTION[] = {};
	private static final IPv6Address EMPTY_ADDRESS[] = {};
	
	private static boolean CACHE_SEGMENTS_BY_PREFIX = true;
	
	private IPv6AddressSection linkLocalPrefix;
	
	public static class IPv6AddressCreator extends IPAddressCreator<IPv6Address, IPv6AddressSection, IPv4AddressSection, IPv6AddressSegment, Inet6Address> {
		private static final long serialVersionUID = 4L;

		private transient IPv6AddressSegment ZERO_PREFIX_SEGMENT, ALL_RANGE_SEGMENT;

		//there are 0x10000 (ie 0xffff + 1 or 64k) possible segment values in IPv6.  We break the cache into 0x100 blocks of size 0x100
		private transient IPv6AddressSegment segmentCache[][];
		
		//we maintain a similar cache for each potential prefixed segment.  
		//Note that there are 2 to the n possible values for prefix n
		//We break up that number into blocks of size 0x100
		private transient IPv6AddressSegment segmentPrefixCache[][][];
		private transient IPv6AddressSegment allPrefixedCache[];

		public IPv6AddressCreator(IPv6AddressNetwork network) {
			super(network);
		}

		@Override
		public void clearCaches() {
			super.clearCaches();
			segmentCache = null;
			allPrefixedCache = null;
			segmentPrefixCache = null;
		}
		
		@Override
		public IPv6AddressNetwork getNetwork() {
			return (IPv6AddressNetwork) super.getNetwork();
		}
		
		@Override
		public IPv6AddressSegment[] createSegmentArray(int length) {
			if(length == 0) {
				return EMPTY_SEGMENTS;
			}
			return new IPv6AddressSegment[length];
		}
		
		@Override
		public IPv6AddressSegment createSegment(int value) {
			if(value >= 0 && value <= IPv6Address.MAX_VALUE_PER_SEGMENT) {
				IPv6AddressSegment result, block[], cache[][] = segmentCache;
				int blockIndex = value >>> 8; // divide by 0x100
				int resultIndex = value - (blockIndex << 8); // mod 0x100
				if(cache == null) {
					segmentCache = cache = new IPv6AddressSegment[((2 * IPv6Address.MAX_VALUE_PER_SEGMENT) - 1) / 0x100][];
					cache[blockIndex] = block = new IPv6AddressSegment[0x100];
					result = block[resultIndex] = new IPv6AddressSegment(value);
				} else {
					block = cache[blockIndex];
					if(block == null) {
						cache[blockIndex] = block = new IPv6AddressSegment[0x100];
						result = block[resultIndex] = new IPv6AddressSegment(value);
					} else {
						result = block[resultIndex];
						if(result == null) {
							result = block[resultIndex] = new IPv6AddressSegment(value);
						}
					}
				}
				return result;
			}
			return new IPv6AddressSegment(value);
		}
		
		@Override
		public IPv6AddressSegment createSegment(int value, Integer segmentPrefixLength) {
			if(segmentPrefixLength == null) {
				return createSegment(value);
			}
			if(value >= 0 && value <= IPv6Address.MAX_VALUE_PER_SEGMENT && segmentPrefixLength >= 0 && segmentPrefixLength <= IPv6Address.BIT_COUNT) {
				if(segmentPrefixLength == 0 && getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
					IPv6AddressSegment result = ZERO_PREFIX_SEGMENT;
					if(result == null) {
						ZERO_PREFIX_SEGMENT = result = new IPv6AddressSegment(0, 0);
					}
					return result;
				}
				if(CACHE_SEGMENTS_BY_PREFIX) {
					int prefixIndex = segmentPrefixLength;
					int valueIndex;
					boolean isAllSubnets = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
					if(isAllSubnets) {
						int mask = getNetwork().getSegmentNetworkMask(segmentPrefixLength);
						value &= mask;
						valueIndex = value >>> (IPv6Address.BITS_PER_SEGMENT- segmentPrefixLength);
					} else {
						valueIndex = value;
					}
					IPv6AddressSegment result, block[], prefixCache[][], cache[][][] = segmentPrefixCache;
					int blockIndex = valueIndex >>> 8; // divide by 0x100
					int resultIndex = valueIndex - (blockIndex << 8); // mod 0x100
					if(cache == null) {
						segmentPrefixCache = cache = new IPv6AddressSegment[IPv6Address.BITS_PER_SEGMENT + 1][][];
						prefixCache = null;
						block = null;
						result = null;
					} else {
						prefixCache = cache[prefixIndex];
						if(prefixCache != null) {
							block = cache[prefixIndex][blockIndex];
							if(block != null) {
								result = block[resultIndex];
							} else {
								result = null;
							}
						} else {
							block = null;
							result = null;
						}
					}
					if(prefixCache == null) {
						int prefixCacheSize = isAllSubnets ? 1 << segmentPrefixLength : IPv6Address.MAX_VALUE_PER_SEGMENT + 1;//number of possible values for each segmentPrefix
						cache[prefixIndex] = prefixCache = new IPv6AddressSegment[(prefixCacheSize + 0x100 - 1) >>> 8][];
					}
					if(block == null) {
						int prefixCacheSize = isAllSubnets ? 1 << segmentPrefixLength : IPv6Address.MAX_VALUE_PER_SEGMENT + 1;//number of possible values for each segmentPrefix
						int highestIndex = prefixCacheSize >>> 8; // divide by 0x100
						if(valueIndex >>> 8 == highestIndex) { //final block: only use an array as large as we need
							block = new IPv6AddressSegment[prefixCacheSize - (highestIndex << 8)]; // mod 0x100
						} else { //all other blocks are size 0x100
							block = new IPv6AddressSegment[0x100];
						}
						prefixCache[blockIndex] = block;
					}
					if(result == null) {
						block[resultIndex] = result = new IPv6AddressSegment(value, segmentPrefixLength);
					}
					return result;
				}
			}
			IPv6AddressSegment result = new IPv6AddressSegment(value, segmentPrefixLength);
			return result;
		}
		
		@Override
		public IPv6AddressSegment createSegment(int lower, int upper, Integer segmentPrefixLength) {
			if(segmentPrefixLength == null) {
				if(lower == upper) {
					return createSegment(lower);
				}
				if(lower == 0 && upper == IPv6Address.MAX_VALUE_PER_SEGMENT) {
					IPv6AddressSegment result = ALL_RANGE_SEGMENT;
					if(result == null) {
						ALL_RANGE_SEGMENT = result = new IPv6AddressSegment(0, IPv6Address.MAX_VALUE_PER_SEGMENT, null);
					}
					return result;
				}
			} else {
				if(lower >= 0 && lower <= IPv6Address.MAX_VALUE_PER_SEGMENT && 
					upper >= 0 && upper <= IPv6Address.MAX_VALUE_PER_SEGMENT && 
						segmentPrefixLength >= 0 && segmentPrefixLength <= IPv6Address.BIT_COUNT) {
					if(segmentPrefixLength == 0 && getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
						return createSegment(0, 0);
					}
					if(CACHE_SEGMENTS_BY_PREFIX) {
						int bitsPerSegment = IPv6Address.BITS_PER_SEGMENT;
						if(segmentPrefixLength > bitsPerSegment) {
							segmentPrefixLength = bitsPerSegment;
						}
						if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
							int mask = getNetwork().getSegmentNetworkMask(segmentPrefixLength);
							lower &= mask;
							if((upper & mask) == lower) {
								return createSegment(lower, segmentPrefixLength);
							}
							int hostMask = getNetwork().getSegmentHostMask(segmentPrefixLength);
							upper |= hostMask;
						}
						if(lower == 0 && upper == IPv6Address.MAX_VALUE_PER_SEGMENT) {
							//cache */26 type segments
							int prefixIndex = segmentPrefixLength;
							IPv6AddressSegment result, cache[] = allPrefixedCache;
							if(cache == null) {
								allPrefixedCache = cache = new IPv6AddressSegment[IPv6Address.BITS_PER_SEGMENT + 1];
								cache[prefixIndex] = result = new IPv6AddressSegment(0, IPv6Address.MAX_VALUE_PER_SEGMENT, segmentPrefixLength);
							} else {
								result = cache[prefixIndex];
								if(result == null) {
									cache[prefixIndex] = result = new IPv6AddressSegment(0, IPv6Address.MAX_VALUE_PER_SEGMENT, segmentPrefixLength);
								}
							}
							return result;
						}
					}
				}
			}
			IPv6AddressSegment result = new IPv6AddressSegment(lower, upper, segmentPrefixLength);
			return result;
		}

		@Override
		public IPv6AddressSection createFullSectionInternal(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefix) {
			return new IPv6AddressSection(lowerValueProvider, upperValueProvider, IPv6Address.SEGMENT_COUNT, prefix);
		}

		@Override
		protected IPv6AddressSection createSectionInternal(byte[] bytes, int segmentCount, Integer prefix, boolean singleOnly) {
			return new IPv6AddressSection(bytes, segmentCount, prefix, false, singleOnly);
		}

		@Override
		protected IPv6AddressSection createSectionInternal(IPv6AddressSegment segments[]) {
			return new IPv6AddressSection(segments, 0, false);
		}
		
		@Override
		protected IPv6AddressSection createPrefixedSectionInternal(IPv6AddressSegment segments[], Integer prefix, boolean singleOnly) {
			return new IPv6AddressSection(segments, 0, false, prefix, singleOnly);
		}
		
		@Override
		protected IPv6AddressSection createSectionInternal(IPv6AddressSegment segments[], IPv4AddressSection embeddedSection) {
			IPv6AddressSection result = new IPv6AddressSection(segments, 0, false);
			result.embeddedIPv4Section = embeddedSection;
			return result;
		}
		
		@Override
		protected IPv6AddressSection createSectionInternal(IPv6AddressSegment segments[], IPv4AddressSection embeddedSection, Integer prefix) {
			IPv6AddressSection result = new IPv6AddressSection(segments, 0, false, prefix, false);
			result.embeddedIPv4Section = embeddedSection;
			return result;
		}
		
		protected IPv6AddressSection createEmbeddedSectionInternal(IPv6AddressSection encompassingSection, IPv6AddressSegment segments[], int startIndex) {
			return new EmbeddedIPv6AddressSection(encompassingSection, segments, startIndex);
		}
		
		@Override
		protected IPv6AddressSection createEmbeddedSectionInternal(IPAddressSection encompassingSection, IPv6AddressSegment segments[]) {
			return new EmbeddedIPv6AddressSection((IPv6AddressSection) encompassingSection, segments, 0);
		}
		
		protected IPv6AddressSection createSectionInternal(IPv6AddressSegment segments[], int startIndex) {
			return new IPv6AddressSection(segments, startIndex, false);
		}
		
		@Override
		protected IPv6AddressSection createSectionInternal(IPv6AddressSegment[] segments, int startIndex, boolean extended) {
			return new IPv6AddressSection(segments, startIndex, false);
		}
		
		@Override
		protected IPv6AddressSection[] createSectionArray(int length) {
			if(length == 0) {
				return EMPTY_SECTION;
			}
			return new IPv6AddressSection[length];
		}
		
		@Override
		public IPv6AddressSection createSection(byte bytes[], int byteStartIndex, int byteEndIndex, Integer prefix) {
			return new IPv6AddressSection(bytes, byteStartIndex, byteEndIndex, -1, prefix, true, false);
		}
		
		protected IPv6AddressSection createSection(byte bytes[], int byteStartIndex, int byteEndIndex, int segmentCount, Integer prefix) {
			return new IPv6AddressSection(bytes, byteStartIndex, byteEndIndex, segmentCount, prefix, true, false);
		}
		
		protected IPv6AddressSection createSectionInternal(byte bytes[], int segmentCount, Integer prefix) {
			return new IPv6AddressSection(bytes, 0, bytes.length, segmentCount, prefix, false, false);
		}
		
		@Override
		public IPv6AddressSection createSection(byte bytes[], Integer prefix) {
			return new IPv6AddressSection(bytes, prefix);
		}
		
		@Override
		public IPv6AddressSection createSection(IPv6AddressSegment segments[]) {
			return new IPv6AddressSection(segments);
		}
		
		@Override
		public IPv6AddressSection createSection(IPv6AddressSegment segments[], Integer networkPrefixLength) {
			return new IPv6AddressSection(segments, networkPrefixLength);
		}
		
		public IPv6AddressSection createSection(MACAddress eui) {
			return new IPv6AddressSection(eui);
		}
		
		public IPv6AddressSection createSection(MACAddressSection eui) {
			return new IPv6AddressSection(eui);
		}
		
		@Override
		protected IPv6Address[] createAddressArray(int length) {
			if(length == 0) {
				return EMPTY_ADDRESS;
			}
			return new IPv6Address[length];
		}
		
		@Override
		protected IPv6Address createAddressInternal(IPv6AddressSegment segments[], CharSequence zone) {
			return createAddressInternal(createSectionInternal(segments), zone);
		}
		
		@Override
		protected IPv6Address createAddressInternal(IPv6AddressSegment segments[]) {
			return new IPv6Address(createSectionInternal(segments));
		}
		
		@Override
		protected IPv6Address createAddressInternal(IPv6AddressSection section, CharSequence zone, HostIdentifierString from) {
			IPv6Address result = super.createAddressInternal(section, zone, from);
			return result;
		}
		
		@Override
		protected IPv6Address createAddressInternal(IPv6AddressSection section, HostIdentifierString from) {
			IPv6Address result = super.createAddressInternal(section, from);
			return result;
		}

		@Override
		protected IPv6Address createAddressInternal(IPv6AddressSection section, CharSequence zone) {
			return new IPv6Address(section, zone, false);
		}
		
		public IPv6Address createAddress(IPv6AddressSection section, CharSequence zone) {
			return new IPv6Address(section, zone);
		}

		@Override
		public IPv6Address createAddress(IPv6AddressSection section) {
			return new IPv6Address(section);
		}

		@Override
		public IPv6Address createAddress(Inet6Address addr) {
			return new IPv6Address(addr);
		}
	};

	public IPv6AddressNetwork() {
		super(IPv6Address.class);
	}
	
	@Override
	public PrefixConfiguration getPrefixConfiguration() {
		return defaultPrefixConfiguration;
	}

	/**
	 * Sets the default prefix configuration used by this network.
	 * 
	 * @see #getDefaultPrefixConfiguration()
	 * @see #getPrefixConfiguration()
	 * @see PrefixConfiguration
	 */
	public static void setDefaultPrefixConfiguration(PrefixConfiguration config) {
		defaultPrefixConfiguration = config;
	}
	
	/**
	 * Gets the default prefix configuration used by this network.
	 * 
	 * @see AddressNetwork#getDefaultPrefixConfiguration()
	 * @see PrefixConfiguration
	 */
	public static PrefixConfiguration getDefaultPrefixConfiguration() {
		return defaultPrefixConfiguration;
	}
	
	@Override
	protected BiFunction<IPv6Address, Integer, IPv6AddressSegment> getSegmentProducer() {
		return (address, index) -> address.getSegment(index);
	}
	
	@Override
	protected Function<IPv6Address, IPv6AddressSection> getSectionProducer() {
		return IPv6Address::getSection;
	}
	
	@Override
	protected IPv6AddressCreator createAddressCreator() {
		return new IPv6AddressCreator(this);
	}
	
	@Override
	protected IPv6Address createLoopback() {
		IPv6AddressCreator creator = getAddressCreator();
		IPv6AddressSegment zero = creator.createSegment(0);
		IPv6AddressSegment segs[] = creator.createSegmentArray(IPv6Address.SEGMENT_COUNT);
		segs[0] = segs[1] = segs[2] = segs[3] = segs[4] = segs[5] = segs[6] = zero;
		segs[7] = creator.createSegment(1);
		return creator.createAddressInternal(segs); /* address creation */
	}
	
	public IPv6AddressSection getLinkLocalPrefix() {
		if(linkLocalPrefix == null) {
			synchronized(this) {
				if(linkLocalPrefix == null) {
					linkLocalPrefix = createLinkLocalPrefix();
				}
			}
		}
		return linkLocalPrefix;
	}
	
	private IPv6AddressSection createLinkLocalPrefix() {
		IPv6AddressCreator creator = getAddressCreator();
		IPv6AddressSegment zeroSeg = creator.createSegment(0);
		IPv6AddressSection linkLocalPrefix = creator.createSectionInternal(new IPv6AddressSegment[] {
				creator.createSegment(0xfe80),
				zeroSeg,
				zeroSeg,
				zeroSeg});
		return linkLocalPrefix;
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
