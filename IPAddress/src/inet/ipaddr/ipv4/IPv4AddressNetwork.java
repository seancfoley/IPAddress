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

package inet.ipaddr.ipv4;

import java.net.Inet4Address;
import java.util.function.BiFunction;
import java.util.function.Function;

import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressNetwork;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.ipv4.IPv4AddressSection.EmbeddedIPv4AddressSection;

/**
 * 
 * @author sfoley
 */
public class IPv4AddressNetwork extends IPAddressNetwork<IPv4Address, IPv4AddressSection, IPv4AddressSection, IPv4AddressSegment, Inet4Address> {
	
	private static final long serialVersionUID = 4L;

	private static PrefixConfiguration defaultPrefixConfiguration = AddressNetwork.getDefaultPrefixConfiguration();

	private static boolean CACHE_SEGMENTS_BY_PREFIX = true;
	
	private static final IPv4AddressSegment EMPTY_SEGMENTS[] = {};
	private static final IPv4AddressSection EMPTY_SECTION[] = {};
	private static final IPv4Address EMPTY_ADDRESS[] = {};
	
	public class IPv4AddressCreator extends IPAddressCreator<IPv4Address, IPv4AddressSection, IPv4AddressSection, IPv4AddressSegment, Inet4Address> {
		
		private static final long serialVersionUID = 4L;

		private transient IPv4AddressSegment ZERO_PREFIX_SEGMENT, ALL_RANGE_SEGMENT;
		private transient IPv4AddressSegment segmentCache[];
		private transient IPv4AddressSegment segmentPrefixCache[][]; 
		private transient IPv4AddressSegment allPrefixedCache[];
		
		public IPv4AddressCreator() {
			super(IPv4AddressNetwork.this);
		}
		
		@Override
		public void clearCaches() {
			super.clearCaches();
			segmentCache = null;
			allPrefixedCache = null;
			segmentPrefixCache = null;
		}
		
		@Override
		public IPv4AddressNetwork getNetwork() {
			return IPv4AddressNetwork.this;
		}

		@Override
		public IPv4AddressSegment[] createSegmentArray(int length) {
			if(length == 0) {
				return EMPTY_SEGMENTS;
			}
			return new IPv4AddressSegment[length];
		}
		
		@Override
		public IPv4AddressSegment createSegment(int value) {
			if(value >= 0 && value <= IPv4Address.MAX_VALUE_PER_SEGMENT) {
				IPv4AddressSegment result, cache[] = segmentCache;
				if(cache == null) {
					segmentCache = cache = new IPv4AddressSegment[IPv4Address.MAX_VALUE_PER_SEGMENT + 1];
					cache[value] = result = new IPv4AddressSegment(value);
				} else {
					result = cache[value];
					if(result == null) {
						cache[value] = result = new IPv4AddressSegment(value);
					}
				}
				return result;
			}
			return new IPv4AddressSegment(value);
		}
		
		@Override
		public IPv4AddressSegment createSegment(int value, Integer segmentPrefixLength) {
			if(segmentPrefixLength == null) {
				return createSegment(value);
			}
			if(value >= 0 && value <= IPv4Address.MAX_VALUE_PER_SEGMENT && segmentPrefixLength >= 0 && segmentPrefixLength <= IPv4Address.BIT_COUNT) {
				if(segmentPrefixLength == 0 && getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
					IPv4AddressSegment result = ZERO_PREFIX_SEGMENT;
					if(result == null) {
						ZERO_PREFIX_SEGMENT = result = new IPv4AddressSegment(0, 0);
					}
					return result;
				}
				if(CACHE_SEGMENTS_BY_PREFIX) {
					int mask = getSegmentNetworkMask(segmentPrefixLength);
					int prefixIndex = segmentPrefixLength;
					int valueIndex;
					boolean isAllSubnets = getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
					if(isAllSubnets) {
						value &= mask;
						valueIndex = value >>> (IPv4Address.BITS_PER_SEGMENT - segmentPrefixLength);
					} else {
						valueIndex = value;
					}
					IPv4AddressSegment result, block[], cache[][] = segmentPrefixCache;
					if(cache == null) {
						segmentPrefixCache = cache = new IPv4AddressSegment[IPv4Address.BITS_PER_SEGMENT + 1][];
						cache[prefixIndex] = block = new IPv4AddressSegment[isAllSubnets ? (1 << prefixIndex) : 256];
						block[valueIndex] = result = new IPv4AddressSegment(value, segmentPrefixLength);
					} else {
						block = cache[prefixIndex];
						if(block == null) {
							cache[prefixIndex] = block = new IPv4AddressSegment[isAllSubnets ? (1 << prefixIndex) : 256];
							block[valueIndex] = result = new IPv4AddressSegment(value, segmentPrefixLength);
						} else {
							result = block[valueIndex];
							if(result == null) {
								block[valueIndex] = result = new IPv4AddressSegment(value, segmentPrefixLength);
							}
						}
					}
					return result;
				}
			}
			IPv4AddressSegment result = new IPv4AddressSegment(value, segmentPrefixLength);
			return result;
		}
		
		@Override
		public IPv4AddressSegment createSegment(int lower, int upper, Integer segmentPrefixLength) {
			if(segmentPrefixLength == null) {
				if(lower == upper) {
					return createSegment(lower);
				}
				if(lower == 0 && upper == IPv4Address.MAX_VALUE_PER_SEGMENT) {
					IPv4AddressSegment result = ALL_RANGE_SEGMENT;
					if(result == null) {
						ALL_RANGE_SEGMENT = result = new IPv4AddressSegment(0, IPv4Address.MAX_VALUE_PER_SEGMENT, null);
							//could optimize:
							//contains
							//getValueCount
							//includesMax
							//includesZero
							//isBoundedBy
							//getSegmentPrefixLength, getDivisionPrefixLength
							//removePrefixLength, withoutPrefixLength, removePrefixLength(boolean)
							//isMultiple
							//isPrefixBlock
							//matches(int)
							//toNormalizedString()
							//getPrefixValueCount
					}
					return result;
				}
			} else {
				if(lower >= 0 && lower <= IPv4Address.MAX_VALUE_PER_SEGMENT &&
						upper >= 0 && upper <= IPv4Address.MAX_VALUE_PER_SEGMENT &&
						segmentPrefixLength >= 0 && segmentPrefixLength <= IPv4Address.BIT_COUNT) {
					if(segmentPrefixLength == 0 && getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
						return createSegment(0, 0);
					}
					if(CACHE_SEGMENTS_BY_PREFIX) {
						int bitsPerSegment = IPv4Address.BITS_PER_SEGMENT;
						if(segmentPrefixLength > bitsPerSegment) {
							segmentPrefixLength = bitsPerSegment;
						}
						if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
							int mask = getSegmentNetworkMask(segmentPrefixLength);
							lower &= mask;
							if((upper & mask) == lower) {
								return createSegment(lower, segmentPrefixLength);
							}
							if(lower == 0 && upper >= mask) {
								//cache */26 type segments
								int prefixIndex = segmentPrefixLength;
								IPv4AddressSegment result, cache[] = allPrefixedCache;
								if(cache == null) {
									allPrefixedCache = cache = new IPv4AddressSegment[IPv4Address.BITS_PER_SEGMENT + 1];
									cache[prefixIndex] = result = new IPv4AddressSegment(0, IPv4Address.MAX_VALUE_PER_SEGMENT, segmentPrefixLength);
								} else {
									result = cache[prefixIndex];
									if(result == null) {
										cache[prefixIndex] = result = new IPv4AddressSegment(0, IPv4Address.MAX_VALUE_PER_SEGMENT, segmentPrefixLength);
									}
								}
								return result;
							}
						} else {
							if(lower == 0 && upper == IPv4Address.MAX_VALUE_PER_SEGMENT) {
								//cache */26 type segments
								int prefixIndex = segmentPrefixLength;
								IPv4AddressSegment result, cache[] = allPrefixedCache;
								if(cache == null) {
									allPrefixedCache = cache = new IPv4AddressSegment[IPv4Address.BITS_PER_SEGMENT + 1];
									cache[prefixIndex] = result = new IPv4AddressSegment(0, IPv4Address.MAX_VALUE_PER_SEGMENT, segmentPrefixLength);
								} else {
									result = cache[prefixIndex];
									if(result == null) {
										cache[prefixIndex] = result = new IPv4AddressSegment(0, IPv4Address.MAX_VALUE_PER_SEGMENT, segmentPrefixLength);
									}
								}
								return result;
							}
						}
					}
				}
			}
			IPv4AddressSegment result = new IPv4AddressSegment(lower, upper, segmentPrefixLength);
			return result;
		}
		

		@Override
		protected IPv4AddressSection[] createSectionArray(int length) {
			if(length == 0) {
				return EMPTY_SECTION;
			}
			return new IPv4AddressSection[length];
		}
		
		@Override
		protected IPv4AddressSection createSectionInternal(IPv4AddressSegment segments[]) {
			return new IPv4AddressSection(segments, false);
		}

		@Override
		protected IPv4AddressSection createPrefixedSectionInternal(IPv4AddressSegment segments[], Integer prefix, boolean singleOnly) {
			return new IPv4AddressSection(segments, false, prefix, singleOnly);
		}

		protected IPv4AddressSection createSectionInternal(int value) {
			return new IPv4AddressSection(value);
		}

		protected IPv4AddressSection createSectionInternal(int value, Integer prefix) {
			return new IPv4AddressSection(value, prefix);
		}

		@Override
		public IPv4AddressSection createFullSectionInternal(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefix) {
			return new IPv4AddressSection(lowerValueProvider, upperValueProvider, IPv4Address.SEGMENT_COUNT, prefix);
		}

		@Override
		protected IPv4AddressSection createSectionInternal(byte[] bytes, int segmentCount, Integer prefix, boolean singleOnly) {
			return new IPv4AddressSection(bytes, segmentCount, prefix, false, singleOnly);
		}

		@Override
		protected IPv4AddressSection createSectionInternal(IPv4AddressSegment[] segments, int startIndex, boolean extended) {
			return new IPv4AddressSection(segments);
		}

		@Override
		public IPv4AddressSection createSection(byte bytes[], int byteStartIndex, int byteEndIndex, Integer prefix) {
			return new IPv4AddressSection(bytes, byteStartIndex, byteEndIndex, -1, prefix, true, false);
		}

		@Override
		public IPv4AddressSection createSection(byte bytes[], Integer prefix) {
			return new IPv4AddressSection(bytes, prefix);
		}
		
		protected IPv4AddressSection createSection(byte bytes[], int byteStartIndex, int byteEndIndex, int segmentCount, Integer prefix) {
			return new IPv4AddressSection(bytes, byteStartIndex, byteEndIndex, segmentCount, prefix);
		}
		
		@Override
		public IPv4AddressSection createSection(IPv4AddressSegment segments[], Integer networkPrefixLength) {
			return new IPv4AddressSection(segments, networkPrefixLength);
		}
		
		@Override
		public IPv4AddressSection createSection(IPv4AddressSegment segments[]) {
			return new IPv4AddressSection(segments);
		}
		
		@Override
		protected IPv4AddressSection createEmbeddedSectionInternal(IPAddressSection encompassingSection, IPv4AddressSegment[] segments) {
			return new EmbeddedIPv4AddressSection(encompassingSection, segments);
		}

		@Override
		protected IPv4Address[] createAddressArray(int length) {
			if(length == 0) {
				return EMPTY_ADDRESS;
			}
			return new IPv4Address[length];
		}
		
		@Override
		protected IPv4Address createAddressInternal(IPv4AddressSegment segments[]) {
			return createAddress(createSectionInternal(segments));
		}
		
		@Override
		protected IPv4Address createAddressInternal(IPv4AddressSection section, CharSequence zone) {
			return createAddress(section);
		}
		
		@Override
		public IPv4Address createAddress(IPv4AddressSection section) {
			return new IPv4Address(section);
		}
		
		@Override
		public IPv4Address createAddress(Inet4Address addr) {
			return new IPv4Address(addr);
		}
	}
	
	public IPv4AddressNetwork() {
		super(IPv4Address.class);
	}
	
	@Override
	public PrefixConfiguration getPrefixConfiguration() {
		return defaultPrefixConfiguration;
	}

	/**
	 * Sets the default prefix configuration used by this network.
	 * 
	 * @see #getPrefixConfiguration()
	 * @see #getDefaultPrefixConfiguration()
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
	protected BiFunction<IPv4Address, Integer, IPv4AddressSegment> getSegmentProducer() {
		return (address, index) -> address.getSegment(index);
	}
	
	@Override
	protected Function<IPv4Address, IPv4AddressSection> getSectionProducer() {
		return IPv4Address::getSection;
	}

	@Override
	protected IPv4AddressCreator createAddressCreator() {
		return new IPv4AddressCreator();
	}
	 
	@Override
	protected IPv4Address createLoopback() {
		IPv4AddressCreator creator = getAddressCreator();
		IPv4AddressSegment zero = creator.createSegment(0);
		IPv4AddressSegment segs[] = creator.createSegmentArray(IPv4Address.SEGMENT_COUNT);
		segs[0] = creator.createSegment(127);
		segs[1] = segs[2] = zero;
		segs[3] = creator.createSegment(1);
		return creator.createAddressInternal(segs); /* address creation */
	}
	
	@Override
	public IPv4AddressCreator getAddressCreator() {
		return (IPv4AddressCreator) super.getAddressCreator();
	}
	
	@Override
	public boolean isIPv4() {
		return true;
	}
	
	@Override
	public IPVersion getIPVersion() {
		return IPVersion.IPV4;
	}
}
