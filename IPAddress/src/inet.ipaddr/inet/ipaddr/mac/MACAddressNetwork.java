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

package inet.ipaddr.mac;

import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.AddressNetwork;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.PrefixLenException;

public class MACAddressNetwork extends AddressNetwork<MACAddressSegment> {
		
	private static final long serialVersionUID = 4L;

	private static PrefixConfiguration defaultPrefixConfiguration = AddressNetwork.getDefaultPrefixConfiguration();

	private static final MACAddressSegment EMPTY_SEGMENTS[] = {};

	public static class MACAddressCreator extends AddressCreator<MACAddress, MACAddressSection, MACAddressSection, MACAddressSegment> implements AddressSegmentCreator<MACAddressSegment> {
		private static final long serialVersionUID = 4L;

		private transient MACAddressSegment ALL_RANGE_SEGMENT;

		private transient MACAddressSegment segmentCache[];

		private final MACAddressNetwork owner;
		
		MACAddressCreator(MACAddressNetwork owner) {
			this.owner = owner;
		}
		
		@Override
		public void clearCaches() {
			super.clearCaches();
			segmentCache = null;
		}

		@Override
		public MACAddressNetwork getNetwork() {
			return owner;
		}

		@Override
		public MACAddressSegment[] createSegmentArray(int length) {
			if(length == 0) {
				return EMPTY_SEGMENTS;
			}
			return new MACAddressSegment[length];
		}
		
		@Override
		public MACAddressSegment createSegment(int value) {
			if(value >= 0 && value <= MACAddress.MAX_VALUE_PER_SEGMENT) {
				MACAddressSegment result, cache[] = segmentCache;
				if(cache == null) {
					segmentCache = cache = new MACAddressSegment[MACAddress.MAX_VALUE_PER_SEGMENT + 1];
					cache[value] = result = new MACAddressSegment(value);
				} else {
					result = cache[value];
					if(result == null) {
						cache[value] = result = new MACAddressSegment(value);
					}
				}
				return result;
			}
			return new MACAddressSegment(value);//this will throw, but call it to throw the correct exception
		}
		
		@Override
		public MACAddressSegment createSegment(int value, Integer segmentPrefixLength) {
			//On ipvx side we have prefix as part of segment, but not here
			//On ipvx side, the address creator for sections defers the prefix handling to the segments creator,
			//which defers the prefix handling to the segment constructor, and then the prefix is applied in the super constructor.
			//Here, we do the same, but when the prefix gets to here, we cannot pass to the segment, so we apply the prefix here
			//But this also gives more caching opportunities
			if(segmentPrefixLength != null) {
				if(segmentPrefixLength < 0) {
					throw new PrefixLenException(segmentPrefixLength);
				}
				if(segmentPrefixLength > MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_BIT_COUNT) {
					throw new PrefixLenException(segmentPrefixLength);
				}
				if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
					if(segmentPrefixLength == 0) {
						MACAddressSegment result = ALL_RANGE_SEGMENT;
						if(result == null) {
							ALL_RANGE_SEGMENT = result = new MACAddressSegment(0, MACAddress.MAX_VALUE_PER_SEGMENT);
						}
						return result;
					}
					int mask = ~0 << (MACAddress.BITS_PER_SEGMENT - segmentPrefixLength);
					int newLower = value & mask;
					int newUpper = value | ~mask;
					return createRangeSegment(newLower, newUpper);
				}
			}
			return createSegment(value);
		}
		
		//different name to avoid confusion with createSegment(int, Integer)
		public MACAddressSegment createRangeSegment(int lower, int upper) {
			if(lower != upper) {
				if(lower == 0 && upper == MACAddress.MAX_VALUE_PER_SEGMENT) {
					MACAddressSegment result = ALL_RANGE_SEGMENT;
					if(result == null) {
						ALL_RANGE_SEGMENT = result = new MACAddressSegment(0, upper);
					}
					return result;
				}
				return new MACAddressSegment(lower, upper);
			}
			return createSegment(lower);
		}
		
		@Override
		public MACAddressSegment createSegment(int lower, int upper, Integer segmentPrefixLength) {
			if(segmentPrefixLength == null) {
				return createRangeSegment(lower, upper);
			}
			if(segmentPrefixLength < 0) {
				throw new PrefixLenException(segmentPrefixLength);
			}
			if(segmentPrefixLength > MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_BIT_COUNT) {
				throw new PrefixLenException(segmentPrefixLength);
			}
			if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
				if(segmentPrefixLength == 0) {
					MACAddressSegment result = ALL_RANGE_SEGMENT;
					if(result == null) {
						ALL_RANGE_SEGMENT = result = new MACAddressSegment(0, MACAddress.MAX_VALUE_PER_SEGMENT);
					}
					return result;
				}
				int max = MACAddress.MAX_VALUE_PER_SEGMENT;
				int mask = (~0 << (MACAddress.BITS_PER_SEGMENT - segmentPrefixLength)) & max;
				int newLower = lower & mask;
				int newUpper = upper | (~mask  & max);
				return createRangeSegment(newLower, newUpper);
			}
			return createRangeSegment(lower, upper);
		}

		@Override
		protected MACAddressSegment createSegmentInternal(int value, Integer segmentPrefixLength, CharSequence addressStr,
				int originalVal, boolean isStandardString, int lowerStringStartIndex, int lowerStringEndIndex) {
			MACAddressSegment segment = createSegment(value, segmentPrefixLength);
			segment.setString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal); 
			return segment;
		}

		@Override
		protected MACAddressSegment createSegmentInternal(int lower, int upper, Integer segmentPrefixLength,
				CharSequence addressStr, int originalLower, int originalUpper, boolean isStandardString,
				boolean isStandardRangeString, int lowerStringStartIndex, int lowerStringEndIndex,
				int upperStringEndIndex) {
			MACAddressSegment segment = createSegment(lower, upper, segmentPrefixLength);
			segment.setString(addressStr, isStandardRangeString, lowerStringStartIndex, upperStringEndIndex, originalLower, originalUpper);
			return segment;
		}
		
		MACAddressSection createSection(long bytes, int startIndex, boolean extended, Integer prefixLength) {
			MACAddressSection result = new MACAddressSection(bytes, startIndex, extended);
			result.assignPrefixLength(prefixLength);
			return result;
		}
		
		MACAddressSection createSection(long bytes, int startIndex, boolean extended) {
			return new MACAddressSection(bytes, startIndex, extended);
		}
		
		MACAddressSection createSection(byte bytes[], int startIndex, boolean extended, Integer prefixLength) {
			MACAddressSection result = new MACAddressSection(bytes, startIndex, extended);
			result.assignPrefixLength(prefixLength);
			return result;
		}
		
		MACAddressSection createSection(byte bytes[], int startIndex, boolean extended) {
			return new MACAddressSection(bytes, startIndex, extended);
		}
		
		MACAddressSection createSection(byte bytes[], int startIndex, int segmentCount, boolean extended, Integer prefixLength) {
			MACAddressSection result = new MACAddressSection(bytes, 0, bytes.length, segmentCount, startIndex, extended, true);
			result.assignPrefixLength(prefixLength);
			return result;
		}
		
		MACAddressSection createSection(byte bytes[], int startIndex, int segmentCount, boolean extended) {
			return new MACAddressSection(bytes, 0, bytes.length, segmentCount, startIndex, extended, true);
		}
		
		MACAddressSection createSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, int startIndex, boolean extended, Integer prefixLength) {
			MACAddressSection result = new MACAddressSection(lowerValueProvider, upperValueProvider, startIndex, extended);
			result.assignPrefixLength(prefixLength);
			return result;
		}
		
		MACAddressSection createSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, int startIndex, boolean extended) {
			return new MACAddressSection(lowerValueProvider, upperValueProvider, startIndex, extended);
		}
		
		@Override
		protected MACAddressSection createSectionInternal(MACAddressSegment[] segments) {
			return new MACAddressSection(false, segments, 0, segments.length > MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT);
		}
		
		@Override
		protected MACAddressSection createPrefixedSectionInternal(MACAddressSegment[] segments, Integer prefixLength, boolean singleOnly) {
			return createPrefixedSectionInternal(segments, prefixLength);
		}

		@Override
		protected MACAddressSection createPrefixedSectionInternal(MACAddressSegment[] segments, Integer prefixLength) {
			MACAddressSection result = new MACAddressSection(false, segments, 0, segments.length > MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT);
			result.assignPrefixLength(prefixLength);
			return result;
		}
		
		protected MACAddressSection createSectionInternal(MACAddressSegment[] segments, boolean extended) {
			return new MACAddressSection(false, segments, 0, extended);
		}
		
		@Override
		protected MACAddressSection createSectionInternal(MACAddressSegment[] segments, int startIndex, boolean extended) {
			return new MACAddressSection(false, segments, startIndex, extended);
		}
		
		MACAddressSection createSection(MACAddressSegment[] segments, boolean extended) {
			return new MACAddressSection(segments, 0, extended);
		}
		
		MACAddressSection createSection(MACAddressSegment[] segments, boolean extended, Integer prefixLength) {
			MACAddressSection result = new MACAddressSection(segments, 0, extended);
			result.assignPrefixLength(prefixLength);
			return result;
		}
		
		@Override
		protected MACAddressSection createSectionInternal(byte bytes[], int segmentCount, Integer prefixLength, boolean singleOnly) {
			MACAddressSection result = new MACAddressSection(bytes, segmentCount, 0, segmentCount > MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT, false);
			result.assignPrefixLength(prefixLength);
			return result;
		}
		
		@Override
		protected MACAddress createAddressInternal(byte[] bytes, CharSequence zone) {
			MACAddressSection section = new MACAddressSection(bytes, bytes.length, 0, bytes.length > MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT, false);
			return createAddress(section);
		}
		
		@Override
		protected MACAddress createAddressInternal(MACAddressSegment[] segments) {
			return createAddress(createSectionInternal(segments));
		}
		
		@Override
		protected MACAddress createAddressInternal(MACAddressSegment segments[], Integer prefix) {
			return createAddress(createPrefixedSectionInternal(segments, prefix));
		}
		
		@Override
		protected MACAddress createAddressInternal(MACAddressSegment[] segments, Integer prefix, boolean singleOnly) {
			return createAddressInternal(segments, prefix);
		}

		@Override
		protected MACAddress createAddressInternal(MACAddressSection section, HostIdentifierString from) {
			MACAddress result = createAddress(section);
			result.cache(from);
			return result;
		}
		
		@Override
		protected MACAddress createAddressInternal(MACAddressSection section, CharSequence zone, HostIdentifierString from) {
			MACAddress result = createAddress(section);
			result.cache(from);
			return result;
		}
		
		@Override
		public MACAddress createAddress(MACAddressSection section) {
			return new MACAddress(section);
		}
	}
	
	protected MACAddressNetwork.MACAddressCreator createAddressCreator() {
		return new MACAddressCreator(this);
	}
	
	@Override
	public MACAddressNetwork.MACAddressCreator getAddressCreator() {
		return creator;
	}
	
	private MACAddressNetwork.MACAddressCreator creator;
	
	public MACAddressNetwork() {
		this.creator = createAddressCreator();
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
}
