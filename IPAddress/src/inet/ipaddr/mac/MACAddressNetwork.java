/*
 * Copyright 2017 Sean C Foley
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

import inet.ipaddr.AddressNetwork;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.format.AddressCreator;

public class MACAddressNetwork extends AddressNetwork {
		
	public static class MACAddressCreator extends AddressCreator<MACAddress, MACAddressSection, MACAddressSection, MACAddressSegment> implements AddressSegmentCreator<MACAddressSegment> {
		MACAddressSegment emptySegments[] = {};
		MACAddressSection emptySection[] = {};
		
		private static MACAddressSegment segmentCache[] = new MACAddressSegment[MACAddress.MAX_VALUE_PER_SEGMENT + 1];
		
		@Override
		public MACAddressSegment[] createSegmentArray(int length) {
			if(length == 0) {
				return emptySegments;
			}
			return new MACAddressSegment[length];
		}
		
		@Override
		public MACAddressSegment createSegment(int value) {
			MACAddressSegment result = segmentCache[value];
			if(result == null) {
				segmentCache[value] = result = new MACAddressSegment(value);
			}
			return result;
		}
		
		@Override
		public MACAddressSegment createSegment(int value, Integer segmentPrefixLength) {
			//On ipvx side we have prefix as part of segment, but not here
			//On ipvx side, the address creator for sections defers the prefix handling to the segments creator,
			//which defers the prefix handling to the segment constructor, and then the prefix is applied in the super constructor.
			//Here, we do the same, but when the prefix gets to here, we cannot pass to the segment, so we apply the prefix here
			//But this also gives more caching opportunities
			if(segmentPrefixLength != null) {
				if(segmentPrefixLength == 0) {
					return MACAddressSegment.ALL_RANGE_SEGMENT;
				}
				int max = MACAddress.MAX_VALUE_PER_SEGMENT;
				int mask = (~0 << (MACAddress.BITS_PER_SEGMENT - segmentPrefixLength)) & max;
				int newLower = value & mask;
				int newUpper = value | (~mask & max);
				return createSegment(newLower, newUpper);
			}
			return createSegment(value);
		}
		
		public MACAddressSegment createSegment(int lower, int upper) {
			if(lower != upper) {
				if(lower == 0 && upper == MACAddress.MAX_VALUE_PER_SEGMENT) {
					return MACAddressSegment.ALL_RANGE_SEGMENT;
				}
				return new MACAddressSegment(lower, upper);
			}
			return createSegment(lower);
		}
		
		@Override
		public MACAddressSegment createSegment(int lower, int upper, Integer segmentPrefixLength) {
			if(segmentPrefixLength == null) {
				return createSegment(lower, upper);
			}
			if(segmentPrefixLength == 0) {
				return MACAddressSegment.ALL_RANGE_SEGMENT;
			}
			int max = MACAddress.MAX_VALUE_PER_SEGMENT;
			int mask = (~0 << (MACAddress.BITS_PER_SEGMENT - segmentPrefixLength)) & max;
			int newLower = lower & mask;
			int newUpper = upper | (~mask  & max);
			return createSegment(newLower, newUpper);
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
			return new MACAddressSection(bytes, startIndex, extended, prefixLength);
		}
		
		MACAddressSection createSection(byte bytes[], int startIndex, boolean extended, Integer prefixLength) {
			return new MACAddressSection(bytes, startIndex, extended, prefixLength);
		}
		
		MACAddressSection createSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, int startIndex, boolean extended, Integer prefixLength) {
			return new MACAddressSection(lowerValueProvider, upperValueProvider, startIndex, extended, prefixLength);
		}
		
		@Override
		protected MACAddressSection createSectionInternal(MACAddressSegment[] segments) {
			return new MACAddressSection(false, segments, 0, segments.length > MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT);
		}
		
		protected MACAddressSection createSectionInternal(MACAddressSegment[] segments, boolean extended) {
			return new MACAddressSection(false, segments, 0, extended);
		}
		
		@Override
		protected MACAddressSection createSectionInternal(MACAddressSegment[] segments, int startIndex, boolean extended) {
			return new MACAddressSection(false, segments, startIndex, extended);
		}
		
		MACAddressSection createSection(MACAddressSegment[] segments, boolean extended, Integer prefixLength) {
			return new MACAddressSection(segments, 0, extended, prefixLength);
		}
		
		@Override
		protected MACAddress createAddressInternal(MACAddressSegment[] segments) {
			return createAddress(createSectionInternal(segments));
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
		return new MACAddressCreator();
	}
	
	public MACAddressNetwork.MACAddressCreator getAddressCreator() {
		return creator;
	}
	
	private MACAddressNetwork.MACAddressCreator creator;
	
	MACAddressNetwork() {
		this.creator = createAddressCreator();
	}
}
