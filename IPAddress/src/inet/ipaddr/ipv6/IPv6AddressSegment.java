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

package inet.ipaddr.ipv6;

import java.util.Iterator;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;

/**
 * This represents a segment of an IP address.  For IPv4, segments are 1 byte.  For IPv6, they are two bytes.
 * 
 * Like String and Integer and various others basic objects, segments are immutable, which also makes them thread-safe.
 * 
 * @author sfoley
 *
 */
public class IPv6AddressSegment extends IPAddressSegment {
	
	private static final long serialVersionUID = 1L;

	public static final int MAX_CHARS = 4;
	
	static final IPv6AddressSegment ZERO_SEGMENT = getSegmentCreator().createSegment(0);
	static final IPv6AddressSegment ALL_SEGMENT = getSegmentCreator().createSegment(IPv6Address.MAX_VALUE_PER_SEGMENT);
	static final IPv6AddressSegment ZERO_PREFIX_SEGMENT = new IPv6AddressSegment(0, 0);
	static final IPv6AddressSegment ALL_RANGE_SEGMENT = new IPv6AddressSegment(0, IPv6Address.MAX_VALUE_PER_SEGMENT, null);
	
	/**
	 * Constructs a segment of an IPv6 address with the given value.
	 * 
	 * @param value the value of the segment
	 */
	public IPv6AddressSegment(int value) {
		super(value);
	}
	
	/**
	 * Constructs a segment of an IPv6 address.
	 * 
	 * @param value the value of the segment.  If the segmentPrefixLength is non-null, the network prefix of the value is used, and the segment represents all segment values with the same network prefix.
	 * @param segmentPrefixLength the segment prefix length, which can be null
	 */
	public IPv6AddressSegment(int value, Integer segmentPrefixLength) {
		super(value, segmentPrefixLength == null ? null : Math.min(IPv6Address.BITS_PER_SEGMENT, segmentPrefixLength));
	}
	
	/**
	 * Constructs a segment of an IPv6 address with the given range of values.
	 * 
	 * @param segmentPrefixLength the segment prefix length, which can be null.    If segmentPrefixLength is non-null, this segment represents a range of segment values with the given network prefix length.
	 * @param lower the lower value of the range of values represented by the segment.  If segmentPrefixLength is non-null, the lower value becomes the smallest value with the same network prefix.
	 * @param upper the upper value of the range of values represented by the segment.  If segmentPrefixLength is non-null, the upper value becomes the largest value with the same network prefix.
	 */
	public IPv6AddressSegment(int lower, int upper, Integer segmentPrefixLength) {
		super(lower, upper, segmentPrefixLength == null ? null : Math.min(IPv6Address.BITS_PER_SEGMENT, segmentPrefixLength));
	}
	
	@Override
	public boolean isIPv6() {
		return true;
	}
	
	@Override
	public IPVersion getIPVersion() {
		return IPVersion.IPV6;
	}
	
	@Override
	protected int getSegmentNetworkMask(int bits) {
		return IPv6Address.network().getSegmentNetworkMask(bits);
	}
	
	@Override
	protected int getSegmentHostMask(int bits) {
		return IPv6Address.network().getSegmentHostMask(bits);
	}
	
	@Override
	public int getMaxSegmentValue() {
		return getMaxSegmentValue(IPVersion.IPV6);
	}
	
	@Override
	public IPv6AddressSegment toNetworkSegment(Integer segmentPrefixLength) {
		return toNetworkSegment(segmentPrefixLength, true);
	}
	
	@Override
	public IPv6AddressSegment toNetworkSegment(Integer segmentPrefixLength, boolean withPrefixLength) {
		if(isNetworkChangedByPrefix(segmentPrefixLength, withPrefixLength)) {
			return super.toNetworkSegment(segmentPrefixLength, withPrefixLength, getSegmentCreator());
		}
		return this;
	}
	
	@Override
	public IPv6AddressSegment toHostSegment(Integer bits) {
		if(isHostChangedByPrefix(bits)) {
			return super.toHostSegment(bits, getSegmentCreator());
		}
		return this;
	}
	
	/* returns a new segment masked by the given mask */
	@Override
	public IPv6AddressSegment toMaskedSegment(IPAddressSegment maskSegment, Integer segmentPrefixLength) throws IPAddressTypeException {
		if(isChangedByMask(maskSegment, segmentPrefixLength)) {
			if(!isMaskCompatibleWithRange(maskSegment, segmentPrefixLength)) {
				throw new IPAddressTypeException(this, maskSegment, "ipaddress.error.maskMismatch");
			}
			int maskValue = maskSegment.getLowerSegmentValue();
			return getSegmentCreator().createSegment(getLowerSegmentValue() & maskValue, getUpperSegmentValue() & maskValue, segmentPrefixLength);
		}
		return this;
	}
	
	protected boolean isChangedByMask(IPAddressSegment maskSegment, Integer segmentPrefixLength) throws IPAddressTypeException {
		if(!(maskSegment instanceof IPv6AddressSegment)) {
			throw new IPAddressTypeException(this, maskSegment, "ipaddress.error.typeMismatch");
		}
		return super.isChangedByMask(maskSegment.getLowerSegmentValue(), segmentPrefixLength);
	}
	
	@Override
	public IPv6AddressSegment getLower() {
		return getLowestOrHighest(this, getSegmentCreator(), true);
	}
	
	@Override
	public IPv6AddressSegment getUpper() {
		return getLowestOrHighest(this, getSegmentCreator(), false);
	}
	
	private static IPv6AddressCreator getSegmentCreator() {
		return IPv6Address.network().getAddressCreator();
	}
	
	@Override
	public Iterator<IPv6AddressSegment> iterator() {
		return iterator(this, getSegmentCreator());
	}
	
	static IPv6AddressSegment getZeroSegment() {
		return ZERO_SEGMENT;
	}
	
	@Override
	protected int getLeadingZerosAdjustment() {
		return Long.SIZE - IPv6Address.BITS_PER_SEGMENT;
	}
	
	@Override
	public int getBitCount() {
		return IPv6Address.BITS_PER_SEGMENT;
	}
	
	@Override
	public int getByteCount() {
		return IPv6Address.BYTES_PER_SEGMENT;
	}
	
	@Override
	public int getDefaultTextualRadix() {
		return IPv6Address.DEFAULT_TEXTUAL_RADIX;
	}
	
	@Override
	public int getDefaultMaxChars() {
		return MAX_CHARS;
	}
	
	/**
	 * Converts this IPv6 address segment into IPv4 segments,
	 * copying them into the given array starting at the given index.
	 * 
	 * If a segment does not fit into the array because the segment index in the array is out of bounds of the array,
	 * then it is not copied.
	 * 
	 * @param segs
	 * @param index
	 */
	public void getIPv4Segments(IPv4AddressSegment segs[], int index) {
		if(!isMultiple()) {
			Integer myPrefix = getSegmentPrefixLength();
			Integer highPrefixBits = getSplitSegmentPrefix(IPv4Address.BITS_PER_SEGMENT, myPrefix, 0);
			Integer lowPrefixBits = getSplitSegmentPrefix(IPv4Address.BITS_PER_SEGMENT, myPrefix, 1);
			IPv4AddressCreator creator = getIPv4AddressCreator();
			if(index >= 0 && index < segs.length) {
				segs[index] = creator.createSegment(highByte(), highPrefixBits);
			}
			if(++index >= 0 && index < segs.length) {
				segs[index] = creator.createSegment(lowByte(), lowPrefixBits);
			}
		} else {
			getIPv4SegmentsMultiple(segs, index);
		}
	}
	
	private void getIPv4SegmentsMultiple(IPv4AddressSegment segs[], int index) {
		Integer myPrefix = getSegmentPrefixLength();
		IPv4AddressCreator creator = getIPv4AddressCreator();
		if(index >= 0 && index < segs.length) {
			int highLower = highByte(getLowerSegmentValue());
			int highUpper = highByte(getUpperSegmentValue());
			Integer highPrefixBits = getSplitSegmentPrefix(IPv4Address.BITS_PER_SEGMENT, myPrefix, 0);
			if(highLower == highUpper) {
				segs[index] = creator.createSegment(highLower, highPrefixBits);
			} else {
				segs[index] = createSegment(highLower, highUpper, highPrefixBits);
			}
		}
		if(++index >= 0 && index < segs.length) {
			int lowLower = lowByte(getLowerSegmentValue());
			int lowUpper = lowByte(getUpperSegmentValue());
			Integer lowPrefixBits = getSplitSegmentPrefix(IPv4Address.BITS_PER_SEGMENT, myPrefix, 1);
			if(lowLower == lowUpper) {
				segs[index] = creator.createSegment(lowLower, lowPrefixBits);
			} else {
				segs[index] = createSegment(lowLower, lowUpper, lowPrefixBits);
			}
		}
	}
	
	/**
	 * Splits this IPv6 address segment into one-byte segments
	 * @return
	 */
	public IPv4AddressSegment[] split() {
		IPv4AddressCreator creator = getIPv4AddressCreator();
		IPv4AddressSegment segs[] = creator.createSegmentArray(IPv6Address.BYTES_PER_SEGMENT / IPv4Address.BYTES_PER_SEGMENT);
		getIPv4Segments(segs, 0);
		return segs;
	}
	
	/**
	 * Splits two IPv6 segments into four IPv4 segments.
	 * 
	 * @param high
	 * @param low
	 * @return
	 */
	static IPv4AddressSegment[] split(IPv6AddressSegment high, IPv6AddressSegment low) {
		IPv4AddressCreator creator = getIPv4AddressCreator();
		IPv4AddressSegment segs[] = creator.createSegmentArray((2 * IPv6Address.BYTES_PER_SEGMENT) / IPv4Address.BYTES_PER_SEGMENT);
		high.getIPv4Segments(segs, 0);
		low.getIPv4Segments(segs, IPv6Address.BYTES_PER_SEGMENT / IPv4Address.BYTES_PER_SEGMENT);
		return segs;
	}

	private static IPv4AddressCreator getIPv4AddressCreator() {
		return IPv4Address.network().getAddressCreator();
	}
	
	private IPv4AddressSegment createSegment(int highLower, int highUpper, Integer highPrefixBits) {
		IPv4AddressCreator creator = getIPv4AddressCreator();
		return creator.createSegment(highLower, highUpper, highPrefixBits);
	}
	
	/**
	 * Joins 1 IPv4 segments into 2 IPv6 segments.
	 * 
	 * @param high
	 * @param low
	 * @return
	 */
	static IPv6AddressSegment join(IPv4AddressSegment high, IPv4AddressSegment low) throws IPAddressTypeException {
		int shift = IPv4Address.BITS_PER_SEGMENT;
		Integer prefix = getJoinedSegmentPrefix(shift, high.getSegmentPrefixLength(), low.getSegmentPrefixLength());
		if(high.isMultiple()) {
			//if the high segment has a range, the low segment must match the full range, 
			//otherwise it is not possible to create an equivalent range when joining
			if(!low.isFullRange()) {
				throw new IPAddressTypeException(high, low, "ipaddress.error.invalidMixedRange");
			}
		}
		return getSegmentCreator().createSegment(
				(high.getLowerSegmentValue() << shift) | low.getLowerSegmentValue(), 
				(high.getUpperSegmentValue() << shift) | low.getUpperSegmentValue(),
				prefix);
	}
	
	public static IPv6AddressSegment join(IPv4AddressSegment one, IPv4AddressSegment two, int upperRangeLower, int upperRangeUpper, int lowerRangeLower, int lowerRangeUpper, Integer segmentPrefixLength) throws IPAddressTypeException {
		int shift = IPv4Address.BITS_PER_SEGMENT;
		if(upperRangeLower != upperRangeUpper) {
			//if the high segment has a range, the low segment must match the full range, 
			//otherwise it is not possible to create an equivalent IPv6 range when joining two IPv4 ranges
			if(segmentPrefixLength != null) {
				if(segmentPrefixLength > shift) {
					segmentPrefixLength -= shift;
				} else {
					segmentPrefixLength = 0;
				}
			} 
			if(!isFullRange(lowerRangeLower, lowerRangeUpper, segmentPrefixLength, IPVersion.IPV4)) {
				throw new IPAddressTypeException(one, two, "ipaddress.error.invalidMixedRange");
			}
		}
		return getSegmentCreator().createSegment(
				(upperRangeLower << shift) | lowerRangeLower,
				(upperRangeUpper << shift) | lowerRangeUpper,
				segmentPrefixLength);
	}
	
	/**
	 * Joins four IPv4 segments into 2 IPv6 segments.
	 * 
	 * @param high
	 * @param low
	 * @return
	 */
	static IPv6AddressSegment[] join(
			IPv4AddressSegment highHigh,
			IPv4AddressSegment highlow,
			IPv4AddressSegment lowHigh,
			IPv4AddressSegment lowLow) throws IPAddressTypeException {
		IPv6AddressSegment segs[] = getSegmentCreator().createSegmentArray(2);
		segs[0] = join(highHigh, highlow);
		segs[1] = join(lowHigh, lowLow);
		return segs;
	}

	@Override
	public boolean contains(IPAddressSegment other) {
		return other.isIPv6() && super.contains(other);
	}
	
	@Override
	public boolean equals(Object other) {
		return (other instanceof IPv6AddressSegment) && isSameValues((IPv6AddressSegment) other);
	}
	
	@Override
	protected int getRangeDigitCountImpl() {
		int prefix = getMinPrefix();
		int bitCount = getBitCount();
		if(prefix < bitCount && isRangeEquivalent(prefix)) {
			int bitsPerCharacter = IPv6Address.BITS_PER_SEGMENT / MAX_CHARS;
			if(prefix % bitsPerCharacter == 0) {
				return (bitCount - prefix) / bitsPerCharacter;
			}
		}
		return 0;
	}
}
