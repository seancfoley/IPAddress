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

import inet.ipaddr.Address;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;

/**
 * This represents a segment of an IP address.  For IPv4, segments are 1 byte.  For IPv6, they are two bytes.
 * 
 * Like String and Integer and various others basic objects, segments are immutable, which also makes them thread-safe.
 * 
 * @author sfoley
 *
 */
public class IPv6AddressSegment extends IPAddressSegment implements Iterable<IPv6AddressSegment> {
	
	private static final long serialVersionUID = 4L;

	public static final int MAX_CHARS = 4;

	/**
	 * Constructs a segment of an IPv6 address with the given value.
	 * 
	 * @throws AddressValueException if value is negative or too large
	 * @param value the value of the segment
	 */
	public IPv6AddressSegment(int value) throws AddressValueException {
		super(value);
		if(value > IPv6Address.MAX_VALUE_PER_SEGMENT) {
			throw new AddressValueException(value);
		}
	}
	
	/**
	 * Constructs a segment of an IPv6 address.
	 * 
	 * @throws AddressValueException if value or prefix length is negative or too large
	 * @param value the value of the segment.  If the segmentPrefixLength is non-null, the network prefix of the value is used, and the segment represents all segment values with the same network prefix.
	 * @param segmentPrefixLength the segment prefix length, which can be null
	 */
	public IPv6AddressSegment(int value, Integer segmentPrefixLength) throws AddressValueException {
		super(value, segmentPrefixLength);
		if(value > IPv6Address.MAX_VALUE_PER_SEGMENT) {
			throw new AddressValueException(value);
		}
		if(segmentPrefixLength != null && segmentPrefixLength > IPv6Address.BIT_COUNT) {
			throw new PrefixLenException(segmentPrefixLength);
		}
	}
	
	/**
	 * Constructs a segment of an IPv6 address with the given range of values.
	 * 
	 * @throws AddressValueException if value or prefix length is negative or too large
	 * @param segmentPrefixLength the segment prefix length, which can be null.    If segmentPrefixLength is non-null, this segment represents a range of segment values with the given network prefix length.
	 * @param lower the lower value of the range of values represented by the segment.  If segmentPrefixLength is non-null, the lower value becomes the smallest value with the same network prefix.
	 * @param upper the upper value of the range of values represented by the segment.  If segmentPrefixLength is non-null, the upper value becomes the largest value with the same network prefix.
	 */
	public IPv6AddressSegment(int lower, int upper, Integer segmentPrefixLength) throws AddressValueException {
		super(lower, upper, segmentPrefixLength);
		if(getUpperSegmentValue() > IPv6Address.MAX_VALUE_PER_SEGMENT) {
			throw new AddressValueException(getUpperSegmentValue());
		}
		if(segmentPrefixLength != null && segmentPrefixLength > IPv6Address.BIT_COUNT) {
			throw new PrefixLenException(segmentPrefixLength);
		}
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
	protected byte[] getBytesImpl(boolean low) {
		int val = low ? getLowerSegmentValue() : getUpperSegmentValue();
		return new byte[] {(byte) (val >> 8), (byte) (0xff & val)};
	}
	
	@Override
	public IPv6AddressNetwork getNetwork() {
		return Address.defaultIpv6Network();
	}
	
	@Override
	protected int getSegmentNetworkMask(int bits) {
		return getNetwork().getSegmentNetworkMask(bits);
	}
	
	@Override
	protected int getSegmentHostMask(int bits) {
		return getNetwork().getSegmentHostMask(bits);
	}
	
	@Override
	public int getMaxSegmentValue() {
		return getMaxSegmentValue(IPVersion.IPV6);
	}
	
	protected IPv6AddressSegment toPrefixedSegment(Integer segmentPrefixLength) {
		if(isChangedByPrefix(segmentPrefixLength, getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets())) {
			return super.toPrefixedSegment(segmentPrefixLength, getSegmentCreator());
		}
		return this;
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

	@Override
	public IPv6AddressSegment getLower() {
		return getLowestOrHighest(this, getSegmentCreator(), true);
	}

	@Override
	public IPv6AddressSegment getUpper() {
		return getLowestOrHighest(this, getSegmentCreator(), false);
	}

	@Override
	public IPv6AddressSegment reverseBits(boolean perByte) {
		if(isMultiple()) {
			if(isReversibleRange(this)) {
				if(isPrefixed()) {
					AddressSegmentCreator<IPv6AddressSegment> creator = getSegmentCreator();
					return creator.createSegment(getLowerSegmentValue(), getUpperSegmentValue(), null);
				}
				return this;
			}
			throw new IncompatibleAddressException(this, "ipaddress.error.reverseRange");
		}
		AddressSegmentCreator<IPv6AddressSegment> creator = getSegmentCreator();
		int oldVal = getLowerSegmentValue();
		int newVal = reverseBits((short) oldVal);
		if(perByte) {
			newVal = ((newVal & 0xff) << 8) | (newVal >>> 8);
		}
		if(oldVal == newVal && !isPrefixed()) {
			return this;
		}
		return creator.createSegment(newVal);
	}
	
	@Override
	public IPv6AddressSegment reverseBytes() {
		if(isMultiple()) {
			if(isReversibleRange(this)) {
				//reversible ranges end up being the same as the original
				if(isPrefixed()) {
					AddressSegmentCreator<IPv6AddressSegment> creator = getSegmentCreator();
					return creator.createSegment(getLowerSegmentValue(), getUpperSegmentValue(), null);
				}
				return this;
			}
			throw new IncompatibleAddressException(this, "ipaddress.error.reverseRange");
		}
		AddressSegmentCreator<IPv6AddressSegment> creator = getSegmentCreator();
		int value = getLowerSegmentValue();
		int newValue = ((value & 0xff) << 8) | (value >>> 8);
		if(value == newValue && !isPrefixed()) {
			return this;
		}
		return creator.createSegment(newValue);
	}
	
	@Override
	public IPv6AddressSegment removePrefixLength(boolean zeroed) {
		return removePrefix(this, zeroed, getSegmentCreator());
	}
	
	@Override
	public IPv6AddressSegment removePrefixLength() {
		return removePrefixLength(true);
	}

	protected IPv6AddressCreator getSegmentCreator() {
		return getNetwork().getAddressCreator();
	}

	@Override
	public Iterable<IPv6AddressSegment> getIterable() {
		return this;
	}
			
	@Override
	public Iterator<IPv6AddressSegment> iterator() {
		return iterator(this, getSegmentCreator(), !isPrefixed());
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
	public int getMaxDigitCount() {
		return MAX_CHARS;
	}
	
	/**
	 * Converts this IPv6 address segment into smaller segments,
	 * copying them into the given array starting at the given index.
	 * 
	 * If a segment does not fit into the array because the segment index in the array is out of bounds of the array,
	 * then it is not copied.
	 * 
	 * @param segs
	 * @param index
	 */
	public <S extends AddressSegment> void getSplitSegments(S segs[], int index, AddressSegmentCreator<S> creator) {
		if(!isMultiple()) {
			int bitSizeSplit = IPv6Address.BITS_PER_SEGMENT >>> 1;
			Integer myPrefix = getSegmentPrefixLength();
			Integer highPrefixBits = getSplitSegmentPrefix(bitSizeSplit, myPrefix, 0);
			Integer lowPrefixBits = getSplitSegmentPrefix(bitSizeSplit, myPrefix, 1);
			if(index >= 0 && index < segs.length) {
				segs[index] = creator.createSegment(highByte(), highPrefixBits);
			}
			if(++index >= 0 && index < segs.length) {
				segs[index] = creator.createSegment(lowByte(), lowPrefixBits);
			}
		} else {
			getSplitSegmentsMultiple(segs, index, creator);
		}
	}
	
	private <S extends AddressSegment> void getSplitSegmentsMultiple(S segs[], int index, AddressSegmentCreator<S> creator) {
		Integer myPrefix = getSegmentPrefixLength();
		int bitSizeSplit = IPv6Address.BITS_PER_SEGMENT >>> 1;
		if(index >= 0 && index < segs.length) {
			int highLower = highByte(getLowerSegmentValue());
			int highUpper = highByte(getUpperSegmentValue());
			Integer highPrefixBits = getSplitSegmentPrefix(bitSizeSplit, myPrefix, 0);
			if(highLower == highUpper) {
				segs[index] = creator.createSegment(highLower, highPrefixBits);
			} else {
				segs[index] = creator.createSegment(highLower, highUpper, highPrefixBits);
			}
		}
		if(++index >= 0 && index < segs.length) {
			int lowLower = lowByte(getLowerSegmentValue());
			int lowUpper = lowByte(getUpperSegmentValue());
			Integer lowPrefixBits = getSplitSegmentPrefix(bitSizeSplit, myPrefix, 1);
			if(lowLower == lowUpper) {
				segs[index] = creator.createSegment(lowLower, lowPrefixBits);
			} else {
				segs[index] = creator.createSegment(lowLower, lowUpper, lowPrefixBits);
			}
		}
	}
	
	@Override
	public boolean contains(AddressSegment other) {
		return other instanceof IPv6AddressSegment && super.contains(other);
	}
	
	@Override
	public boolean equals(Object other) {
		if(this == other) {
			return true;
		}
		return (other instanceof IPv6AddressSegment) && isSameValues((IPv6AddressSegment) other);
	}
	
	@Override
	protected int getRangeDigitCountImpl() {
		int prefix = getMinPrefixLengthForBlock();
		int bitCount = getBitCount();
		if(prefix < bitCount && isSinglePrefixBlock(prefix)) {
			int bitsPerCharacter = IPv6Address.BITS_PER_SEGMENT / MAX_CHARS;
			if(prefix % bitsPerCharacter == 0) {
				return (bitCount - prefix) / bitsPerCharacter;
			}
		}
		return 0;
	}
}
