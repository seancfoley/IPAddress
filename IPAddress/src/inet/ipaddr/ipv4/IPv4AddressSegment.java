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

package inet.ipaddr.ipv4;

import java.util.Iterator;

import inet.ipaddr.Address;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSegment;

/**
 * This represents a segment of an IP address.  For IPv4, segments are 1 byte.  For IPv6, they are two bytes.
 * 
 * Like String and Integer and various others basic objects, segments are immutable, which also makes them thread-safe.
 * 
 * @author sfoley
 *
 */
public class IPv4AddressSegment extends IPAddressSegment implements Iterable<IPv4AddressSegment> {
	
	private static final long serialVersionUID = 4L;

	/**
	 * When printed with the default radix of 10, the max number of characters per segment
	 */
	public static final int MAX_CHARS = 3;

	/**
	 * Constructs a segment of an IPv4 address with the given value.
	 * 
	 * @throws AddressValueException if value is negative or too large
	 * @param value the value of the segment
	 */
	public IPv4AddressSegment(int value) throws AddressValueException {
		super(value);
		if(value > IPv4Address.MAX_VALUE_PER_SEGMENT) {
			throw new AddressValueException(value);
		}
	}
	
	/**
	 * Constructs a segment of an IPv4 address.
	 * 
	 * @throws AddressValueException if value or prefix length is negative or too large
	 * @param value the value of the segment.  If the segmentPrefixLength is non-null, the network prefix of the value is used, and the segment represents all segment values with the same network prefix.
	 * @param segmentPrefixLength the segment prefix, which can be null
	 */
	public IPv4AddressSegment(int value, Integer segmentPrefixLength) throws AddressValueException {
		super(value, segmentPrefixLength);
		if(value > IPv4Address.MAX_VALUE_PER_SEGMENT) {
			throw new AddressValueException(value);
		}
		if(segmentPrefixLength != null && segmentPrefixLength > IPv4Address.BIT_COUNT) {
			throw new PrefixLenException(segmentPrefixLength);
		}
	}
	
	/**
	 * Constructs a segment of an IPv4 address that represents a range of values.
	 * 
	 * @throws AddressValueException if either lower or upper value or prefix length is negative or too large
	 * @param segmentPrefixLength the segment prefix length, which can be null.    If segmentPrefixLength is non-null, this segment represents a range of segment values with the given network prefix length.
	 * @param lower the lower value of the range of values represented by the segment.  If segmentPrefixLength is non-null, the lower value becomes the smallest value with the same network prefix.
	 * @param upper the upper value of the range of values represented by the segment.  If segmentPrefixLength is non-null, the upper value becomes the largest value with the same network prefix.
	 */
	public IPv4AddressSegment(int lower, int upper, Integer segmentPrefixLength) throws AddressValueException {
		super(lower, upper, segmentPrefixLength);
		if(getUpperSegmentValue() > IPv4Address.MAX_VALUE_PER_SEGMENT) {
			throw new AddressValueException(getUpperSegmentValue());
		}
		if(segmentPrefixLength != null && segmentPrefixLength > IPv4Address.BIT_COUNT) {
			throw new PrefixLenException(segmentPrefixLength);
		}
	}

	@Override
	public boolean isIPv4() {
		return true;
	}
	
	@Override
	public IPVersion getIPVersion() {
		return IPVersion.IPV4;
	}
	
	@Override
	protected byte[] getBytesImpl(boolean low) {
		return new byte[] {(byte) (low ? getLowerSegmentValue() : getUpperSegmentValue())};
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
		return getMaxSegmentValue(IPVersion.IPV4);
	}
	
	protected IPv4AddressSegment toPrefixedSegment(Integer segmentPrefixLength) {
		if(isChangedByPrefix(segmentPrefixLength, getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets())) {
			return super.toPrefixedSegment(segmentPrefixLength, getSegmentCreator());
		}
		return this;
	}
	
	@Override
	public IPv4AddressSegment toNetworkSegment(Integer segmentPrefixLength) {
		return toNetworkSegment(segmentPrefixLength, true);
	}
	
	@Override
	public IPv4AddressSegment toNetworkSegment(Integer segmentPrefixLength, boolean withPrefixLength) {
		if(isNetworkChangedByPrefix(segmentPrefixLength, withPrefixLength)) {
			return super.toNetworkSegment(segmentPrefixLength, withPrefixLength, getSegmentCreator());
		}
		return this;
	}

	@Override
	public IPv4AddressSegment toHostSegment(Integer bits) {
		if(isHostChangedByPrefix(bits)) {
			return super.toHostSegment(bits, getSegmentCreator());
		}
		return this;
	}

	@Override
	public IPv4AddressSegment getLower() {
		return getLowestOrHighest(this, getSegmentCreator(), true);
	}
	
	@Override
	public IPv4AddressSegment getUpper() {
		return getLowestOrHighest(this, getSegmentCreator(), false);
	}
	
	@Override
	public IPv4AddressNetwork getNetwork() {
		return Address.defaultIpv4Network();
	}

	public IPv4AddressCreator getSegmentCreator() {
		return getNetwork().getAddressCreator();
	}
	
	@Override
	public Iterable<IPv4AddressSegment> getIterable() {
		return this;
	}
	
	@Override
	public Iterator<IPv4AddressSegment> iterator() {
		return iterator(this, getSegmentCreator(), !isPrefixed(), null);
	}
	
	@Override
	public Iterator<IPv4AddressSegment> prefixBlockIterator() {
		return iterator(this, getSegmentCreator(), true, getSegmentPrefixLength());
	}

	@Override
	public int getBitCount() {
		return IPv4Address.BITS_PER_SEGMENT;
	}

	@Override
	public int getByteCount() {
		return IPv4Address.BYTES_PER_SEGMENT;
	}
	
	@Override
	public int getDefaultTextualRadix() {
		return IPv4Address.DEFAULT_TEXTUAL_RADIX;
	}
	
	@Override
	public int getMaxDigitCount() {
		return MAX_CHARS;
	}
	
	@Override
	public IPv4AddressSegment reverseBits(boolean perByte) {
		return reverseBits();
	}
	
	public IPv4AddressSegment reverseBits() {
		if(isMultiple()) {
			if(isReversibleRange(this)) {
				if(isPrefixed()) {
					AddressSegmentCreator<IPv4AddressSegment> creator = getSegmentCreator();
					return creator.createSegment(getLowerSegmentValue(), getUpperSegmentValue(), null);
				}
				return this;
			}
			throw new IncompatibleAddressException(this, "ipaddress.error.reverseRange");
		}
		int oldVal = getLowerSegmentValue();
		int newVal = reverseBits((byte) oldVal);
		if(oldVal == newVal && !isPrefixed()) {
			return this;
		}
		AddressSegmentCreator<IPv4AddressSegment> creator = getSegmentCreator();
		return creator.createSegment(newVal);
	}
	
	@Override
	public IPv4AddressSegment reverseBytes() {
		return removePrefix(this, false, getSegmentCreator());
	}
	
	@Override
	public IPv4AddressSegment removePrefixLength(boolean zeroed) {
		return removePrefix(this, zeroed, getSegmentCreator());
	}
	
	@Override
	public IPv4AddressSegment removePrefixLength() {
		return removePrefixLength(true);
	}

	@Override
	public boolean contains(AddressSegment other) {
		return other instanceof IPv4AddressSegment && containsSeg(other);
	}
	
	@Override
	public boolean equals(Object other) {
		if(this == other) {
			return true;
		}
		return other instanceof IPv4AddressSegment && isSameValues((IPv4AddressSegment) other);
	}
	
	/**
	 * Joins with another IPv4 segment to produce a IPv6 segment.
	 * 
	 * @param creator
	 * @param low
	 * @return
	 */
	 public IPv6AddressSegment join(IPv6AddressCreator creator, IPv4AddressSegment low) throws IncompatibleAddressException {
		int shift = IPv4Address.BITS_PER_SEGMENT;
		Integer prefix = getJoinedSegmentPrefixLength(shift, getSegmentPrefixLength(), low.getSegmentPrefixLength());
		if(isMultiple()) {
			//if the high segment has a range, the low segment must match the full range, 
			//otherwise it is not possible to create an equivalent range when joining
			if(!low.isFullRange()) {
				throw new IncompatibleAddressException(this, low, "ipaddress.error.invalidMixedRange");
			}
		}
		return creator.createSegment(
				(getLowerSegmentValue() << shift) | low.getLowerSegmentValue(), 
				(getUpperSegmentValue() << shift) | low.getUpperSegmentValue(),
				prefix);
	}

	static Integer getJoinedSegmentPrefixLength(int bitsPerSegment, Integer highBits, Integer lowBits) {
		if(lowBits == null) {
			return null;
		}
		if(lowBits == 0) {
			return highBits;
		}
		return lowBits + bitsPerSegment;
	}
}
