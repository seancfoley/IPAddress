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

import java.util.Iterator;

import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.AddressDivisionBase;
import inet.ipaddr.format.standard.AddressDivision;
import inet.ipaddr.format.standard.AddressDivisionGrouping.StringOptions;
import inet.ipaddr.format.util.AddressDivisionWriter;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;
import inet.ipaddr.mac.MACAddressSection.MACStringCache;

public class MACAddressSegment extends AddressDivision implements AddressSegment, Iterable<MACAddressSegment> {

	private static final long serialVersionUID = 4L;
	
	public static final int MAX_CHARS = 2;
	
	private final int value; //the lower value of the segment
	private final int upperValue; //the upper value of a range; if not a range it is the same as value
	
	/**
	 * Constructs a segment of an IPv4 or IPv6 address with the given value.
	 * 
	 * @throws AddressValueException if value is negative or too large
	 * @param value the value of the segment
	 */
	public MACAddressSegment(int value) {
		if(value < 0 || value > MACAddress.MAX_VALUE_PER_SEGMENT) {
			throw new AddressValueException(value);
		}
		this.value = this.upperValue = value;
	}
	
	/**
	 * Constructs a segment of a MAC address that represents a range of values.
	 * 
	 * @throws AddressValueException if value is negative or too large
	 * @param lower the lower value of the range of values represented by the segment.
	 * @param upper the upper value of the range of values represented by the segment.
	 */
	public MACAddressSegment(int lower, int upper) {
		if(lower > upper) {
			int tmp = lower;
			lower = upper;
			upper = tmp;
		}
		if(lower < 0 || upper < 0 || upper > MACAddress.MAX_VALUE_PER_SEGMENT) {
			throw new AddressValueException(lower < 0 ? lower : upper);
		}
		this.value = lower;
		this.upperValue = upper;
	}
	
	@Override
	protected byte[] getBytesImpl(boolean low) {
		return new byte[] { (byte) (low ? getSegmentValue() : getUpperSegmentValue())};
	}
	
	protected boolean isPrefixBlock(int segmentPrefixLength) {
		if(segmentPrefixLength < MACAddress.BITS_PER_SEGMENT) {
			int mask = ~0 << (MACAddress.BITS_PER_SEGMENT - segmentPrefixLength);
			int lower = getSegmentValue();
			int newLower = lower & mask;
			if(lower != newLower) {
				return false;
			}
			int upper = getUpperSegmentValue();
			return upper == (upper | ~mask);
		}
		return true;
	}
	
	protected MACAddressSegment toPrefixBlockSegment(int segmentPrefixLength) {
		if(segmentPrefixLength < MACAddress.BITS_PER_SEGMENT && !isPrefixBlock(segmentPrefixLength)) {
			int lower = getSegmentValue();
			int upper = getUpperSegmentValue();
			int mask = ~0 << (MACAddress.BITS_PER_SEGMENT - segmentPrefixLength);
			lower &= mask;
			upper |= ~mask;
			return getSegmentCreator().createRangeSegment(lower, upper);
		}
		return this;
	}
	
	protected MACAddressSegment setPrefixedSegment(Integer oldPrefixLength, Integer segmentPrefixLength, boolean zeroed) {
		return setPrefixedSegment(this, oldPrefixLength, segmentPrefixLength, zeroed, getSegmentCreator());
	}

	private MACAddressCreator getSegmentCreator() {
		return getNetwork().getAddressCreator();
	}
	
	@Override
	public MACAddressNetwork getNetwork() {
		return MACAddress.defaultMACNetwork();
	}
	
	@Override
	public int getValueCount() {
		return getUpperSegmentValue() - getSegmentValue() + 1;
	}
	
	int getPrefixValueCount(int segmentPrefixLength) {
		int shiftAdjustment = MACAddress.BITS_PER_SEGMENT - segmentPrefixLength;
		return (getUpperSegmentValue() >>> shiftAdjustment) - (getSegmentValue() >>> shiftAdjustment) + 1;
	}
	
	@Override
	public long getDivisionValueCount() {
		return getValueCount();
	}
	
	@Override
	public int getBitCount() {
		return MACAddress.BITS_PER_SEGMENT;
	}

	@Override
	public int getByteCount() {
		return MACAddress.BYTES_PER_SEGMENT;
	}

	@Override
	public long getMaxValue() {
		return MACAddress.MAX_VALUE_PER_SEGMENT;
	}

	@Override
	public long getDivisionValue() {
		return getSegmentValue();
	}

	@Override
	public long getUpperDivisionValue() {
		return getUpperSegmentValue();
	}
	
	/**
	 * returns the lower value
	 */
	@Override
	public int getSegmentValue() {
		return value;
	}
	
	/**
	 * returns the upper value
	 */
	@Override
	public int getUpperSegmentValue() {
		return upperValue;
	}
	
	private MACAddressSegment getLowestOrHighest(boolean lowest) {
		if(!isMultiple()) {
			return this;
		}
		return getSegmentCreator().createSegment(lowest ? getSegmentValue() : getUpperSegmentValue());
	}
	
	@Override
	public MACAddressSegment getLower() {
		return getLowestOrHighest(true);
	}
	
	@Override
	public MACAddressSegment getUpper() {
		return getLowestOrHighest(false);
	}
	
	@Override
	public MACAddressSegment reverseBits(boolean perByte) {
		return reverseBits();
	}
	
	public MACAddressSegment reverseBits() {
		if(isMultiple()) {
			if(isReversibleRange(this)) {
				return this;
			}
			throw new IncompatibleAddressException(this, "ipaddress.error.reverseRange");
		}
		int oldValue = value;
		int newValue = reverseBits((byte) oldValue);
		if(oldValue == newValue) {
			return this;
		}
		AddressSegmentCreator<MACAddressSegment> creator = getSegmentCreator();
		return creator.createSegment(newValue);
	}
	
	@Override
	public MACAddressSegment reverseBytes() {
		return this;
	}
	
	@Override
	public boolean isBoundedBy(int value) {
		return getUpperSegmentValue() < value;
	}
	
	@Override
	protected boolean isSameValues(AddressDivisionBase other) {
		return other instanceof MACAddressSegment && isSameValues((MACAddressSegment) other);
	}

	protected boolean isSameValues(MACAddressSegment otherSegment) {
		return value == otherSegment.value && upperValue == otherSegment.upperValue;
	}

	@Override
	public int hashCode() {
		return hash(value, upperValue, getBitCount());
	}
	
	static int hash(int lower, int upper, int bitCount) {
		return lower | (upper << bitCount);
	}
	
	@Override
	public boolean equals(Object other) {
		return this == other || (other instanceof MACAddressSegment && ((MACAddressSegment) other).isSameValues(this));
	}

	/**
	 * 
	 * @param other
	 * @return whether this subnet segment contains the given address segment
	 */
	public boolean contains(MACAddressSegment other) {
		return other.value >= value && other.upperValue <= upperValue;
	}
	
	@Override
	public int getDefaultTextualRadix() {
		return MACAddress.DEFAULT_TEXTUAL_RADIX;
	}

	@Override
	public int getMaxDigitCount() {
		return MAX_CHARS;
	}
	
	@Override
	public boolean matches(int value) {
		return super.matches(value);
	}
	
	@Override
	public boolean matchesWithMask(int value, int mask) {
		return super.matchesWithMask(value, mask);
	}
	
	@Override
	public boolean matchesWithMask(int lowerValue, int upperValue, int mask) {
		return super.matchesWithMask(lowerValue, upperValue, mask);
	}

	void setString(
			CharSequence addressStr, 
			boolean isStandardString,
			int lowerStringStartIndex,
			int lowerStringEndIndex,
			int originalLowerValue) {
		if(cachedWildcardString == null && isStandardString && originalLowerValue == getDivisionValue()) {
			cachedWildcardString = addressStr.subSequence(lowerStringStartIndex, lowerStringEndIndex).toString();
		}
	}
	
	void setString(CharSequence addressStr, 
			boolean isStandardRangeString,
			int lowerStringStartIndex,
			int upperStringEndIndex,
			int rangeLower,
			int rangeUpper) {
		if(cachedWildcardString == null) {
			if(isFullRange()) {
				cachedWildcardString = MACAddress.SEGMENT_WILDCARD_STR;
			} else if(isStandardRangeString && rangeLower == getDivisionValue() && rangeUpper == getUpperDivisionValue()) {
				cachedWildcardString = addressStr.subSequence(lowerStringStartIndex, upperStringEndIndex).toString();
			}
		}
	}
	
	@Override
	public Iterable<MACAddressSegment> getIterable() {
		return this;
	}

	@Override
	public Iterator<MACAddressSegment> iterator() {
		return iterator(this, getSegmentCreator(), true, null, false, false);
	}
	
	Iterator<MACAddressSegment> prefixBlockIterator(int segmentPrefixLength) {
		return iterator(this, getSegmentCreator(), true, segmentPrefixLength, true, true);
	}
	
	Iterator<MACAddressSegment> prefixIterator(int segmentPrefixLength) {
		return iterator(this, getSegmentCreator(), true, segmentPrefixLength, true, false);
	}

	@Override
	public int getMaxSegmentValue() {
		return MACAddress.MAX_VALUE_PER_SEGMENT;
	}

	@Override
	public boolean prefixEquals(AddressSegment o, int segmentPrefixLength) {
		if(segmentPrefixLength < 0) {
			throw new PrefixLenException(segmentPrefixLength);
		}
		if(o instanceof MACAddressSegment) {
			MACAddressSegment other = (MACAddressSegment) o;
			int shift = getBitCount() - segmentPrefixLength;
			if(shift <= 0) {
				return isSameValues(other);
			}
			return (other.getSegmentValue() >>> shift) == (getSegmentValue() >>> shift) && 
					(other.getUpperSegmentValue() >>> shift) <= (getUpperSegmentValue() >>> shift);
		}
		return false;
	}
	
	@Override
	public boolean contains(AddressSegment other) {
		return other instanceof MACAddressSegment && other.getSegmentValue() >= value && other.getUpperSegmentValue() <= upperValue;
	}
	
	@Override
	public String toHexString(boolean with0xPrefix) {
		return toNormalizedString(with0xPrefix ? MACStringCache.hexPrefixedParams : MACStringCache.hexParams);
	}

	@Override
	public String toNormalizedString() {
		return toNormalizedString(MACStringCache.canonicalParams);
	}
	
	public String toNormalizedString(StringOptions options) {
		AddressDivisionWriter params =  MACAddressSection.toParams(options);
		StringBuilder builder = new StringBuilder(params.getDivisionStringLength(this));
		return params.appendDivision(builder, this).toString();
	}
	
	/**
	 * @return whether the division range includes the block of values for the given prefix length
	 */
	@Override
	public boolean containsPrefixBlock(int divisionPrefixLen) {
		return isPrefixBlock(getDivisionValue(), getUpperDivisionValue(), divisionPrefixLen);
	}


	/**
	 * Returns whether the division range matches exactly the block of values for the given prefix length.
	 * 
	 * @return whether the range of this division matches the range for a single prefix with a single value and the given prefix length.
	 * 
	 * @param divisionPrefixLen
	 * @return whether the range of this segment matches the block of address divisions for that prefix.
	 */
	@Override
	public boolean containsSinglePrefixBlock(int divisionPrefixLen) {
		return isSinglePrefixBlock(getDivisionValue(), getUpperDivisionValue(), divisionPrefixLen);
	}
	
}
