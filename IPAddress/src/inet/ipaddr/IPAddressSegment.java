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

package inet.ipaddr;

import java.util.Iterator;

import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSection.IPStringCache;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.format.standard.AddressDivision;
import inet.ipaddr.format.standard.IPAddressDivision;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressStringWriter;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * This represents a single segment of an IP address.  For IPv4, segments are 1 byte.  For IPv6, they are two bytes.
 * 
 * IPAddressSegment objects are immutable and thus also thread-safe.
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressSegment extends IPAddressDivision implements AddressSegment {
	
	private static final long serialVersionUID = 4L;
	
	// These two values define the uniqueness of a segment with respect to equality and comparison, while the prefix is ignored as these values encapsulate the range of addresses created by the prefix.
	private final int value; // the lower value of the segment
	private final int upperValue; // the upper value of a CIDR or other type of range, if not a range it is the same as value
	
	/**
	 * Constructs a segment of an IPv4 or IPv6 address with the given value.
	 * 
	 * @param value the value of the segment
	 */
	protected IPAddressSegment(int value) {
		if(value < 0) {
			throw new AddressValueException(value);
		}
		this.value = this.upperValue = value;
	}
	
	/**
	 * Constructs a segment of an IPv4 or IPv6 address.
	 * 
	 * @param value the value of the segment.
	 * 		If the segmentPrefixLength is non-null, the network prefix of the value is used, and the segment represents all segment values with the same network prefix (all network or subnet segments, in other words).
	 * @param segmentPrefixLength the segment prefix bits, which can be null
	 */
	protected IPAddressSegment(int value, Integer segmentPrefixLength) {
		this(value, value, segmentPrefixLength);
	}
	
	/**
	 * Constructs a segment of an IPv4 or IPv6 address that represents a range of values.
	 * 
	 * @param segmentPrefixLength the segment prefix bits, which can be null.  If segmentPrefixLength is non-null, this segment represents a range of segment values with the given network prefix length.
	 * @param lower the lower value of the range of values represented by the segment.  If segmentPrefixLength is non-null, the lower value becomes the smallest value with the same network prefix.
	 * @param upper the upper value of the range of values represented by the segment.  If segmentPrefixLength is non-null, the upper value becomes the largest value with the same network prefix.
	 */
	protected IPAddressSegment(int lower, int upper, Integer segmentPrefixLength) {
		super(segmentPrefixLength);
		if(lower < 0 || upper < 0) {
			throw new AddressValueException(lower < 0 ? lower : upper);
		}
		if(lower > upper) {
			int tmp = lower;
			lower = upper;
			upper = tmp;
		}
		segmentPrefixLength = getSegmentPrefixLength();
		if(segmentPrefixLength == null || segmentPrefixLength >= getBitCount() || !getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			this.value = lower;
			this.upperValue = upper;
		} else {
			int mask = getSegmentNetworkMask(segmentPrefixLength);
			this.value = lower & mask;
			this.upperValue = upper | getSegmentHostMask(segmentPrefixLength);
		}
	}
	
	@Override
	public abstract IPAddressNetwork<?, ?, ?, ?, ?> getNetwork();
	
	public boolean isIPv4() {
		return false;
	}
	
	public boolean isIPv6() {
		return false;
	}
	
	public abstract IPVersion getIPVersion();

	protected static Integer getSplitSegmentPrefix(int bitsPerSegment, Integer networkPrefixLength, int segmentIndex) {
		return IPAddressSection.getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, segmentIndex);
	}
	
	@Override
	protected long getDivisionNetworkMask(int bits) {
		return getSegmentNetworkMask(bits);
	}
	
	@Override
	protected long getDivisionHostMask(int bits) {
		return getSegmentHostMask(bits);
	}
	
	protected abstract int getSegmentNetworkMask(int bits);
	
	protected abstract int getSegmentHostMask(int bits);
	
	@Override
	public int getMinPrefixLengthForBlock() {
		if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() && isPrefixed() && getSegmentPrefixLength() == 0) {
			return 0;
		}
		return super.getMinPrefixLengthForBlock();
	}
	
	public static int getMaxSegmentValue(IPVersion version) {
		return version.isIPv4() ? IPv4Address.MAX_VALUE_PER_SEGMENT : IPv6Address.MAX_VALUE_PER_SEGMENT;
	}

	protected boolean isChangedByPrefix(Integer bits, boolean smallerOnly) {
		boolean hasBits = (bits != null);
		if(hasBits && (bits < 0 || bits > getBitCount())) {
			throw new PrefixLenException(this, bits);
		}
		if(smallerOnly) {
			if(isPrefixed()) {
				return hasBits && bits < getSegmentPrefixLength();
			}
		} else {
			if(isPrefixed()) {
				return !hasBits || bits != getSegmentPrefixLength().intValue();
			}
		}
		return hasBits;
	}

	protected <S extends IPAddressSegment> S toPrefixedSegment(Integer segmentPrefixLength, AddressSegmentCreator<S> creator) {
		int lower = getSegmentValue();
		int upper = getUpperSegmentValue();
		boolean hasBits = (segmentPrefixLength != null);
		if(lower != upper) {
			//note that the case where our segmentPrefix is less than the requested prefix bits has already been accounted for in isNetworkChangedByPrefix
			//so we are not handling that here
			if(!hasBits) {
				return creator.createSegment(lower, upper, null);
			}
			return creator.createSegment(lower, upper, segmentPrefixLength);
		}
		return hasBits ? creator.createSegment(lower, segmentPrefixLength) : creator.createSegment(lower);
	}

	@Override
	public boolean isPrefixBlock() {
		return (isPrefixed() && getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) || super.isPrefixBlock();
	}
	
	protected boolean isNetworkChangedByPrefix(Integer bits, boolean withPrefixLength) {
		boolean hasBits = (bits != null);
		if(hasBits && (bits < 0 || bits > getBitCount())) {
			throw new PrefixLenException(this, bits);
		}
		withPrefixLength &= hasBits;
		boolean thisHasPrefix = isPrefixed();
		if(withPrefixLength != thisHasPrefix) {
			return true;
		}
		if(hasBits && bits != getDivisionPrefixLength()) {
			return true;
		}
		return
			//this call differs from the host side.  On the host side, we check that the network portion is 0
			//on the network side, we check that the host side is the full range, not 0.  
			//This means that any resulting network section is the same regardless of whether a prefix is used: we don't need a prefix.
			!hasBits || !containsPrefixBlock(bits);
	}
	
	/**
	 * used by constructors of IPAddressSection, see {@link IPAddress#getNetworkSection(int, boolean)}
	 */
	public IPAddressSegment toNetworkSegment(Integer segmentPrefixLength) {
		return toNetworkSegment(segmentPrefixLength, true);
	}
	
	/**
	 * used by getNetworkSection and by constructors of IPAddressSection, see {@link IPAddress#getNetworkSection(int, boolean)}
	 */
	public abstract IPAddressSegment toNetworkSegment(Integer segmentPrefixLength, boolean withPrefixLength);

	protected <S extends IPAddressSegment> S toNetworkSegment(Integer segmentPrefixLength, boolean withPrefixLength, AddressSegmentCreator<S> creator) {
		int newLower = getSegmentValue();
		int newUpper = getUpperSegmentValue();
		if(segmentPrefixLength != null) {
			int mask = getSegmentNetworkMask(segmentPrefixLength);
			newLower &= mask;
			newUpper |= getSegmentHostMask(segmentPrefixLength);
		}
		boolean hasBits = (segmentPrefixLength != null);
		withPrefixLength &= hasBits;
		if(newLower != newUpper) {
			//note that the case where our segmentPrefix is less than the requested prefix bits has already been accounted for in isNetworkChangedByPrefix
			//so we are not handling that here
			if(!withPrefixLength) {
				return creator.createSegment(newLower, newUpper, null);
			}
			return creator.createSegment(newLower, newUpper, segmentPrefixLength);
		}
		return withPrefixLength ? creator.createSegment(newLower, segmentPrefixLength) : creator.createSegment(newLower);
	}
	
	/**
	 * used by getHostSection, see {@link IPAddress#getHostSection(int)}
	 */
	public abstract IPAddressSegment toHostSegment(Integer segmentPrefixLength);
	
	protected <S extends IPAddressSegment> S toHostSegment(Integer segmentPrefixLength, AddressSegmentCreator<S> creator) {
		int mask = (segmentPrefixLength == null) ? 0 : getSegmentHostMask(segmentPrefixLength);
		int newLower = getSegmentValue() & mask;
		int newUpper = getUpperSegmentValue() & mask;
		if(newLower != newUpper) {
			return creator.createSegment(newLower, newUpper, null);
		}
		return creator.createSegment(newLower);
	}
	
	protected boolean isHostChangedByPrefix(Integer bits) {
		boolean hasBits = (bits != null);
		if(hasBits && (bits < 0 || bits > getBitCount())) {
			throw new PrefixLenException(this, bits);
		}
		//a host segment has no prefix, so if this remains unchanged it must have no prefix length
		if(isPrefixed()) {
			return true;
		}
		int mask = !hasBits ? 0 : getSegmentHostMask(bits);
		//additionally, the value must match the value for the given network prefix length
		int value = getSegmentValue();
		int upperValue = getUpperSegmentValue();
		return value != (value & mask) || upperValue != (upperValue & mask);
	}
	
	/**
	 * returns a new segment masked by the given mask 
	 * 
	 * This method applies the mask first to every address in the range, and it does not preserve any existing prefix.
	 * The given prefix will be applied to the range of addresses after the mask.
	 * If the combination of the two does not result in a contiguous range, then {@link IncompatibleAddressException} is thrown.
	 * 
	 */
	protected boolean isChangedByMask(int maskValue, Integer segmentPrefixLength) throws IncompatibleAddressException {
		boolean hasBits = (segmentPrefixLength != null);
		if(hasBits && (segmentPrefixLength < 0 || segmentPrefixLength > getBitCount())) {
			throw new PrefixLenException(this, segmentPrefixLength);
		}
		
		//note that the mask can represent a range (for example a CIDR mask), 
		//but we use the lowest value (maskSegment.value) in the range when masking (ie we discard the range)
		int value = getSegmentValue();
		int upperValue = getUpperSegmentValue();
		return value != (value & maskValue) ||
				upperValue != (upperValue & maskValue) ||
						(isPrefixed() ? !getSegmentPrefixLength().equals(segmentPrefixLength) : hasBits);
	}
	
	protected boolean isChangedByOr(int maskValue, Integer segmentPrefixLength) throws IncompatibleAddressException {
		boolean hasBits = (segmentPrefixLength != null);
		if(hasBits && (segmentPrefixLength < 0 || segmentPrefixLength > getBitCount())) {
			throw new PrefixLenException(this, segmentPrefixLength);
		}
		
		//note that the mask can represent a range (for example a CIDR mask), 
		//but we use the lowest value (maskSegment.value) in the range when masking (ie we discard the range)
		int value = getSegmentValue();
		int upperValue = getUpperSegmentValue();
		return value != (value | maskValue) ||
				upperValue != (upperValue | maskValue) ||
				(isPrefixed() ? !getSegmentPrefixLength().equals(segmentPrefixLength) : hasBits);
	}

	/**
	 * Check that the range resulting from the mask is contiguous, otherwise we cannot represent it.
	 * 
	 * For instance, for the range 0 to 3 (bits are 00 to 11), if we mask all 4 numbers from 0 to 3 with 2 (ie bits are 10), 
	 * then we are left with 1 and 3.  2 is not included.  So we cannot represent 1 and 3 as a contiguous range.
	 * 
	 * The underlying rule is that mask bits that are 0 must be above the resulting range in each segment.
	 * 
	 * Any bit in the mask that is 0 must not fall below any bit in the masked segment range that is different between low and high.
	 * 
	 * Any network mask must eliminate the entire segment range.  Any host mask is fine.
	 * 
	 * @param maskValue
	 * @param segmentPrefixLength
	 * @return
	 * @throws PrefixLenException
	 */
	public boolean isMaskCompatibleWithRange(int maskValue, Integer segmentPrefixLength) throws PrefixLenException {
		if(!isMultiple()) {
			return true;
		}
		return super.isMaskCompatibleWithRange(maskValue, segmentPrefixLength, getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets());
	}
	
	/**
	 * Similar to masking, checks that the range resulting from the bitwise or is contiguous.
	 * 
	 * @param maskValue
	 * @param segmentPrefixLength
	 * @return
	 * @throws PrefixLenException
	 */
	public boolean isBitwiseOrCompatibleWithRange(int maskValue, Integer segmentPrefixLength) throws PrefixLenException {
		return super.isBitwiseOrCompatibleWithRange(maskValue, segmentPrefixLength, getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets());
	}

	/**
	 * If this segment represents a range of values, returns a segment representing just the lowest value in the range, otherwise returns this.
	 * @return
	 */
	@Override
	public abstract IPAddressSegment getLower();
	
	/**
	 * If this segment represents a range of values, returns a segment representing just the highest value in the range, otherwise returns this.
	 * @return
	 */
	@Override
	public abstract IPAddressSegment getUpper();
	
	protected static <S extends IPAddressSegment> S getLowestOrHighest(S original, AddressSegmentCreator<S> segmentCreator, boolean lowest) {
		if(!original.isMultiple() && !original.isPrefixed()) {//like with the iterator, we do not return segments with prefix, even if it is the full bit length
			return original;
		}
		return segmentCreator.createSegment(lowest ? original.getSegmentValue() : original.getUpperSegmentValue(), 
				original.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() ? null : original.getSegmentPrefixLength());
	}

	@Override
	public abstract Iterable<? extends IPAddressSegment> getIterable();

	@Override
	public abstract Iterator<? extends IPAddressSegment> iterator();
	
	/**
	 * Iterates through the individual prefix blocks.
	 * <p>
	 * If the series has no prefix length, then this is equivalent to {@link #iterator()}
	 */
	public abstract Iterator<? extends IPAddressSegment> prefixBlockIterator();
	
	/**
	 * Iterates through the individual prefixes.
	 * <p>
	 * If the series has no prefix length, then this is equivalent to {@link #iterator()}
	 */
	public abstract Iterator<? extends IPAddressSegment> prefixIterator();
	
	/**
	 * Iterates through the individual prefix blocks according to the given segment prefix length.
	 * Any existing prefix length is disregarded.
	 */
	public abstract Iterator<? extends IPAddressSegment> prefixBlockIterator(int prefixLength);

	public static int getBitCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BITS_PER_SEGMENT : IPv6Address.BITS_PER_SEGMENT;
	}

	public static int getByteCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BYTES_PER_SEGMENT : IPv6Address.BYTES_PER_SEGMENT;
	}

	public static int getDefaultTextualRadix(IPVersion version) {
		return version.isIPv4() ? IPv4Address.DEFAULT_TEXTUAL_RADIX : IPv6Address.DEFAULT_TEXTUAL_RADIX;
	}

	@Override
	public boolean matches(int value) {
		return super.matches(value);
	}
	
	public boolean matchesWithPrefixMask(int value, Integer segmentPrefixLength) {
		return super.matchesWithPrefixMask(value, segmentPrefixLength);
	}
	
	@Override
	public boolean matchesWithMask(int value, int mask) {
		return super.matchesWithMask(value, mask);
	}
	
	@Override
	public boolean matchesWithMask(int lowerValue, int upperValue, int mask) {
		return super.matchesWithMask(lowerValue, upperValue, mask);
	}
	
	@Override
	public int getValueCount() {
		return getUpperSegmentValue() - getSegmentValue() + 1;
	}
	
	/**
	 * Counts the number of prefixes in this address segment.
	 * <p>
	 * If this segment has no prefix length, this is equivalent to {@link #getValueCount()}
	 * 
	 * @return
	 */
	public int getPrefixValueCount() {
		Integer prefixLength = getSegmentPrefixLength();
		if(prefixLength == null) {
			return getValueCount();
		}
		int shiftAdjustment = getBitCount() - prefixLength;
		return (getUpperSegmentValue() >>> shiftAdjustment) - (getSegmentValue() >>> shiftAdjustment) + 1;
	}
	
	@Override
	public long getDivisionValueCount() {
		return getValueCount();
	}
	
	protected int highByte() {
		return highByte(getSegmentValue());
	}
	
	protected int lowByte() {
		return lowByte(getSegmentValue());
	}
	
	protected static int highByte(int value) {
		return value >> 8;
	}
	
	protected static int lowByte(int value) {
		return value & 0xff;
	}
	
	@Override
	public long getMaxValue() {
		return getMaxSegmentValue();
	}

	@Override
	public boolean isMultiple() {
		return getSegmentValue() != getUpperSegmentValue();
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
	
	/**
	 * returns the lower value as a long, although for individual segments {@link #getSegmentValue()} provides the same value as an int
	 */
	@Override
	public long getDivisionValue() {
		return getSegmentValue();
	}
	
	/**
	 * returns the lower upper value as a long, although for individual segments {@link #getUpperSegmentValue()} provides the same value as an int
	 */
	@Override
	public long getUpperDivisionValue() {
		return getUpperSegmentValue();
	}
	
	@Override
	public abstract IPAddressSegment reverseBits(boolean perByte);
	
	@Override
	public abstract IPAddressSegment reverseBytes();

	public abstract IPAddressSegment removePrefixLength();
	
	public abstract IPAddressSegment removePrefixLength(boolean zeroed);
	
	public abstract IPAddressSegment withoutPrefixLength();
	
	protected static <S extends IPAddressSegment> S removePrefix(S original, boolean zeroed, AddressSegmentCreator<S> creator) {
		if(original.isPrefixed()) {
			int lower = original.getSegmentValue();
			int upper = original.getUpperSegmentValue();
			if(zeroed) {
				int maskBits = original.getSegmentNetworkMask(original.getSegmentPrefixLength());
				if(!original.isMaskCompatibleWithRange(maskBits, null)) {
					throw new IncompatibleAddressException(original, maskBits, "ipaddress.error.maskMismatch");
				}
				return creator.createSegment(lower & maskBits, upper & maskBits, null);
			}
			return creator.createSegment(lower, upper, null);
		}
		return original;
	}
	
	@Override
	public boolean isBoundedBy(int value) {
		return getUpperSegmentValue() < value;
	}
	
	public Integer getSegmentPrefixLength() {
		return getDivisionPrefixLength();
	}
	
	@Override
	public int hashCode() {
		return hash(getSegmentValue(), getUpperSegmentValue(), getBitCount());
	}
	
	static int hash(int lower, int upper, int bitCount) {
		return lower | (upper << bitCount);
	}

	protected boolean isSameValues(AddressSegment otherSegment) {
		//note that it is the range of values that matters, the prefix bits do not
		return getSegmentValue() == otherSegment.getSegmentValue() && getUpperSegmentValue() == otherSegment.getUpperSegmentValue();
	}

	public boolean prefixEquals(IPAddressSegment other) {
		Integer prefLength = getSegmentPrefixLength();
		if(prefLength == null) {
			return equals(other);
		}
		return prefixEquals(other, prefLength);
	}
	
	@Override
	public boolean prefixEquals(AddressSegment other, int prefixLength) {
		if(prefixLength < 0) {
			throw new PrefixLenException(prefixLength);
		}
		int shift = getBitCount() - prefixLength;
		if(shift <= 0) {
			return isSameValues(other);
		}
		return (other.getSegmentValue() >>> shift) == (getSegmentValue() >>> shift) && 
				(other.getUpperSegmentValue() >>> shift) == (getUpperSegmentValue() >>> shift);
	}
	
	/**
	 * 
	 * @param other
	 * @return whether this subnet segment contains the given address segment
	 */
	protected boolean containsSeg(AddressSegment other) {
		return this == other || (other.getSegmentValue() >= getSegmentValue() && other.getUpperSegmentValue() <= getUpperSegmentValue());
	}

	@Override
	public boolean includesZero() {
		return getSegmentValue() == 0;
	}
	
	@Override
	public boolean includesMax() {
		return getUpperSegmentValue() == getMaxSegmentValue();
	}
	
	boolean containsPrefixBlock(int lowerVal, int upperVal, int divisionPrefixLen) {
		return isPrefixBlock(lowerVal, upperVal, divisionPrefixLen);
	}
	
	boolean containsSinglePrefixBlock(int lowerVal, int upperVal, int divisionPrefixLen) {
		return isSinglePrefixBlock(lowerVal, upperVal, divisionPrefixLen);
	}

	@Override
	public String toHexString(boolean with0xPrefix) {
		return toNormalizedString(with0xPrefix ? IPStringCache.hexPrefixedParams : IPStringCache.hexParams);
	}

	@Override
	public String toNormalizedString() {
		return toNormalizedString(IPStringCache.canonicalSegmentParams);
	}

	public String toNormalizedString(IPStringOptions options) {
		IPAddressStringWriter<IPAddressStringDivisionSeries> params =  IPAddressSection.toIPParams(options);
		StringBuilder builder = new StringBuilder(params.getDivisionStringLength(this));
		return params.appendDivision(builder, this).toString();
	}
	
	protected static int toUnsignedStringLength(int value, int radix) {
		return AddressDivision.toUnsignedStringLength(value, radix);
	}
	
	protected static StringBuilder toUnsignedString(int value, int radix, StringBuilder appendable) {
		return toUnsignedString(value, radix, 0, false, DIGITS, appendable);
	}

	void setStandardString(
			CharSequence addressStr, 
			boolean isStandardString,
			int lowerStringStartIndex,
			int lowerStringEndIndex,
			int originalLowerValue) {
		if(cachedString == null && isStandardString && originalLowerValue == getDivisionValue()) {
			cachedString = addressStr.subSequence(lowerStringStartIndex, lowerStringEndIndex).toString();
		}
	}

	void setWildcardString(
			CharSequence addressStr, 
			boolean isStandardString,
			int lowerStringStartIndex,
			int lowerStringEndIndex,
			int lowerValue) {
		if(cachedWildcardString == null && isStandardString && lowerValue == getDivisionValue() && lowerValue == getUpperDivisionValue()) {
			cachedWildcardString = addressStr.subSequence(lowerStringStartIndex, lowerStringEndIndex).toString();
		}
	}
	
	void setStandardString(
			CharSequence addressStr, 
			boolean isStandardString,
			boolean isStandardRangeString,
			int lowerStringStartIndex,
			int lowerStringEndIndex,
			int upperStringEndIndex,
			int rangeLower,
			int rangeUpper) {
		if(cachedString == null) {
			if(isSinglePrefixBlock()) {
				if(isStandardString && rangeLower == getDivisionValue()) {
					cachedString = addressStr.subSequence(lowerStringStartIndex, lowerStringEndIndex).toString();
				}
			} else if(isFullRange()) {
				cachedString = IPAddress.SEGMENT_WILDCARD_STR;
			} else if(isStandardRangeString && rangeLower == getDivisionValue()) {
				long upper = getUpperDivisionValue();
				if(isPrefixed()) {
					upper &= getDivisionNetworkMask(getDivisionPrefixLength());
				}
				if(rangeUpper == upper) {
					cachedString = addressStr.subSequence(lowerStringStartIndex, upperStringEndIndex).toString();
				}
			}
		}
	}
	
	void setWildcardString(
			CharSequence addressStr, 
			boolean isStandardRangeString,
			int lowerStringStartIndex,
			int upperStringEndIndex,
			int rangeLower,
			int rangeUpper) {
		if(cachedWildcardString == null) {
			if(isFullRange()) {
				cachedWildcardString = IPAddress.SEGMENT_WILDCARD_STR;
			} else if(isStandardRangeString && rangeLower == getDivisionValue() && rangeUpper == getUpperDivisionValue()) {
				cachedWildcardString = addressStr.subSequence(lowerStringStartIndex, upperStringEndIndex).toString();
			}
		}
	}
}
