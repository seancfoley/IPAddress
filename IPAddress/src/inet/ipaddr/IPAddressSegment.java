package inet.ipaddr;


import java.util.Iterator;
import java.util.NoSuchElementException;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressTypeNetwork.IPAddressSegmentCreator;
import inet.ipaddr.format.IPAddressDivision;
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
public abstract class IPAddressSegment extends IPAddressDivision {
	
	private static final long serialVersionUID = 1L;
	
	//These two values define the uniqueness of a segment with respect to equality and comparison, while the prefix is ignored as these values encapsulate the range of addresses created by the prefix.
	//In other words, the prefix denotes how many of the bits are network and nothing more, which has no impact on the range of values.
	private final int value; //the lower value of the segment
	private final int upperValue; //the upper value of a CIDR or other type of range, if not a range it is the same as value
	
	/**
	 * Constructs a segment of an IPv4 or IPv6 address with the given value.
	 * 
	 * @param value the value of the segment
	 */
	protected IPAddressSegment(int value) {
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
		segmentPrefixLength = getSegmentPrefixLength();
		if(segmentPrefixLength == null) {
			this.value = lower;
			this.upperValue = upper;
		} else {
			int mask = getSegmentNetworkMask(segmentPrefixLength);
			this.value = lower & mask;
			this.upperValue = upper | getSegmentHostMask(segmentPrefixLength);
		}
	}
	
	public boolean isIPv4() {
		return false;
	}
	
	public boolean isIPv6() {
		return false;
	}
	
	public abstract IPVersion getIPVersion();
	
	protected static Integer getSplitSegmentPrefix(int bitsPerSegment, Integer networkPrefixLength, int segmentIndex) {
		return IPAddressSection.getSplitSegmentPrefixLength(bitsPerSegment, networkPrefixLength, segmentIndex);
	}
	
	protected static Integer getJoinedSegmentPrefix(int bitsPerSegment, Integer highBits, Integer lowBits) {
		return IPAddressSection.getJoinedSegmentPrefixLength(bitsPerSegment, highBits, lowBits);
	}
	
	static int getSegmentNetworkMask(IPVersion version, int bits) {
		return IPAddress.network(version).getSegmentNetworkMask(bits);
	}

	static int getSegmentHostMask(IPVersion version, int bits) {
		return IPAddress.network(version).getSegmentHostMask(bits);
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
	
	public int getMinPrefix() {
		if(isPrefixed() && getSegmentPrefixLength() == 0) {
			return 0;
		}
		int result = getBitCount();
		int lowerZeros = Integer.numberOfTrailingZeros(value);
		if(lowerZeros != 0) {
			int upperOnes = Integer.numberOfTrailingZeros(~upperValue);
			if(upperOnes != 0) {
				int prefixedBitCount = Math.min(lowerZeros, upperOnes);
				result -= prefixedBitCount;
			}
		}
		return result;
	}
	
	public static int getMaxSegmentValue(IPVersion version) {
		return version.isIPv4() ? IPv4Address.MAX_VALUE_PER_SEGMENT : IPv6Address.MAX_VALUE_PER_SEGMENT;
	}
	
	protected boolean isNetworkChangedByPrefix(Integer bits, boolean withPrefixLength) {
		boolean hasBits = (bits != null);
		if(hasBits && (bits < 0 || bits > getBitCount())) {
			throw new IPAddressTypeException(this, bits, "ipaddress.error.prefixSize");
		}
		withPrefixLength &= hasBits;
		boolean thisHasPrefix = isPrefixed();
		if(withPrefixLength != thisHasPrefix) {
			return true;
		}
		return thisHasPrefix ? bits.intValue() < getSegmentPrefixLength().intValue() : 
			//this isRangeUnchanged call differs from the host side.  On the host side, we check that the network portion is 0
			//on the network side, we check that the host side is the full range, not 0.  This means that any resulting network section is the same regardless of whether a prefix is used: we don't need a prefix.
			!isRangeUnchanged(bits); 
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
	
	protected <T extends IPAddressSegment> T toNetworkSegment(Integer segmentPrefixLength, boolean withPrefixLength, IPAddressSegmentCreator<T> creator) {
		int newLower = value;
		int newUpper = upperValue;
		if(segmentPrefixLength != null) {
			int mask = getSegmentNetworkMask(segmentPrefixLength);
			newLower &= mask;
			newUpper &= mask;
			newUpper |= getSegmentHostMask(segmentPrefixLength);
		}
		if(newLower != newUpper) {
			//note that the case where our segmentPrefix is less than the requested prefix bits has already been accounted for in isNetworkChangedByPrefix
			//so we are not handling that here
			if(!withPrefixLength) {
				return creator.createSegment(newLower, newUpper, null);
			}
			if(segmentPrefixLength == null || !isRangeEquivalent(newLower, newUpper, segmentPrefixLength)) {
				return creator.createSegment(newLower, newUpper, segmentPrefixLength);
			}
			return creator.createSegment(newLower, segmentPrefixLength);
		}
		return withPrefixLength ? creator.createSegment(newLower, segmentPrefixLength) : creator.createSegment(newLower);
	}
	
	/**
	 * used by getHostSection, see {@link IPAddress#getHostSection(int)}
	 */
	public abstract IPAddressSegment toHostSegment(Integer segmentPrefixLength);
	
	protected <T extends IPAddressSegment> T toHostSegment(Integer segmentPrefixLength, IPAddressSegmentCreator<T> creator) {
		int mask = (segmentPrefixLength == null) ? 0 : getSegmentHostMask(segmentPrefixLength);
		int newLower = value & mask;
		int newUpper = upperValue & mask;
		if(newLower != newUpper) {
			return creator.createSegment(newLower, newUpper, null);
		}
		return creator.createSegment(newLower);
	}
	
	protected boolean isHostChangedByPrefix(Integer bits) {
		boolean hasBits = (bits != null);
		if(hasBits && (bits < 0 || bits > getBitCount())) {
			throw new IPAddressTypeException(this, bits, "ipaddress.error.prefixSize");
		}
		//a host segment has no prefix, so if this remains unchanged it must have no prefix length
		if(isPrefixed()) {
			return true;
		}
		int mask = !hasBits ? 0 : getSegmentHostMask(bits);
		//additionally, the value must match the value for the given network prefix length
		return value != (value & mask) || upperValue != (upperValue & mask);
	}
	
	/**
	 * returns a new segment masked by the given mask 
	 * 
	 * This method applies the mask first to every address in the range, and it does not preserve any existing prefix.
	 * The given prefix will be applied to the range of addresses after the mask.
	 * If the combination of the two does not result in a contiguous range of addresses, then IPAddressTypeException is thrown.
	 * 
	 * See {@link IPAddress#toSubnet(int)},
	 * {@link IPAddress#toSubnet(IPAddress, Integer)},
	 * {@link IPAddress#isMaskCompatibleWithRange(IPAddress, Integer)}
	 */
	public abstract IPAddressSegment toMaskedSegment(IPAddressSegment maskSegment, Integer segmentPrefixLength) throws IPAddressTypeException;
	
	protected boolean isChangedByMask(int maskValue, Integer segmentPrefixLength) throws IPAddressTypeException {
		boolean hasBits = (segmentPrefixLength != null);
		if(hasBits && (segmentPrefixLength < 0 || segmentPrefixLength > getBitCount())) {
			throw new IPAddressTypeException(this, segmentPrefixLength, "ipaddress.error.prefixSize");
		}
		
		//note that the mask can represent a range (for example a CIDR mask), 
		//but we use the lowest value (maskSegment.value) in the range when masking (ie we discard the range)
		return value != (value & maskValue) ||
				upperValue != (upperValue & maskValue) ||
						(isPrefixed() ? !getSegmentPrefixLength().equals(segmentPrefixLength) : hasBits);
	}
	
	public boolean isMaskCompatibleWithRange(IPAddressSegment maskSegment, Integer segmentPrefixLength) {
		IPVersion version = getIPVersion();
		if(!version.equals(maskSegment.getIPVersion())) {
			throw new IPAddressTypeException(this, maskSegment, "ipaddress.error.typeMismatch");
		}
		int maskValue = maskSegment.value; //for mask we only use the lower value
		return isMaskCompatibleWithRange(maskValue, segmentPrefixLength);
	}
	
	public boolean isMaskCompatibleWithRange(int maskValue, Integer segmentPrefix) {
		return super.isMaskCompatibleWithRange(maskValue, segmentPrefix);
	}

	/**
	 * If this segment represents a range of values, returns a segment representing just the lowest value in the range, otherwise returns this.
	 * @return
	 */
	public abstract IPAddressSegment getLower();
	
	/**
	 * If this segment represents a range of values, returns a segment representing just the highest value in the range, otherwise returns this.
	 * @return
	 */
	public abstract IPAddressSegment getUpper();
	
	protected static <S extends IPAddressSegment> S getLowestOrHighest(S original, IPAddressSegmentCreator<S> segmentCreator, boolean lowest) {
		if(!original.isMultiple() && !original.isPrefixed()) {//like with the iterator, we do not return segments with prefix, even if it is the full bit length
			return original;
		}
		return segmentCreator.createSegment(lowest ? original.getLowerSegmentValue() : original.getUpperSegmentValue());
	}
	
	public abstract Iterator<? extends IPAddressSegment> iterator();	
	
	protected static <S extends IPAddressSegment> Iterator<S> iterator(S original, IPAddressSegmentCreator<S> creator) {
		if(!original.isMultiple()) {
			return new Iterator<S>() {
				boolean done;
				
				@Override
				public boolean hasNext() {
					return !done;
				}

			   @Override
				public S next() {
			    	if(!hasNext()) {
			    		throw new NoSuchElementException();
			    	}
			    	done = true;
			    	S thisSegment = original;
			    	
			    	//Even though this segment represents a single value, it still might have a prefix extending to the end of the segment
			    	//Iterators must return non-prefixed segments.
			    	//This is required by the IPAddressSection iterator which uses an array of segment iterators.
			    	//If the segments at the end with prefixes of 0 iterate through all values with no prefix, 
			    	//then so must the preceding segment with a non-zero prefix,
			    	//even if that non-zero prefix extends to the end of the segment.
		    		if(thisSegment.isPrefixed()) {
			    		S result = creator.createSegment(thisSegment.getLowerSegmentValue());
			    		return result;
			    	}
			    	return thisSegment;
			    }

			    @Override
				public void remove() {
			    	throw new UnsupportedOperationException();
			    }
			};
		}
		return new Iterator<S>() {
			boolean done;
			int current = original.getLowerSegmentValue();
			
			@Override
			public boolean hasNext() {
				return !done;
			}

		    @Override
			public S next() {
		    	if(done) {
		    		throw new NoSuchElementException();
		    	}
		    	S result = creator.createSegment(current);
		    	done = ++current > original.getUpperSegmentValue();
		    	return result;
		    }

		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}
	
	public static int getBitCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BITS_PER_SEGMENT : IPv6Address.BITS_PER_SEGMENT;
	}
	
	public static int getByteCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BYTES_PER_SEGMENT : IPv6Address.BYTES_PER_SEGMENT;
	}
	
	public static int getDefaultTextualRadix(IPVersion version) {
		return version.isIPv4() ? IPv4Address.DEFAULT_TEXTUAL_RADIX : IPv6Address.DEFAULT_TEXTUAL_RADIX;
	}
	
	public boolean matches(int value) {
		return super.matches(value);
	}
	
	public boolean matchesWithPrefix(int value, Integer segmentPrefixLength) {
		return super.matchesWithPrefix(value, segmentPrefixLength);
	}
	
	public boolean matchesWithMask(int value, int mask) {
		return super.matchesWithMask(value, mask);
	}
	
	@Override
	public long getCount() {
		return upperValue - value + 1;
	}
	
	protected int highByte() {
		return highByte(value);
	}
	
	protected int lowByte() {
		return lowByte(value);
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
	
	public abstract int getMaxSegmentValue();

	@Override
	public boolean isMultiple() {
		return value != upperValue;
	}
	
	/**
	 * returns the lower value
	 */
	public int getLowerSegmentValue() {
		return value;
	}
	
	/**
	 * returns the upper value
	 */
	public int getUpperSegmentValue() {
		return upperValue;
	}
	
	/**
	 * returns the lower value as a long, although for individual segments {@link #getLowerSegmentValue()} provides the same value as an int
	 */
	@Override
	public long getLowerValue() {
		return value;
	}
	
	/**
	 * returns the lower upper value as a long, although for individual segments {@link #getUpperSegmentValue()} provides the same value as an int
	 */
	@Override
	public long getUpperValue() {
		return upperValue;
	}
	
	public Integer getSegmentPrefixLength() {
		return getDivisionPrefixLength();
	}
	
	@Override
	protected boolean isSameValues(IPAddressDivision other) {
		if(other instanceof IPAddressSegment) {
			return isSameValues((IPAddressSegment) other);
		}
		return false;
	}
	
	protected boolean isSameValues(IPAddressSegment otherSegment) {
		//note that it is the range of values that matters, the prefix bits do not
		return value == otherSegment.value && upperValue == otherSegment.upperValue;
	}

	@Override
	public int hashCode() {
		return hash(value, upperValue, getBitCount());
	}
	
	static int hash(int lower, int upper, int bitCount) {
		return lower | (upper << bitCount);
	}

	/**
	 * 
	 * @param other
	 * @return whether this subnet segment contains the given address segment
	 */
	public boolean contains(IPAddressSegment other) {
		return other.value >= value && other.upperValue <= upperValue;
	}

	public static boolean isFullRange(int lower, int upper, Integer prefix, IPVersion version) {
		if(prefix != null) {
			lower &= getSegmentNetworkMask(version, prefix);
			upper |= getSegmentHostMask(version, prefix);
		}
		return isFullRange(lower, upper, version);
	}

	public static boolean isFullRange(int lower, int upper, IPVersion version) {
		return lower == 0 && upper == getMaxSegmentValue(version);
	}
	
	protected static boolean toUnsignedStringFast(int value, int radix, StringBuilder appendable) {
		return toUnsignedStringFast(value, radix, false, appendable);
	}
	
	protected static void getRangeString(int lower, int upper, int radix, StringBuilder appendable) {
		getRangeString(lower, upper, IPAddress.RANGE_SEPARATOR_STR, 0, 0, null, radix, false, appendable);
	}
	
	void setStandardString(
			String addressStr, 
			boolean isStandardString,
			int lowerStringStartIndex,
			int lowerStringEndIndex,
			int originalLowerValue) {
		if(cachedString == null && isStandardString && originalLowerValue == getLowerValue()) {
			cachedString = addressStr.substring(lowerStringStartIndex, lowerStringEndIndex);
		}
	}

	void setWildcardString(
			String addressStr, 
			boolean isStandardString,
			int lowerStringStartIndex,
			int lowerStringEndIndex,
			int lowerValue) {
		if(cachedWildcardString == null && isStandardString && lowerValue == getLowerValue() && lowerValue == getUpperValue()) {
			cachedWildcardString = addressStr.substring(lowerStringStartIndex, lowerStringEndIndex);
		}
	}
	
	void setStandardString(
			String addressStr, 
			boolean isStandardString,
			boolean isStandardRangeString,
			int lowerStringStartIndex,
			int lowerStringEndIndex,
			int upperStringEndIndex,
			int rangeLower,
			int rangeUpper) {
		if(cachedString == null) {
			if(isRangeEquivalentToPrefix()) {
				if(isStandardString && rangeLower == getLowerValue()) {
					cachedString = addressStr.substring(lowerStringStartIndex, lowerStringEndIndex);
				}
			} else if(isFullRange()) {
				cachedString = IPAddress.SEGMENT_WILDCARD_STR;
			} else if(isStandardRangeString && rangeLower == getLowerValue()) {
				long upper = getUpperValue();
				if(ADJUST_RANGES_BY_PREFIX && isPrefixed()) {
					upper &= getDivisionNetworkMask(getDivisionPrefixLength());
				}
				if(rangeUpper == upper) {
					cachedString = addressStr.substring(lowerStringStartIndex, upperStringEndIndex);
				}
			}
		}
	}
	
	void setWildcardString(String addressStr, 
			boolean isStandardRangeString,
			int lowerStringStartIndex,
			int upperStringEndIndex,
			int rangeLower,
			int rangeUpper) {
		if(cachedWildcardString == null) {
			if(isFullRange()) {
				cachedWildcardString = IPAddress.SEGMENT_WILDCARD_STR;
			} else if(isStandardRangeString && rangeLower == getLowerValue() && rangeUpper == getUpperValue()) {
				cachedWildcardString = addressStr.substring(lowerStringStartIndex, upperStringEndIndex);
			}
		}
	}

}
