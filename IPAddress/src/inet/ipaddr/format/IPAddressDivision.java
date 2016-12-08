package inet.ipaddr.format;

import java.io.Serializable;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressSection.WildcardOptions.Wildcards;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv6.IPv6AddressSegment;

/**
 * A combination of one or more IP address segments.
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressDivision implements Comparable<IPAddressDivision>, Serializable {

	private static final long serialVersionUID = 1L;
	
	//when printing a string, whether the prefix affects the printed range, for instance, whether to print 100-127/5 or 100-124/5
	public static final boolean ADJUST_RANGES_BY_PREFIX = true;
	
	private static final String zeroes[] = new String[] {
		"",
		"0",
		"00",
		"000",
		"0000"
	};
	
	private static final char[] digits = {
        '0' , '1' , '2' , '3' , '4' , '5' ,
        '6' , '7' , '8' , '9' , 'a' , 'b' ,
        'c' , 'd' , 'e' , 'f' , 'g' , 'h' ,
        'i' , 'j' , 'k' , 'l' , 'm' , 'n' ,
        'o' , 'p' , 'q' , 'r' , 's' , 't' ,
        'u' , 'v' , 'w' , 'x' , 'y' , 'z'
    };

	private static final char[] upperDigits = {
        '0' , '1' , '2' , '3' , '4' , '5' ,
        '6' , '7' , '8' , '9' , 'A' , 'B' ,
        'C' , 'D' , 'E' , 'F' , 'G' , 'H' ,
        'I' , 'J' , 'K' , 'L' , 'M' , 'N' ,
        'O' , 'P' , 'Q' , 'R' , 'S' , 'T' ,
        'U' , 'V' , 'W' , 'X' , 'Y' , 'Z'
    };
	
	private final Integer divisionNetworkPrefix;//the prefix length for this division, or null if there is none
	
	//cached for performance reasons - especially valuable since segments can be shared amongst different addresses as we do with the masks
	protected transient String cachedString;
	protected transient String cachedWildcardString;
			
	protected IPAddressDivision() {
		this(null);
	}
	
	protected IPAddressDivision(Integer networkPrefixLength) {
		this.divisionNetworkPrefix = networkPrefixLength;
	}
	
	/**
	 * @return whether this segment represents multiple values
	 */
	public boolean isMultiple() {
		return getLowerValue() != getUpperValue();
	}
	
	public abstract int getBitCount();
	
	public abstract int getByteCount();
	
	public boolean isPrefixed() {
		return divisionNetworkPrefix != null;
	}
	
	/**
	 * Returns the network prefix for the division.
	 * 
	 * The network prefix is 16 for an address like 1.2.0.0/16.
	 * 
	 * When it comes to each address division or segment, the prefix for the division is the
	 * prefix obtained when applying the address or section prefix.
	 * 
	 * For instance, with the address 1.2.0.0/20, 
	 * segment 1 has no prefix because the address prefix 20 extends beyond the 8 bits in the first segment, it does not even apply to the segment, 
	 * segment 2 has no prefix because the address prefix extends beyond bits 9 to 16 which lie in the second segment, it does not apply to that segment either,
	 * segment 3 has the prefix 4 because the address prefix 20 corresponds to the first 4 bits in the 3rd segment,
	 * which means that the first 4 bits are part of the network section of the address or segment,
	 * and segment 4 has the prefix 0 because not a single bit is in the network section of the address or segment
	 * 
	 * The prefix applied across the address is null ... null ... (1 to segment bit length) ... 0 ... 0
	 * 
	 * If the segment has no prefix then null is returned.
	 * 
	 * @return
	 */
	public Integer getDivisionPrefixLength() {
		return divisionNetworkPrefix;
	}
	
	protected abstract long getMaxValue();
	
	public boolean isZero() {
		return !isMultiple() && getLowerValue() == 0;
	}
	
	public abstract long getLowerValue();
	
	public abstract long getUpperValue();
	
	public long getCount() {
		return getUpperValue() - getLowerValue() + 1;
	}
	
	public boolean rangeIsWithin(long lower, long upper) {
		return getLowerValue() >= lower && getUpperValue() <= upper;
	}
	
	public boolean valueIsWithin(long lower, long upper) {
		long value = getLowerValue();
		return value >= lower && value <= upper;
	}
	
	public boolean matches(long value) {
		return !isMultiple() && value == getLowerValue();
	}
	
	public boolean matchesWithPrefix(long value, Integer divisionPrefixLen) {
		if(divisionPrefixLen == null) {
			return matches(value);
		}
		long mask = getDivisionNetworkMask(divisionPrefixLen);
		long matchingValue = value & mask;
		return matchingValue == (getLowerValue() & mask) && matchingValue == (getUpperValue() & mask);
	}
	
	public boolean matchesWithMask(int value, long mask) {
		if(isMultiple()) {
			//we want to ensure that any of the bits that can change from value to upperValue is masked out (zeroed) by the mask.
			//In other words, when masked we need all values represented by this segment to become just a single value
			long diffBits = getLowerValue() ^ getUpperValue();
			int leadingZeros = Long.numberOfLeadingZeros(diffBits) - getLeadingZerosAdjustment();
			//the bits that can change are all bits following the first leadingZero bits
			//all the bits that follow must be zeroed out by the mask
			if((getDivisionHostMask(leadingZeros) & mask) != 0L) {
				return false;
			} //else we know that the mask zeros out all the bits that can change from value to upperValue, so now we just compare with either one
		}
		return (value & mask) == (getLowerValue() & mask);
	}
	
	protected abstract long getDivisionNetworkMask(int bits);
	
	protected abstract long getDivisionHostMask(int bits);
	
	/**
	 * If this is equivalent to the mask for a CIDR prefix, it returns that prefix length.
	 * Otherwise, it returns null.
	 * A CIDR network mask is an address with all 1s in the network section (the upper bits) and then all 0s in the host section.
	 * A CIDR host mask is an address with all 0s in the network section (the lower bits) and then all 1s in the host section.
	 * The prefix length is the length of the network section.
	 * 
	 * Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length used to construct this object.
	 * The prefix length used to construct indicates the network and host portion of this address.  
	 * The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host of an address with that prefix length.
	 * Therefore the two values can be different values, or one can be null while the other is not.
	 * 
	 * This method applies only to the lower value of the range if this segment represents multiple values.
	 * 
	 * @see IPAddressSection#getEquivalentPrefix()
	 * 
	 * @param network whether to check for a network mask or a host mask
	 * @return the prefix length corresponding to this mask, or null if this address is not a CIDR prefix mask
	 */
	public Integer getMaskPrefixLength(boolean network) {
		long val, invertedVal;
		if(network) {
			val = getLowerValue();
			invertedVal = ~val & getMaxValue();
		} else {
			invertedVal = getLowerValue();
			val = ~invertedVal & getMaxValue();
		}
		int bitCount = getBitCount();
		int hostLength  = Math.min(Long.numberOfTrailingZeros(val), bitCount);
		long shifted = invertedVal >>> hostLength;
		return shifted == 0 ? bitCount - hostLength : null;
	}
	
	protected abstract boolean isSameValues(IPAddressDivision other);
	
	/** 
	 * @param lowerValue
	 * @return whether the range of this segment matches the range of a segment with the given value and the CIDR prefix length of this segment
	 */
	public boolean isSamePrefixedRange(long lowerValue) {
		return isPrefixed() ? isSamePrefixedRange(lowerValue, getDivisionPrefixLength()) : (lowerValue == getLowerValue() && !isMultiple());
	}
	
	/**
	 * @param lowerValue
	 * @param divisionPrefixLen
	 * @return whether the range of this segment matches the range of a segment with the given value and CIDR prefix length
	 */
	private boolean isSamePrefixedRange(long lowerValue, int divisionPrefixLen) {
		long mask = getDivisionNetworkMask(divisionPrefixLen);
		long expectedValue = lowerValue & mask;
		return getLowerValue() == expectedValue
			&&  getUpperValue() == (lowerValue | getDivisionHostMask(divisionPrefixLen));
	}
	
	private static boolean testRange(long lowerValue, long upperValue, long finalUpperValue, long networkMask, long hostMask) {
		return lowerValue == (lowerValue & networkMask)
				&& finalUpperValue == (upperValue | hostMask);
	}
	
	/**
	 * 
	 * @param segmentValue
	 * @param divisionPrefixLen
	 * @return whether the given range remains the same with the given prefix applied 
	 */
	private boolean isRangeUnchanged(long segmentValue, long upperValue, int divisionPrefixLen) {
		return testRange(segmentValue,
				upperValue,
				upperValue,
				getDivisionNetworkMask(divisionPrefixLen),
				getDivisionHostMask(divisionPrefixLen));
	}
	
	/**
	 * 
	 * @param segmentValue
	 * @param divisionPrefixLen
	 * @return whether the given range of segmentValue to upperValue is equivalent to the range of segmentValue with the prefix of divisionPrefixLen 
	 */
	protected boolean isRangeEquivalent(long segmentValue, long upperValue, int divisionPrefixLen) {
		return testRange(segmentValue,
				segmentValue,
				upperValue,
				getDivisionNetworkMask(divisionPrefixLen),
				getDivisionHostMask(divisionPrefixLen));
	}
	
	/**
	 * @param divisionPrefixLen
	 * @return whether the range of this segment can be specified only using the segment's lower value and the given prefix length
	 * 	If the prefix is null or equal to the bit length, then this returns true for non-multiple addresses.
	 */
	public boolean isRangeEquivalent(Integer divisionPrefixLen) {
		if(divisionPrefixLen == null) {
			return !isMultiple();
		}
		if(divisionPrefixLen == 0) {
			return isFullRange();
		}
		return isRangeEquivalent(getLowerValue(), getUpperValue(), divisionPrefixLen);
	}
	
	/**
	 * 
	 * @param divisionPrefixLen
	 * @return whether the given range remains the same with the given prefix applied 
	 */
	public boolean isRangeUnchanged(Integer divisionPrefixLen) {
		if(divisionPrefixLen == null) {
			return true;
		}
		if(divisionPrefixLen == 0) {
			return isFullRange();
		}
		return isRangeUnchanged(getLowerValue(), getUpperValue(), divisionPrefixLen);
	}
	
	/**
	 * @return whether the range of this segment can be specified only using the segment's lower value and the segment's prefix length
	 */
	public boolean isRangeEquivalentToPrefix() {
		return isRangeEquivalent(getDivisionPrefixLength());
	}
	
	public boolean isFullRange() {
		return getLowerValue() == 0 && getUpperValue() == getMaxValue();
	}

	public boolean isMaskCompatibleWithRange(long maskValue, Integer divisionPrefixLen) {
		boolean hasBits = (divisionPrefixLen != null);
		if(hasBits && (divisionPrefixLen < 0 || divisionPrefixLen > getBitCount())) {
			throw new IPAddressTypeException(this, divisionPrefixLen, "ipaddress.error.prefixSize");
		}
		if(!isMultiple()) {
			return true;
		}
		if(!hasBits) {
			divisionPrefixLen = getBitCount();
		}
		long networkMask = getDivisionNetworkMask(divisionPrefixLen); //only the bits we care about
		long value = getLowerValue();
		long upperValue = getUpperValue();
		
		//algorithm:
		//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
		//then we find the highest bit in the mask that is 1 that is the same or below highestDifferingBitInRange (if such a bit exists)
		
		//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
		//if this latter bit exists, then any bit below it in the mask must be 1 to include the entire range.
		
		long differing = (value ^ upperValue) & networkMask;
		if(differing != 0 /* bits differ */ && differing != 1 /* it's not just the last digit that differs, which has nothing below it */) {
			int leadingZerosAdjustment = getLeadingZerosAdjustment();
			int highestDifferingBitInRange = Long.numberOfLeadingZeros(differing) - leadingZerosAdjustment;
			long maskMask = getDivisionHostMask(highestDifferingBitInRange);
			long differingMasked = maskValue & maskMask;
			boolean foundDiffering = (differingMasked != 0 && differingMasked != 1);
			if(foundDiffering) {
				int highestDifferingBitMasked = Long.numberOfLeadingZeros(differingMasked) - leadingZerosAdjustment;
				//anything below highestDifferingBitMasked in the mask must be ones 
				maskValue |= getDivisionHostMask(divisionPrefixLen); //but only the bits we care about
				long hostMask = getDivisionHostMask(highestDifferingBitMasked + 1);
				if((maskValue & hostMask) != hostMask) { //check if all ones below
					return false;
				}
			}
		}
		return true;
	}
	
	@Override
	public int compareTo(IPAddressDivision other) {
		return IPAddress.addressComparator.compare(this, other);
	}
	
	/**
	 * @return returns the number of superfluous and unused digits in the long representation of value/upperValue
	 */
	protected abstract int getLeadingZerosAdjustment();
	
	/**
	 * @return the default radix for textual representations of addresses (10 for IPv4, 16 for IPv6)
	 */
	public abstract int getDefaultTextualRadix();
	
	/**
	 * @return the max number of characters per segment when using the default radix
	 */
	public abstract int getDefaultMaxChars();
	
	private static boolean isAlphabetic(long i) {
		return i >= 0xa;
	}
	
	public boolean hasAlphabeticDigits(int base, boolean lowerOnly) {
		if(base <= 1) {
			throw new IllegalArgumentException();
		}
		if(base <= 10) {
			return false;
		}
		boolean isPowerOfTwo;
		int shift = 0;
		long mask = 0;
		switch(base) {
			case 0x10://fast path for base 16 used by IPv6
				isPowerOfTwo = true;
				shift = 4; //log2(base)
				mask = 0xf; //2^shift - 1
				break;
			default:
				isPowerOfTwo = (base & (base - 1)) == 0;
				if(isPowerOfTwo) {
					shift = Integer.numberOfTrailingZeros(base);
					mask = ~(~0L << shift); //allBitSize must be 6 digits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
				}
		}
		boolean handledUpper = false;
		long value = getLowerValue();
		do {
			while(value > 0) {
				if(isAlphabetic(isPowerOfTwo ? (mask & value) : (value % base))) {
					return true;
				}
				value = isPowerOfTwo ? (value >> shift) : (value / base);
			}
			if(handledUpper || lowerOnly) {
				break;
			}
			value = getUpperValue();
			handledUpper = true;
		} while(true);
		return false;
	}
	
	public static int defaultMaxCharsPerSegment(IPVersion version) {
		return version.isIPv4() ? IPv4AddressSegment.MAX_CHARS : IPv6AddressSegment.MAX_CHARS;
	}
	
	public int getDefaultMaxChars(int radix) {
		int defaultRadix = getDefaultTextualRadix();
		if(radix == defaultRadix) {
			return getDefaultMaxChars();
		}
		return getCharWidth(getMaxValue(), radix);
	}
	
	public static int getCharWidth(long value, int radix) {
		int result = 1;
		while(true) {
			value /= radix;
			if(value == 0) {
				break;
			}
			result++;
		}
		return result;
	}
	
	//note this is used by IPAddressStringBuilder.getExpandableSegments during string building. So the prefixes don't work with wildcards at this time.
	public int getMaxLeadingZeros(int radix) {
		if(!isRangeEquivalentToPrefix()) {
			return 0;
		}
		int width = getCharWidth(getLowerValue(), radix);
		return Math.max(0, getDefaultMaxChars(radix) - width);
	}
	
	private int adjustLeadingZeroCount(int leadingZeroCount, long value, int radix) {
		if(leadingZeroCount < 0) {
			int width = getCharWidth(value, radix);
			return Math.max(0, getDefaultMaxChars() - width);
		}
		return leadingZeroCount;
	}
	
	private static void getSplitChar(int count, char splitDigitSeparator, String characters, StringBuilder builder) {
		while(count-- > 0) {
			builder.append(characters);
			builder.append(splitDigitSeparator);
		}
		builder.setLength(builder.length() - 1);
	}
	
	private static void getSplitChar(int count, char splitDigitSeparator, char character, StringBuilder builder) {
		while(count-- > 0) {
			builder.append(character);
			builder.append(splitDigitSeparator);
		}
		builder.setLength(builder.length() - 1);
	}

	private static void getLeadingZeros(int leadingZeroCount, boolean splitDigits, char splitDigitSeparator, StringBuilder builder) {
		if(splitDigits) {
			getSplitChar(leadingZeroCount, splitDigitSeparator, '0', builder);
			return;
		}
		String stringArray[] = zeroes;
		if(leadingZeroCount >= stringArray.length) {
			int increment = stringArray.length - 1;
			String incrementStr = stringArray[increment];
			while(leadingZeroCount >= increment) {
				builder.append(incrementStr);
				leadingZeroCount -= increment;
			}
			builder.append(stringArray[leadingZeroCount]);
			return;
		}
		builder.append(stringArray[leadingZeroCount]);
	}
	
	private static void getLeadingZeros(int leadingZeroCount, StringBuilder builder) {
		getLeadingZeros(leadingZeroCount, false, (char) 0, builder);
	}
	
	/////// strings below
	
	@Override
	public String toString() {
		return getString();
	}
	
	/**
	 * Produces a normalized string to represent the segment.
	 * If the segment CIDR prefix length covers the range, then it is assumed to be a CIDR, and the string has only the lower value of the CIDR range.
	 * Otherwise, the explicit range will be printed.
	 * @return
	 */
	public String getString() {
		String result = cachedString;
		if(result == null) {
			synchronized(this) {
				result = cachedString;
				if(result == null) {
					if(isRangeEquivalentToPrefix()) { //covers the case of !isMultiple, ie single addresses
						result = toDefaultString(getLowerValue(), getDefaultTextualRadix());
					} else if(isFullRange()) {
						result = IPAddress.SEGMENT_WILDCARD_STR;
					} else {
						long upperValue = getUpperValue();
						if(ADJUST_RANGES_BY_PREFIX && isPrefixed()) {
							long mask = getDivisionNetworkMask(getDivisionPrefixLength());
							upperValue &= mask;
						}
						result = toDefaultRangeString(getLowerValue(), upperValue, getDefaultTextualRadix());
					}
					cachedString = result;
				}
			}
		}
		return result;
	}

	/**
	 * Produces a string to represent the segment, favouring wildcards and range characters over the network prefix to represent subnets.
	 * If it exists, the segment CIDR prefix is ignored and the explicit range is printed.
	 * @return
	 */
	public String getWildcardString() {
		String result = cachedWildcardString;
		if(result == null) {
			synchronized(this) {
				result = cachedWildcardString;
				if(result == null) {
					if(!isMultiple() || !isPrefixed()) {
						result = getString();
					} else if(isFullRange()) {
						result = IPAddress.SEGMENT_WILDCARD_STR;
					} else {
						result = toDefaultRangeString(getLowerValue(), getUpperValue(), getDefaultTextualRadix());
					}
					cachedWildcardString = result;
				}
			}
		}
		return result;
	}
	
	/**
	 * Produces a string to represent the segment, favouring wildcards and range characters over the network prefix to represent subnets.
	 * Use this instead of getWildcardString() if you have a customized wildcard or range separator or you have a non-zero leadingZeroCount,
	 * or you have a string prefix, or you have a non-default radix (for IPv4 default radix is 10, for IPv6 it is 16)
	 * 
	 */
	public void getWildcardString(
			Wildcards wildcards,
			int leadingZeroCount,//-1 means max leading zeros
			String stringPrefix,
			int radix,
			boolean uppercase,
			boolean splitDigits,
			char splitDigitSeparator,
			boolean reverseSplitDigits,
			StringBuilder appendable) {
		if(!isMultiple()) {
			if(stringPrefix != null) {
				appendable.append(stringPrefix);
			}
			long lowerValue = getLowerValue();
			if(splitDigits) {
				if(reverseSplitDigits) {
					toUnsignedString(getLowerValue(), radix, -1, uppercase, splitDigits, splitDigitSeparator, reverseSplitDigits, appendable);
					if(leadingZeroCount != 0) {
						appendable.append(splitDigitSeparator);
						getLeadingZeros(leadingZeroCount, splitDigits, splitDigitSeparator, appendable);
					}
				} else {
					if(leadingZeroCount != 0) {
						getLeadingZeros(leadingZeroCount, splitDigits, splitDigitSeparator, appendable);
						appendable.append(splitDigitSeparator);
					}
					toUnsignedString(getLowerValue(), radix, -1, uppercase, splitDigits, splitDigitSeparator, reverseSplitDigits, appendable);
				}
			} else {
				if(leadingZeroCount != 0) {
					leadingZeroCount = adjustLeadingZeroCount(leadingZeroCount, lowerValue, radix);
					getLeadingZeros(leadingZeroCount, appendable);
				}
				if((!uppercase || radix <= 10) && radix == getDefaultTextualRadix()) {
					appendable.append(getWildcardString());
				} else {
					toUnsignedString(getLowerValue(), radix, uppercase, appendable);
				}
			}
			return;
		}
		if(isFullRange()) {
			String wildcard = wildcards.wildcard;
			if(wildcard != null) {
				if(wildcard.equals(IPAddress.SEGMENT_WILDCARD_STR)) {
					if(splitDigits) {
						getSplitChar(getDefaultMaxChars(), splitDigitSeparator, '*', appendable);
					} else {
						appendable.append(getWildcardString());//call getWildcardString to cache the result
					}
				} else {
					if(splitDigits) {
						getSplitChar(getDefaultMaxChars(), splitDigitSeparator, wildcard, appendable);
					} else {
						appendable.append(wildcard);
					}
				}
				return;
			}
		}
		
		//check the remaining case where we can defer to getWildcardString which is cached:
		//no character prefix, and using the same wildcards as getWildcardString
		String rangeSeparator = wildcards.rangeSeparator;
		int rangeDigitCount = wildcards.singleWildcard == null ? 0 : getRangeDigitCount(radix);
		if(leadingZeroCount == 0 && rangeSeparator.equals(IPAddress.RANGE_SEPARATOR_STR) && rangeDigitCount == 0 && radix == getDefaultTextualRadix() && !splitDigits) {
			if(stringPrefix != null) {
				appendable.append(stringPrefix);
			}
			appendable.append(getWildcardString());
			return;
		}
		
		//TODO can do better here.  as with masks, other ranges can work if the lower range(s) is full, eg 1.2.3-4.* or 1.2.3.4-5 or 1.2-3.*.*
		//So, take the radix.  Take lower and higher.  For each digit, figure out if low and high match the radix.
		//For non range values for splits we create the num at end of buffer then copy it over to lower on buffer
		//So how do we do it for range values?  First we find the lengths of each in the range.  Then we go through the digits one by one, both nums at the same time.
		//I think we need TWO separate sections, one for each number reversed:
		//1.2.3.21-654
		//1.2.3.____12___456 becomes 1.2.3.0-6.1-5.2-4
		//but in reality that is not valid, lower ranges must be full
		//1.2.3.0-699 works
		//1.2.3.____0___996 becomes 1.2.3.0-6.0-9.0-9 and the last 2 ranges run from 0 to 9
		//1.2.3.__100___996 becomes 1.2.3.1-6.0-9.0-9 and the last 2 ranges run from 0 to 9
		if(splitDigits) {
			throw new IPAddressTypeException(this, "ipaddress.error.splitMismatch");
		}
		//TODO maybe I can do repeated calls to getRangeString?  Yeah.  Slightly inefficient though.  Could do the same for the non-range split digits.
		//Doing both forward and reverse is tricky though.
		//Could do each number separately and then rearrange.  But not optimal.
		//Probabyl best to go with the original.
		//In fact, doing the loop with both numbers at same time works nicely I think, it makes sure we have equal number of digits for both sides of range.
		//OK, tht should do it.  Also, need to alter the rangeDigit section, nbut that will be similar to handling '*' and handling a single number
		//I think we need to separate the splitDigit path right here and not alter the getRangeString method
				
		//TODO must also account for splitDigitSeparator and reverseSplitDigits when handling splitDigits
		
		long lowerVal = getLowerValue();
		long upperVal = getUpperValue();
		getRangeString(
				lowerVal,
				upperVal,
				wildcards.rangeSeparator,
				wildcards.singleWildcard,
				adjustLeadingZeroCount(leadingZeroCount, lowerVal, radix),
				adjustLeadingZeroCount(leadingZeroCount, upperVal, radix),
				stringPrefix,
				radix,
				rangeDigitCount,
				uppercase,
				appendable);
	}

	private static String toDefaultRangeString(long val1, long val2, int radix) {
		int len1, len2, value1, value2, quotient, remainder; //we iterate on //value == quotient * radix + remainder
		if(radix == 10) {
			if(val1 < 10) {
				len1 = 1;
			} else if(val1 < 100) {
				len1 = 2;
			} else if(val1 < 1000) {
				len1 = 3;
			} else {
				return getRangeString(val1, val2, IPAddress.RANGE_SEPARATOR_STR, null, 0, 0, null, radix, 0, false);
			}
			value1 = (int) val1;
			if(val2 < 10) {
				len2 = 1;
			} else if(val2 < 100) {
				len2 = 2;
			} else if(val2 < 1000) {
				len2 = 3;
			} else {
				return getRangeString(val1, val2, IPAddress.RANGE_SEPARATOR_STR, null, 0, 0, null, radix, 0, false);
			}
			value2 = (int) val2;
			len2 += len1 + 1;
			char chars[] = new char[len2];
			chars[len1] = IPAddress.RANGE_SEPARATOR;
			char dig[] = digits;
			do {
				//value == quotient * 10 + remainder
				quotient = (value1 * 0xcccd) >>> 19; //floor of n/10 is floor of ((0xcccd * n / (2 ^ 16)) / (2 ^ 3))
				remainder = value1 - ((quotient << 3) + (quotient << 1)); //multiplication by 2 added to multiplication by 2 ^ 3 is multiplication by 2 + 8 = 10
				chars[--len1] = dig[remainder];
				value1 = quotient;
	        } while(value1 != 0);
			do {
				quotient = (value2 * 0xcccd) >>> 19;
				remainder = value2 - ((quotient << 3) + (quotient << 1));
				chars[--len2] = dig[remainder];
				value2 = quotient;
	        } while(value2 != 0);
			return new String(chars);
		}
		if(radix == 16) {
			if(val1 < 0x10) {
				len1 = 1;
			} else if(val1 < 0x100) {
				len1 = 2;
			} else if(val1 < 0x1000) {
				len1 = 3;
			} else if(val1 < 0x10000) {
				len1 = 4;
			} else {
				return getRangeString(val1, val2, IPAddress.RANGE_SEPARATOR_STR, null, 0, 0, null, radix, 0, false);
			}
			value1 = (int) val1;
			if(val2 < 0x10) {
				len2 = 1;
			} else if(val2 < 0x100) {
				len2 = 2;
			} else if(val2 < 0x1000) {
				len2 = 3;
			} else if(val2 < 0x10000) {
				len2 = 4;
			} else {
				return getRangeString(val1, val2, IPAddress.RANGE_SEPARATOR_STR, null, 0, 0, null, radix, 0, false);
			}
			value2 = (int) val2;
			len2 += len1 + 1;
			char chars[] = new char[len2];
			chars[len1] = IPAddress.RANGE_SEPARATOR;
			char dig[] = digits;
			do {//value1 == quotient * 16 + remainder
				quotient = value1 >>> 4;
				remainder = value1 - (quotient << 4);
				chars[--len1] = dig[remainder];
				value1 = quotient;
			} while(value1 != 0);
			do {
				quotient = value2 >>> 4;
				remainder = value2 - (quotient << 4);
				chars[--len2] = dig[remainder];
				value2 = quotient;
			} while(value2 != 0);
			return new String(chars);
		}
		return getRangeString(val1, val2, IPAddress.RANGE_SEPARATOR_STR, null, 0, 0, null, radix, 0, false);
	}
	
	private static String toDefaultString(long val, int radix) {
		switch((int) val) {
			case 0:
				return "0";
			case 1:
				return "1";
			default:
		}
		int len, quotient, remainder, value; //we iterate on //value == quotient * radix + remainder
		if(radix == 10) {
			if(val < 10) {
				return String.valueOf(digits, (int) val, 1);
			} else if(val < 100) {
				len = 2;
				value = (int) val;
			} else if(val < 1000) {
				len = 3;
				value = (int) val;
			} else {
				return Long.toString(val, radix);
			}
			char chars[] = new char[len];
			char dig[] = digits;
			do {
				//value == quotient * 10 + remainder
				quotient = (value * 0xcccd) >>> 19; //floor of n/10 is floor of ((0xcccd * n / (2 ^ 16)) / (2 ^ 3))
				remainder = value - ((quotient << 3) + (quotient << 1)); //multiplication by 2 added to multiplication by 2 ^ 3 is multiplication by 2 + 8 = 10
				chars[--len] = dig[remainder];
				value = quotient;
	        } while(value != 0);
			return new String(chars);
		}
		if(radix == 16) {
			if(val < 0x10) {
				return String.valueOf(digits, (int) val, 1);
			} else if(val < 0x100) {
				len = 2;
				value = (int) val;
			} else if(val < 0x1000) {
				len = 3;
				value = (int) val;
			} else if(val < 0x10000) {
				if(val == 0xffff) {
					return "ffff";
				}
				value = (int) val;
				len = 4;
			} else {
				return Long.toString(val, radix);
			}
			char chars[] = new char[len];
			char dig[] = digits;
			do {//value2 == quotient * 16 + remainder
				quotient = value >>> 4;
				remainder = value - (quotient << 4);
				chars[--len] = dig[remainder];
				value = quotient;
			} while(value != 0);
			return new String(chars);
		}
		return Long.toString(val, radix);
	}

	protected static boolean fastToUnsignedString(int value, int radix, boolean uppercase, StringBuilder appendable) {
		switch(value) {
			case 0:
				appendable.append('0');
				return true;
			case 1:
				appendable.append('1');
				return true;
			default:
				//for values larger than 1, result can be different with different radix (radix is 2 and up)
		}
		int quotient, remainder; //we iterate on //value == quotient * radix + remainder
		if(radix == 10) {
			//this needs value2 <= 0xffff (ie 16 bits or less)
			if(value < 10) {
				char dig[] = digits;
				appendable.append(dig[value]);
				return true;
			} else if(value < 100) {
				appendable.append("  ");
			} else if(value < 1000) {
				if(value == 127) {
					appendable.append("127");
					return true;
				}
				if(value == 255) {
					appendable.append("255");
					return true;
				}
				appendable.append("   ");
			} else if(value < 10000) {
				appendable.append("    ");
			} else {
				appendable.append("     ");
			}
			char dig[] = digits;
			int index = appendable.length();
			do {
				//value == quotient * 10 + remainder
				quotient = (value * 0xcccd) >>> 19; //floor of n/10 is floor of ((0xcccd * n / 2 ^ 16) / 2 ^ 3)
				remainder = value - ((quotient << 3) + (quotient << 1)); //multiplication by 2 added to multiplication by 2 ^ 3 is multiplication by 2 + 8 = 10
				appendable.setCharAt(--index, dig[remainder]);
				value = quotient;
	        } while(value != 0);
			return true;
	    }
		if(radix == 16) {
			if(value < 0xa) {
				appendable.append(digits[value]);
				return true;
			} else if(value < 0x10) {
				appendable.append((uppercase ? upperDigits : digits)[value]);
				return true;
			} else if(value < 0x100) {
				appendable.append("  ");
			} else if(value < 0x1000) {
				appendable.append("   ");
			} else {
				if(value == 0xffff) {
					appendable.append(uppercase ? "FFFF" : "ffff");
					return true;
				}
				appendable.append("    ");
			}
			int index = appendable.length();
			char dig[] = uppercase ? upperDigits : digits;
			do {//value2 == quotient * 16 + remainder
				quotient = value >>> 4;
				remainder = value - (quotient << 4);
				appendable.setCharAt(--index, dig[remainder]);
				value = quotient;
			} while(value != 0);
			return true;
		}
		if(radix == 8) {
			char dig[] = digits;
			if(value < 010) {
				appendable.append(dig[value]);
				return true;
			} else if(value < 0100) {
				appendable.append("  ");
			} else if(value < 01000) {
				appendable.append("   ");
			} else if(value < 010000) {
				appendable.append("    ");
			} else if(value < 0100000) { 
				appendable.append("     ");
			} else {
				appendable.append("      ");
			}
			int index = appendable.length();
			do {//value2 == quotient * 16 + remainder
				quotient = value >>> 3;
				remainder = value - (quotient << 3);
				appendable.setCharAt(--index, dig[remainder]);
				value = quotient;
			} while(value != 0);
			return true;
		}
		if(radix == 2) {
			//count the number of digits
			//note that we already know value != 0 and that value <= 0xffff
			//and we use both of those facts
			int digitCount = 15;
			int val = value;
			if (val >>> 8 == 0) { 
				digitCount -=  8;
			} else {
				val >>>= 8;
			}
			if (val >>> 4 == 0) {
				digitCount -=  4;
			} else {
				val >>>= 4;
			}
			if (val >>> 2 == 0) {
				digitCount -= 2;
			} else {
				val >>>= 2;
			}
			//at this point, if (val & 2) != 0 we have undercounted the digit count by 1
			//either way, we start with the first digit '1' and adjust the digit count accordingly
			if((val & 2) == 0) {
				--digitCount;
			}
			appendable.append('1');
			char dig[] = digits;
			while(digitCount > 0) {
				char c = dig[(value >>> --digitCount) & 1];
				appendable.append(c);
			}
			return true;
		}
		return false;
	}
	
	private static void toUnsignedString(
			long value,
			int radix,
			boolean uppercase,
			StringBuilder appendable) {
		if(value <= 0xffff && fastToUnsignedString((int) value, radix, uppercase, appendable)) {
			return;
		}
		toUnsignedString(value, radix, -1, uppercase, false, (char) 0, false, appendable);
		return;
	}
	
	private static void toUnsignedString(
			long value,
			int radix,
			int choppedDigits,
			boolean uppercase, 
			boolean splitDigits,
			char splitDigitSeparator,
			boolean reverseSplitDigits,
			StringBuilder appendable) {
		//Here we reserve space for the digits without knowing ahead of time how many digits there will be. 
		//Then we calculate the digits in reverse order following that space,
		//Then afterwards we copy the reversed digits back to reserved space in the correct order.
		//For instance, if the address is 1.2.3.456, and we have in the builder 1.2.3.,
		//then we reserve space 1.2.3._____,
		//then we calculate the digits in reverse order 1.2.3._____654,
		//then we put them in the reserved space in correct order 1.2.3.456_____,
		//and then we chop the extra to make 1.2.3.456
		int len = appendable.length();
		appendable.append("                                                            ");//63 chars leaves enough space for the longest long in binary
		if(splitDigits) {
			appendable.append(appendable);//double the size
		}
		int spaceLen = appendable.length();
		char dig[] = uppercase ? upperDigits : digits;
		if(value <= Integer.MAX_VALUE) {
			int value2 = (int) value;
			while(value2 >= radix) {
				int index = value2 % radix;
				appendable.append(dig[index]);
				value2 /= radix;
			}
			appendable.append(dig[value2]);
		} else {
			while(value >= radix) {
				int index = (int) (value % radix);
				appendable.append(dig[index]);
				value /= radix;
			}
			appendable.append(dig[(int) value]);
		}
		if(choppedDigits > 0) {
			spaceLen += choppedDigits;
		}
		int charLen = appendable.length();
		if(splitDigits) {
			if(reverseSplitDigits) {
				while(spaceLen < charLen) {
					appendable.setCharAt(len++, appendable.charAt(spaceLen++));
					appendable.setCharAt(len++, splitDigitSeparator);
				}
			} else {
				while(--charLen >= spaceLen) {
					appendable.setCharAt(len++, appendable.charAt(charLen));
					appendable.setCharAt(len++, splitDigitSeparator);  
				}
			}
			--len;
		} else {
			while(--charLen >= spaceLen) {
				appendable.setCharAt(len++, appendable.charAt(charLen));
			}
		}
		appendable.setLength(len);
	}
	
	/**
	 * Produces a string to represent the segment.
	 * <p>
	 * Use this instead of {@link #getWildcardString(Wildcards, int, String, int, boolean, StringBuilder)}
	 * if you wish to avoid printing wildcards in the host section of the address.
	 * <p>
	 * Use this instead of getString() if you have a customized wildcard or range separator or you have a non-zero leadingZeroCount,
	 * or you have a string prefix, or you have a non-default radix (for IPv4 default radix is 10, for IPv6 it is 16)
	 */
	public void getPrefixAdjustedWildcardString(
			Wildcards wildcards,
			int leadingZeroCount,//-1 means max leading zeros
			String stringPrefix,
			int radix,
			boolean uppercase,
			StringBuilder appendable) {
		boolean isDefaultRadix = (radix == getDefaultTextualRadix());
		if(isRangeEquivalentToPrefix()) {
			//nothing to adjust, no wildcards in use
			if(stringPrefix != null) {
				appendable.append(stringPrefix);
			}
			if(leadingZeroCount != 0) {
				long lowerValue = getLowerValue();
				leadingZeroCount = adjustLeadingZeroCount(leadingZeroCount, lowerValue, radix);
				getLeadingZeros(leadingZeroCount, appendable);
			}
			if(isDefaultRadix && (!uppercase || radix <= 10)) {
				appendable.append(getString());
			} else {
				toUnsignedString(getLowerValue(), radix, uppercase, appendable);
			}
			return;
		}
		//if we can defer to getWildcardString then we do so
		if(!isPrefixed() || !isMultiple() || !ADJUST_RANGES_BY_PREFIX) {
			getWildcardString(wildcards, leadingZeroCount, stringPrefix, radix, uppercase, false, (char) 0, false, appendable);
			return;
		}
		if(isFullRange()) {
			String wildcard = wildcards.wildcard;
			if(wildcard != null) {
				if(wildcard.equals(IPAddress.SEGMENT_WILDCARD_STR)) {
					appendable.append(getWildcardString());
				} else {
					appendable.append(wildcard);
				}
				return;
			}
		}
		//if the wildcards match those in use by getString(), and there is no character prefix, let's defer to getString() so that it is cached
		String rangeSeparator = wildcards.rangeSeparator;
		int rangeDigitCount = wildcards.singleWildcard == null ? 0 : getRangeDigitCount(radix);
		if(leadingZeroCount == 0 && IPAddress.RANGE_SEPARATOR_STR.equals(rangeSeparator) && rangeDigitCount == 0 && isDefaultRadix) {
			//we call getString() to cache the result, and we call getString instead of getWildcardString() because it will also mask with the segment prefix length
			if(stringPrefix != null) {
				appendable.append(stringPrefix);
			}
			String str = getString();
			if(uppercase) {
				str = str.toUpperCase();
			}
			appendable.append(str);
			return;
		}
		//here we adjust by prefix, using this mask
		long mask = getDivisionNetworkMask(getDivisionPrefixLength());
		long lowerMasked = getLowerValue() & mask;
		long upperMasked = getUpperValue() & mask;
		int lowerLeadingZeroCount = adjustLeadingZeroCount(leadingZeroCount, lowerMasked, radix);
		int upperLeadingZeroCount = adjustLeadingZeroCount(leadingZeroCount, upperMasked, radix);
		getRangeString(lowerMasked, upperMasked, rangeSeparator, wildcards.singleWildcard, lowerLeadingZeroCount, upperLeadingZeroCount, stringPrefix, radix, rangeDigitCount, uppercase, appendable);
	}
	
	private int getRangeDigitCount(int radix) {
		if(getLowerValue() == getUpperValue()) {
			return 0;
		}
		if(radix == getDefaultTextualRadix()) {
			return getRangeDigitCountImpl();
		}
		return calculateRangeDigitCount(radix, getLowerValue(), getUpperValue(), getMaxValue());
	}
	
	protected int getRangeDigitCountImpl() {
		return calculateRangeDigitCount(getDefaultTextualRadix(), getLowerValue(), getUpperValue(), getMaxValue());
	}
	
	private static int calculateRangeDigitCount(int radix, long value, long upperValue, long maxValue) {
		int factor = radix;
		int numDigits = 1;
		while(true) {
			long lowerRemainder = value % factor;
			if(lowerRemainder == 0) {
				long max = (maxValue / factor == upperValue / factor) ? maxValue % factor : factor - 1;
				long upperRemainder = upperValue % factor;
				if(upperRemainder == max) {
					if(upperValue - upperRemainder == value) {
						return numDigits;
					} else {
						numDigits++;
						factor *= radix;
						continue;
					}
				}
			}
			return 0;
		}
	}
	
	private static String getRangeString(
			long lower,
			long upper,
			String rangeSeparator,
			String singleWildcard,
			int lowerLeadingZerosCount,
			int upperLeadingZerosCount,
			String stringPrefix,
			int radix,
			int rangeDigits,
			boolean uppercase) {
		StringBuilder builder = new StringBuilder(20);
		getRangeString(lower, upper, rangeSeparator, singleWildcard, lowerLeadingZerosCount, upperLeadingZerosCount, stringPrefix, radix, rangeDigits, uppercase, builder);
		return builder.toString();
	}
	
	protected static void getRangeString(
			long lower,
			long upper,
			String rangeSeparator,
			String singleWildcard,
			int lowerLeadingZerosCount,
			int upperLeadingZerosCount,
			String stringPrefix,
			int radix,
			int rangeDigits,
			boolean uppercase,
			StringBuilder appendable) {
		if(rangeDigits != 0) {
			//Note: ranges like ___ intended to represent 0-fff cannot work because the range does not include 2 digit and 1 digit numbers
			//This only happens when the lower value is 0 and there is more than 1 range digit
			//That's because you can then omit any leading zeros.
			//Ranges like f___ representing f000-ffff are fine.
			if(lower != 0 || rangeDigits == 1) { 
				if(stringPrefix != null) {
					appendable.append(stringPrefix);
				}
				if(lowerLeadingZerosCount > 0) {
					getLeadingZeros(lowerLeadingZerosCount, appendable);
				}
				toUnsignedString(lower, radix, rangeDigits, uppercase, false, (char) 0, false, appendable);
				for(int i = 0; i < rangeDigits; i++) {
					appendable.append(singleWildcard);
				}
				return;
			}
		}
		if(rangeSeparator == null) {
			throw new NullPointerException();//should never reach here
		}
		if(stringPrefix != null) {
			appendable.append(stringPrefix);
		}
		if(lowerLeadingZerosCount > 0) {
			getLeadingZeros(lowerLeadingZerosCount, appendable);
		}
		toUnsignedString(lower, radix, uppercase, appendable);
		appendable.append(rangeSeparator);
		if(stringPrefix != null) {
			appendable.append(stringPrefix);
		}
		if(upperLeadingZerosCount > 0) {
			getLeadingZeros(upperLeadingZerosCount, appendable);
		}
		toUnsignedString(upper, radix, uppercase, appendable);
		return;
	}
}
