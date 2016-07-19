package inet.ipaddr.format;

import java.io.Serializable;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressSection.WildcardOptions.Wildcards;
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
	
	private static boolean testRange(long lowerValue, long upperValue, long finalUpperValue, int divisionPrefixLen, long networkMask, long hostMask) {
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
				divisionPrefixLen,
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
				divisionPrefixLen,
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
	
	private String getLeadingZeros(int digits) {
		if(digits >= zeroes.length) {
			StringBuilder builder = new StringBuilder(digits);
			int increment = zeroes.length - 1;
			String incrementStr = zeroes[increment];
			while(digits >= increment) {
				builder.append(incrementStr);
				digits -= increment;
			}
			builder.append(zeroes[digits]);
			return builder.toString();
		}
		return zeroes[digits];
	}
	
	private String getLeadingZerosFor(long value, int radix) {
		int width = getCharWidth(value, radix);
		int expansion = Math.max(0, getDefaultMaxChars() - width);
		if(expansion > 0) {
			return getLeadingZeros(expansion);
		}
		return null;
	}
	
	private String getLeadingZerosFor(long value, int radix, int leadingZeroCount) {
		if(leadingZeroCount != 0) {
			if(leadingZeroCount < 0) {
				return getLeadingZerosFor(value, radix);
			} else {
				return getLeadingZeros(leadingZeroCount);
			}
		}
		return null;
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
						long value = getLowerValue();
						result = toUnsignedString(value, getDefaultTextualRadix());
					} else if(isFullRange()) {
						result = IPAddress.SEGMENT_WILDCARD_STR;
					} else {
						if(ADJUST_RANGES_BY_PREFIX && isPrefixed()) {
							long mask = getDivisionNetworkMask(getDivisionPrefixLength());
							result = getRangeString(getLowerValue(), getUpperValue() & mask, IPAddress.RANGE_SEPARATOR_STR, null, 0, null, getDefaultTextualRadix(), 0, false);
						} else {
							result = getRangeString(getLowerValue(), getUpperValue(), IPAddress.RANGE_SEPARATOR_STR, null, 0, null, getDefaultTextualRadix(), 0, false);
						}
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
						result = getRangeString(getLowerValue(), getUpperValue(), IPAddress.RANGE_SEPARATOR_STR, null, 0, null, getDefaultTextualRadix(), 0, false);
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
			int leadingZeroCount,
			String stringPrefix,
			int radix,
			boolean uppercase,
			StringBuilder appendable) {
		boolean isDefaultRadix = (radix == getDefaultTextualRadix());
		if(!isMultiple()) {
			if(stringPrefix != null) {
				appendable.append(stringPrefix);
			}
			String zerosPrefix = getLeadingZerosFor(getLowerValue(), radix, leadingZeroCount);
			if(zerosPrefix != null) {
				appendable.append(zerosPrefix);
			}
			if(isDefaultRadix && (!uppercase || radix <= 10)) {
				appendable.append(getWildcardString());
			} else {
				toUnsignedString(getLowerValue(), radix, -1, uppercase, appendable);
			}
			return;
		}
		if(isFullRange()) {
			String wildcard = wildcards.wildcard;
			if(wildcard != null) {
				if(wildcard.equals(IPAddress.SEGMENT_WILDCARD_STR)) {
					appendable.append(getWildcardString());//call getWildcardString to cache the result
				} else {
					appendable.append(wildcard);
				}
				return;
			}
		}
		//check the remaining case where we can defer to getWildcardString which is cached:
		//no character prefix, and using the same wildcards as getWildcardString
		String rangeSeparator = wildcards.rangeSeparator;
		int rangeDigitCount = wildcards.singleWildcard == null ? 0 : getRangeDigitCount(radix);
		if(leadingZeroCount == 0 && rangeSeparator.equals(IPAddress.RANGE_SEPARATOR_STR) && rangeDigitCount == 0 && isDefaultRadix) {
			if(stringPrefix != null) {
				appendable.append(stringPrefix);
			}
			appendable.append(getWildcardString());
			return;
		}
		getRangeString(getLowerValue(), getUpperValue(), wildcards.rangeSeparator, wildcards.singleWildcard, leadingZeroCount, stringPrefix, radix, rangeDigitCount, uppercase, appendable);
	}
	
	protected static String toUnsignedString(long value, int radix) {
		if(value == 0) {
			return "0";
		}
		return Long.toString(value, radix);
	}
	
	private static boolean fastToUnsignedString(int value, int radix, boolean uppercase, StringBuilder appendable) {
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
	
	protected static void toUnsignedString(long value, int radix, int rangeDigits, boolean uppercase, StringBuilder appendable) {
		if(value <= 0xffff && rangeDigits <= 0) {
			if(fastToUnsignedString((int) value, radix, uppercase, appendable)) {
				return;
			}
		}
		
		//Slow path
		
		//Here we reserve space for the digits, then we calculate the digits in reverse order following that space,
		//then afterwards we copy the reversed digits back to reserved space in the correct order.
		//For instance, if the address is 1.2.3.456 we have in the builder 1.2.3.,
		//then we reserve space 1.2.3._____,
		//then we calculate the digits in reverse order 1.2.3._____654,
		//then we put them in the reserved space in correct order 1.2.3.456_____,
		//and then we chop 1.2.3.456
		int len = appendable.length();
		appendable.append("          "); //10 chars leaves enough space
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
		int charLen = appendable.length();
		if(rangeDigits > 0) {
			spaceLen += rangeDigits;
		}
		while(--charLen >= spaceLen) {
			appendable.setCharAt(len++, appendable.charAt(charLen));
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
			int leadingZeroCount,
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
			long value = getLowerValue();
			String zerosPrefix = getLeadingZerosFor(value, radix, leadingZeroCount);
			if(zerosPrefix != null) {
				appendable.append(zerosPrefix);
			}
			if(isDefaultRadix && (!uppercase || radix <= 10)) {
				appendable.append(getString());
			} else {
				toUnsignedString(getLowerValue(), radix, -1, uppercase, appendable);
			}
			return;
		}
		//if we can defer to getWildcardString then we do so
		if(!isPrefixed() || !isMultiple() || !ADJUST_RANGES_BY_PREFIX) {
			getWildcardString(wildcards, leadingZeroCount, stringPrefix, radix, uppercase, appendable);
			return;
		}
		if(isFullRange()) {
			String wildcard = wildcards.wildcard;
			if(wildcard != null) {
				if(wildcard.equals(IPAddress.SEGMENT_WILDCARD_STR)) {
					//getWildcardString(appendable);//call this to cache the result
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
		getRangeString(getLowerValue() & mask, getUpperValue() & mask, rangeSeparator, wildcards.singleWildcard, leadingZeroCount, stringPrefix, radix, rangeDigitCount, uppercase, appendable);
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
	
	private String getRangeString(
			long lower,
			long upper,
			String rangeSeparator,
			String singleWildcard,
			int leadingZerosCount,
			String stringPrefix,
			int radix,
			int rangeDigits,
			boolean uppercase) {
		StringBuilder builder = new StringBuilder(20);
		getRangeString(lower, upper, rangeSeparator, singleWildcard, leadingZerosCount, stringPrefix, radix, rangeDigits, uppercase, builder);
		return builder.toString();
	}
			
	private void getRangeString(
			long lower,
			long upper,
			String rangeSeparator,
			String singleWildcard,
			int leadingZerosCount,
			String stringPrefix,
			int radix,
			int rangeDigits,
			boolean uppercase,
			StringBuilder appendable) {
		String lowerZerosPrefix = getLeadingZerosFor(lower, radix, leadingZerosCount);
		if(rangeDigits != 0) {
			//Note: ranges like ___ intended to represent 0-fff do not work because the range does not include 2 digit and 1 digit numbers
			//This only happens when the lower value is 0 and the is more than 1 range digit
			//That's because you can then omit any leading zeros.
			//Ranges like f___ representing f000-ffff are fine.
			if(lower != 0 || rangeDigits == 1) { 
				if(stringPrefix != null) {
					appendable.append(stringPrefix);
				}
				if(lowerZerosPrefix != null) {
					appendable.append(lowerZerosPrefix);
				}
				toUnsignedString(lower, radix, rangeDigits, uppercase, appendable);
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
		if(lowerZerosPrefix != null) {
			appendable.append(lowerZerosPrefix);
		}
		toUnsignedString(lower, radix, -1, uppercase, appendable);
		appendable.append(rangeSeparator);
		if(stringPrefix != null) {
			appendable.append(stringPrefix);
		}
		String upperZerosPrefix = getLeadingZerosFor(upper, radix, leadingZerosCount);
		if(upperZerosPrefix != null) {
			appendable.append(upperZerosPrefix);
		}
		toUnsignedString(upper, radix, -1, uppercase, appendable);
		return;
	}
}
