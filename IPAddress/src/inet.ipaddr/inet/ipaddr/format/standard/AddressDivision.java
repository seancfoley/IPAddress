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

package inet.ipaddr.format.standard;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;

import inet.ipaddr.Address;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.AddressDivisionBase;

/**
 * A division of an address.
 * 
 * @author sfoley
 *
 */
public abstract class AddressDivision extends AddressDivisionBase {

	private static final long serialVersionUID = 4L;

	protected AddressDivision() {}

	@Override
	protected byte[] getBytesImpl(boolean low) {
		int bitCount = getBitCount();
		byte bytes[] = new byte[(bitCount + 7) >> 3];
		int byteIndex = bytes.length - 1, bitIndex = 8;
		long segmentValue = low ? getDivisionValue() : getUpperDivisionValue();
		while(true) {
			bytes[byteIndex] |= segmentValue << (8 - bitIndex);
			segmentValue >>= bitIndex;
			if(bitCount <= bitIndex) {
				return bytes;
			}
			bitCount -= bitIndex;
			bitIndex = 8;
			byteIndex--;
		}
	}
	
	/**
	 * @return whether this segment represents multiple values
	 */
	@Override
	public boolean isMultiple() {
		return getDivisionValue() != getUpperDivisionValue();
	}

	@Override
	public int getMinPrefixLengthForBlock() {
		int result = getBitCount();
		int lowerZeros = Long.numberOfTrailingZeros(getDivisionValue());
		if(lowerZeros != 0) {
			int upperOnes = Long.numberOfTrailingZeros(~getUpperDivisionValue());
			if(upperOnes != 0) {
				int prefixedBitCount = Math.min(lowerZeros, upperOnes);
				result -= prefixedBitCount;
			}
		}
		return result;
	}

	@Override
	public Integer getPrefixLengthForSingleBlock() {
		int divPrefix = getMinPrefixLengthForBlock();
		long lowerValue = getDivisionValue();
		long upperValue = getUpperDivisionValue();
		int bitCount = getBitCount();
		if(divPrefix == bitCount) {
			if(lowerValue == upperValue) {
				return AddressDivisionGrouping.cacheBits(divPrefix);
			}
		} else {
			int shift = bitCount - divPrefix;
			if(lowerValue >>> shift == upperValue >>> shift) {
				return AddressDivisionGrouping.cacheBits(divPrefix);
			}
		}
		return null;
	}

	@Override
	protected String getDefaultSegmentWildcardString() {
		return Address.SEGMENT_WILDCARD_STR;
	}
	
	@Override
	protected String getDefaultRangeSeparatorString() {
		return Address.RANGE_SEPARATOR_STR;
	}
	
	public long getMaxValue() {
		return ~(~0L << getBitCount());
	}
	
	@Override
	public boolean isZero() {
		return !isMultiple() && includesZero();
	}
	
	@Override
	public boolean includesZero() {
		return getDivisionValue() == 0L;
	}
	
	@Override
	public boolean isMax() {
		return !isMultiple() && includesMax();
	}
	
	@Override
	public boolean includesMax() {
		return getUpperDivisionValue() == getMaxValue();
	}
	
	public abstract long getDivisionValue();
	
	public abstract long getUpperDivisionValue();
	
	@Override
	public int hashCode() {
		int res = hashCode;
		if(res == 0) {
			hashCode = res = createHashCode(getDivisionValue(), getUpperDivisionValue());
		}
		return res;
	}
	
	@Override
	public BigInteger getValue() {
		return BigInteger.valueOf(getDivisionValue());
	}
	
	@Override
	public BigInteger getUpperValue() {
		return BigInteger.valueOf(getUpperDivisionValue());
	}
	
	public long getDivisionValueCount() {
		return getUpperDivisionValue() - getDivisionValue() + 1;
	}
	
	@Override
	public BigInteger getPrefixCount(int divisionPrefixLength) {
		return BigInteger.valueOf(getDivisionPrefixCount(divisionPrefixLength));
	}
	
	public long getDivisionPrefixCount(int divisionPrefixLength) {
		if(divisionPrefixLength < 0) {
			throw new PrefixLenException(this, divisionPrefixLength);
		}
		int bitCount = getBitCount();
		if(bitCount <= divisionPrefixLength) {
			return getDivisionValueCount();
		}
		int shiftAdjustment = bitCount - divisionPrefixLength;
		return (getUpperDivisionValue() >>> shiftAdjustment) - (getDivisionValue() >>> shiftAdjustment) + 1;
	}
	
	@Override
	public BigInteger getCount() {
		return BigInteger.valueOf(getDivisionValueCount());
	}
	
	static boolean testRange(long lowerValue, long upperValue, long finalUpperValue, long networkMask, long hostMask) {
		return lowerValue == (lowerValue & networkMask)
				&& finalUpperValue == (upperValue | hostMask);
	}
	
	/**
	 * Returns whether the division range includes the block of values for its prefix length
	 */
	protected boolean isPrefixBlock(long divisionValue, long upperValue, int divisionPrefixLen) {
		if(divisionPrefixLen == 0) {
			return divisionValue == 0 && upperValue == getMaxValue();
		}
		long ones = ~0L;
		long divisionBitMask = ~(ones << getBitCount());
		long divisionPrefixMask = ones << (getBitCount() - divisionPrefixLen);
		long divisionNonPrefixMask = ~divisionPrefixMask;
		return testRange(divisionValue,
				upperValue,
				upperValue,
				divisionPrefixMask & divisionBitMask,
				divisionNonPrefixMask);
	}

	/**
	 * 
	 * @param divisionValue
	 * @param divisionPrefixLen
	 * @return whether the given range of segmentValue to upperValue is equivalent to the range of segmentValue with the prefix of divisionPrefixLen 
	 */
	protected boolean isSinglePrefixBlock(long divisionValue, long upperValue, int divisionPrefixLen) {
		long ones = ~0L;
		long divisionBitMask = ~(ones << getBitCount());
		long divisionPrefixMask = ones << (getBitCount() - divisionPrefixLen);
		long divisionNonPrefixMask = ~divisionPrefixMask;
		return testRange(divisionValue,
				divisionValue,
				upperValue,
				divisionPrefixMask & divisionBitMask,
				divisionNonPrefixMask);
	}
	
	/**
	 * Returns true if the possible values of this division fall below the given value.
	 */
	@Override
	public boolean isBoundedBy(int value) {
		return getUpperDivisionValue() < value;
	}
	
	public boolean matches(long value) {
		return !isMultiple() && value == getDivisionValue();
	}
	
	public boolean matchesWithMask(long value, long mask) {
		if(isMultiple()) {
			//we want to ensure that any of the bits that can change from value to upperValue is masked out (zeroed) by the mask.
			//In other words, when masked we need all values represented by this segment to become just a single value
			long diffBits = getDivisionValue() ^ getUpperDivisionValue();
			int leadingZeros = Long.numberOfLeadingZeros(diffBits);
			//the bits that can change are all bits following the first leadingZero bits
			//all the bits that follow must be zeroed out by the mask
			long fullMask = ~0L >>> leadingZeros;
			if((fullMask & mask) != 0L) {
				return false;
			} //else we know that the mask zeros out all the bits that can change from value to upperValue, so now we just compare with either one
		}
		return value == (getDivisionValue() & mask);
	}
	
	/**
	 * returns whether masking with the given mask results in a valid contiguous range for this segment,
	 * and if it does, if it matches the range obtained when masking the given values with the same mask.
	 * 
	 * @param lowerValue
	 * @param upperValue
	 * @param mask
	 * @return
	 */
	public boolean matchesWithMask(long lowerValue, long upperValue, long mask) {
		if(lowerValue == upperValue) {
			return matchesWithMask(lowerValue, mask);
		}
		if(!isMultiple()) {
			//we know lowerValue and upperValue are not the same, so impossible to match those two values with a single value
			return false;
		}
		long thisValue = getDivisionValue();
		long thisUpperValue = getUpperDivisionValue();
		if(!isMaskCompatibleWithRange(thisValue, thisUpperValue, mask, getMaxValue())) {
			return false;
		}
		return lowerValue == (thisValue & mask) && upperValue == (thisUpperValue & mask);
	}
	
	@Override
	protected boolean isSameValues(AddressDivisionBase other) {
		if(other instanceof AddressDivision) {
			AddressDivision otherDivision = (AddressDivision) other;
			return getDivisionValue() == otherDivision.getDivisionValue() &&
					getUpperDivisionValue() == otherDivision.getUpperDivisionValue();
		}
		return false;
	}
	
	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof AddressDivision) {
			// we call isSameValues on the other object to defer to subclasses overriding that method in object o
			// in particular, if the other is IPv4/6/MAC/AddressSection, then we call the overridden isSameGrouping
			// in those classes which check for IPv4/6/MAC type/version.
			// Also, those other classes override equals to ensure flip doesn't go the other way
			AddressDivision other = (AddressDivision) o;
			return getBitCount() == other.getBitCount() && other.isSameValues(this);
		}
		return false;
	}
	
	//when divisionPrefixLen is null, isAutoSubnets has no effect
	protected static boolean isMaskCompatibleWithRange(long value, long upperValue, long maskValue, long maxValue) {
		if(value == upperValue || maskValue == maxValue || maskValue == 0) {
			return true;
		}

		//algorithm:
		//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
		//then we find the highest bit in the mask that is 1 that is the same or below highestDifferingBitInRange (if such a bit exists)
		
		//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
		//if this latter bit exists, then any bit below it in the mask must be 1 to include the entire range.
		
		long differing = value ^ upperValue;
		boolean foundDiffering = (differing != 0);
		boolean differingIsLowestBit = (differing == 1);
		if(foundDiffering && !differingIsLowestBit) {
			int highestDifferingBitInRange = Long.numberOfLeadingZeros(differing);
			long maskMask = ~0L >>> highestDifferingBitInRange;
			long differingMasked = maskValue & maskMask;
			foundDiffering = (differingMasked != 0);
			differingIsLowestBit = (differingMasked == 1);
			if(foundDiffering && !differingIsLowestBit) {
				//anything below highestDifferingBitMasked in the mask must be ones
				//Also, if we have masked out any 1 bit in the original, then anything that we do not mask out that follows must be all 1s
				int highestDifferingBitMasked = Long.numberOfLeadingZeros(differingMasked);
				long hostMask = ~0L >>> (highestDifferingBitMasked + 1);//for the first mask bit that is 1, all bits that follow must also be 1
				if((maskValue & hostMask) != hostMask) { //check if all ones below
					return false;
				}
				if(highestDifferingBitMasked > highestDifferingBitInRange) {
					//We have masked out a 1 bit, so we need to check that all bits in upper value that we do not mask out are also 1 bits, otherwise we end up missing values in the masked range
					//This check is unnecessary for prefix-length subnets, only non-standard ranges might fail this check.
					//For instance, if we have range 0000 to 1010
					//and we mask upper and lower with 0111
					//we get 0000 to 0010, but 0111 was in original range, and the mask of that value retains that value
					//so that value needs to be in final range, and it's not.
					//What went wrong is that we masked out the top bit, and any other bit that is not masked out must be 1.
					//To work, our original range needed to be 0000 to 1111, with the three 1s following the first masked-out 1
					long hostMaskUpper = ~0L >>> highestDifferingBitMasked;
					if((upperValue & hostMaskUpper) != hostMaskUpper) {
						return false;
					}
				}
			}
		}
		return true;
	}
	
	protected static boolean isBitwiseOrCompatibleWithRange(long value, long upperValue, long maskValue, long maxValue) {
		if(value == upperValue || maskValue == maxValue || maskValue == 0) {
			return true;
		}
		//algorithm:
		//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
		//then we find the highest bit in the mask that is 0 that is the same or below highestDifferingBitInRange (if such a bit exists)
		
		//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
		//if this latter bit exists, then any bit below it in the mask must be 0 to include the entire range.
		
		long differing = value ^ upperValue;
		boolean foundDiffering = (differing != 0);
		boolean differingIsLowestBit = (differing == 1);
		if(foundDiffering && !differingIsLowestBit) {
			int highestDifferingBitInRange = Long.numberOfLeadingZeros(differing);
			long maskMask = ~0L >>> highestDifferingBitInRange;
			long differingMasked = maskValue & maskMask;
			foundDiffering = (differingMasked != maskMask);
			differingIsLowestBit = ((differingMasked | 1) == maskMask);
			if(foundDiffering && !differingIsLowestBit) {
				//anything below highestDifferingBitMasked in the mask must be zeros 
				//Also, if we or'ed out any 0 bit in the original with a 1 in the mask, then anything that we do not mask out that follows must be all 0s
				int highestDifferingBitMasked = Long.numberOfLeadingZeros(~differingMasked & maskMask);
				long hostMask = ~0L >>> (highestDifferingBitMasked + 1);
				if((maskValue & hostMask) != 0) { //check if all zeros below
					return false;
				}
				if(highestDifferingBitMasked > highestDifferingBitInRange) {
					//we have or-ed out a 0 bit, so we need to check that all bits in lower value that we do not or out are also 0 bits, otherwise we end up missing values in the masked range
					//this is always true for prefix subnets, only non-standard ranges might fail here
					long hostMaskLower = ~0L >>> highestDifferingBitMasked;
					if((value & hostMaskLower) != 0) {
						return false;
					}
				}
			}
		}
		return true;
	}
	
	public boolean hasUppercaseVariations(int radix, boolean lowerOnly) {
		if(radix <= 1) {
			throw new IllegalArgumentException();
		}
		if(radix <= 10) {
			return false;
		}
		boolean isPowerOfTwo;
		int shift = 0;
		long mask = 0;
		switch(radix) {
			case 0x10://fast path for base 16
				isPowerOfTwo = true;
				shift = 4; //log2(base)
				mask = 0xf; //2^shift - 1
				break;
			default:
				isPowerOfTwo = (radix & (radix - 1)) == 0;
				if(isPowerOfTwo) {
					shift = Integer.numberOfTrailingZeros(radix);
					mask = ~(~0L << shift); //allBitSize must be 6 digits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
				}
		}
		boolean handledUpper = false;
		long value = getDivisionValue();
		do {
			while(value > 0) {
				long checkVal = isPowerOfTwo ? (mask & value) : (value % radix);
				if(checkVal >= 0xa) {
					return true;
				}
				if(isPowerOfTwo) {
					value >>>= shift;
				} else {
					value /= radix;
				}
			}
			if(handledUpper || lowerOnly) {
				break;
			}
			value = getUpperDivisionValue();
			handledUpper = true;
		} while(true);
		return false;
	}

	@Override
	public int getDigitCount(int radix) {
		if(!isMultiple() && radix == getDefaultTextualRadix()) {//optimization - just get the string, which is cached, which speeds up further calls to this or getString()
			return getWildcardString().length();
		}
		return getDigitCount(getUpperDivisionValue(), radix);
	}

	@Override
	public int getMaxDigitCount(int radix) {
		int defaultRadix = getDefaultTextualRadix();
		if(radix == defaultRadix) {
			return getMaxDigitCount();
		}
		return getMaxDigitCount(radix, getBitCount(), getMaxValue());
	}
	
	@Override
	protected int adjustLowerLeadingZeroCount(int leadingZeroCount, int radix) {
		return adjustLeadingZeroCount(leadingZeroCount, getDivisionValue(), radix);
	}
	
	@Override
	protected int adjustUpperLeadingZeroCount(int leadingZeroCount, int radix) {
		return adjustLeadingZeroCount(leadingZeroCount, getUpperDivisionValue(), radix);
	}
	
	private int adjustLeadingZeroCount(int leadingZeroCount, long value, int radix) {
		if(leadingZeroCount < 0) {
			int width = getDigitCount(value, radix);
			return Math.max(0, getMaxDigitCount(radix) - width);
		}
		return leadingZeroCount;
	}

	@Override
	protected String getWildcardString() {
		return super.getWildcardString();
	}
	
	@Override
	protected int getLowerStringLength(int radix) {
		return toUnsignedStringLength(getDivisionValue(), radix);
	}
	
	@Override
	protected int getUpperStringLength(int radix) {
		return toUnsignedStringLength(getUpperDivisionValue(), radix);
	}
	
	@Override
	protected void getLowerString(int radix, boolean uppercase, StringBuilder appendable) {
		toUnsignedString(getDivisionValue(), radix, 0, uppercase, uppercase ? UPPERCASE_DIGITS : DIGITS, appendable);
	}
	
	@Override
	protected void getUpperString(int radix, boolean uppercase, StringBuilder appendable) {
		toUnsignedString(getUpperDivisionValue(), radix, 0, uppercase, uppercase ? UPPERCASE_DIGITS : DIGITS, appendable);
	}
	
	@Override
	protected void getUpperStringMasked(int radix, boolean uppercase, StringBuilder appendable) {
		getUpperString(radix, uppercase, appendable);
	}
	
	@Override
	protected void getLowerString(int radix, int rangeDigits, boolean uppercase, StringBuilder appendable) {
		toUnsignedString(getDivisionValue(), radix, rangeDigits, uppercase, uppercase ? UPPERCASE_DIGITS : DIGITS, appendable);
	}
	
	@Override
	protected void getSplitLowerString(int radix, int choppedDigits, boolean uppercase, 
			char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix, StringBuilder appendable) {
		toSplitUnsignedString(getDivisionValue(), radix, choppedDigits, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable);
	}
	
	@Override
	protected void getSplitRangeString(String rangeSeparator, String wildcard, int radix, boolean uppercase, 
			char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix, StringBuilder appendable) {
		toUnsignedSplitRangeString(
			getDivisionValue(),
			getUpperDivisionValue(),
			rangeSeparator,
			wildcard,
			radix,
			uppercase, 
			splitDigitSeparator,
			reverseSplitDigits,
			stringPrefix,
			appendable);
	}
	
	@Override
	protected int getSplitRangeStringLength(String rangeSeparator, String wildcard, int leadingZeroCount, int radix, boolean uppercase, 
			char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix) {
		return toUnsignedSplitRangeStringLength(
			getDivisionValue(),
			getUpperDivisionValue(),
			rangeSeparator,
			wildcard,
			leadingZeroCount,
			radix,
			uppercase, 
			splitDigitSeparator,
			reverseSplitDigits,
			stringPrefix);
	}

	@Override
	protected String getDefaultLowerString() {
		return toDefaultString(getDivisionValue(), getDefaultTextualRadix());
	}
	
	@Override
	protected String getDefaultRangeString() {
		return getDefaultRangeString(getDivisionValue(), getUpperDivisionValue(), getDefaultTextualRadix());
	}

	protected String getDefaultRangeString(long val1, long val2, int radix) {
		int len1, len2, value1, value2, quotient, remainder; //we iterate on //value == quotient * radix + remainder
		if(radix == 10) {
			if(val2 < 10) {
				len2 = 1;
			} else if(val2 < 100) {
				len2 = 2;
			} else if(val2 < 1000) {
				len2 = 3;
			} else {
				return buildDefaultRangeString(radix);
			}
			value2 = (int) val2;
			if(val1 < 10) {
				len1 = 1;
			} else if(val1 < 100) {
				len1 = 2;
			} else if(val1 < 1000) {
				len1 = 3;
			} else {
				return buildDefaultRangeString(radix);
			}
			value1 = (int) val1;
			
			len2 += len1 + 1;
			char chars[] = new char[len2];
			chars[len1] = IPAddress.RANGE_SEPARATOR;
			char dig[] = DIGITS;
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
			if(val2 < 0x10) {
				len2 = 1;
			} else if(val2 < 0x100) {
				len2 = 2;
			} else if(val2 < 0x1000) {
				len2 = 3;
			} else if(val2 < 0x10000) {
				len2 = 4;
			} else {
				return buildDefaultRangeString(radix);
			}
			value2 = (int) val2;
			if(val1 < 0x10) {
				len1 = 1;
			} else if(val1 < 0x100) {
				len1 = 2;
			} else if(val1 < 0x1000) {
				len1 = 3;
			} else if(val1 < 0x10000) {
				len1 = 4;
			} else {
				return buildDefaultRangeString(radix);
			}
			value1 = (int) val1;
			len2 += len1 + 1;
			char chars[] = new char[len2];
			chars[len1] = IPAddress.RANGE_SEPARATOR;
			char dig[] = DIGITS;
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
		return buildDefaultRangeString(radix);
	}
	
	private String buildDefaultRangeString(int radix) {
		StringBuilder builder = new StringBuilder(20);
		getRangeString(IPAddress.RANGE_SEPARATOR_STR, 0, 0, "", radix, false, false, builder);
		return builder.toString();
	}
	
	protected static String toDefaultString(long val, int radix) {
		//0 and 1 are common segment values, and additionally they are the same regardless of radix (even binary)
		//so we have a fast path for them
		if(val == 0L) {
			return "0";
		}
		if(val == 1L) {
			return "1";
		}
		int len, quotient, remainder, value; //we iterate on //value == quotient * radix + remainder
		if(radix == 10) {
			if(val < 10) {
				return String.valueOf(DIGITS, (int) val, 1);
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
			char dig[] = DIGITS;
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
				return String.valueOf(DIGITS, (int) val, 1);
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
			char dig[] = DIGITS;
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
	
	protected static int toUnsignedStringLengthFast(int value, int radix) {
		return AddressDivisionBase.toUnsignedStringLength(value, radix);
	}

	private static int toUnsignedSplitRangeStringLength(
			long lower,
			long upper,
			String rangeSeparator,
			String wildcard,
			int leadingZerosCount,
			int radix,
			boolean uppercase, 
			char splitDigitSeparator,
			boolean reverseSplitDigits,
			String stringPrefix) {
		int digitsLength = -1;//we will count one too many split digit separators in here
		int stringPrefixLength = stringPrefix.length();
		do {
			int upperDigit = (int) (upper % radix);
			int lowerDigit = (int) (lower % radix);
			boolean isFull = (lowerDigit == 0) && (upperDigit == radix - 1);
			if(isFull) {
				digitsLength += wildcard.length() + 1;
			} else {
				//if not full range, they must not be the same either, otherwise they would be illegal for split range.
				//this is because we know whenever entering the loop that upper != lower, and we know this also means the least significant digits must differ.
				digitsLength += (stringPrefixLength << 1) + 4 /* 1 for each digit, 1 for range separator, 1 for split digit separator */;
			}
			upper /= radix;
			lower /= radix;
		} while(upper != lower);
		int remaining = (upper == 0) ? 0 : toUnsignedStringLength(upper, radix);
		remaining += leadingZerosCount;
		if(remaining > 0) {
			digitsLength += remaining * (stringPrefixLength + 2 /* one for each splitDigitSeparator, 1 for each digit */);
		}
		return digitsLength;
	}

	protected static BigInteger getRadixPower(BigInteger radix, int power) {
		return AddressDivisionBase.getRadixPower(radix, power);
	}
	
	
	
	

	private static void toSplitUnsignedString(
			long value,
			int radix,
			int choppedDigits,
			boolean uppercase, 
			char splitDigitSeparator,
			boolean reverseSplitDigits,
			String stringPrefix,
			StringBuilder appendable) {
		int front = appendable.length();
		appendDigits(value, radix, choppedDigits, uppercase, splitDigitSeparator, stringPrefix, appendable);
		if(!reverseSplitDigits) {
			int back = appendable.length() - 1;
			int stringPrefixLen = stringPrefix.length();
			front += stringPrefixLen;
			while(front < back) {
				char frontChar = appendable.charAt(front);
				appendable.setCharAt(front, appendable.charAt(back));
				appendable.setCharAt(back, frontChar);
				front += 2;
				back -= 2;
				front += stringPrefixLen;
				back -= stringPrefixLen;
			}
		}
	}
	
	private static void toUnsignedSplitRangeString(
			long lower,
			long upper,
			String rangeSeparator,
			String wildcard,
			int radix,
			boolean uppercase, 
			char splitDigitSeparator,
			boolean reverseSplitDigits,
			String stringPrefix,
			StringBuilder appendable) {
		//A split can be invalid.  Consider xxx.456-789.
		//The number 691, which is in the range 456-789, is not in the range 4-7.5-8.6-9
		//In such cases we throw IncompatibleAddressException
		//To avoid such cases, we must have lower digits covering the full range, for example 400-799 in which lower digits are both 0-9 ranges.
		//If we have 401-799 then 500 will not be included when splitting.
		//If we have 400-798 then 599 will not be included when splitting.
		//If we have 410-799 then 500 will not be included when splitting.
		//If we have 400-789 then 599 will not be included when splitting.
		int front = appendable.length();
		appendDigits(lower, upper, rangeSeparator, wildcard, radix, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable);
		if(!reverseSplitDigits) {
			int back = appendable.length() - 1;
			while(front < back) {
				char frontChar = appendable.charAt(front);
				appendable.setCharAt(front++, appendable.charAt(back));
				appendable.setCharAt(back--, frontChar);
			}
		}
	}

	private static void appendDigits(
			long value,
			int radix,
			int choppedDigits,
			boolean uppercase, 
			char splitDigitSeparator,
			String stringPrefix,
			StringBuilder appendable) {
		boolean useInts = value <= Integer.MAX_VALUE;
		int value2 = useInts ? (int) value : radix;
		char dig[] = uppercase ? UPPERCASE_DIGITS : DIGITS;
		int index;
		int prefLen = stringPrefix.length();
		while(value2 >= radix) {
			if(useInts) {
				int val = value2;
				value2 /= radix;
				if(choppedDigits > 0) {
					choppedDigits--;
					continue;
				}
				index = val % radix;
			} else {
				long val = value;
				value /= radix;
				if(value <= Integer.MAX_VALUE) {
					useInts = true;
					value2 = (int) value;
				}
				if(choppedDigits > 0) {
					choppedDigits--;
					continue;
				}
				index = (int) (val % radix);
			}
			if(prefLen > 0) {
				appendable.append(stringPrefix);
			}
			appendable.append(dig[index]);
			appendable.append(splitDigitSeparator);
		}
		if(choppedDigits == 0) {
			if(prefLen > 0) {
				appendable.append(stringPrefix);
			}
			appendable.append(dig[value2]);
		}
	}
	
	private static void appendDigits(
			long lower,
			long upper,
			String rangeSeparator,
			String wildcard,
			int radix,
			boolean uppercase, 
			char splitDigitSeparator,
			boolean reverseSplitDigits,
			String stringPrefix, 
			StringBuilder appendable) {
		char dig[] = uppercase ? UPPERCASE_DIGITS : DIGITS;
		boolean previousWasFullRange = true;
		boolean useInts = upper <= Integer.MAX_VALUE;
		int upperInt, lowerInt;
		if(useInts) {
			upperInt = (int) upper;
			lowerInt = (int) lower;
		} else {
			upperInt = lowerInt = radix;
		}
		int prefLen = stringPrefix.length();
		while(true) {
			int upperDigit, lowerDigit;
			if(useInts) {
				int ud = upperInt;
				upperDigit = upperInt % radix;
				upperInt /= radix;
				if(ud == lowerInt) {
					lowerInt = upperInt;
					lowerDigit = upperDigit;
				} else {
					lowerDigit = lowerInt % radix;
					lowerInt /= radix;
				}
			} else {
				long ud = upper;
				upperDigit = (int) (upper % radix);
				upper /= radix;
				if(ud == lower) {
					lower = upper;
					lowerDigit = upperDigit;
				} else {
					lowerDigit = (int) (lower % radix);
					lower /= radix;
				}
				if(upper <= Integer.MAX_VALUE) {
					useInts = true;
					upperInt = (int) upper;
					lowerInt = (int) lower;
				}
			}
			if(lowerDigit == upperDigit) {
				previousWasFullRange = false;
				if(reverseSplitDigits) {
					if(prefLen > 0) {
						appendable.append(stringPrefix);
					}
					appendable.append(dig[lowerDigit]);
				} else {
					//in this case, whatever we do here will be completely reversed following this method call
					appendable.append(dig[lowerDigit]);
					for(int k = prefLen - 1; k >= 0; k--) {
						appendable.append(stringPrefix.charAt(k));
					}
				}
			} else {
				if(!previousWasFullRange) {
					throw new IncompatibleAddressException(lower, upper, "ipaddress.error.splitMismatch");
				}
				previousWasFullRange = (lowerDigit == 0) && (upperDigit == radix - 1);
				if(previousWasFullRange && wildcard != null) {
					if(reverseSplitDigits) {
						appendable.append(wildcard);
					} else {
						//in this case, whatever we do here will be completely reversed following this method call
						for(int k = wildcard.length() - 1; k >= 0; k--) {
							appendable.append(wildcard.charAt(k));
						}
					}
				} else {
					if(reverseSplitDigits) {
						if(prefLen > 0) {
							appendable.append(stringPrefix);
						}
						appendable.append(dig[lowerDigit]);
						appendable.append(rangeSeparator);
						appendable.append(dig[upperDigit]);
					} else {
						//in this case, whatever we do here will be completely reversed following this method call
						appendable.append(dig[upperDigit]);
						appendable.append(rangeSeparator);
						appendable.append(dig[lowerDigit]);
						for(int k = prefLen - 1; k >= 0; k--) {
							appendable.append(stringPrefix.charAt(k));
						}
					}
				}
			}
			if(upperInt == 0) {
				break;
			}
			appendable.append(splitDigitSeparator);
		}
	}

	@Override
	protected int getRangeDigitCount(int radix) {
		if(!isMultiple()) {
			return 0;
		}
		if(radix == getDefaultTextualRadix()) {
			return getRangeDigitCountImpl();
		}
		return calculateRangeDigitCount(radix, getDivisionValue(), getUpperDivisionValue(), getMaxValue());
	}
	
	protected int getRangeDigitCountImpl() {
		return calculateRangeDigitCount(getDefaultTextualRadix(), getDivisionValue(), getUpperDivisionValue(), getMaxValue());
	}

	private static int calculateRangeDigitCount(int radix, long value, long upperValue, long maxValue) {
		int factor = radix;
		int numDigits = 1;
		while(true) {
			long lowerRemainder = value % factor;
			if(lowerRemainder == 0) {
				//Consider in ipv4 the segment 24_  
				//what does this mean?  It means 240 to 249 (not 240 to 245)
				//Consider 25_.  It means 250-255.
				//so the last digit ranges between 0-5 or 0-9 depending on whether the front matches the max possible front of 25.
				//If the front matches, the back ranges from 0 to the highest value of 255.
				//if the front does not match, the back must range across all values for the radix (0-9)
				long max = (maxValue / factor == upperValue / factor) ? maxValue % factor : factor - 1;
				long upperRemainder = upperValue % factor;
				if(upperRemainder == max) {
					//whatever range there is must be accounted entirely by range digits, otherwise the range digits is 0
					//so here we check if that is the case
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
	
	protected static int reverseBits(byte b) {
		int x = b;
		x = ((x & 0xaa) >>> 1) | ((x & 0x55) << 1);
		x = ((x & 0xcc) >>> 2) | ((x & 0x33) << 2);
		x = (0xff & ((x >>> 4) | (x << 4)));
		return x;
	}
	
	protected static int reverseBits(short b) {
		int x = b;
		x = ((x & 0xaaaa) >>> 1) | ((x & 0x5555) << 1);
		x = ((x & 0xcccc) >>> 2) | ((x & 0x3333) << 2);
		x = ((x & 0xf0f0) >>> 4) | ((x & 0x0f0f) << 4);
		return 0xffff & ((x >>> 8) | (x << 8));
	}
	
	protected static int reverseBits(int i) {
		int x = i;
		x = ((x & 0xaaaaaaaa) >>> 1) | ((x & 0x55555555) << 1);
		x = ((x & 0xcccccccc) >>> 2) | ((x & 0x33333333) << 2);
		x = ((x & 0xf0f0f0f0) >>> 4) | ((x & 0x0f0f0f0f) << 4);
		x = ((x & 0xff00ff00) >>> 8) | ((x & 0x00ff00ff) << 8);
		return (x >>> 16) | (x << 16);
	}
	
	protected static <S extends AddressSegment> Iterator<S> identityIterator(S original) {
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
		    	return original;
	    	}
	
		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}
		
	protected static <S extends AddressSegment> Iterator<S> iterator(
			S original,
			AddressSegmentCreator<S> creator,
			//Even though a segment represents a single value, it still might have a prefix extending to the end of the segment
	    	//Iterators may or may not return prefixed segments matching the original prefix of the segment
			boolean prefixMatchesIteratorPrefix,
			Integer segmentPrefixLength,
			boolean isPrefixIterator,
			boolean isBlockIterator) {
		int shiftAdjustment, shiftMask, upperShiftMask;
		int originalLower = original.getSegmentValue();
		int originalUpper = original.getUpperSegmentValue();
		if(isPrefixIterator) {
			shiftAdjustment = original.getBitCount() - segmentPrefixLength;
			if(shiftAdjustment > 0) {
				shiftMask = ~0 << shiftAdjustment;
				upperShiftMask = ~shiftMask;
			} else {
				isPrefixIterator = false;
				shiftMask = upperShiftMask = 0;
			}
		} else {
			shiftAdjustment = shiftMask = upperShiftMask = 0;
		}
		boolean isPrefixI = isPrefixIterator;
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
			    	S result;
			    	if(isPrefixI) {
			    		result = creator.createSegment(originalLower & shiftMask, originalLower | upperShiftMask, segmentPrefixLength);
			    	} else if(prefixMatchesIteratorPrefix) {
			    		return original;
			    	} else {
			    		result = creator.createSegment(originalLower, originalUpper, segmentPrefixLength);
			    	}
			    	return result;
			    }
		
			    @Override
				public void remove() {
			    	throw new UnsupportedOperationException();
			    }
			};
		}
		return new Iterator<S>() {
			private boolean notDone = true, notFirst;
			private int current = originalLower, last = originalUpper; {
				if(isPrefixI) {
					current >>>= shiftAdjustment;
					last >>>= shiftAdjustment;
				}
			}
			
			@Override
			public boolean hasNext() {
				return notDone;
			}
		
		    @Override
			public S next() {
		    	if(!notDone) {
		    		throw new NoSuchElementException();
		    	}
		    	S result;
		    	if(isPrefixI) {
		    		int cur = current;
		    		int blockLow = cur << shiftAdjustment;
		    		int blockHigh = blockLow | upperShiftMask;
		    		current = ++cur;
		    		boolean notD = cur <= last;
		    		if(isBlockIterator) {
		    			result = creator.createSegment(blockLow, blockHigh, segmentPrefixLength);
		    			if(!notD) {
		    				notDone = false;
		    			}
		    		} else if(notD && notFirst) {
		    			result = creator.createSegment(blockLow, blockHigh, segmentPrefixLength);
		    		} else if (notD) {
		    			result = creator.createSegment(originalLower, blockHigh, segmentPrefixLength);
		    			notFirst = true;
		    		} else {
		    			notDone = false;
		    			if (notFirst) {
			    			result = creator.createSegment(blockLow, originalUpper, segmentPrefixLength);
			    		} else {
			    			result = creator.createSegment(originalLower, originalUpper, segmentPrefixLength);
			    		}
		    		}
		    	} else {
		    		result = creator.createSegment(current, segmentPrefixLength);
		    		notDone = ++current <= last;
		    	}
		    	return result;
		    }
		
		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}
	
	protected static <S extends AddressSegment> S setPrefixedSegment(
			S original,
			Integer oldSegmentPrefixLength,
			Integer newSegmentPrefixLength,
			boolean zeroed,
			AddressSegmentCreator<S> creator) {
		if(Objects.equals(oldSegmentPrefixLength, newSegmentPrefixLength)) {
			return original;
		}
		int newLower, newUpper;
		if(zeroed) {
			int prefixMask;
			int bitCount = original.getBitCount();
			int allOnes = ~0;
			if(oldSegmentPrefixLength != null) {
				if(newSegmentPrefixLength == null) {
					prefixMask = allOnes << (bitCount - oldSegmentPrefixLength);
				} else if(oldSegmentPrefixLength > newSegmentPrefixLength) {
					prefixMask = allOnes << (bitCount - newSegmentPrefixLength);
					prefixMask |= ~(allOnes << (bitCount - oldSegmentPrefixLength));
				} else {
					prefixMask = allOnes << (bitCount - oldSegmentPrefixLength);
					prefixMask |= ~(allOnes << (bitCount - newSegmentPrefixLength));
				}
			} else {
				//we know newSegmentPrefixLength != null
				prefixMask = allOnes << (bitCount - newSegmentPrefixLength);
			}
			newLower = original.getSegmentValue() & prefixMask;
			newUpper = original.getUpperSegmentValue() & prefixMask;
		} else {
			newLower = original.getSegmentValue();
			newUpper = original.getUpperSegmentValue();
		}
		return creator.createSegment(newLower, newUpper, newSegmentPrefixLength);
	}
	
	protected static <S extends AddressSegment> boolean isReversibleRange(S segment) {
		//consider the case of reversing the bits or a range
		//Any range that can be successfully reversed must span all bits (otherwise after flipping you'd have a range in which the lower bit is constant, which is impossible in any contiguous range)
		//So that means at least one value has 0xxxx and another has 1xxxx (using 5 bits for our example). This means you must have the values 01111 and 10000 since the range is contiguous.
		//But reversing a range twice results in the original again, meaning the reversed must also be reversible, so the reversed also has 01111 and 10000.
		//So this means both the original and the reversed also have those two patterns flipped, which are 00001 and 11110.
		//So this means both ranges must span from at most 1 to at least 11110.  
		//However, the two remaining values, 0 and 11111, are optional, as they are boundary value and remain themselves when reversed, and hence have no effect on whether the reversed range is contiguous.
		//So the only reversible ranges are 0-11111, 0-11110, 1-11110, and 1-11111.
		
		//-----------------------
		//Consider the case of reversing the bytes of a range.
		//Any range that can be successfully reversed must span all bits 
		//(otherwise after flipping you'd have a range in which a lower bit is constant, which is impossible in any contiguous range)
		//So that means at least one value has 0xxxxx and another has 1xxxxx (we use 6 bits for our example, and we assume each byte has 3 bits). 
		//This means you must have the values 011111 and 100000 since the range is contiguous.
		//But reversing a range twice results in the original again, meaning the reversed must also be reversible, so the reversed also has 011111 and 100000.
		
		//So this means both the original and the reversed also have those two patterns flipped, which are 111011 and 000100.
		//So the range must have 000100, 011111, 100000, 111011, so it must be at least 000100 to 111011.
		//So what if the range does not have 000001?  then the reversed range cannot have 001000, the reversed address.  But we know it spans 000100 to 111011.
		//So the original must have 000001.  
		//What if it does not have 111110?  Then the reversed cannot have 110111.  But we know it ranges from 000100 to 111011.  So the original must have 111110.
		//But once again, the two remaining values are optional, so we have the same potential ranges: 0-111111, 0-111110, 1-111110, and 1-111111
		return segment.getSegmentValue() <= 1 && segment.getUpperSegmentValue() >= segment.getMaxSegmentValue() - 1;
	}
}
