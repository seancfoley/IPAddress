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

package inet.ipaddr.format;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.NoSuchElementException;

import inet.ipaddr.Address;
import inet.ipaddr.AddressNetwork.AddressSegmentCreator;
import inet.ipaddr.AddressSegment;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.IPAddress;

/**
 * A division of an address.
 * 
 * @author sfoley
 *
 */
public abstract class AddressDivision extends AddressDivisionBase implements Comparable<AddressDivision> {

	private static final long serialVersionUID = 4L;

	protected AddressDivision() {}

	@Override
	protected byte[] getBytesImpl(boolean low) {
		int bitCount = getBitCount();
		byte bytes[] = new byte[(bitCount + 7) >> 3];
		int byteIndex = bytes.length - 1, bitIndex = 8;
		long segmentValue = low ? getLowerValue() : getUpperValue();
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
		return getLowerValue() != getUpperValue();
	}
	
	protected int getMinPrefixLengthForBlock() {
		int result = getBitCount();
		int lowerZeros = Long.numberOfTrailingZeros(getLowerValue());
		if(lowerZeros != 0) {
			int upperOnes = Long.numberOfTrailingZeros(~getUpperValue());
			if(upperOnes != 0) {
				int prefixedBitCount = Math.min(lowerZeros, upperOnes);
				result -= prefixedBitCount;
			}
		}
		return result;
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
		return getLowerValue() == 0L;
	}
	
	@Override
	public boolean isMax() {
		return !isMultiple() && includesMax();
	}
	
	@Override
	public boolean includesMax() {
		return getUpperValue() == getMaxValue();
	}
	
	public abstract long getLowerValue();
	
	public abstract long getUpperValue();
	
	public long getDivisionValueCount() {
		return getUpperValue() - getLowerValue() + 1;
	}
	
	@Override
	public BigInteger getCount() {
		return BigInteger.valueOf(getDivisionValueCount());
	}
	
	/**
	 * Returns true if the possible values of this division fall below the given value.
	 */
	@Override
	public boolean isBoundedBy(int value) {
		return getUpperValue() < value;
	}
	
	public boolean matches(long value) {
		return !isMultiple() && value == getLowerValue();
	}
	
	public boolean matchesWithMask(long value, long mask) {
		if(isMultiple()) {
			//we want to ensure that any of the bits that can change from value to upperValue is masked out (zeroed) by the mask.
			//In other words, when masked we need all values represented by this segment to become just a single value
			long diffBits = getLowerValue() ^ getUpperValue();
			int leadingZeros = Long.numberOfLeadingZeros(diffBits);
			//the bits that can change are all bits following the first leadingZero bits
			//all the bits that follow must be zeroed out by the mask
			long fullMask = ~0L >>> leadingZeros;
			if((fullMask & mask) != 0L) {
				return false;
			} //else we know that the mask zeros out all the bits that can change from value to upperValue, so now we just compare with either one
		}
		return value == (getLowerValue() & mask);
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
		long thisValue = getLowerValue();
		long thisUpperValue = getUpperValue();
		if(!isMaskCompatibleWithRange(thisValue, thisUpperValue, mask, getMaxValue())) {
			return false;
		}
		return lowerValue == (thisValue & mask) && upperValue == (thisUpperValue & mask);
	}
	
	protected abstract boolean isSameValues(AddressDivision other);
	
	@Override
	public boolean isFullRange() {
		return includesZero() && includesMax();
	}
	
	@Override
	public int compareTo(AddressDivision other) {
		return IPAddress.DEFAULT_ADDRESS_COMPARATOR.compare(this, other);
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
		long value = getLowerValue();
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
			value = getUpperValue();
			handledUpper = true;
		} while(true);
		return false;
	}

	@Override
	public int getDigitCount(int radix) {
		if(!isMultiple() && radix == getDefaultTextualRadix()) {//optimization - just get the string, which is cached, which speeds up further calls to this or getString()
			return getWildcardString().length();
		}
		return getDigitCount(getUpperValue(), radix);
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
		return adjustLeadingZeroCount(leadingZeroCount, getLowerValue(), radix);
	}
	
	@Override
	protected int adjustUpperLeadingZeroCount(int leadingZeroCount, int radix) {
		return adjustLeadingZeroCount(leadingZeroCount, getUpperValue(), radix);
	}
	
	private int adjustLeadingZeroCount(int leadingZeroCount, long value, int radix) {
		if(leadingZeroCount < 0) {
			int width = getDigitCount(value, radix);
			return Math.max(0, getMaxDigitCount(radix) - width);
		}
		return leadingZeroCount;
	}

	@Override
	protected int getLowerStringLength(int radix) {
		return toUnsignedStringLength(getLowerValue(), radix);
	}
	
	@Override
	protected int getUpperStringLength(int radix) {
		return toUnsignedStringLength(getUpperValue(), radix);
	}
	
	@Override
	protected void getLowerString(int radix, boolean uppercase, StringBuilder appendable) {
		toUnsignedString(getLowerValue(), radix, 0, uppercase, uppercase ? UPPERCASE_DIGITS : DIGITS, appendable);
	}
	
	@Override
	protected void getUpperString(int radix, boolean uppercase, StringBuilder appendable) {
		toUnsignedString(getUpperValue(), radix, 0, uppercase, uppercase ? UPPERCASE_DIGITS : DIGITS, appendable);
	}
	
	@Override
	protected void getUpperStringMasked(int radix, boolean uppercase, StringBuilder appendable) {
		getUpperString(radix, uppercase, appendable);
	}
	
	@Override
	protected void getLowerString(int radix, int rangeDigits, boolean uppercase, StringBuilder appendable) {
		toUnsignedString(getLowerValue(), radix, rangeDigits, uppercase, uppercase ? UPPERCASE_DIGITS : DIGITS, appendable);
	}
	
	@Override
	protected void getSplitLowerString(int radix, int choppedDigits, boolean uppercase, 
			char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix, StringBuilder appendable) {
		toSplitUnsignedString(getLowerValue(), radix, choppedDigits, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable);
	}
	
	@Override
	protected void getSplitRangeString(String rangeSeparator, String wildcard, int radix, boolean uppercase, 
			char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix, StringBuilder appendable) {
		toUnsignedSplitRangeString(
			getLowerValue(),
			getUpperValue(),
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
			getLowerValue(),
			getUpperValue(),
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
	protected String getDefaultString() {
		return toDefaultString(getLowerValue(), getDefaultTextualRadix());
	}
	
	@Override
	protected String getDefaultRangeString() {
		return getDefaultRangeString(getLowerValue(), getUpperValue(), getDefaultTextualRadix());
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
	
	private static boolean toUnsignedStringFast(int value, int radix, int choppedDigits, boolean uppercase, char dig[], StringBuilder appendable) {
		if(toUnsignedStringFast(value, radix, uppercase, dig, appendable)) {
			if(choppedDigits > 0) {
				appendable.setLength(appendable.length() - choppedDigits);
			}
			return true;
		}
		return false;
	}

	private static boolean toUnsignedStringFast(int value, int radix, boolean uppercase, char dig[], StringBuilder appendable) {
		if(value <= 1) {//for values larger than 1, result can be different with different radix (radix is 2 and up)
			if(value == 0) {
				appendable.append('0');
			} else {
				appendable.append('1');
			}
			return true;
		}
		int quotient, remainder; //we iterate on //value == quotient * radix + remainder
		if(radix == 10) {
			//this needs value2 <= 0xffff (ie 16 bits or less)
			if(value < 10) {
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
				appendable.append(dig[value]);
				return true;
			} else if(value < 0x10) {
				appendable.append(dig[value]);
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
			do {//value2 == quotient * 16 + remainder
				quotient = value >>> 4;
				remainder = value - (quotient << 4);
				appendable.setCharAt(--index, dig[remainder]);
				value = quotient;
			} while(value != 0);
			return true;
		}
		if(radix == 8) {
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
			while(digitCount > 0) {
				char c = dig[(value >>> --digitCount) & 1];
				appendable.append(c);
			}
			return true;
		}
		return false;
	}

	protected static StringBuilder toUnsignedString(long value, int radix, int choppedDigits, boolean uppercase, char dig[], StringBuilder appendable) {
		if(value > 0xffff || !toUnsignedStringFast((int) value, radix, choppedDigits, uppercase, dig, appendable)) {
			toUnsignedString(value, radix, choppedDigits, dig, appendable);
		}
		return appendable;
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

	protected static int toUnsignedStringLength(long value, int radix) {
		int result;
		if(value > 0xffff || (result = toUnsignedStringLengthFast((int) value, radix)) < 0) {
			result = toUnsignedStringLengthSlow(value, radix);
		}
		return result;
	}
	
	private static int toUnsignedStringLengthSlow(long value, int radix) {
		int count = 1;
		boolean useInts = value <= Integer.MAX_VALUE;
		int value2 = useInts ? (int) value : radix;
		while(value2 >= radix) {
			if(useInts) {
				value2 /= radix;
			} else {
				value /= radix;
				if(value <= Integer.MAX_VALUE) {
					useInts = true;
					value2 = (int) value;
				}
			}
			++count;
		}
		return count;
	}
	
	protected static int toUnsignedStringLengthFast(int value, int radix) {
		if(value <= 1) {//for values larger than 1, result can be different with different radix (radix is 2 and up)
			return 1;
		}
		if(radix == 10) {
			//this needs value <= 0xffff (ie 16 bits or less) which is a prereq to calling this method
			if(value < 10) {
				return 1;
			} else if(value < 100) {
				return 2;
			} else if(value < 1000) {
				return 3;
			} else if(value < 10000) {
				return 4;
			}
			return 5;
	    }
		if(radix == 16) {
			//this needs value <= 0xffff (ie 16 bits or less)
			if(value < 0x10) {
				return 1;
			} else if(value < 0x100) {
				return 2;
			} else if(value < 0x1000) {
				return 3;
			}
			return 4;
		}
		if(radix == 8) {
			//this needs value <= 0xffff (ie 16 bits or less)
			if(value < 010) {
				return 1;
			} else if(value < 0100) {
				return 2;
			} else if(value < 01000) {
				return 3;
			} else if(value < 010000) {
				return 4;
			} else if(value < 0100000) {
				return 5;
			}
			return 6;
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
			if((val & 2) != 0) {
				++digitCount;
			}
			return digitCount;
		}
		return -1;
	}
	
	private static void toUnsignedString(
			long value,
			int radix,
			int choppedDigits,
			char dig[],
			StringBuilder appendable) {
		int front = appendable.length();
		appendDigits(value, radix, choppedDigits, dig, appendable);
		int back = appendable.length() - 1;
		while(front < back) {
			char frontChar = appendable.charAt(front);
			appendable.setCharAt(front++, appendable.charAt(back));
			appendable.setCharAt(back--, frontChar);
		}
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
			char dig[],
			StringBuilder appendable) {
		boolean useInts = value <= Integer.MAX_VALUE;
		int value2 = useInts ? (int) value : radix;
		int index;
		while(value2 >= radix) {
			if(useInts) {
				int val2 = value2;
				value2 /= radix;
				if(choppedDigits > 0) {
					choppedDigits--;
					continue;
				}
				index = val2 % radix;
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
			appendable.append(dig[index]);
		}
		if(choppedDigits == 0) {
			appendable.append(dig[value2]);
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
	
	protected static <S extends AddressSegment> Iterator<S> iterator(S original, AddressSegmentCreator<S> creator, boolean returnThisSegment) {
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
			    	
			    	//Even though a segment represents a single value, it still might have a prefix extending to the end of the segment
			    	//Iterators must return non-prefixed segments.
			    	//This is required by the IPAddressSection iterator which uses an array of segment iterators.
			    	//If the segments at the end with prefixes of 0 iterate through all values with no prefix, 
			    	//then so must the preceding segment with a non-zero prefix,
			    	//even if that non-zero prefix extends to the end of the segment.
		    		if(!returnThisSegment) {
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
	
	protected static <S extends AddressSegment> S setPrefixedSegment(S original, Integer oldPrefixLength, Integer segmentPrefixLength, AddressSegmentCreator<S> creator) {
		if(oldPrefixLength == null) {
			return creator.createSegment(original.getLowerSegmentValue(), original.getUpperSegmentValue(), segmentPrefixLength);
		}
		if(segmentPrefixLength == null || segmentPrefixLength > oldPrefixLength) {
			//zero out the bits between old and new
			int prefixMask = ~0 << (original.getBitCount() - oldPrefixLength);
			if(segmentPrefixLength != null) {
				int newPrefixMask = ~(~0 << (original.getBitCount() - segmentPrefixLength));
				prefixMask |= newPrefixMask;
			}
			int newLower = original.getLowerSegmentValue() & prefixMask;
			int newUpper = original.getUpperSegmentValue() & prefixMask;
			return creator.createSegment(newLower, newUpper, segmentPrefixLength);
		}
		return creator.createSegment(original.getLowerSegmentValue(), original.getUpperSegmentValue(), segmentPrefixLength);
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
		return segment.getLowerSegmentValue() <= 1 && segment.getUpperSegmentValue() >= segment.getMaxSegmentValue() - 1;
	}
}
