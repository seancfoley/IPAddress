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
import java.util.Arrays;

import inet.ipaddr.Address;
import inet.ipaddr.AddressTypeException;
import inet.ipaddr.format.util.AddressSegmentParams;

/**
 * This class supports a segment of an arbitrary number of bits.
 * 
 * For a bit count less than or equal to 63 bits, AddressDivision is a more efficient choice.
 * 
 * @author sfoley
 *
 */
public class AddressLargeDivision extends AddressDivisionBase {

	private static BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);
	
	public static final char EXTENDED_DIGITS_RANGE_SEPARATOR = Address.ALTERNATIVE_RANGE_SEPARATOR;
	public static final String EXTENDED_DIGITS_RANGE_SEPARATOR_STR = String.valueOf(EXTENDED_DIGITS_RANGE_SEPARATOR);
	
	public static final char[] EXTENDED_DIGITS = {
			 '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 
			 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 
			 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 
			 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 
			 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 
			 'y', 'z', '!', '#', '$', '%', '&', '(', ')', '*', '+', '-', 
			 ';', '<', '=', '>', '?', '@', '^', '_', '`', '{', '|', '}', 
			 '~' };
	
	private static final long serialVersionUID = 3L;
	
	private final BigInteger value, upperValue, maxValue, upperValueMasked;
	private final BigInteger defaultRadix;//we keep radix as a big integer because some operations required it, but we only support integer radices so it can be converted via BigInteger.intValue() at any time
	private final int bitCount;
	private final Integer networkPrefixLength;
	private final boolean isRangeEquivalentToPrefix;
	
	public AddressLargeDivision(
			byte bytes[], byte upperBytes[], int bitCount, int defaultRadix, Integer networkPrefixLength) {
		this.bitCount = bitCount;
		this.defaultRadix = BigInteger.valueOf(defaultRadix);
		boolean isUpperMasked = networkPrefixLength == null;
		boolean isRangeEquivalentToPrefix;
		byte maskedBytes[] = null;
		if(!isUpperMasked) {
			int shift = bitCount - networkPrefixLength;
			int byteIndex = (shift + 7) / 8;
			int mask = ~0 << (shift % 8);
			bytes[byteIndex] &= mask;
			isUpperMasked = bytes == upperBytes;
			isRangeEquivalentToPrefix = isUpperMasked;
			if(!isUpperMasked) {
				byte upper = upperBytes[byteIndex];
				byte newUpper = (byte) (upper & mask);
				isUpperMasked = newUpper == upper;
				isRangeEquivalentToPrefix = newUpper == (bytes[byteIndex] & mask);
				if(isRangeEquivalentToPrefix) {
					for(int i = byteIndex - 1; i >= 0; i--) {
						if(bytes[i] != upperBytes[i]) {
							isRangeEquivalentToPrefix = false;
							break;
						}
					}
				}
				
				if(isUpperMasked) {
					for(int i = byteIndex; i < upperBytes.length; i++) {
						if(bytes[i] != 0) {
							isUpperMasked = false;
							break;
						}
					}
				}
				if(!isUpperMasked) {
					maskedBytes = Arrays.copyOf(upperBytes, upperBytes.length);
					maskedBytes[byteIndex] = newUpper;
					Arrays.fill(maskedBytes, byteIndex + 1, maskedBytes.length, (byte) 0);
				}
			}
		} else {
			isRangeEquivalentToPrefix = true;
			if(bytes != upperBytes) {
				for(int i = bytes.length - 1; i >= 0; i--) {
					if(bytes[i] != upperBytes[i]) {
						isRangeEquivalentToPrefix = false;
						break;
					}
				}
			}
		}
		this.isRangeEquivalentToPrefix = isRangeEquivalentToPrefix;
		upperValue = new BigInteger(1, upperBytes);
		upperValueMasked = isUpperMasked ? upperValue : new BigInteger(1, maskedBytes);
		value = (bytes == upperBytes) ? upperValue : new BigInteger(1, bytes);
		maxValue = getMaxValue(bitCount);
		this.networkPrefixLength = networkPrefixLength;
	}
	
	public AddressLargeDivision(byte bytes[], int bitCount, int defaultRadix, Integer prefix) {
		this(bytes, bytes, bitCount, defaultRadix, prefix);
	}

	@Override
	public boolean isBoundedBy(int val) {
		BigInteger bigVal = BigInteger.valueOf(val);
		return upperValue.compareTo(bigVal) < 0;
	}

	@Override
	public int getDigitCount(int radix) {
		if(!isMultiple() && radix == getDefaultTextualRadix()) {//optimization - just get the string, which is cached, which speeds up further calls to this method or getString()
			return getString().length();
		}
		return getDigitCountStatic(upperValue, radix);
	}

	@Override
	public BigInteger getCount() {
		return upperValue.subtract(value).add(BigInteger.ONE);
	}

	@Override
	public int getBitCount() {
		return bitCount;
	}

	@Override
	public boolean isMultiple() {
		return !value.equals(upperValue);
	}

	@Override
	public boolean isZero() {
		return value.equals(BigInteger.ZERO) && !isMultiple();
	}

	@Override
	public boolean isFullRange() {
		return value.equals(BigInteger.ZERO) && upperValue.equals(maxValue);
	}

	@Override
	protected byte[] getBytesImpl(boolean low) {
		return low ? value.toByteArray() : upperValue.toByteArray();
	}

	@Override
	public int getDefaultTextualRadix() {
		return defaultRadix.intValue();
	}

	@Override
	public int getMaxDigitCount() {
		return getMaxDigitCount(defaultRadix.intValue(), bitCount, maxValue);
	}

	@Override
	public int getMaxDigitCount(int radix) {
		return getMaxDigitCount(radix, bitCount, maxValue);
	}

	@Override
	protected int adjustLowerLeadingZeroCount(int leadingZeroCount, int radix) {
		return adjustLeadingZeroCount(leadingZeroCount, value, radix);
	}

	@Override
	protected int adjustUpperLeadingZeroCount(int leadingZeroCount, int radix) {
		return adjustLeadingZeroCount(leadingZeroCount, upperValue, radix);
	}
	
	private int adjustLeadingZeroCount(int leadingZeroCount, BigInteger value, int radix) {
		if(leadingZeroCount < 0) {
			int width = getDigitCount(value, radix);
			return Math.max(0, getMaxDigitCount(radix) - width);
		}
		return leadingZeroCount;
	}
	
	private int getDigitCount(BigInteger val, int radix) {
		BigInteger bigRadix = defaultRadix.intValue() == radix ? defaultRadix : BigInteger.valueOf(radix);
		return getDigitCount(val, bigRadix);
	}
	
	private static int getDigitCountStatic(BigInteger val, int radix) {
		return getDigitCount(val, BigInteger.valueOf(radix));
	}
	
	private String toDefaultString(BigInteger val, int radix, boolean uppercase, int choppedDigits) {
		BigInteger bigRadix = defaultRadix.intValue() == radix ? defaultRadix : BigInteger.valueOf(radix);
		return toDefaultString(val, bigRadix, uppercase, choppedDigits, getMaxDigitCount(radix, bitCount, null));
	}

	private static void toDefaultStringRecursive(BigInteger val, BigInteger radix, boolean uppercase, int choppedDigits, int digitCount, char dig[], boolean highest, StringBuilder builder) {
		//if we ensure that our recursion always defers to the most significant digits first, then we can simply append to a string builder
		if(val.compareTo(LONG_MAX) <= 0) {
			long longVal = val.longValue();
			int intRadix = radix.intValue();
			if(!highest) {
				getLeadingZeros(digitCount - AddressDivision.toUnsignedStringLength(longVal, intRadix), builder);
			}
			AddressDivision.toUnsignedString(longVal, intRadix, choppedDigits, uppercase, dig, builder);
		} else {
			int halfCount = digitCount >>> 1;
			if(halfCount > choppedDigits) {
				BigInteger radixPower = getRadixPower(radix, halfCount);
				BigInteger highLow[] = val.divideAndRemainder(radixPower);
				BigInteger high = highLow[0];
				BigInteger low = highLow[1];
				if(highest && high.equals(BigInteger.ZERO)) {
					toDefaultStringRecursive(low, radix, uppercase, choppedDigits, halfCount, dig, true, builder);
				} else {
					if(digitCount > choppedDigits) {
						toDefaultStringRecursive(high, radix, uppercase, Math.max(0,  choppedDigits - halfCount), digitCount - halfCount, dig, highest, builder);
					}
					toDefaultStringRecursive(low, radix, uppercase, choppedDigits, halfCount, dig, false, builder);
				}
			}
		}
	}
	
	private boolean isExtendedDigits() {
		return isExtendedDigits(defaultRadix.intValue());
	}
	
	private static boolean isExtendedDigits(int radix) {
		return radix > 36;
	}
	
	private static char[] getDigits(int radix, boolean uppercase) {
		if(isExtendedDigits(radix)) {
			return EXTENDED_DIGITS;
		}
		return uppercase ? UPPED_DIGITS : DIGITS;
	}
	
	private static String toDefaultString(BigInteger val, BigInteger radix, boolean uppercase, int choppedDigits, int maxDigits) {
		if(val.equals(BigInteger.ZERO)) {
			return "0";
		}
		if(val.equals(BigInteger.ONE)) {
			return "1";
		}
		char dig[] = getDigits(radix.intValue(), uppercase);
		StringBuilder builder = new StringBuilder();
		if(maxDigits > 0) {//maxDigits is 0 or less if the max digits is unknown
			if(maxDigits > choppedDigits) {
				toDefaultStringRecursive(val, radix, uppercase, choppedDigits, maxDigits, dig, true, builder);
			}
		} else {
			do {//value2 == quotient * 16 + remainder
				BigInteger divisorRemainder[] = val.divideAndRemainder(radix);
				BigInteger quotient = divisorRemainder[0];
				BigInteger remainder = divisorRemainder[1];
				if(choppedDigits > 0) {
					--choppedDigits;
					continue;
				}
				builder.append(dig[remainder.intValue()]);
				val = quotient;
			} while(!val.equals(BigInteger.ZERO));
			builder.reverse();
		}
		return builder.toString();
	}

	@Override
	protected String getDefaultString() {
		return toDefaultString(value, defaultRadix, false, 0, getMaxDigitCount());
	}

	@Override
	protected String getDefaultRangeString() {
		return toDefaultString(value, defaultRadix, false, 0, getMaxDigitCount()) + 
				getDefaultRangeSeparatorString() + 
				toDefaultString(upperValue, defaultRadix, false, 0, getMaxDigitCount());
	}
	
	@Override
	protected String getDefaultSegmentWildcardString() {
		return isExtendedDigits() ? null : Address.SEGMENT_WILDCARD_STR;
	}
	
	@Override
	protected String getDefaultRangeSeparatorString() {
		return isExtendedDigits()  ? EXTENDED_DIGITS_RANGE_SEPARATOR_STR : Address.RANGE_SEPARATOR_STR;
	}

	@Override
	protected int getLowerStringLength(int radix) {
		return getDigitCount(value, defaultRadix);
	}

	@Override
	protected int getUpperStringLength(int radix) {
		return getDigitCount(upperValue, defaultRadix);
	}

	@Override
	protected void getLowerString(int radix, boolean uppercase, StringBuilder appendable) {
		appendable.append(toDefaultString(value, radix, uppercase, 0));
	}

	@Override
	protected void getLowerString(int radix, int choppedDigits, boolean uppercase, StringBuilder appendable) {
		appendable.append(toDefaultString(value, radix, uppercase, choppedDigits));
	}

	@Override
	protected void getUpperString(int radix, boolean uppercase, StringBuilder appendable) {
		appendable.append(toDefaultString(upperValue, radix, uppercase, 0));
	}

	@Override
	protected void getUpperStringMasked(int radix, boolean uppercase, StringBuilder appendable) {
		appendable.append(toDefaultString(upperValueMasked, radix, uppercase, 0));
	}

	@Override
	protected void getSplitLowerString(int radix, int choppedDigits, boolean uppercase,
			char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix, StringBuilder appendable) {
		StringBuilder builder = new StringBuilder();
		getLowerString(radix, choppedDigits, uppercase, builder);
		for(int i = 0; i < builder.length(); i++) {
			if(i > 0) {
				appendable.append(splitDigitSeparator);
			}
			if(stringPrefix != null) {
				appendable.append(stringPrefix);
			}
			appendable.append(builder.charAt(reverseSplitDigits ? (builder.length() - i - 1) : i));
		}
	}

	@Override
	protected void getSplitRangeString(String rangeSeparator, String wildcard, int radix, boolean uppercase,
			char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix, StringBuilder appendable) {
		StringBuilder lowerBuilder = new StringBuilder();
		StringBuilder upperBuilder = new StringBuilder();
		getLowerString(radix, uppercase, lowerBuilder);
		getUpperString(radix, uppercase, upperBuilder);
		int diff = upperBuilder.length() - lowerBuilder.length();
		if(diff > 0) {
			StringBuilder newLowerBuilder = new StringBuilder();
			while(diff-- > 0) {
				newLowerBuilder.append('0');
			}
			newLowerBuilder.append(lowerBuilder);
			lowerBuilder = newLowerBuilder;
		}
		boolean previousWasFull = true;
		boolean nextMustBeFull = false;
		char dig[] = getDigits(radix, uppercase);
		char zeroDigit = dig[0];
		char highestDigit = dig[radix - 1];
		int len = lowerBuilder.length();
		for(int i = 0; i < len; i++) {
			int index = reverseSplitDigits ? (len - i - 1) : i;
			char lower = lowerBuilder.charAt(index);
			char upper = upperBuilder.charAt(index);
			if(i > 0) {
				appendable.append(splitDigitSeparator);
			}
			if(lower == upper) {
				if(nextMustBeFull) {
					throw new AddressTypeException(lower, upper, "ipaddress.error.splitMismatch");
				}
				if(stringPrefix != null) {
					appendable.append(stringPrefix);
				}
				appendable.append(lower);
			} else {
				boolean isFullRange = (lower == zeroDigit) && (upper == highestDigit);
				if(isFullRange) {
					appendable.append(wildcard);
				} else {
					if(nextMustBeFull) {
						throw new AddressTypeException(lower, upper, "ipaddress.error.splitMismatch");
					}
					if(stringPrefix != null) {
						appendable.append(stringPrefix);
					}
					appendable.append(lower);
					appendable.append(rangeSeparator);
					appendable.append(upper);
				}
				if(reverseSplitDigits) {
					if(!previousWasFull) {
						throw new AddressTypeException(lower, upper, "ipaddress.error.splitMismatch");
					}
					previousWasFull = isFullRange;
				} else {
					nextMustBeFull = true;
				}
				
			}
		}
	}

	@Override
	protected int getSplitRangeStringLength(String rangeSeparator, String wildcard, int leadingZeroCount,
			int radix, boolean uppercase, char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix) {
		int digitsLength = -1;
		int stringPrefixLength = (stringPrefix == null) ? 0 : stringPrefix.length();
		StringBuilder lowerBuilder = new StringBuilder();
		StringBuilder upperBuilder = new StringBuilder();
		getLowerString(radix, uppercase, lowerBuilder);
		getUpperString(radix, uppercase, upperBuilder);
		char dig[] = getDigits(radix, uppercase);
		char zeroDigit = dig[0];
		char highestDigit = dig[radix - 1];
		int remainingAfterLoop = leadingZeroCount;
		for(int i = 1; i <= upperBuilder.length(); i++) {
			char lower = (i <= lowerBuilder.length()) ? lowerBuilder.charAt(lowerBuilder.length() - i) : 0;
			int upperIndex = upperBuilder.length() - i;
			char upper = upperBuilder.charAt(upperIndex);
			boolean isFullRange = (lower == zeroDigit) && (upper == highestDigit);
			if(isFullRange) {
				digitsLength += wildcard.length() + 1;
			} else if (lower != upper ){
				digitsLength += (stringPrefixLength << 1) + 4 ; //1 for each digit, 1 for range separator, 1 for split digit separator
			} else {
				//this and any remaining must be singles
				remainingAfterLoop += upperIndex + 1;
				break;
			}
		}
		if(remainingAfterLoop > 0) {
			digitsLength += remainingAfterLoop * (stringPrefixLength + 2);// one for each splitDigitSeparator, 1 for each digit 
		}
		return digitsLength;
	}

	@Override
	protected boolean lowerValueIsZero() {
		return value.equals(BigInteger.ZERO);
	}

	@Override
	protected int getRangeDigitCount(int radix) {
		if(!isMultiple()) {
			return 0;
		}
		BigInteger val = value, upperVal = upperValue;
		int count = 1;
		BigInteger bigRadix = BigInteger.valueOf(radix);
		BigInteger bigUpper = BigInteger.valueOf(radix - 1);
		while(true) {
			BigInteger highLow[] = val.divideAndRemainder(bigRadix);
			BigInteger quotient = highLow[0];
			BigInteger remainder = highLow[1];
			if(remainder.equals(BigInteger.ZERO)) {
				highLow = upperVal.divideAndRemainder(bigRadix);
				BigInteger upperQuotient = highLow[0];
				remainder = highLow[1];
				if(remainder.equals(bigUpper)) {
					val = quotient;
					upperVal = upperQuotient;
					if(val.equals(upperVal)) {
						return count;
					} else {
						count++;
						continue;
					}
				}
			}
			return 0;
		}
	}
	
	@Override
	public int getConfiguredString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable) {
		if(params.preferWildcards() || params.isSplitDigits()) {
			return getStandardString(segmentIndex, params, appendable);
		}
		return getPrefixAdjustedString(segmentIndex, params, appendable);
	}
	
	@Override
	protected boolean isRangeAdjustedToPrefix() {
		return networkPrefixLength == null || networkPrefixLength == bitCount || !IPAddressDivision.ADJUST_RANGES_BY_PREFIX;
	}
	
	@Override
	protected boolean isRangeEquivalentToPrefix() {
		return isRangeEquivalentToPrefix;
	}
}
