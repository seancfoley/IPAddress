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
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.util.AddressSegmentParams;

/**
 * This class supports a segment of an arbitrary number of bits.
 * 
 * For a bit count less than or equal to 63 bits, AddressDivision is a more efficient choice.
 * 
 * @author sfoley
 *
 */
public class IPAddressLargeDivision extends AddressDivisionBase implements IPAddressStringDivision {

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
	
	private static final long serialVersionUID = 4L;
	
	private final BigInteger value, upperValue, maxValue, upperValueMasked;
	private final BigInteger defaultRadix;//we keep radix as a big integer because some operations required it, but we only support integer radices so it can be converted via BigInteger.intValue() at any time
	private final int bitCount;
	private final Integer networkPrefixLength;
	private final boolean isSinglePrefixBlock, isPrefixBlock;
	protected transient String cachedWildcardString;
	
	public IPAddressLargeDivision(byte bytes[], int bitCount, int defaultRadix) throws AddressValueException {
		maxValue = getMaxValue(bitCount);
		this.bitCount = bitCount;
		this.defaultRadix = BigInteger.valueOf(defaultRadix);
		isPrefixBlock = isSinglePrefixBlock = false;
		upperValueMasked = upperValue = value = new BigInteger(1, bytes);
		networkPrefixLength = null;
		if(upperValue.compareTo(maxValue) > 0) {
			throw new AddressValueException(upperValue);
		}
	}
	
	/**
	 * 
	 * @param bytes
	 * @param bitCount
	 * @param defaultRadix
	 * @param network can be null if prefixLength is null
	 * @param prefixLength
	 */
	public IPAddressLargeDivision(byte bytes[], int bitCount, int defaultRadix, IPAddressNetwork<?, ?, ?, ?, ?> network, Integer prefixLength) throws AddressValueException {
		if(prefixLength != null && prefixLength < 0) {
			throw new PrefixLenException(prefixLength);
		}
		maxValue = getMaxValue(bitCount);
		this.bitCount = bitCount;
		this.defaultRadix = BigInteger.valueOf(defaultRadix);
		if(prefixLength == null || prefixLength >= bitCount) {
			if(prefixLength != null && prefixLength > bitCount) {
				prefixLength = bitCount;
			}
			isPrefixBlock = isSinglePrefixBlock = prefixLength != null;
			upperValueMasked = upperValue = value = new BigInteger(1, bytes);
		} else {
			bytes = extend(bytes, bitCount);
			byte upperBytes[] = bytes.clone();
			int shift = bitCount - prefixLength;
			int byteShift = (shift + 7) / 8;
			int byteIndex = bytes.length - byteShift;
			int mask = 0xff & (~0 << (((shift - 1) % 8) + 1));
			if(network.getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
				bytes[byteIndex] &= mask;
				Arrays.fill(bytes, byteIndex + 1, bytes.length, (byte) 0);
				upperValueMasked = value = new BigInteger(1, bytes);
				upperBytes[byteIndex] |= ~mask;
				Arrays.fill(upperBytes, byteIndex + 1, bytes.length, (byte) 0xff);
				upperValue = new BigInteger(1, upperBytes);
				isPrefixBlock = isSinglePrefixBlock = true;
			} else {
				byte maskedUpperBytes[] = upperBytes.clone();
				maskedUpperBytes[byteIndex] &= mask;
				Arrays.fill(maskedUpperBytes, byteIndex + 1, bytes.length, (byte) 0);
				upperValueMasked = new BigInteger(1, maskedUpperBytes);
				upperValue = value = new BigInteger(1, bytes);
				isPrefixBlock = isSinglePrefixBlock = false;
			}
		}
		if(upperValue.compareTo(maxValue) > 0) {
			throw new AddressValueException(upperValue);
		}
		networkPrefixLength = prefixLength;
	}

	public IPAddressLargeDivision(
			byte bytes[], byte upperBytes[], int bitCount, int defaultRadix, IPAddressNetwork<?, ?, ?, ?, ?> network, Integer prefixLength) throws AddressValueException {
		if(prefixLength != null && prefixLength < 0) {
			throw new PrefixLenException(prefixLength);
		}
		bytes = extend(bytes, bitCount);
		upperBytes = extend(upperBytes, bitCount);
		maxValue = getMaxValue(bitCount);
		this.bitCount = bitCount;
		this.defaultRadix = BigInteger.valueOf(defaultRadix);
		if(prefixLength == null || prefixLength >= bitCount) {
			if(prefixLength != null && prefixLength > bitCount) {
				prefixLength = bitCount;
			}
			BigInteger low, high;
			if(Arrays.equals(bytes, upperBytes)) {
				low = high = new BigInteger(1, bytes);
			} else {
				low = new BigInteger(1, bytes);
				high = new BigInteger(1, upperBytes);
				if(low.compareTo(high) > 0) {
					BigInteger tmp = high;
					high = low;
					low = tmp;
				}
			}
			isSinglePrefixBlock = isPrefixBlock = prefixLength != null;
			value = low;
			upperValueMasked = upperValue = high;
		} else {
			int shift = bitCount - prefixLength;
			int byteShift = (shift + 7) / 8;
			int byteIndex = bytes.length - byteShift;
			int mask = 0xff & (~0 << (((shift - 1) % 8) + 1));
			int upperByteIndex = upperBytes.length - byteShift;
			if(network.getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
				BigInteger low, high, highMasked;
				while(true) {
					bytes[byteIndex] &= mask;
					Arrays.fill(bytes, byteIndex + 1, bytes.length, (byte) 0);
					low = new BigInteger(1, bytes);
					
					upperBytes[upperByteIndex] |= ~mask;
					Arrays.fill(upperBytes, upperByteIndex + 1, upperBytes.length, (byte) 0xff);
					high = new BigInteger(1, upperBytes);
				
					byte maskedUpperBytes[] = upperBytes.clone();
					maskedUpperBytes[upperByteIndex] &= mask;
					Arrays.fill(maskedUpperBytes, upperByteIndex + 1, upperBytes.length, (byte) 0);
					highMasked = new BigInteger(1, maskedUpperBytes);
					
					if(low.compareTo(high) > 0) {
						byte tmp[] = upperBytes;
						upperBytes = bytes;
						bytes = tmp;
						continue;
					}
					break;
				}
				value = low;
				upperValue = high;
				upperValueMasked = highMasked;
				isPrefixBlock = true;
				isSinglePrefixBlock = isPrefixSubnetBlock(bytes, upperBytes, bitCount, prefixLength, true, false);
			} else {
				BigInteger low, high;
				if(Arrays.equals(bytes, upperBytes)) {
					low = high = new BigInteger(1, bytes);
					isPrefixBlock = isSinglePrefixBlock = false;
				} else {
					low = new BigInteger(1, bytes);
					high = new BigInteger(1, upperBytes);
					boolean backIsPrefixed = isPrefixSubnetBlock(bytes, upperBytes, bitCount, prefixLength, false, true);
					if(backIsPrefixed) {
						isPrefixBlock = true;
						isSinglePrefixBlock = isPrefixSubnetBlock(bytes, upperBytes, bitCount, prefixLength, true, false);
					} else {
						isPrefixBlock = isSinglePrefixBlock = false;
					}
					if(low.compareTo(high) > 0) {
						BigInteger tmp = high;
						high = low;
						low = tmp;
					}
				}
				value = low;
				upperValue = high;
				byte maskedUpperBytes[] = upperBytes.clone();
				maskedUpperBytes[byteIndex] &= mask;
				Arrays.fill(maskedUpperBytes, byteIndex + 1, bytes.length, (byte) 0);
				upperValueMasked = new BigInteger(1, maskedUpperBytes);
			}
			
		}
		if(upperValue.compareTo(maxValue) > 0) {
			throw new AddressValueException(upperValue);
		}
		networkPrefixLength = prefixLength;
	}
	
	private static boolean isPrefixSubnetBlock(byte bytes[], byte upperBytes[], int bitCount, Integer prefix, boolean front, boolean back) {
		if(prefix == null) {
			return false;
		}
		int shift = bitCount - prefix;
		int byteShift = (shift + 7) / 8;
		int byteIndex = bytes.length - byteShift;
		int mask = 0xff & (~0 << (((shift - 1) % 8) + 1));
		byte lowerByte = bytes[byteIndex];
		byte upperByte = upperBytes[byteIndex];
		if(front) {
			int lower = lowerByte & mask;
			int upper = upperByte & mask;
			if(lower != upper) {
				return false;
			}
			for(int i = byteIndex - 1; i >= 0; i--) {
				if(bytes[i] != upperBytes[i]) {
					return false;
				}
			}
		}
		if(back) {
			int hostMask = 0xff & ~mask;
			int lower = lowerByte & hostMask;
			int upper = upperByte & hostMask;
			if(lower != 0 || upper != hostMask) {
				return false;
			}
			for(int i = byteIndex + 1; i < bytes.length; i++) {
				if(bytes[i] != 0 || upperBytes[i] != (byte) 0xff) {
					return false;
				}
			}
		}
		return true;
	}
	
	private static byte[] extend(byte bytes[], int bitCount) {
		return convert(bytes, (bitCount + 7) / 8, "");
	}
	
	private static byte[] convert(byte bytes[], int requiredByteCount, String key) {
		int len = bytes.length;
		if(len < requiredByteCount) {
			byte oldBytes[] = bytes;
			bytes = new byte[requiredByteCount];
			int diff = bytes.length - oldBytes.length;
			int mostSignificantBit = 0x80 & oldBytes[0];
			if(mostSignificantBit != 0) {//sign extension
				Arrays.fill(bytes, 0, diff, (byte) 0xff);
			}
			System.arraycopy(oldBytes, 0, bytes, diff, oldBytes.length);
		} else {
			if(len > requiredByteCount) {
				int i = 0;
				do {
					if(bytes[i++] != 0) {
						throw new AddressValueException(key, len);
					}
				} while(--len > requiredByteCount);
				bytes = Arrays.copyOfRange(bytes, i, bytes.length);
			}
		}
		return bytes;
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
	public boolean includesZero() {
		return value.equals(BigInteger.ZERO);
	}
	
	@Override
	public boolean includesMax() {
		return upperValue.equals(maxValue);
	}

	@Override
	public boolean isMax() {
		return includesMax() && !isMultiple();
	}
	
	@Override
	public boolean isZero() {
		return includesZero() && !isMultiple();
	}

	@Override
	public boolean isFullRange() {
		return includesZero() && includesMax();
	}

	@Override
	protected byte[] getBytesImpl(boolean low) {
		return convert(low ? value.toByteArray() : upperValue.toByteArray(), (bitCount + 7) / 8, "");
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
		return uppercase ? UPPERCASE_DIGITS : DIGITS;
	}
	
	@Override
	protected void appendUppercase(CharSequence str, int radix, StringBuilder appendable) {
		if(radix > 10 && !isExtendedDigits()) {
			for(int i = 0; i < str.length(); i++) {
				char c = str.charAt(i);
				if(c >= 'a' && c <= 'z') {
					c += 'A' - 'a';
				}
				appendable.append(c);
			}
		} else {
			appendable.append(str);
		}
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
	
	/**
	 * Produces a normalized string to represent the segment.
	 * If the segment CIDR prefix length covers the range, then it is assumed to be a CIDR, and the string has only the lower value of the CIDR range.
	 * Otherwise, the explicit range will be printed.
	 * @return
	 */
	@Override
	public String getString() {
		String result = cachedString;
		if(result == null) {
			synchronized(this) {
				result = cachedString;
				if(result == null) {
					if(isSinglePrefixBlock() || !isMultiple()) { //covers the case of !isMultiple, ie single addresses, when there is no prefix or the prefix is the bit count
						result = getDefaultString();
					} else if(!isFullRange() || (result = getDefaultSegmentWildcardString()) == null) {
						if(isPrefixed() && isPrefixBlock(getDivisionPrefixLength())) {
							result = getDefaultMaskedRangeString();
						} else {
							result = getDefaultRangeString();
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
	@Override
	public String getWildcardString() {
		String result = cachedWildcardString;
		if(result == null) {
			synchronized(this) {
				result = cachedWildcardString;
				if(result == null) {
					if(!isPrefixed() || !isMultiple()) {
						result = getString();
					} else if(!isFullRange() || (result = getDefaultSegmentWildcardString()) == null) {
						result = getDefaultRangeString();
					}
					cachedWildcardString = result;
				}
			}
		}
		return result;
	}

	@Override
	protected String getDefaultString() {
		return toDefaultString(value, defaultRadix, false, 0, getMaxDigitCount());
	}

	@Override
	protected String getDefaultRangeString() {
		int maxDigitCount = getMaxDigitCount();
		return toDefaultString(value, defaultRadix, false, 0, maxDigitCount) + 
				getDefaultRangeSeparatorString() + 
				toDefaultString(upperValue, defaultRadix, false, 0, maxDigitCount);
	}
	
	protected String getDefaultMaskedRangeString() {
		int maxDigitCount = getMaxDigitCount();
		return toDefaultString(value, defaultRadix, false, 0, maxDigitCount) + 
				getDefaultRangeSeparatorString() + 
				toDefaultString(upperValueMasked, defaultRadix, false, 0, maxDigitCount);
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
		int prefLen = stringPrefix.length();
		for(int i = 0; i < builder.length(); i++) {
			if(i > 0) {
				appendable.append(splitDigitSeparator);
			}
			if(prefLen > 0) {
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
		int prefLen = stringPrefix.length();
		for(int i = 0; i < len; i++) {
			int index = reverseSplitDigits ? (len - i - 1) : i;
			char lower = lowerBuilder.charAt(index);
			char upper = upperBuilder.charAt(index);
			if(i > 0) {
				appendable.append(splitDigitSeparator);
			}
			if(lower == upper) {
				if(nextMustBeFull) {
					throw new IncompatibleAddressException(lower, upper, "ipaddress.error.splitMismatch");
				}
				if(prefLen > 0) {
					appendable.append(stringPrefix);
				}
				appendable.append(lower);
			} else {
				boolean isFullRange = (lower == zeroDigit) && (upper == highestDigit);
				if(isFullRange) {
					appendable.append(wildcard);
				} else {
					if(nextMustBeFull) {
						throw new IncompatibleAddressException(lower, upper, "ipaddress.error.splitMismatch");
					}
					if(prefLen > 0) {
						appendable.append(stringPrefix);
					}
					appendable.append(lower);
					appendable.append(rangeSeparator);
					appendable.append(upper);
				}
				if(reverseSplitDigits) {
					if(!previousWasFull) {
						throw new IncompatibleAddressException(lower, upper, "ipaddress.error.splitMismatch");
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
		int stringPrefixLength = stringPrefix.length();
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
	public int getPrefixAdjustedRangeString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable) {
		return super.getPrefixAdjustedRangeString(segmentIndex, params, appendable);
	}

	public boolean isPrefixBlock() {
		return isPrefixBlock;
	}
	
	/**
	 * Returns whether the division range matches the block of values for its prefix length
	 */
	@Override
	public boolean isSinglePrefixBlock() {
		return isSinglePrefixBlock;
	}

	@Override
	public Integer getDivisionPrefixLength() {
		return networkPrefixLength;
	}
	
	public boolean isPrefixed() {
		return networkPrefixLength != null;
	}

	@Override
	public boolean isPrefixBlock(Integer divisionPrefixLen) {
		if(divisionPrefixLen == null) {
			return true;
		}
		if(divisionPrefixLen == 0) {
			return isFullRange();
		}
		int prefixLen = divisionPrefixLen;
		BigInteger lower = value, upper = upperValue;
		int hostBits = bitCount - prefixLen;
		long fullMask = ~0L;
		do {
			long low = lower.longValue(); //returns lower % 2^64
			long up = upper.longValue();
			if(hostBits <= 64) {
				long networkMask, hostMask;
				if(hostBits == 64) {
					networkMask = 0;
					hostMask = fullMask;
				} else {
					networkMask = fullMask << hostBits;//prefixLen must be 6 digits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
					hostMask = ~networkMask; 
				}
				long maskedLow = low & networkMask;
				long maskedUp = up | hostMask;
				return low == maskedLow
						&& up == maskedUp;
			} else {
				if(low != 0 || up != fullMask) {
					return false;
				}
			}
			lower = lower.shiftRight(64);
			upper = upper.shiftRight(64);
			hostBits -= 64;
		} while(!upper.equals(BigInteger.ZERO));
		return false;
	}
}
