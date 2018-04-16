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
import java.util.TreeMap;

import inet.ipaddr.format.AddressDivisionGrouping.StringOptions.Wildcards;
import inet.ipaddr.format.util.AddressSegmentParams;

/**
 * Base class for address divisions.
 * 
 * @author sfoley
 *
 */
public abstract class AddressDivisionBase implements AddressItem, AddressStringDivision {

	private static final long serialVersionUID = 4L;
	
	private static final String zeros[];
	
	static {
		int zerosLength = 20;
		zeros = new String[zerosLength];
		zeros[0] = "";
		for(int i = 1; i < zerosLength; i++) {
			zeros[i] = zeros[i - 1] + '0';
		}
	}
	
	protected static final char[] DIGITS = {
        '0' , '1' , '2' , '3' , '4' , '5' ,
        '6' , '7' , '8' , '9' , 'a' , 'b' ,
        'c' , 'd' , 'e' , 'f' , 'g' , 'h' ,
        'i' , 'j' , 'k' , 'l' , 'm' , 'n' ,
        'o' , 'p' , 'q' , 'r' , 's' , 't' ,
        'u' , 'v' , 'w' , 'x' , 'y' , 'z'
    };

	protected static final char[] UPPERCASE_DIGITS = {
        '0' , '1' , '2' , '3' , '4' , '5' ,
        '6' , '7' , '8' , '9' , 'A' , 'B' ,
        'C' , 'D' , 'E' , 'F' , 'G' , 'H' ,
        'I' , 'J' , 'K' , 'L' , 'M' , 'N' ,
        'O' , 'P' , 'Q' , 'R' , 'S' , 'T' ,
        'U' , 'V' , 'W' , 'X' , 'Y' , 'Z'
    };

	private static TreeMap<Long, Integer> maxDigitMap = new TreeMap<Long, Integer>();

	private static TreeMap<Long, BigInteger> radixPowerMap = new TreeMap<Long, BigInteger>();

	//cached for performance reasons - especially valuable since segments can be shared amongst different addresses as we do with the masks
	protected transient String cachedString;
	
	/* the cached address bytes */
	private transient byte[] lowerBytes, upperBytes;
	
	protected AddressDivisionBase() {}
	
	/**
	 * Gets the bytes for the lowest address in the range represented by this address division.
	 * <p>
	 * Since bytes are signed values while addresses are unsigned, values greater than 127 are
	 * represented as the (negative) two's complement value of the actual value.
	 * You can get the unsigned integer value i from byte b using i = 0xff &amp; b.
	 * 
	 * @return
	 */
	@Override
	public byte[] getBytes() {
		byte cached[] = lowerBytes;
		if(cached == null) {
			lowerBytes = cached = getBytesImpl(true);
		}
		return cached.clone();
	}
	
	/**
	 * Gets the value for the lowest address in the range represented by this address division.
	 * <p>
	 * If the value fits in the specified array at the specified index, the same array is returned with the value copied at the specified index.  
	 * Otherwise, a new array is allocated and returned with the value copied at the specified index, and the rest of the array contents the same as the original.
	 * <p>
	 * You can use {@link #getBitCount()} to determine the required array length for the bytes.
	 * <p>
	 * Since bytes are signed values while addresses are unsigned, values greater than 127 are
	 * represented as the (negative) two's complement value of the actual value.
	 * You can get the unsigned integer value i from byte b using i = 0xff &amp; b.
	 * 
	 * @return
	 */
	@Override
	public byte[] getBytes(byte bytes[], int index) {
		byte cached[] = lowerBytes;
		if(cached == null) {
			lowerBytes = cached = getBytesImpl(true);
		}
		return getBytes(bytes, index, cached);
	}

	/**
	 * Equivalent to {@link #getBytes(byte[], int)} with index of 0.
	 */
	@Override
	public byte[] getBytes(byte bytes[]) {
		return getBytes(bytes, 0);
	}

	private byte[] getBytes(byte[] provided, int startIndex, byte[] cached) {
		int byteCount = (getBitCount() + 7) >> 3;
		if(provided == null || provided.length < byteCount + startIndex) {
			if(startIndex > 0) {
				byte bytes2[] = new byte[byteCount + startIndex];
				if(provided != null) {
					System.arraycopy(provided, 0, bytes2, 0, Math.min(startIndex, provided.length));
				}
				System.arraycopy(cached, 0, bytes2, startIndex, cached.length);
				return bytes2;
			}
			return cached.clone();
		} 
		System.arraycopy(cached, 0, provided, startIndex, byteCount);
		return provided;
	}
	
	@Override
	public byte[] getUpperBytes() {
		if(!isMultiple()) {
			return getBytes();
		}
		byte cached[] = upperBytes;
		if(cached == null) {
			upperBytes = cached = getBytesImpl(false);
		}
		return cached.clone();
	}
	
	@Override
	public byte[] getUpperBytes(byte bytes[], int index) {
		if(!isMultiple()) {
			return getBytes(bytes, index);
		}
		byte cached[] = upperBytes;
		if(cached == null) {
			upperBytes = cached = getBytesImpl(false);
		}
		return getBytes(bytes, index, cached);
	}
	
	@Override
	public byte[] getUpperBytes(byte bytes[]) {
		return getUpperBytes(bytes, 0);
	}
	
	protected abstract byte[] getBytesImpl(boolean low);
	
	/**
	 * @return the default radix for textual representations of addresses (10 for IPv4, 16 for IPv6)
	 */
	public abstract int getDefaultTextualRadix();
	
	/**
	 * @return the number of digits for the maximum possible value of the division when using the default radix
	 */
	public abstract int getMaxDigitCount();

	protected static int getMaxDigitCount(int radix, int bitCount, BigInteger maxValue) {
		long key = (((long) radix) << 32) | bitCount;
		Integer digs = maxDigitMap.get(key);
		if(digs == null) {
			if(maxValue == null) {
				maxValue = getMaxValue(bitCount);
			}
			digs = getDigitCount(maxValue, BigInteger.valueOf(radix));
			maxDigitMap.put(key, digs);
		}
		return digs;
	}
	
	protected static BigInteger getMaxValue(int bitCount) {
		int maxBytes = (bitCount + 7) / 8;
		int topBits = bitCount % 8;
		if(topBits == 0) {
			topBits = 8;
		}
		byte max[] = new byte[maxBytes];
		max[0] = (byte) ~(~0 << topBits);
		for(int i = 1; i < max.length; i++) {
			max[i] = ~0;
		}
		return new BigInteger(1, max);
	}
	
	protected static int getDigitCount(BigInteger val, BigInteger radix) {
		if(val.equals(BigInteger.ZERO) || val.equals(BigInteger.ONE)) {
			return 1;
		}
		int result = 1;
		while(true) {
			val = val.divide(radix);
			if(val.equals(BigInteger.ZERO)) {
				break;
			}
			result++;
		}
		return result;
	}
	
	static int getMaxDigitCount(int radix, int bitCount, long maxValue) {
		long key = (((long) radix) << 32) | bitCount;
		Integer digs = maxDigitMap.get(key);
		if(digs == null) {
			digs = getDigitCount(maxValue, radix);
			maxDigitMap.put(key, digs);
		}
		return digs;
	}
	
	public static int getDigitCount(long value, int radix) {
		int result = 1;
		if(radix == 16) {
			while(true) {
				value >>>= 4;
				if(value == 0) {
					break;
				}
				result++;
			}
		} else {
			if(radix == 10) {
				if(value < 10) {
					return 1;
				} else if(value < 100) {
					return 2;
				} else if(value < 1000) {
					return 3;
				}
				value /= 1000;
				result = 3;//we start with 3 in the loop below
			} else if(radix == 8) {
				while(true) {
					value >>>= 3;
					if(value == 0) {
						break;
					}
					result++;
				}
				return result;
			}
			while(true) {
				value /= radix;
				if(value == 0) {
					break;
				}
				result++;
			}
		}
		return result;
	}
	
	/**
	 * Caches the results of radix to the given power.
	 * 
	 * @param radix
	 * @param power
	 * @return
	 */
	protected static BigInteger getRadixPower(BigInteger radix, int power) {
		long key = (((long) radix.intValue()) << 32) | power;
		BigInteger result = radixPowerMap.get(key);
		if(result == null) {
			if(power == 1) {
				result = radix;
			} else if((power & 1) == 0) {
				BigInteger halfPower = getRadixPower(radix, power >> 1);
				result = halfPower.multiply(halfPower);
			} else {
				BigInteger halfPower = getRadixPower(radix, (power - 1) >> 1);
				result = halfPower.multiply(halfPower).multiply(radix);
			}
			radixPowerMap.put(key, result);
		}
		return result;
	}
	
	protected abstract int adjustLowerLeadingZeroCount(int leadingZeroCount, int radix);
	
	protected abstract int adjustUpperLeadingZeroCount(int leadingZeroCount, int radix);

	private static void getSplitChar(int count, char splitDigitSeparator, String characters, String stringPrefix, StringBuilder builder) {
		while(count-- > 0) {
			if(stringPrefix.length() > 0) {
				builder.append(stringPrefix);
			}
			builder.append(characters);
			builder.append(splitDigitSeparator);
		}
		builder.setLength(builder.length() - 1);
	}
	
	private static void getSplitChar(int count, char splitDigitSeparator, char character, String stringPrefix, StringBuilder builder) {
		int prefLen = stringPrefix.length();
		while(count-- > 0) {
			if(prefLen > 0) {
				builder.append(stringPrefix);
			}
			builder.append(character);
			builder.append(splitDigitSeparator);
		}
		builder.setLength(builder.length() - 1);
	}

	private static void getSplitLeadingZeros(int leadingZeroCount, char splitDigitSeparator, String stringPrefix, StringBuilder builder) {
		getSplitChar(leadingZeroCount, splitDigitSeparator, '0', stringPrefix, builder);
	}

	protected static void getLeadingZeros(int leadingZeroCount, StringBuilder builder) {
		if(leadingZeroCount > 0) {
			String stringArray[] = zeros;
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
	}
	
	@Override
	public String toString() {
		return getString();
	}

	/**
	 * A simple string using just the lower value and the default radix.
	 * 
	 * @return
	 */
	protected abstract String getDefaultString();
	
	/**
	 * A simple string using just the lower and upper values and the default radix, separated by the default range character.
	 * 
	 * @return
	 */
	protected abstract String getDefaultRangeString();
	
	/**
	 * This is the wildcard string to be used when producing the default strings with getString() or getWildcardString()
	 * 
	 * Since no parameters for the string are provided, default settings are used, but they must be consistent with the address.
	 * 
	 * For instance, generally the '*' is used as a wildcard to denote all possible values for a given segment,
	 * but in some cases that character is used for a segment separator.
	 * 
	 * Note that this only applies to "default" settings, there are additional string methods that allow you to specify these separator characters.
	 * Those methods must be aware of the defaults as well, to know when they can defer to the defaults and when they cannot.
	 * 
	 * @return
	 */
	protected abstract String getDefaultSegmentWildcardString();
	
	/**
	 * This is the wildcard string to be used when producing the default strings with getString() or getWildcardString()
	 * 
	 * Since no parameters for the string are provided, default settings are used, but they must be consistent with the address.
	 * 
	 * For instance, generally the '-' is used as a range separator, but in some cases that character is used for a segment separator.
	 * 
	 * Note that this only applies to "default" settings, there are additional string methods that allow you to specify these separator characters.
	 * Those methods must be aware of the defaults as well, to know when they can defer to the defaults and when they cannot.
	 * 
	 * @return
	 */
	protected abstract String getDefaultRangeSeparatorString();

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
					if(!isMultiple()) {
						result = getDefaultString();
					} else if(!isFullRange() || (result = getDefaultSegmentWildcardString()) == null) {
						result = getDefaultRangeString();
					}
					cachedString = result;
				}
			}
		}
		return result;
	}

	protected String getWildcardString() {
		return getString();
	}
	
	private String getCachedString() {
		String result = cachedString;
		if(result == null) {
			synchronized(this) {
				result = cachedString;
				if(result == null) {
					cachedString = result = getDefaultString();
				}
			}
		}
		return result;
	}
	
	protected void setDefaultAsFullRangeString() {
		if(cachedString == null) {
			String result = getDefaultSegmentWildcardString();
			if(result != null) {
				synchronized(this) {
					cachedString = result;
				}
			}
		}
	}
	
	protected void setDefaultAsFullRangeWildcardString() {
		setDefaultAsFullRangeString();
	}

	protected abstract int getLowerStringLength(int radix);
	
	protected abstract int getUpperStringLength(int radix);
	
	protected abstract void getLowerString(int radix, boolean uppercase, StringBuilder appendable);
	
	protected abstract void getLowerString(int radix, int choppedDigits, boolean uppercase, StringBuilder appendable);
	
	protected abstract void getUpperString(int radix, boolean uppercase, StringBuilder appendable);
	
	protected abstract void getUpperStringMasked(int radix, boolean uppercase, StringBuilder appendable);
	
	protected abstract void getSplitLowerString(int radix, int choppedDigits, boolean uppercase, 
			char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix, StringBuilder appendable);
	
	protected abstract void getSplitRangeString(String rangeSeparator, String wildcard, int radix, boolean uppercase, 
			char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix, StringBuilder appendable);
	
	protected abstract int getSplitRangeStringLength(String rangeSeparator, String wildcard, int leadingZeroCount, int radix, boolean uppercase, 
			char splitDigitSeparator, boolean reverseSplitDigits, String stringPrefix);

	protected abstract int getRangeDigitCount(int radix);
	
	protected void appendUppercase(CharSequence str, int radix, StringBuilder appendable) {
		if(radix > 10) {
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
	
	private static int getFullRangeString(String wildcard, StringBuilder appendable) {
		if(appendable == null) {
			return wildcard.length();
		}
		appendable.append(wildcard);
		return 0;
	}
	
	int getPrefixAdjustedRangeString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable) {
		int leadingZeroCount = params.getLeadingZeros(segmentIndex);
		int radix = params.getRadix();
		int lowerLeadingZeroCount = adjustLowerLeadingZeroCount(leadingZeroCount, radix);
		int upperLeadingZeroCount = adjustUpperLeadingZeroCount(leadingZeroCount, radix);

		//if the wildcards match those in use by getString(), and there is no character prefix, let's defer to getString() so that it is cached
		Wildcards wildcards = params.getWildcards();
		String rangeSeparator = wildcards.rangeSeparator;
		int rangeDigitCount = wildcards.singleWildcard == null ? 0 : getRangeDigitCount(radix);
		
		//If we can, we reuse the standard string to construct this string (must have the same radix and no chopped digits)
		//We can insert leading zeros, string prefix, and a different separator string if necessary
		//Also, we cannot in the case of full range (in which case we are only here because we do not want '*')
		if(rangeDigitCount == 0 && radix == getDefaultTextualRadix() && !isFullRange()) {
			//we call getString() to cache the result, and we call getString instead of getWildcardString() because it will also mask with the segment prefix length
			String str = getString();
			String rangeSep = getDefaultRangeSeparatorString();
			String stringPrefix = params.getSegmentStrPrefix();
			int prefLen = stringPrefix.length();
			if(lowerLeadingZeroCount == 0 && upperLeadingZeroCount == 0 && rangeSep.equals(rangeSeparator) && prefLen == 0) {
				if(appendable == null) {
					return str.length();
				} else {
					if(params.isUppercase()) {
						appendUppercase(str, radix, appendable);
					} else {
						appendable.append(str);
					}
					return 0;
				}
			} else {
				if(appendable == null) {
					int count = str.length() + (rangeSeparator.length() - rangeSep.length()) +
							lowerLeadingZeroCount + upperLeadingZeroCount;
					if(prefLen > 0) {
						count += prefLen << 1;
					}
					return count;
				} else {
					int firstEnd = str.indexOf(rangeSep);
					if(prefLen > 0) {
						appendable.append(stringPrefix);
					}
					if(lowerLeadingZeroCount > 0) {
						getLeadingZeros(lowerLeadingZeroCount, appendable);
					}
					appendable.append(str.substring(0, firstEnd));
					appendable.append(rangeSeparator);
					if(prefLen > 0) {
						appendable.append(stringPrefix);
					}
					if(upperLeadingZeroCount > 0) {
						getLeadingZeros(upperLeadingZeroCount, appendable);
					}
					appendable.append(str.substring(firstEnd + rangeSep.length()));
					return 0;
				}
			}
		}
		rangeDigitCount = adjustRangeDigits(rangeDigitCount);
		if(leadingZeroCount < 0 && appendable == null) {
			int charLength = getMaxDigitCount(radix);
			String stringPrefix = params.getSegmentStrPrefix();
			int prefLen = stringPrefix.length();
			if(rangeDigitCount != 0) {
				int count = charLength;
				if(prefLen > 0) {
					count += prefLen;
				}
				return count;
			}
			int count = charLength << 1;
			if(prefLen > 0) {
				count += prefLen << 1;
			}
			count += rangeSeparator.length();
			return count;
		}
		if(rangeDigitCount != 0) {
			return getRangeDigitString(segmentIndex, params, appendable);
		}
		return getRangeString(segmentIndex, params, lowerLeadingZeroCount, upperLeadingZeroCount, true, appendable);
	}
	
	@Override
	public int getLowerStandardString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable) {
		int count = 0;
		String stringPrefix = params.getSegmentStrPrefix();
		int prefLen = stringPrefix.length();
		if(prefLen > 0) {
			if(appendable == null) {
				count += prefLen;
			} else {
				appendable.append(stringPrefix);
			}
		}
		int radix = params.getRadix();
		int leadingZeroCount = params.getLeadingZeros(segmentIndex);
		leadingZeroCount = adjustLowerLeadingZeroCount(leadingZeroCount, radix);
		if(leadingZeroCount != 0) {
			if(appendable == null) {
				if(leadingZeroCount < 0) {
					return count + getMaxDigitCount(radix);
				} else {
					count += leadingZeroCount;
				}
			} else {
				leadingZeroCount = adjustLowerLeadingZeroCount(leadingZeroCount, radix);
				getLeadingZeros(leadingZeroCount, appendable);
			}
		}
		boolean uppercase = params.isUppercase();
		if(radix == getDefaultTextualRadix()) {
			String str = getCachedString();
			if(appendable == null) {
				return count + str.length();
			} else if(uppercase) {
				appendUppercase(str, radix, appendable);
			} else {
				appendable.append(str);
			}
		} else {
			if(appendable == null) {
				return count + getLowerStringLength(radix);
			} else {
				getLowerString(radix, uppercase, appendable);
			}
		}
		return 0;
	}

	/**
	 * Produces a string to represent the segment, using wildcards and range characters.
	 * Use this instead of getWildcardString() if you have a customized wildcard or range separator or you have a non-zero leadingZeroCount,
	 * or you have a non-standard radix (for IPv4 standard radix is 10, for IPv6 it is 16)
	 * 
	 */
	@Override
	public int getStandardString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable) {
		if(!isMultiple()) {
			boolean splitDigits = params.isSplitDigits();
			if(splitDigits) {
				int radix = params.getRadix();
				int leadingZeroCount = params.getLeadingZeros(segmentIndex);
				leadingZeroCount = adjustLowerLeadingZeroCount(leadingZeroCount, radix);
				String stringPrefix = params.getSegmentStrPrefix();
				int prefLen = stringPrefix.length();
				if(appendable == null) {
					int len;
					if(leadingZeroCount != 0) {
						if(leadingZeroCount < 0) {
							len = getMaxDigitCount(radix);
						} else {
							len = getLowerStringLength(radix) + leadingZeroCount;
						}
					} else {
						len = getLowerStringLength(radix);
					}
					int count = (len << 1) - 1;
					if(prefLen > 0) {
						count += len * prefLen;
					}
					return count;
				} else {
					char splitDigitSeparator = params.getSplitDigitSeparator() == null ? 0 : params.getSplitDigitSeparator();
					boolean reverseSplitDigits = params.isReverseSplitDigits();
					boolean uppercase = params.isUppercase();
					if(reverseSplitDigits) {
						getSplitLowerString(radix, 0, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable);
						if(leadingZeroCount != 0) {
							appendable.append(splitDigitSeparator);
							getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable);
						}
					} else {
						if(leadingZeroCount != 0) {
							getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable);
							appendable.append(splitDigitSeparator);
						}
						getSplitLowerString(radix, 0, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable);
					}
					return 0;
				}
			}
			return getLowerStandardString(segmentIndex, params, appendable);
		}
		if(isFullRange()) {
			String wildcard = params.getWildcards().wildcard;
			if(wildcard != null) {
				if(wildcard.equals(getDefaultSegmentWildcardString())) {
					setDefaultAsFullRangeWildcardString();//cache
				}
				boolean splitDigits = params.isSplitDigits();
				if(splitDigits) {
					int radix = params.getRadix();
					if(appendable == null) {
						int len = getMaxDigitCount(radix);
						int count = len * (wildcard.length() + 1) - 1;
						return count;
					}
					char splitDigitSeparator = params.getSplitDigitSeparator() == null ? 0 : params.getSplitDigitSeparator();
					getSplitChar(getMaxDigitCount(radix), splitDigitSeparator, wildcard, "", appendable);
					return 0;
				}
				return getFullRangeString(wildcard, appendable);
			}
		}
		return getRangeString(segmentIndex, params, appendable);
	}
	
	protected int getRangeString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable) {
		boolean splitDigits = params.isSplitDigits();
		int radix = params.getRadix();
		int leadingZeroCount = params.getLeadingZeros(segmentIndex);
		Wildcards wildcards = params.getWildcards();
		String rangeSeparator = wildcards.rangeSeparator;
		int rangeDigitCount = wildcards.singleWildcard == null ? 0 : getRangeDigitCount(radix);
		
		int lowerLeadingZeroCount = adjustLowerLeadingZeroCount(leadingZeroCount, radix);
		int upperLeadingZeroCount = adjustUpperLeadingZeroCount(leadingZeroCount, radix);

		//check the case where we can use the result of getWildcardString which is cached.
		//It must have same radix and no chopped digits, and no splitting or reversal of digits.
		//We can insert leading zeros, string prefix, and a different separator string if necessary.
		//Also, we cannot in the case of full range (in which case we are only here because we do not want '*')
		if(rangeDigitCount == 0 && 
				radix == getDefaultTextualRadix() && 
				!splitDigits &&
				!isFullRange()) {
			String str = getWildcardString();
			String rangeSep = getDefaultRangeSeparatorString();
			String stringPrefix = params.getSegmentStrPrefix();
			int prefLen = stringPrefix.length();
			if(lowerLeadingZeroCount == 0 && upperLeadingZeroCount == 0 &&
					prefLen == 0 &&
					rangeSeparator.equals(rangeSep)) {
				if(appendable == null) {
					return str.length();
				}
				appendable.append(str);
				return 0;
			} else {
				if(appendable == null) {
					int count = str.length() + (rangeSeparator.length() - rangeSep.length())  + lowerLeadingZeroCount + upperLeadingZeroCount;
					if(prefLen > 0) {
						count += prefLen << 1;
					}
					return count;
				} else {
					int firstEnd = str.indexOf(rangeSep);
					if(prefLen > 0) {
						appendable.append(stringPrefix);
					}
					if(lowerLeadingZeroCount > 0) {
						getLeadingZeros(lowerLeadingZeroCount, appendable);
					}
					appendable.append(str.substring(0, firstEnd));
					appendable.append(rangeSeparator);
					if(prefLen > 0) {
						appendable.append(stringPrefix);
					}
					if(upperLeadingZeroCount > 0) {
						getLeadingZeros(upperLeadingZeroCount, appendable);
					}
					appendable.append(str.substring(firstEnd + rangeSep.length()));
					return 0;
				}
			}
		}
		/*
		 split digits that result in digit ranges of * are similar to range digits range digits
		 eg f00-fff is both f__ and f.*.*
		 One difference is that for decimal last range digit is 0-5 (ie 255) but for split we only check full range (0-9)
		 eg 200-255 is 2__  but not 2.*.*
		 another difference: when calculating range digits, the count is 0 unless the entire range can be written as range digits
		 eg f10-fff has no range digits but is f.1-f.*
		 */
		if(!splitDigits && leadingZeroCount < 0 && appendable == null) {
			String stringPrefix = params.getSegmentStrPrefix();
			int prefLen = stringPrefix.length();
			int charLength = getMaxDigitCount(radix);
			if(rangeDigitCount != 0) {
				int count = charLength;
				if(prefLen > 0) {
					count += prefLen;
				}
				return count;
			}
			int count = charLength << 1;
			if(prefLen > 0) {
				count += prefLen << 1;
			}
			count += rangeSeparator.length();
			return count;
		}
		rangeDigitCount = adjustRangeDigits(rangeDigitCount);
		if(rangeDigitCount != 0) {
			if(splitDigits) {
				return getSplitRangeDigitString(segmentIndex, params, appendable);
			} else {
				return getRangeDigitString(segmentIndex, params, appendable);
			}
		}
		if(splitDigits) {
			return getSplitRangeString(segmentIndex, params, appendable);
		}
		return getRangeString(segmentIndex, params, lowerLeadingZeroCount, upperLeadingZeroCount, false, appendable);
	}
	
	protected int getSplitRangeDigitString(
			int segmentIndex,
			AddressSegmentParams params,
			StringBuilder appendable) {
		int radix = params.getRadix();
		int leadingZerosCount = params.getLeadingZeros(segmentIndex);
		leadingZerosCount = adjustLowerLeadingZeroCount(leadingZerosCount, radix);
		String stringPrefix = params.getSegmentStrPrefix();
		if(appendable == null) {
			int len = getLowerStringLength(radix) + leadingZerosCount;
			int count = (len << 1) - 1;
			int prefLen = stringPrefix.length();
			if(prefLen > 0) {
				count += len * prefLen;
			}
			return count;
		} else {
			Wildcards wildcards = params.getWildcards();
			int rangeDigits = adjustRangeDigits(getRangeDigitCount(radix));
			char splitDigitSeparator = params.getSplitDigitSeparator() == null ? 0 : params.getSplitDigitSeparator();
			boolean reverseSplitDigits = params.isReverseSplitDigits();
			boolean uppercase = params.isUppercase();
			if(reverseSplitDigits) {
				getSplitChar(rangeDigits, splitDigitSeparator, wildcards.singleWildcard, stringPrefix, appendable);
				appendable.append(splitDigitSeparator);
				getSplitLowerString(radix, rangeDigits, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable);
				if(leadingZerosCount > 0) {
					appendable.append(splitDigitSeparator);
					getSplitLeadingZeros(leadingZerosCount, splitDigitSeparator, stringPrefix, appendable);
				}
			} else {
				if(leadingZerosCount != 0) {
					getSplitLeadingZeros(leadingZerosCount, splitDigitSeparator, stringPrefix, appendable);
					appendable.append(splitDigitSeparator);
				}
				getSplitLowerString(radix, rangeDigits, uppercase, splitDigitSeparator, reverseSplitDigits, stringPrefix, appendable);
				appendable.append(splitDigitSeparator);
				getSplitChar(rangeDigits, splitDigitSeparator, wildcards.singleWildcard, stringPrefix, appendable);
			}
		}
		return 0;
	}
	
	protected int getRangeDigitString(
			int segmentIndex,
			AddressSegmentParams params,
			StringBuilder appendable) {
		int radix = params.getRadix();
		int leadingZerosCount = params.getLeadingZeros(segmentIndex);
		leadingZerosCount = adjustLowerLeadingZeroCount(leadingZerosCount, radix);
		String stringPrefix = params.getSegmentStrPrefix();
		int prefLen = stringPrefix.length();
		Wildcards wildcards = params.getWildcards();
		int rangeDigits = adjustRangeDigits(getRangeDigitCount(radix));
		if(appendable == null) {
			return getLowerStringLength(radix) + leadingZerosCount + prefLen;
		} else {
			if(prefLen > 0) {
				appendable.append(stringPrefix);
			}
			if(leadingZerosCount > 0) {
				getLeadingZeros(leadingZerosCount, appendable);
			}
			boolean uppercase = params.isUppercase();
			getLowerString(radix, rangeDigits, uppercase, appendable);
			for(int i = 0; i < rangeDigits; i++) {
				appendable.append(wildcards.singleWildcard);
			}
		}
		return 0;
	}
	
	int adjustRangeDigits(int rangeDigits) {
		if(rangeDigits != 0) {
			//Note: ranges like ___ intended to represent 0-fff cannot work because the range does not include 2 digit and 1 digit numbers
			//This only happens when the lower value is 0 and there is more than 1 range digit
			//That's because you can then omit any leading zeros.
			//Ranges like f___ representing f000-ffff are fine.
			if(!includesZero() || rangeDigits == 1) { 
				return rangeDigits;
			}
		}
		return 0;
	}

	protected int getRangeString(
			int segmentIndex,
			AddressSegmentParams params,
			int lowerLeadingZerosCount,
			int upperLeadingZerosCount,
			boolean maskUpper,
			StringBuilder appendable) {
		String stringPrefix = params.getSegmentStrPrefix();
		int radix = params.getRadix();
		String rangeSeparator = params.getWildcards().rangeSeparator;
		boolean uppercase = params.isUppercase();
		return getRangeString(rangeSeparator, lowerLeadingZerosCount, upperLeadingZerosCount, stringPrefix, radix, uppercase, maskUpper, appendable);
	}
	
	protected int getRangeString(
			String rangeSeparator,
			int lowerLeadingZerosCount,
			int upperLeadingZerosCount,
			String stringPrefix,
			int radix,
			boolean uppercase,
			boolean maskUpper,
			StringBuilder appendable) {
		int prefLen = stringPrefix.length();
		boolean hasStringPrefix = prefLen > 0;
		if(appendable == null) {
			int count = lowerLeadingZerosCount + upperLeadingZerosCount + 
					getLowerStringLength(radix) + getUpperStringLength(radix) + rangeSeparator.length();
			if(hasStringPrefix) {
				count += prefLen << 1;
			}
			return count;
		} else {
			if(hasStringPrefix) {
				appendable.append(stringPrefix);
			}
			if(lowerLeadingZerosCount > 0) {
				getLeadingZeros(lowerLeadingZerosCount, appendable);
			}
			getLowerString(radix, uppercase, appendable);
			appendable.append(rangeSeparator);
			if(hasStringPrefix) {
				appendable.append(stringPrefix);
			}
			if(upperLeadingZerosCount > 0) {
				getLeadingZeros(upperLeadingZerosCount, appendable);
			}
			if(maskUpper) {
				getUpperStringMasked(radix, uppercase, appendable);
			} else {
				getUpperString(radix, uppercase, appendable);
			}
		}
		return 0;
	}
	
	protected int getSplitRangeString(
			int segmentIndex,
			AddressSegmentParams params,
			StringBuilder appendable) {
		String stringPrefix = params.getSegmentStrPrefix();
		int radix = params.getRadix();
		int leadingZeroCount = params.getLeadingZeros(segmentIndex);
		//for split ranges, it is the leading zeros of the upper value that matters
		leadingZeroCount = adjustUpperLeadingZeroCount(leadingZeroCount, radix);
		Wildcards wildcards = params.getWildcards();
		boolean uppercase = params.isUppercase();
		char splitDigitSeparator = params.getSplitDigitSeparator() == null ? 0 : params.getSplitDigitSeparator();
		boolean reverseSplitDigits = params.isReverseSplitDigits();
		String rangeSeparator = wildcards.rangeSeparator;
		if(appendable == null) {
			return getSplitRangeStringLength(
					rangeSeparator,
					wildcards.wildcard,
					leadingZeroCount,
					radix,
					uppercase, 
					splitDigitSeparator,
					reverseSplitDigits,
					stringPrefix);
		} else {
			boolean hasLeadingZeros = leadingZeroCount != 0;
			if(hasLeadingZeros && !reverseSplitDigits) {
				getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable);
				appendable.append(splitDigitSeparator);
				hasLeadingZeros = false;
			}
			getSplitRangeString(
					rangeSeparator,
					wildcards.wildcard,
					radix,
					uppercase, 
					splitDigitSeparator,
					reverseSplitDigits,
					stringPrefix,
					appendable);
			if(hasLeadingZeros) {
				appendable.append(splitDigitSeparator);
				getSplitLeadingZeros(leadingZeroCount, splitDigitSeparator, stringPrefix, appendable);
			}
		}
		return 0;
	}
}

