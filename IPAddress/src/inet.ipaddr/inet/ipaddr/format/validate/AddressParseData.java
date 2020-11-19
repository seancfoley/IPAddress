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

package inet.ipaddr.format.validate;

import java.io.Serializable;
import java.math.BigInteger;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.mac.MACAddress;

/**
 * Maintains the data collected during parsing, the data that will be used to construct an address
 * 
 * @author scfoley@us.ibm.com
 *
 */
class AddressParseData implements Serializable {
	
	private static final long serialVersionUID = 4L;

	private static final int UPPER_ADJUSTMENT = 8;
	
	// these are for the flags
	// a standard string is a string showing only the lower value of a segment.  A standard range string shows both values, low to high, with the standard separator.
	public static final int KEY_WILDCARD = 0x10000, KEY_SINGLE_WILDCARD = 0x20000, KEY_STANDARD_STR = 0x40000,
			KEY_STANDARD_RANGE_STR = 0x80000, KEY_RANGE_WILDCARD = 0x100000, KEY_INFERRED_LOWER_BOUNDARY = 0x200000, KEY_INFERRED_UPPER_BOUNDARY = 0x400000, KEY_MERGED_MIXED = 0x800000;
	private static final int KEY_RADIX = 0xff;
	private static final int KEY_BIT_SIZE = 0xff00;
	private static final int BIT_SIZE_SHIFT = 8;

	public static final int KEY_LOWER_RADIX_INDEX = 0, KEY_BIT_SIZE_INDEX = KEY_LOWER_RADIX_INDEX, FLAGS_INDEX = KEY_LOWER_RADIX_INDEX; // the flags, radix and bit size are stored in the same int, the radix takes the low byte, the bit size the next byte, the remaining 16 bits are available for flags.
	
	public static final int KEY_UPPER_RADIX_INDEX = KEY_LOWER_RADIX_INDEX + UPPER_ADJUSTMENT;
	
	// these are for the segment values - they must be even-numbered 
	public static final int KEY_LOWER = 2, KEY_EXTENDED_LOWER = 4;
	public static final int KEY_UPPER = KEY_LOWER + UPPER_ADJUSTMENT, KEY_EXTENDED_UPPER = KEY_EXTENDED_LOWER + UPPER_ADJUSTMENT;
		
	// these are for the indices
	public static final int KEY_LOWER_STR_DIGITS_INDEX = 1, KEY_LOWER_STR_START_INDEX = 6, KEY_LOWER_STR_END_INDEX = 7,
			KEY_UPPER_STR_DIGITS_INDEX = KEY_LOWER_STR_DIGITS_INDEX + UPPER_ADJUSTMENT, KEY_UPPER_STR_START_INDEX = KEY_LOWER_STR_START_INDEX + UPPER_ADJUSTMENT, KEY_UPPER_STR_END_INDEX = KEY_LOWER_STR_END_INDEX + UPPER_ADJUSTMENT;
	
	private static final int SEGMENT_DATA_SIZE = 16, SEGMENT_INDEX_SHIFT = 4;

	private static final int IPV4_SEGMENT_DATA_SIZE = SEGMENT_DATA_SIZE * 4, IPV6_SEGMENT_DATA_SIZE = SEGMENT_DATA_SIZE * 8;
	
	private int segmentData[];
	
	private int segmentCount;
	
	private boolean anyWildcard;
	private boolean isEmpty, isAll;
	private boolean isSingleSegment;
	
	// these are indices into the original string used while parsing
	private int consecutiveSepIndex = -1;
	private int consecutiveSepSegmentIndex = -1;
	private int addressEndIndex;
	
	protected final CharSequence str;
	
	AddressParseData(CharSequence str) {
		this.str = str;
	}
	
	CharSequence getString() {
		return str;
	}
	
	void initSegmentData(int segmentCapacity) {
		int dataSize;
		if(segmentCapacity == 4) {
			dataSize = IPV4_SEGMENT_DATA_SIZE;
		} else if(segmentCapacity == 8) {
			dataSize = IPV6_SEGMENT_DATA_SIZE;
		}  else if(segmentCapacity == 1) {
			dataSize = SEGMENT_DATA_SIZE; // SEGMENT_DATA_SIZE * segmentCapacity
		} else {
			dataSize = segmentCapacity * SEGMENT_DATA_SIZE;
		}
		segmentData = new int[dataSize];
	}
	
	void releaseSegmentData() {
		segmentData = null;
	}

	int[] getSegmentData() {
		return segmentData;
	}
	
	void incrementSegmentCount() {
		++segmentCount;
	}
	
	public int getSegmentCount() {
		return segmentCount;
	}
	
	int getConsecutiveSeparatorSegmentIndex() {
		return consecutiveSepSegmentIndex;
	}
	
	void setConsecutiveSeparatorSegmentIndex(int val) {
		consecutiveSepSegmentIndex = val;
	}
	
	int getConsecutiveSeparatorIndex() {
		return consecutiveSepIndex;
	}
	
	void setConsecutiveSeparatorIndex(int val) {
		consecutiveSepIndex = val;
	}
	
	public boolean isProvidingEmpty() {
		return isEmpty;
	}
	
	void setEmpty(boolean val) {
		isEmpty = val;
	}
	
	boolean isAll() {
		return isAll;
	}
	
	void setAll() {
		isAll = true;
	}
	
	int getAddressEndIndex() {
		return addressEndIndex;
	}
	
	void setAddressEndIndex(int val) {
		addressEndIndex = val;
	}
	
	void setSingleSegment() {
		isSingleSegment = true;
	}
	
	boolean isSingleSegment() {
		return isSingleSegment;
	}
	
	void setHasWildcard() {
		anyWildcard = true;
	}
	
	boolean hasWildcard() {
		return anyWildcard;
	}

	void unsetFlag(int segmentIndex, int flagIndicator) {
		int index = (segmentIndex << SEGMENT_INDEX_SHIFT) | FLAGS_INDEX;
		int segmentData[] = getSegmentData();
		segmentData[index] &= ~flagIndicator;
	}
	
	boolean getFlag(int segmentIndex, int flagIndicator) {
		int segmentData[] = getSegmentData();
		return (segmentData[(segmentIndex << SEGMENT_INDEX_SHIFT) | FLAGS_INDEX] & flagIndicator) != 0;
	}
	
	boolean hasEitherFlag(int segmentIndex, int flagIndicator1, int flagIndicator2) {
		return getFlag(segmentIndex, flagIndicator1 | flagIndicator2);
	}
	
	int getRadix(int segmentIndex, int indexIndicator) {
		int segmentData[] = getSegmentData();
		int radix = (segmentData[(segmentIndex << SEGMENT_INDEX_SHIFT) | indexIndicator] & KEY_RADIX);
		if(radix == 0) {
			return IPv6Address.DEFAULT_TEXTUAL_RADIX; // 16 is the default, we only set the radix if not 16
		}
		return radix;
	}
	
	int getBitLength(int segmentIndex) {
		int segmentData[] = getSegmentData();
		int bitLength = (segmentData[(segmentIndex << SEGMENT_INDEX_SHIFT) | KEY_BIT_SIZE_INDEX] & KEY_BIT_SIZE) >>> BIT_SIZE_SHIFT;
		return bitLength;
	}
	
	void setBitLength(int segmentIndex, int length) {
		int segmentData[] = getSegmentData();
		segmentData[(segmentIndex << SEGMENT_INDEX_SHIFT) | KEY_BIT_SIZE_INDEX] |= ((length << BIT_SIZE_SHIFT) & KEY_BIT_SIZE);
	}

	void setIndex(int segmentIndex,
			int indexIndicator0, int value0,
			int indexIndicator1, int value1,
			int indexIndicator2, int value2,
			int indexIndicator3, int value3,
			int indexIndicator4, int value4,
			int indexIndicator5, int value5) {
		int baseIndex = segmentIndex << SEGMENT_INDEX_SHIFT;
		int segmentData[] = getSegmentData();
		segmentData[baseIndex | indexIndicator0] = value0;
		segmentData[baseIndex | indexIndicator1] = value1;
		segmentData[baseIndex | indexIndicator2] = value2;
		segmentData[baseIndex | indexIndicator3] = value3;
		segmentData[baseIndex | indexIndicator4] = value4;
		segmentData[baseIndex | indexIndicator5] = value5;
	}
	
	int getIndex(int segmentIndex, int indexIndicator) {
		return getIndex(segmentIndex , indexIndicator, getSegmentData());
	}
	
	static int getIndex(int segmentIndex, int indexIndicator, int segmentData[]) {
		return segmentData[(segmentIndex << SEGMENT_INDEX_SHIFT) | indexIndicator];
	}
	
	void set7IndexFlags(int segmentIndex,
			int indexIndicator0, int value0,
			int indexIndicator1, int value1,
			int indexIndicator2, int value2,
			int indexIndicator3, int value3,
			int indexIndicator4, int value4,
			int indexIndicator5, int value5,
			int indexIndicator6, int value6) {
		int baseIndex = segmentIndex << SEGMENT_INDEX_SHIFT;
		int segmentData[] = getSegmentData();
		segmentData[baseIndex | indexIndicator0] = value0;
		segmentData[baseIndex | indexIndicator1] = value1;
		segmentData[baseIndex | indexIndicator2] = value2;
		segmentData[baseIndex | indexIndicator3] = value3;
		segmentData[baseIndex | indexIndicator4] = value4;
		segmentData[baseIndex | indexIndicator5] = value5;
		segmentData[baseIndex | indexIndicator6] = value6;
	}
	
	void set8IndexFlags(int segmentIndex,
			int indexIndicator0, int value0,
			int indexIndicator1, int value1,
			int indexIndicator2, int value2,
			int indexIndicator3, int value3,
			int indexIndicator4, int value4,
			int indexIndicator5, int value5,
			int indexIndicator6, int value6,
			int indexIndicator7, int value7) {
		int baseIndex = segmentIndex << SEGMENT_INDEX_SHIFT;
		int segmentData[] = getSegmentData();
		segmentData[baseIndex | indexIndicator0] = value0;
		segmentData[baseIndex | indexIndicator1] = value1;
		segmentData[baseIndex | indexIndicator2] = value2;
		segmentData[baseIndex | indexIndicator3] = value3;
		segmentData[baseIndex | indexIndicator4] = value4;
		segmentData[baseIndex | indexIndicator5] = value5;
		segmentData[baseIndex | indexIndicator6] = value6;
		segmentData[baseIndex | indexIndicator7] = value7;
	}
	
	void set8Index4ValuesFlags(int segmentIndex,
			int indexIndicator0, int value0,
			int indexIndicator1, int value1,
			int indexIndicator2, int value2,
			int indexIndicator3, int value3,
			int indexIndicator4, int value4,
			int indexIndicator5, int value5,
			int indexIndicator6, int value6, 
			int indexIndicator7, int value7, 
			int indexIndicator8, long value8, 
			int indexIndicator9, long value9, 
			int indexIndicator10, long value10,
			int indexIndicator11, long value11) {
		int baseIndex = segmentIndex << SEGMENT_INDEX_SHIFT;
		int segmentData[] = getSegmentData();
		setIndexValuesFlags(baseIndex, segmentData, 
				indexIndicator0, value0,
				indexIndicator1, value1,
				indexIndicator2, value2,
				indexIndicator3, value3,
				indexIndicator4, value4,
				indexIndicator5, value5,
				indexIndicator6, value6, 
				indexIndicator8, value8,
				indexIndicator9, value9);
		segmentData[baseIndex | indexIndicator7] = value7;
		
		int index = baseIndex | indexIndicator10;
		segmentData[index] = (int) (value10 >>> Integer.SIZE);
		segmentData[index | 1] = (int) (value10 & 0xffffffff);
		
		index = baseIndex | indexIndicator11;
		segmentData[index] = (int) (value11 >>> Integer.SIZE);
		segmentData[index | 1] = (int) (value11 & 0xffffffff);
	}
	
	void set7Index4ValuesFlags(int segmentIndex,
			int indexIndicator0, int value0,
			int indexIndicator1, int value1,
			int indexIndicator2, int value2,
			int indexIndicator3, int value3,
			int indexIndicator4, int value4,
			int indexIndicator5, int value5,
			int indexIndicator6, int value6,
			int indexIndicator7, long value7, 
			int indexIndicator8, long value8, 
			int indexIndicator9, long value9, 
			int indexIndicator10, long value10) {
		int baseIndex = segmentIndex << SEGMENT_INDEX_SHIFT;
		int segmentData[] = getSegmentData();
		setIndexValuesFlags(baseIndex, segmentData, 
				indexIndicator0, value0,
				indexIndicator1, value1,
				indexIndicator2, value2,
				indexIndicator3, value3,
				indexIndicator4, value4,
				indexIndicator5, value5,
				indexIndicator6, value6,
				indexIndicator7, value7,
				indexIndicator8, value8);
		int index = baseIndex | indexIndicator9;
		segmentData[index] = (int) (value9 >>> Integer.SIZE);
		segmentData[index | 1] = (int) (value9 & 0xffffffff);
		
		index = baseIndex | indexIndicator10;
		segmentData[index] = (int) (value10 >>> Integer.SIZE);
		segmentData[index | 1] = (int) (value10 & 0xffffffff);
	}
	
	void set8Index2ValuesFlags(int segmentIndex,
			int indexIndicator0, int value0,
			int indexIndicator1, int value1,
			int indexIndicator2, int value2,
			int indexIndicator3, int value3,
			int indexIndicator4, int value4,
			int indexIndicator5, int value5,
			int indexIndicator6, int value6,
			int indexIndicator7, int value7, 
			int indexIndicator8, long value8,
			int indexIndicator9, long value9) {
		int baseIndex = segmentIndex << SEGMENT_INDEX_SHIFT;
		int segmentData[] = getSegmentData();
		setIndexValuesFlags(baseIndex, segmentData, 
				indexIndicator0, value0,
				indexIndicator1, value1,
				indexIndicator2, value2,
				indexIndicator3, value3,
				indexIndicator4, value4,
				indexIndicator5, value5,
				indexIndicator6, value6,
				indexIndicator8, value8, 
				indexIndicator9, value9);
		segmentData[baseIndex | indexIndicator7] = value7;
	}
	
	void set7Index2ValuesFlags(int segmentIndex,
			int indexIndicator0, int value0,
			int indexIndicator1, int value1,
			int indexIndicator2, int value2,
			int indexIndicator3, int value3,
			int indexIndicator4, int value4,
			int indexIndicator5, int value5,
			int indexIndicator6, int value6,
			int indexIndicator7, long value7, 
			int indexIndicator8, long value8) {
		int baseIndex = segmentIndex << SEGMENT_INDEX_SHIFT;
		int segmentData[] = getSegmentData();
		setIndexValuesFlags(baseIndex, segmentData, 
				indexIndicator0, value0,
				indexIndicator1, value1,
				indexIndicator2, value2,
				indexIndicator3, value3,
				indexIndicator4, value4,
				indexIndicator5, value5,
				indexIndicator6, value6,
				indexIndicator7, value7, 
				indexIndicator8, value8);
	}
	
	private static void setIndexValuesFlags(
			int baseIndex, 
			int segmentData[],
			int indexIndicator0, int value0,
			int indexIndicator1, int value1,
			int indexIndicator2, int value2,
			int indexIndicator3, int value3,
			int indexIndicator4, int value4,
			int indexIndicator5, int value5,
			int indexIndicator6, int value6,
			int indexIndicator7, long value7, 
			int indexIndicator8, long value8) {
		segmentData[baseIndex | indexIndicator0] = value0;
		segmentData[baseIndex | indexIndicator1] = value1;
		segmentData[baseIndex | indexIndicator2] = value2;
		segmentData[baseIndex | indexIndicator3] = value3;
		segmentData[baseIndex | indexIndicator4] = value4;
		segmentData[baseIndex | indexIndicator5] = value5;
		segmentData[baseIndex | indexIndicator6] = value6;
		
		int index = baseIndex | indexIndicator7;
		segmentData[index] = (int) (value7 >>> Integer.SIZE);
		segmentData[index | 1] = (int) (value7 & 0xffffffff);
		
		index = baseIndex | indexIndicator8;
		segmentData[index] = (int) (value8 >>> Integer.SIZE);
		segmentData[index | 1] = (int) (value8 & 0xffffffff);
	}

	void setValue(int segmentIndex, int indexIndicator, long value) {
		int index = (segmentIndex << SEGMENT_INDEX_SHIFT) | indexIndicator;
		int upperValue = (int) (value >>> Integer.SIZE);
		int lowerValue = (int) (value & 0xffffffff);
		int segmentData[] = getSegmentData();
		segmentData[index] = upperValue;
		segmentData[index | 1] = lowerValue;
	}
	
	long getValue(int segmentIndex, int indexIndicator) {
		return getValue(segmentIndex, indexIndicator, getSegmentData());
	}
	
	protected static long getValue(int segmentIndex, int indexIndicator, int segmentData[]) {
		int index = (segmentIndex << SEGMENT_INDEX_SHIFT) | indexIndicator;
		long upperValue = (long) segmentData[index];
		long lowerValue = 0xffffffffL & (long) (segmentData[index | 1]);
		long value = (upperValue << 32) | lowerValue;
		return value;
	}
	
	boolean isMergedMixed(int index) {
		return getFlag(index, KEY_MERGED_MIXED);
	}
	
	boolean isWildcard(int index) {
		return getFlag(index, KEY_WILDCARD);
	}
	
	boolean hasRange(int index) {
		return hasEitherFlag(index, KEY_SINGLE_WILDCARD, KEY_RANGE_WILDCARD);
	}
	
	boolean isInferredUpperBoundary(int index) {
		return getFlag(index, KEY_INFERRED_UPPER_BOUNDARY);
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		CharSequence str = getString();
		builder.append("address string: ").append(str).append('\n');
		int addressEndIndex = getAddressEndIndex();
		if(addressEndIndex > 0 && addressEndIndex < str.length()) {
			builder.append("address end: ").append(str.subSequence(addressEndIndex, str.length())).append('\n');
		}
		int segmentCount = getSegmentCount();
		builder.append("segment count: ").append(segmentCount).append('\n');
		if(segmentCount > 0) {
			for(int i = 0; i < segmentCount; i++) {
				builder.append("segment ").append(i).append(":\n");
				boolean isWildcard = isWildcard(i);
				if(isWildcard) {
					builder.append("\tis wildcard").append('\n');
				} else {
					long lower = getValue(i, KEY_LOWER);
					long upper = getValue(i, KEY_UPPER);
					long extendedUpper = getValue(i, KEY_EXTENDED_UPPER);
					long extendedLower = getValue(i, KEY_EXTENDED_LOWER);
					BigInteger lowerResult;
					if(extendedLower != 0) {
						BigInteger extended = BigInteger.valueOf(extendedLower);
						BigInteger shiftMore = extended.shiftLeft(Long.SIZE);
						BigInteger notExtended = BigInteger.valueOf(lower);
						lowerResult = shiftMore.or(notExtended);
						builder.append("\tvalue: ").append(lowerResult).append('\n');
						builder.append("\tvalue in hex: ").append(lowerResult.toString(16)).append('\n');
					} else {
						builder.append("\tvalue: ").append(lower).append('\n');
						builder.append("\tvalue in hex: ").append(Long.toHexString(lower)).append('\n');
						lowerResult = null;
					}
					builder.append("\tstring: ").append(str.subSequence(getIndex(i, KEY_LOWER_STR_START_INDEX), getIndex(i, KEY_LOWER_STR_END_INDEX))).append('\n');
					builder.append("\tradix: ").append(getRadix(i, KEY_LOWER_RADIX_INDEX)).append('\n');
					builder.append("\tis standard: ").append(getFlag(i, KEY_STANDARD_STR)).append('\n');
					if(extendedUpper != 0) {
						BigInteger extended = BigInteger.valueOf(extendedUpper);
						BigInteger shiftMore = extended.shiftLeft(Long.SIZE);
						BigInteger notExtended = BigInteger.valueOf(upper);
						BigInteger result = shiftMore.or(notExtended);
						if(!result.equals(lowerResult)) {
							builder.append("\tupper value: ").append(result).append('\n');
							builder.append("\tupper value in hex: ").append(result.toString(16)).append('\n');
							builder.append("\tupper string: ").append(str.subSequence(getIndex(i, KEY_UPPER_STR_START_INDEX), getIndex(i, KEY_UPPER_STR_END_INDEX))).append('\n');
							builder.append("\tupper radix: ").append(getRadix(i, KEY_UPPER_RADIX_INDEX)).append('\n');
							builder.append("\tis standard range: ").append(getFlag(i, KEY_STANDARD_RANGE_STR)).append('\n');
						}
					} else {
						if(upper != lower) {
							builder.append("\tupper value: ").append(upper).append('\n');
							builder.append("\tupper value in hex: ").append(Long.toHexString(upper)).append('\n');
							builder.append("\tupper string: ").append(str.subSequence(getIndex(i, KEY_UPPER_STR_START_INDEX),getIndex(i, KEY_UPPER_STR_END_INDEX))).append('\n');
							builder.append("\tupper radix: ").append(getRadix(i, KEY_UPPER_RADIX_INDEX)).append('\n');
							builder.append("\tis standard range: ").append(getFlag(i, KEY_STANDARD_RANGE_STR)).append('\n');
						}
					}
					if(getFlag(i, KEY_SINGLE_WILDCARD)) {
						builder.append("\thas single wildcard: ").append('\n');
					}
				}
			}
			builder.append("has a wildcard segment: ").append(hasWildcard()).append('\n');
			int consecutiveSepIndex = getConsecutiveSeparatorIndex();
			if(consecutiveSepIndex >= 0) {
				builder.append("has compressed segment(s) at character ").append(consecutiveSepIndex + 1).append('\n');
			}
			if(isSingleSegment()) {
				builder.append("is single segment").append('\n');
			}
		} else if (isProvidingEmpty()) {
			builder.append("is empty").append('\n');
		} else if (isAll()) {
			builder.append("is all addresses").append('\n');
		}
		return builder.toString();
	}
}

/**
 * Stores the data from a parsed address.  This data can later be translated into {@link IPv4Address} or {@link IPv6Address} objects.
 * @author sfoley
 *
 */
class IPAddressParseData extends AddressParseData {

	private static final long serialVersionUID = 4L;
	
	private ParsedHostIdentifierStringQualifier qualifier = ParsedHost.NO_QUALIFIER;
	private int qualifierIndex = -1;
	
	private boolean hasPrefixSeparator, isZoned;
	
	private IPVersion ipVersion;
	
	private boolean is_inet_aton_joined;
	protected boolean has_inet_aton_value; // either octal 01 or hex 0x1
	protected boolean hasIPv4LeadingZeros;
	protected boolean isBinary;
	
	ParsedIPAddress mixedParsedAddress;

	private boolean isBase85, isBase85Zoned;
	
	IPAddressParseData(CharSequence str) {
		super(str);
	}

	AddressParseData getAddressParseData() {
		return this;
	}
	
	public IPVersion getProviderIPVersion() {
		return ipVersion;
	}

	void setVersion(IPVersion val) {
		ipVersion = val;
	}
	
	public boolean isProvidingIPv6() {
		IPVersion version = getProviderIPVersion();
		return version != null && version.isIPv6();
	}
	
	public boolean isProvidingIPv4() {
		IPVersion version = getProviderIPVersion();
		return version != null && version.isIPv4();
	}

	void set_inet_aton_joined(boolean val) {
		is_inet_aton_joined = val;
	}

	boolean is_inet_aton_joined() {
		return is_inet_aton_joined;
	}
	
	void set_has_inet_aton_value(boolean val) {
		has_inet_aton_value = val;
	}
	
	boolean has_inet_aton_value() {
		return has_inet_aton_value;
	}
	
	void setHasIPv4LeadingZeros(boolean val) {
		hasIPv4LeadingZeros = val;
	}
	
	boolean hasIPv4LeadingZeros() {
		return hasIPv4LeadingZeros;
	}
	
	void setHasBinaryDigits(boolean val) {
		isBinary = val;
	}
	
	boolean hasBinaryDigits() {
		return isBinary;
	}
	
	ParsedHostIdentifierStringQualifier getQualifier() {
		return qualifier;
	}
	
	void setQualifier(ParsedHostIdentifierStringQualifier qualifier) {
		this.qualifier = qualifier;
	}
	
	void clearQualifier() {
		qualifierIndex = -1;
		isBase85Zoned = hasPrefixSeparator = isZoned = false;
		qualifier = ParsedHost.NO_QUALIFIER;
	}
	
	void setQualifierIndex(int index) {
		qualifierIndex = index;
	}

	int getQualifierIndex() {
		return qualifierIndex;
	}

	boolean isZoned() {
		return isZoned;
	}
	
	void setZoned(boolean val) {
		isZoned = val;
	}
	
	void setHasPrefixSeparator(boolean val) {
		hasPrefixSeparator = val;
	}
	
	public boolean hasPrefixSeparator() {
		return hasPrefixSeparator;
	}
	
	public boolean isProvidingBase85IPv6() {
		return isBase85;
	}
	
	void setBase85(boolean val) {
		isBase85 = val;
	}
	
	boolean isBase85Zoned() {
		return isBase85Zoned;
	}
	
	void setBase85Zoned(boolean val) {
		isBase85Zoned = val;
	}

	boolean isCompressed() {
		return getAddressParseData().getConsecutiveSeparatorIndex() >= 0;
	}

	boolean isCompressed(int index, int segmentData[]) {
		int end = AddressParseData.getIndex(index, AddressParseData.KEY_UPPER_STR_END_INDEX, segmentData);
		int start = AddressParseData.getIndex(index, AddressParseData.KEY_LOWER_STR_START_INDEX, segmentData);
		return start == end;
	}
	
	boolean isCompressed(int index) {
		AddressParseData addressParseData = getAddressParseData();
		return isCompressed(index, addressParseData.getSegmentData());
	}

	public boolean isProvidingMixedIPv6() {
		return mixedParsedAddress != null;
	}

	void setMixedParsedAddress(ParsedIPAddress val) {
		mixedParsedAddress = val;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(getAddressParseData());
		builder.append("ip version: ").append(getProviderIPVersion());
		if(isProvidingIPv6()) {
			if(isProvidingMixedIPv6()) {
				if(isZoned()) {
					builder.append(", with zone ");
					printQualifier(builder);
				}
				if(hasPrefixSeparator()) {
					builder.append(", with prefix length ");
					printQualifier(builder);
				}
				builder.append(", with IPv4 embedded address: ").append('\n').append(mixedParsedAddress);
			} else {
				if(isProvidingBase85IPv6()) {
					builder.append(" base 85");
					if(isBase85Zoned()) {
						builder.append(", with zone ");
						printQualifier(builder);
					}
				} else {
					if(isZoned()) {
						builder.append(", with zone ");
						printQualifier(builder);
					}
				}
				if(hasPrefixSeparator()) {
					builder.append(", with prefix length ");
					printQualifier(builder);
				}
				builder.append('\n');
			}
		} else if(isProvidingIPv4()) {
			if(hasPrefixSeparator()) {
				builder.append(", with prefix length  ");
				printQualifier(builder);
			}
			if(is_inet_aton_joined()) {
				builder.append(", with joined segments");
			}
			if(has_inet_aton_value()) {
				builder.append(", with at least one hex or octal value");
			}
			builder.append('\n');
		}
		return builder.toString();
	}

	private void printQualifier(StringBuilder builder) {
		AddressParseData addressParseData = getAddressParseData();
		int qualifierIndex = getQualifierIndex();
		if(qualifierIndex >= 0) {//zone, prefix, or port
			CharSequence str = addressParseData.getString();
			builder.append(str.subSequence(qualifierIndex, str.length()));
		} else {
			builder.append("unknown");
		}
	}
}

class MACAddressParseData extends AddressParseData {
	
	private static final long serialVersionUID = 4L;
	
	static enum MACFormat {
		DASHED(MACAddress.DASH_SEGMENT_SEPARATOR),
		COLON_DELIMITED(MACAddress.COLON_SEGMENT_SEPARATOR),
		DOTTED(MACAddress.DOTTED_SEGMENT_SEPARATOR),
		SPACE_DELIMITED(MACAddress.SPACE_SEGMENT_SEPARATOR);
		
		private char separator;
		
		MACFormat(char separator) {
			this.separator = separator;
		}
		
		char getSeparator() {
			return separator;
		}
		
		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append("mac format:").append(super.toString()).append('\n');
			builder.append("segment separator:").append(separator).append('\n');
			return builder.toString();
		}
	};
	
	private boolean isDoubleSegment;
	private boolean isExtended;
	
	private MACFormat format;
	
	MACAddressParseData(CharSequence str) {
		super(str);
	}
	
	AddressParseData getAddressParseData() {
		return this;
	}
	
	MACFormat getFormat() {
		return format;
	}
	
	void setFormat(MACFormat val) {
		format = val;
	}
	
	void setDoubleSegment(boolean val) {
		isDoubleSegment = val;
	}
	
	boolean isDoubleSegment() {
		return isDoubleSegment;
	}
	
	void setExtended(boolean val) {
		isExtended = val;
	}
	
	boolean isExtended() {
		return isExtended;
	}
	
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(getAddressParseData());
		if(isDoubleSegment()) {
			builder.append("is double segment").append('\n');
		}
		builder.append("bit length:").append(isExtended() ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_BIT_COUNT : MACAddress.MEDIA_ACCESS_CONTROL_BIT_COUNT).append('\n');
		MACFormat format = getFormat();
		if(format != null) {
			builder.append(format);
		}
		return builder.toString();
	}
}

