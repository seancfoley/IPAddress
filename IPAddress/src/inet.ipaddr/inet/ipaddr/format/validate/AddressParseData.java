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

	// these are for the flags
	public static final int KEY_WILDCARD = 0x1, KEY_SINGLE_WILDCARD = 0x2, KEY_STANDARD_STR = 0x4, KEY_STANDARD_RANGE_STR = 0x8, KEY_RANGE_WILDCARD = 0x10;
		
	// these are for the segment values
	public static final int KEY_LOWER = 2, KEY_UPPER = 4, KEY_EXTENDED_LOWER = 6, KEY_EXTENDED_UPPER = 8;

	// for the radices
	public static final int KEY_LOWER_RADIX = 0, KEY_UPPER_RADIX = 16;

	// these are for the indices
	public static final int KEY_LOWER_STR_DIGITS_INDEX = 10, KEY_LOWER_STR_START_INDEX = 11, KEY_LOWER_STR_END_INDEX = 12,
				KEY_UPPER_STR_DIGITS_INDEX = 13, KEY_UPPER_STR_START_INDEX = 14, KEY_UPPER_STR_END_INDEX = 15;
		
	private static final int FLAGS_INDEX = 0;
	private static final int RADIX_INDEX = 1;
	
	private static final int SEGMENT_DATA_SIZE = KEY_UPPER_STR_END_INDEX + 1;
	
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
	
	static int totalCount;
	public static long averageT;
	
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
	
	void setAll(boolean val) {
		isAll = val;
	}
	
	int getAddressEndIndex() {
		return addressEndIndex;
	}
	
	void setAddressEndIndex(int val) {
		addressEndIndex = val;
	}
	
	void setSingleSegment(boolean val) {
		isSingleSegment = val;
	}
	
	boolean isSingleSegment() {
		return isSingleSegment;
	}
	
	void setHasWildcard(boolean val) {
		anyWildcard = val;
	}
	
	boolean hasWildcard() {
		return anyWildcard;
	}
	
	void setFlag(int segmentIndex, int flagIndicator, boolean value) {
		int index = (segmentIndex << 4) | FLAGS_INDEX;
		int segmentData[] = getSegmentData();
		if(value) {
			segmentData[index] |= flagIndicator;
		} else {
			segmentData[index] &= ~flagIndicator;
		}
	}
	
	boolean getFlag(int segmentIndex, int flagIndicator) {
		int segmentData[] = getSegmentData();
		return (segmentData[(segmentIndex << 4) | FLAGS_INDEX] & flagIndicator) != 0;
	}
	
	static boolean hasEitherFlag(int segmentIndex, int flagIndicator1, int flagIndicator2, int segmentData[]) {
		int flags = segmentData[(segmentIndex << 4) | FLAGS_INDEX];
		return ((flags & flagIndicator1) | (flags & flagIndicator2)) != 0;
	}
	
	boolean hasEitherFlag(int segmentIndex, int flagIndicator1, int flagIndicator2) {
		int segmentData[] = getSegmentData();
		return hasEitherFlag(segmentIndex, flagIndicator1, flagIndicator2, segmentData);
	}
	
	void setRadix(int segmentIndex, int indexIndicator, int value) {
		int segmentData[] = getSegmentData();
		int radixData = segmentData[(segmentIndex << 4) | RADIX_INDEX];
		radixData = (radixData & ~(0xffff << indexIndicator)) | ((0xffff & value) << indexIndicator);
		segmentData[(segmentIndex << 4) + RADIX_INDEX] = radixData;
	}
	
	void setRadix(int segmentIndex, int indexIndicator0, int value0, int indexIndicator1, int value1) {
		int radixData = ((0xffff & value0) << indexIndicator0) | ((0xffff & value1) << indexIndicator1);
		int segmentData[] = getSegmentData();
		segmentData[(segmentIndex << 4) + RADIX_INDEX] = radixData;
	}
	
	int getRadix(int segmentIndex, int indexIndicator) {
		int segmentData[] = getSegmentData();
		int radixData = segmentData[(segmentIndex << 4) | RADIX_INDEX];
		return 0xffff & (radixData >>> indexIndicator);
	}

	void setIndex(int segmentIndex, int indexIndicator, int value) {
		int segmentData[] = getSegmentData();
		segmentData[(segmentIndex << 4) | indexIndicator] = value;
	}
	
	void setIndex(int segmentIndex,
			int indexIndicator0, int value0,
			int indexIndicator1, int value1,
			int indexIndicator2, int value2,
			int indexIndicator3, int value3,
			int indexIndicator4, int value4,
			int indexIndicator5, int value5) {
		int baseIndex = segmentIndex << 4;
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
		return segmentData[(segmentIndex << 4) | indexIndicator];
	}
	
	void setValue(int segmentIndex, int indexIndicator0, long value0, int indexIndicator1, long value1) {
		int baseIndex = segmentIndex << 4;
		
		int index = baseIndex | indexIndicator0;
		int segmentData[] = getSegmentData();
		segmentData[index] = (int) (value0 >>> 32);
		segmentData[index + 1] = (int) (value0 & 0xffffffff);
		
		index = baseIndex | indexIndicator1;
		segmentData[index] = (int) (value1 >>> 32);
		segmentData[index + 1] = (int) (value1 & 0xffffffff);
	}
	
	void setValue(int segmentIndex, 
			int indexIndicator0, long value0, 
			int indexIndicator1, long value1, 
			int indexIndicator2, long value2, 
			int indexIndicator3, long value3) {
		int baseIndex = segmentIndex << 4;
		
		int segmentData[] = getSegmentData();
		int index = baseIndex | indexIndicator0;
		segmentData[index] = (int) (value0 >>> 32);
		segmentData[index + 1] = (int) (value0 & 0xffffffff);
		
		index = baseIndex | indexIndicator1;
		segmentData[index] = (int) (value1 >>> 32);
		segmentData[index + 1] = (int) (value1 & 0xffffffff);
		
		index = baseIndex | indexIndicator2;
		segmentData[index] = (int) (value2 >>> 32);
		segmentData[index + 1] = (int) (value2 & 0xffffffff);
		
		index = baseIndex | indexIndicator3;
		segmentData[index] = (int) (value3 >>> 32);
		segmentData[index + 1] = (int) (value3 & 0xffffffff);
	}

	void setValue(int segmentIndex, int indexIndicator, long value) {
		int index = (segmentIndex << 4) | indexIndicator;
		int upperValue = (int) (value >>> 32);
		int lowerValue = (int) (value & 0xffffffff);
		int segmentData[] = getSegmentData();
		segmentData[index] = upperValue;
		segmentData[index + 1] = lowerValue;
	}
	
	long getValue(int segmentIndex, int indexIndicator) {
		return getValue(segmentIndex, indexIndicator, getSegmentData());
	}
	
	protected static long getValue(int segmentIndex, int indexIndicator, int segmentData[]) {
		int index = (segmentIndex << 4) | indexIndicator;
		long upperValue = (long) segmentData[index];
		long lowerValue = 0xffffffffL & (long) (segmentData[index + 1]);
		long value = (upperValue << 32) | lowerValue;
		return value;
	}
	
	boolean isWildcard(int index) {
		return getFlag(index, KEY_WILDCARD);
	}
	
	boolean hasRange(int index) {
		return hasEitherFlag(index, KEY_SINGLE_WILDCARD, KEY_RANGE_WILDCARD);
	}
	
	static boolean hasRange(int index, int segmentData[]) {
		return hasEitherFlag(index, KEY_SINGLE_WILDCARD, KEY_RANGE_WILDCARD, segmentData);
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
					//int indices[] = this.indices[i];
					builder.append("\tstring: ").append(str.subSequence(getIndex(i, KEY_LOWER_STR_START_INDEX), getIndex(i, KEY_LOWER_STR_END_INDEX))).append('\n');
					builder.append("\tradix: ").append(getIndex(i, KEY_LOWER_RADIX)).append('\n');
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
							builder.append("\tupper radix: ").append(getIndex(i, KEY_UPPER_RADIX)).append('\n');
							builder.append("\tis standard range: ").append(getFlag(i, KEY_STANDARD_RANGE_STR)).append('\n');
						}
					} else {
						if(upper != lower) {
							builder.append("\tupper value: ").append(upper).append('\n');
							builder.append("\tupper value in hex: ").append(Long.toHexString(upper)).append('\n');
							builder.append("\tupper string: ").append(str.subSequence(getIndex(i, KEY_UPPER_STR_START_INDEX),getIndex(i, KEY_UPPER_STR_END_INDEX))).append('\n');
							builder.append("\tupper radix: ").append(getIndex(i, KEY_UPPER_RADIX)).append('\n');
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
	
	private ParsedIPAddress mixedParsedAddress;

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

	ParsedIPAddress getMixedParsedAddress() {
		return mixedParsedAddress;
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
				builder.append(", with IPv4 embedded address: ").append('\n').append(getMixedParsedAddress());
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

