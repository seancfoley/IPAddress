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

package inet.ipaddr;

import java.math.BigInteger;
import java.util.Iterator;

import inet.ipaddr.AddressComparator.CountComparator;
import inet.ipaddr.format.AddressDivision;
import inet.ipaddr.format.AddressDivisionSeries;

/**
 * @custom.core
 * @author sfoley
 *
 */
public abstract class Address implements AddressSegmentSeries, Comparable<Address> {
	
	private static final long serialVersionUID = 3L;

	public static interface SegmentValueProvider {
		int getValue(int segmentIndex, int segmentByteCount);
	}
	
	public static final String HEX_PREFIX = "0x";
	public static final String OCTAL_PREFIX = "0";
	public static final char RANGE_SEPARATOR = '-';
	public static final String RANGE_SEPARATOR_STR = String.valueOf(RANGE_SEPARATOR);
	public static final char ALTERNATIVE_RANGE_SEPARATOR = '›';
	public static final String ALTERNATIVE_RANGE_SEPARATOR_STR = String.valueOf(ALTERNATIVE_RANGE_SEPARATOR);
	public static final char SEGMENT_WILDCARD = '*';
	public static final String SEGMENT_WILDCARD_STR = String.valueOf(SEGMENT_WILDCARD);
	public static final String ALTERNATIVE_SEGMENT_WILDCARD_STR = "¿";
	public static final char SEGMENT_SQL_WILDCARD = '%';
	public static final String SEGMENT_SQL_WILDCARD_STR = String.valueOf(SEGMENT_SQL_WILDCARD);
	public static final char SEGMENT_SQL_SINGLE_WILDCARD = '_';
	public static final String SEGMENT_SQL_SINGLE_WILDCARD_STR = String.valueOf(SEGMENT_SQL_SINGLE_WILDCARD);
	
	public static final AddressComparator addressComparator = new CountComparator();
	
	/* the segments.  For IPv4, each element is actually just 1 byte and the array has 4 elements, while for IPv6, each element is 2 bytes and the array has 8 elements. */
	final AddressSection addressSection;

	/* an object encapsulating a string representing the address, which is the one used to construct the address if the address was constructed from a string */
	protected HostIdentifierString fromString;

	/**
	 * Constructs an address.
	 * @param section the address segments
	 */
	public Address(AddressSection section) {
		addressSection = section;
	}
	
	protected static String getMessage(String key) {
		return HostIdentifierException.getMessage(key);
	}

	@Override
	public int getSegmentCount() {
		return addressSection.getSegmentCount();
	}
	
	@Override
	public int getDivisionCount() {
		return addressSection.getDivisionCount();
	}
	
	@Override
	public int getBitCount() {
		return addressSection.getBitCount();
	}

	@Override
	public int getByteCount() {
		return addressSection.getByteCount();
	}

	public AddressSection getSection() {
		return addressSection;
	}

	@Override
	public AddressSection getSection(int index) {
		return getSection().getSection(index);
	}

	@Override
	public AddressSection getSection(int index, int endIndex) {
		return getSection().getSection(index, endIndex);
	}
	
	@Override
	public AddressDivision getDivision(int index) {
		return addressSection.getDivision(index);
	}
	
	@Override
	public AddressSegment getSegment(int index) {
		return addressSection.getSegment(index);
	}

	@Override
	public AddressSegment[] getSegments() {
		return addressSection.getSegments();
	}
	
	@Override
	public void getSegments(AddressSegment segs[]) {
		addressSection.getSegments(segs);
	}
	
	@Override
	public void getSegments(int start, int end, AddressSegment segs[], int index) {
		addressSection.getSegments(start, end, segs, index);
	}
	
	/**
	 * @return the maximum possible segment value for this type of address.  
	 * Note this is not the maximum value of the segments in this specific address.
	 */
	public abstract int getMaxSegmentValue();
	
	@Override
	public abstract Iterable<? extends Address> getIterable();
	
	@Override
	public abstract Iterator<? extends Address> iterator();
	
	@Override
	public Iterator<? extends AddressSegment[]> segmentsIterator() {
		return getSection().segmentsIterator();
	}
	
	@Override
	public abstract Address getLower();
	
	@Override
	public abstract Address getUpper();
	
	@Override
	public boolean isMultipleByPrefix() {
		return addressSection.isMultipleByPrefix();
	}
	
	/**
	 * @return whether this address represents more than one address.
	 * Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
	 */
	@Override
	public boolean isMultiple() {
		return addressSection.isMultiple();
	}

	/**
	 * @return whether this address represents a network prefix or the set of all addresses with the same network prefix
	 */
	@Override
	public boolean isPrefixed() {
		return addressSection.isPrefixed();
	}
	
	/**
	 * the largest number of high bits for which this address represents all addresses with the same set of high bits
	 */
	@Override
	public Integer getPrefixLength() {
		return addressSection.getPrefixLength();
	}
	
	@Override
	public int getMinPrefix() {
		return getSection().getMinPrefix();
	}

	/**
	 * Returns a prefix length for which the range of this address can be specified only using the address lower value and the prefix length
	 * 
	 * If no such prefix exists, returns null.
	 * 
	 * IP address examples:
	 * 1.2.3.4 returns 32
	 * 1.2.*.* returns 16
	 * 1.2.*.0/24 returns 16 
	 * 1.2.*.4 returns null
	 * 1.2.252-255.* returns 22
	 * 1.2.3.4/x returns x
	 * 
	 * @return the prefix length or null if it does not exist
	 */
	@Override
	public Integer getEquivalentPrefix() {
		return getSection().getEquivalentPrefix();
	}
	
	/**
	 * @see java.net.InetAddress#isMulticastAddress()
	 */
	public abstract boolean isMulticast();
	
	/**
	 * Gets the count of addresses that this address may represent.
	 * 
	 * If this address is not a CIDR network prefix and it has no range, then there is only one such address.
	 * 
	 * @return
	 */
	@Override
	public BigInteger getCount() {
		return addressSection.getCount();
	}
	
	@Override
	public int isMore(AddressDivisionSeries other) {
		return addressSection.isMore(other);
	}

	@Override
	public byte[] getBytes() {
		return addressSection.getBytes();
	}
	
	@Override
	public byte[] getBytes(byte bytes[]) {
		return addressSection.getBytes(bytes);
	}
	
	/**
	 * Gets the bytes for the highest address in the range represented by this address.
	 * 
	 * @return
	 */
	@Override
	public byte[] getUpperBytes() {
		return addressSection.getUpperBytes();
	}
	
	@Override
	public byte[] getUpperBytes(byte bytes[]) {
		return addressSection.getUpperBytes(bytes);
	}

	@Override
	public boolean isZero() {
		return addressSection.isZero();
	}
	
	@Override
	public boolean isFullRange() {
		return addressSection.isFullRange();
	}
	
	public abstract boolean isLocal();
	
	@Override
	public int hashCode() {
		return addressSection.hashCode();
	}
	
	@Override
	public int compareTo(Address other) {
		if(this == other) {
			return 0;
		}
		return addressComparator.compare(this, other);
	}

	protected abstract boolean isFromSameString(HostIdentifierString otherString);
	
	public boolean isSameAddress(Address other) {
		return other == this || getSection().equals(other.getSection());
	}
	
	/**
	 * Two Address objects are equal if they represent the same set of addresses.
	 */
	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof Address) {
			Address other = (Address) o;
			if(isFromSameString(other.fromString)) {
				return true;
			}
			return isSameAddress(other);
		}
		return false;
	}
	
	public abstract boolean contains(Address other);
	
	/**
	 * @return whether this address represents more than one address and the set of addresses is determined entirely by the prefix length.
	 */
	@Override
	public boolean isRangeEquivalentToPrefix() {
		return addressSection.isRangeEquivalentToPrefix();
	}
	
	/**
	 * Returns a host identifier string representation for this address,
	 * which will be validated already.
	 * 
	 * @return
	 */
	public HostIdentifierString toAddressString() {
		return fromString;
	}

	/**
	 * Writes this address as a single hexadecimal value with always the exact same number of characters, with or without a preceding 0x prefix.
	 * 
	 * If this section represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 */
	@Override
	public String toHexString(boolean with0xPrefix) {
		return addressSection.toHexString(with0xPrefix);
	}

	/**
	 * The normalized string returned by this method is a common and consistent representation of the address.
	 * 
	 * The string returned by this method is unique for each address.
	 */
	@Override
	public String toNormalizedString() {
		return addressSection.toNormalizedString();
	}
	
	/**
	 * This produces a canonical string.
	 * 
	 * RFC 5952 describes canonical representations for Ipv6
	 * http://en.wikipedia.org/wiki/IPv6_address#Recommended_representation_as_text
	 * http://tools.ietf.org/html/rfc5952
	 * 
	 * Each address has a unique canonical string, not counting the prefix, which can give two equal addresses different strings.
	 */
	@Override
	public String toCanonicalString() {
		return addressSection.toCanonicalString();
	}
	
	/**
	 * Produce short strings for the address in the usual address format.
	 * 
	 * Each address has a unique compressed string.
	 * 
	 */
	@Override
	public String toCompressedString() {
		return addressSection.toCompressedString();
	}
	
	@Override
	public String toString() {
		return toNormalizedString();
	}
	
	@Override
	public abstract Address reverseSegments();
	
	@Override
	public abstract Address reverseBits(boolean perByte);
	
	@Override
	public abstract Address reverseBytes();
	
	@Override
	public abstract Address reverseBytesPerSegment();
	
	@Override
	public abstract Address removePrefixLength();
	
	@Override
	public abstract Address adjustPrefixBySegment(boolean nextSegment);

	@Override
	public abstract Address adjustPrefixLength(int adjustment);

	@Override
	public abstract Address setPrefixLength(int prefixLength);
	
	@Override
	public abstract Address applyPrefixLength(int networkPrefixLength);
}
