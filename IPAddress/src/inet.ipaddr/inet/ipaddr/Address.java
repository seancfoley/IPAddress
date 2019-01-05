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

package inet.ipaddr;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.function.Function;

import inet.ipaddr.AddressComparator.CountComparator;
import inet.ipaddr.AddressComparator.ValueComparator;
import inet.ipaddr.format.AddressDivisionSeries;
import inet.ipaddr.ipv4.IPv4AddressNetwork;
import inet.ipaddr.ipv6.IPv6AddressNetwork;
import inet.ipaddr.mac.MACAddressNetwork;

/**
 * @custom.core
 * @author sfoley
 *
 */
public abstract class Address implements AddressSegmentSeries {
	
	private static final long serialVersionUID = 4L;
	
	public static interface AddressValueProvider {
		
		int getSegmentCount();

		SegmentValueProvider getValues();
		
		default SegmentValueProvider getUpperValues() {
			return getValues();
		}
	}
	
	/**
	 * @custom.core
	 * @author sfoley
	 *
	 */
	public static interface SegmentValueProvider {
		int getValue(int segmentIndex);
	}

	public static final String HEX_PREFIX = "0x";
	public static final String OCTAL_PREFIX = "0";
	public static final char RANGE_SEPARATOR = '-';
	public static final String RANGE_SEPARATOR_STR = String.valueOf(RANGE_SEPARATOR);
	public static final char ALTERNATIVE_RANGE_SEPARATOR = '»';
	public static final String ALTERNATIVE_RANGE_SEPARATOR_STR = String.valueOf(ALTERNATIVE_RANGE_SEPARATOR);
	public static final char SEGMENT_WILDCARD = '*';
	public static final String SEGMENT_WILDCARD_STR = String.valueOf(SEGMENT_WILDCARD);
	public static final String ALTERNATIVE_SEGMENT_WILDCARD_STR = "¿";
	public static final char SEGMENT_SQL_WILDCARD = '%';
	public static final String SEGMENT_SQL_WILDCARD_STR = String.valueOf(SEGMENT_SQL_WILDCARD);
	public static final char SEGMENT_SQL_SINGLE_WILDCARD = '_';
	public static final String SEGMENT_SQL_SINGLE_WILDCARD_STR = String.valueOf(SEGMENT_SQL_SINGLE_WILDCARD);
	
	public static final AddressComparator DEFAULT_ADDRESS_COMPARATOR = new CountComparator(true);
	public static final AddressComparator ADDRESS_LOW_VALUE_COMPARATOR = new ValueComparator(true, false);

	private static MACAddressNetwork macNetwork;
	private static IPv6AddressNetwork ipv6Network;
	private static IPv4AddressNetwork ipv4Network;

	/* the segments.  For IPv4, each element is actually just 1 byte and the array has 4 elements, 
	 * while for IPv6, each element is 2 bytes and the array has 8 elements. */
	final AddressSection addressSection;

	/* an object encapsulating a string representing the address, which is the one used to construct the address if the address was constructed from a string */
	protected HostIdentifierString fromString;
	
	/**
	 * Constructs an address.
	 * @param section the address segments
	 */
	protected Address(AddressSection section) {
		addressSection = section;
		if(!getNetwork().equals(addressSection.getNetwork())) {
			throw new NetworkMismatchException(addressSection);
		}
	}
	
	protected Address(Function<Address, AddressSection> supplier) {
		addressSection = supplier.apply(this);
		if(!getNetwork().equals(addressSection.getNetwork())) {
			throw new NetworkMismatchException(addressSection);
		}
	}
	
	public static IPv6AddressNetwork defaultIpv6Network() {
		if(ipv6Network == null) {
			synchronized(Address.class) {
				if(ipv6Network == null) {
					ipv6Network = new IPv6AddressNetwork();
				}
			}
		}
		return ipv6Network;
	}

	public static IPv4AddressNetwork defaultIpv4Network() {
		if(ipv4Network == null) {
			synchronized(Address.class) {
				if(ipv4Network == null) {
					ipv4Network = new IPv4AddressNetwork();
				}
			}
		}
		return ipv4Network;
	}
	
	public static MACAddressNetwork defaultMACNetwork() {
		if(macNetwork == null) {
			synchronized(Address.class) {
				if(macNetwork == null) {
					macNetwork = new MACAddressNetwork();
				}
			}
		}
		return macNetwork;
	}
	
	protected static String getMessage(String key) {
		return HostIdentifierException.getMessage(key);
	}

	@Override
	public int getSegmentCount() {
		return getSection().getSegmentCount();
	}
	
	@Override
	public int getDivisionCount() {
		return getSection().getDivisionCount();
	}
	
	@Override
	public int getBitCount() {
		return getSection().getBitCount();
	}

	@Override
	public int getByteCount() {
		return getSection().getByteCount();
	}

	@Override
	public AddressSection getSection() {
		return addressSection;
	}

	@Override
	public void getSegments(AddressSegment segs[]) {
		getSection().getSegments(segs);
	}

	@Override
	public void getSegments(int start, int end, AddressSegment segs[], int index) {
		getSection().getSegments(start, end, segs, index);
	}

	@Override
	public abstract Iterable<? extends Address> getIterable();

	@Override
	public abstract Iterator<? extends Address> iterator();
	
	@Override
	public abstract Iterator<? extends Address> prefixIterator();
	
	@Override
	public abstract Iterator<? extends Address> prefixBlockIterator();
	
	@Override
	public abstract Address increment(long increment) throws AddressValueException;
	
	@Override
	public abstract Address incrementBoundary(long increment) throws AddressValueException;
	
	@Override
	public abstract Address getLower();
	
	@Override
	public abstract Address getUpper();
	
	/**
	 * Returns whether this address represents more than a single individual address, whether it is a subnet.
	 * 
	 * Such addresses include CIDR/IP addresses (eg 1.2.3.0/25) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
	 * 
	 * @return whether this address represents more than one address.
	 */
	@Override
	public boolean isMultiple() {
		return getSection().isMultiple();
	}

	/**
	 * Returns whether this address has an associated prefix length
	 * 
	 * @return whether this address has an associated prefix length
	 */
	@Override
	public boolean isPrefixed() {
		return getSection().isPrefixed();
	}
	
	/**
	 * the largest number of high bits for which this address represents all addresses with the same set of high bits
	 */
	@Override
	public Integer getPrefixLength() {
		return getSection().getPrefixLength();
	}
	
	/**
	 * Returns the smallest prefix length possible such that this includes the block of addresses for that prefix.
	 * <p>
	 * If the entire range can be dictated this way, then this method returns the same value as {@link #getPrefixLengthForSingleBlock()}.  
	 * Otherwise, this method will return the minimal possible prefix that can be paired with this address, while {@link #getPrefixLengthForSingleBlock()} will return null.
	 *<p>
	 * In cases where the final bit in this address division series is constant, this returns the bit length of this address division series.
	 *
	 * @return the prefix length
	 */
	@Override
	public int getMinPrefixLengthForBlock() {
		return getSection().getMinPrefixLengthForBlock();
	}

	/**
	 * Returns a prefix length for which the range of this address subnet matches the the block of addresses for that prefix.
	 * <p>
	 * If the range can be dictated this way, then this method returns the same value as {@link #getMinPrefixLengthForBlock()}.
	 * <p>
	 * If no such prefix exists, returns null.
	 * <p>
	 * If this segment grouping represents a single value, returns the bit length of this address division series.
	 * <p>
	 * IP address examples:
	 * 1.2.3.4 returns 32
	 * 1.2.*.* returns 16
	 * 1.2.*.0/24 returns 16 in the case of PrefixConfiguration == ALL_PREFIXES_ARE_SUBNETS, 32 otherwise
	 * 1.2.*.4 returns null
	 * 1.2.252-255.* returns 22
	 * 1.2.3.4/x returns x in the case of PrefixConfiguration == ALL_PREFIXES_ARE_SUBNETS, 32 otherwise
	 * 1.2.0.0/16 returns 16 in the case of PrefixConfiguration == ALL_PREFIXES_ARE_SUBNETS or PREFIXED_ZERO_HOSTS_ARE_SUBNETS, 32 otherwise
	 * 
	 * @return the prefix length or null if it does not exist
	 */
	@Override
	public Integer getPrefixLengthForSingleBlock() {
		return getSection().getPrefixLengthForSingleBlock();
	}
	
	/**
	 * Whether the MAC address or IP address or other form of address is multicast.
	 * 
	 * @see java.net.InetAddress#isMulticastAddress()
	 */
	public abstract boolean isMulticast();
	
	/**
	 * Gets the count of addresses that this address may represent.
	 * 
	 * If this address is not a subnet block of multiple addresses or has no range of values, then there is only one such address.
	 * 
	 * @return
	 */
	@Override
	public BigInteger getCount() {
		return getSection().getCount();
	}
	
	/**
	 * Gets the count of prefixes in this address for the given prefix length.
	 * 
	 * If this address is not a subnet block of multiple addresses or has no range of values, then there is only one.
	 * 
	 * @return
	 */
	@Override
	public BigInteger getPrefixCount(int prefixLength) {
		return getSection().getPrefixCount(prefixLength);
	}

	/**
	 * If this has a prefix length, the count of the range of values in the prefix.
	 * 
	 * If this has no prefix, returns the same value as {@link #getCount()}
	 * 
	 * @return
	 */
	@Override
	public BigInteger getPrefixCount() {
		return getSection().getPrefixCount();
	}

	@Override
	public BigInteger getBlockCount(int segmentCount) {
		return getSection().getBlockCount(segmentCount);
	}

	@Override
	public int isMore(AddressDivisionSeries other) {
		return getSection().isMore(other);
	}

	@Override
	public byte[] getBytes() {
		return getSection().getBytes();
	}

	@Override
	public byte[] getBytes(byte bytes[]) {
		return getSection().getBytes(bytes);
	}

	@Override
	public byte[] getBytes(byte bytes[], int index) {
		return getSection().getBytes(bytes, index);
	}

	/**
	 * Gets the bytes for the highest address in the range of addresses represented by this address instance.
	 * 
	 * @return
	 */
	@Override
	public byte[] getUpperBytes() {
		return getSection().getUpperBytes();
	}

	@Override
	public byte[] getUpperBytes(byte bytes[]) {
		return getSection().getUpperBytes(bytes);
	}

	@Override
	public byte[] getUpperBytes(byte bytes[], int index) {
		return getSection().getUpperBytes(bytes, index);
	}

	@Override
	public BigInteger getValue() {
		return getSection().getValue();
	}
	
	@Override
	public BigInteger getUpperValue() {
		return getSection().getUpperValue();
	}

	@Override
	public boolean isZero() {
		return getSection().isZero();
	}
	
	@Override
	public boolean includesZero() {
		return getSection().includesZero();
	}
	
	@Override
	public boolean isMax() {
		return getSection().isMax();
	}
	
	@Override
	public boolean includesMax() {
		return getSection().includesMax();
	}
	
	@Override
	public boolean isFullRange() {
		return getSection().isFullRange();
	}
	
	/**
	 * Whether the address can be considered a local address (as opposed to a global one)
	 * @return
	 */
	public abstract boolean isLocal();
	
	@Override
	public int hashCode() {
		return getSection().hashCode();
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
	
	public boolean prefixEquals(Address other) {
		if(other == this) {
			return true;
		}
		return getSection().prefixEquals(other.getSection());
	}
	
	/**
	 * Returns whether this is same type and version of the given address and whether it contains all values in the given address or subnet
	 * 
	 * @param other
	 * @return
	 */
	public boolean contains(Address other) {
		if(other == this) {
			return true;
		}
		return getSection().contains(other.getSection());
	}

	@Override
	public boolean isSequential() {
		return getSection().isSequential();
	}

	/**
	 * Returns a host identifier string representation for this address,
	 * which will be already validated.
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
		return getSection().toHexString(with0xPrefix);
	}

	/**
	 * The normalized string returned by this method is a common and consistent representation of the address.
	 * <p>
	 * The string returned by this method is unique for each address.
	 */
	@Override
	public String toNormalizedString() {
		return getSection().toNormalizedString();
	}
	
	/**
	 * This produces a canonical string.
	 * <p>
	 * RFC 5952 describes canonical representations for Ipv6
	 * http://en.wikipedia.org/wiki/IPv6_address#Recommended_representation_as_text
	 * http://tools.ietf.org/html/rfc5952
	 * <p>
	 * Each address has a unique canonical string, not counting the prefix.  The prefix can cause two equal addresses to have different strings.
	 */
	@Override
	public String toCanonicalString() {
		return getSection().toCanonicalString();
	}
	
	/**
	 * Produce short strings for the address in the usual address format.
	 * 
	 * Each address has a unique compressed string.
	 * 
	 */
	@Override
	public String toCompressedString() {
		return getSection().toCompressedString();
	}
	
	@Override
	public String toString() {
		return toCanonicalString();
	}
	
	@Override
	public String[] getDivisionStrings() {
		return getSection().getDivisionStrings();
	}
	
	@Override
	public String[] getSegmentStrings() {
		return getSection().getSegmentStrings();
	}
	
	@Override
	public abstract Address reverseSegments();
	
	@Override
	public abstract Address reverseBits(boolean perByte);
	
	@Override
	public abstract Address reverseBytes();
	
	@Override
	public abstract Address reverseBytesPerSegment();
	
	/**
	 * Returns whether the address range has a prefix length and includes the block of values for its prefix length.
	 */
	@Override
	public boolean isPrefixBlock() {
		return getSection().isPrefixBlock();
	}

	@Override
	public boolean containsPrefixBlock(int prefixLength) {
		return getSection().containsPrefixBlock(prefixLength);
	}
	
	/**
	 * Returns whether the address range the block of values for a single prefix identified by its prefix length.
	 * This is similar to {@link #isPrefixBlock()} except that it returns false when
	 * the subnet has multiple prefixes.
	 * 
	 * For instance, 1.*.*.* /16 return false for this method and returns true for {@link #isPrefixBlock()}
	 */
	@Override
	public boolean isSinglePrefixBlock() {
		return getSection().isSinglePrefixBlock();
	}
	
	@Override
	public boolean containsSinglePrefixBlock(int prefixLength) {
		return getSection().containsSinglePrefixBlock(prefixLength);
	}

	@Override
	public abstract Address toPrefixBlock();
	
	@Override
	public abstract Address removePrefixLength();
	
	@Override
	public abstract Address withoutPrefixLength();
	
	@Override @Deprecated
	public abstract Address removePrefixLength(boolean zeroed);
	
	@Override
	public abstract Address adjustPrefixBySegment(boolean nextSegment);

	@Override
	public abstract Address adjustPrefixBySegment(boolean nextSegment, boolean zeroed);

	@Override
	public abstract Address adjustPrefixLength(int adjustment);

	@Override
	public abstract Address adjustPrefixLength(int adjustment, boolean zeroed);

	@Override
	public abstract Address setPrefixLength(int prefixLength);
	
	@Override
	public abstract Address setPrefixLength(int prefixLength, boolean zeroed);
	
	@Override
	public abstract Address applyPrefixLength(int networkPrefixLength);
}
