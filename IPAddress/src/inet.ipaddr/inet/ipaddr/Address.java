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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Stream;

import inet.ipaddr.AddressComparator.CountComparator;
import inet.ipaddr.AddressComparator.ValueComparator;
import inet.ipaddr.format.util.AddressComponentSpliterator;
import inet.ipaddr.ipv4.IPv4AddressNetwork;
import inet.ipaddr.ipv6.IPv6AddressNetwork;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressNetwork;

/**
 * An address, or a collection of multiple addresses.  Each segment can represent a single value or a range of values.
 * <p>
 * To construct one from a {@link java.lang.String} use 
 * {@link inet.ipaddr.IPAddressString} or  {@link inet.ipaddr.MACAddressString}
 * 
 * @custom.core
 * @author sfoley
 *
 */
public abstract class Address implements AddressSegmentSeries {

	private static final long serialVersionUID = 4L;

	/**
	 * @custom.core
	 * @author sfoley
	 *
	 */
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
	@FunctionalInterface
	public static interface SegmentValueProvider {
		int getValue(int segmentIndex);
	}

	public static final String HEX_PREFIX = "0x";
	public static final String OCTAL_PREFIX = "0";
	public static final char RANGE_SEPARATOR = '-';
	public static final String RANGE_SEPARATOR_STR = String.valueOf(RANGE_SEPARATOR);
	public static final char ALTERNATIVE_RANGE_SEPARATOR = '\u00bb'; //'»'; javadoc whines about this char
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
	public static final AddressComparator ADDRESS_HIGH_VALUE_COMPARATOR = new ValueComparator(true, true);

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
		if(!getNetwork().isCompatible(addressSection.getNetwork())) {
			throw new NetworkMismatchException(addressSection);
		}
	}

	protected Address(Function<Address, AddressSection> supplier) {
		addressSection = supplier.apply(this);
		if(!getNetwork().isCompatible(addressSection.getNetwork())) {
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
	public abstract AddressComponentSpliterator<? extends Address> spliterator();

	@Override
	public abstract Stream<? extends Address> stream();

	@Override
	public abstract Iterator<? extends Address> prefixIterator();
	
	@Override
	public abstract AddressComponentSpliterator<? extends Address> prefixSpliterator();

	@Override
	public abstract Stream<? extends Address> prefixStream();

	@Override
	public abstract Iterator<? extends Address> prefixBlockIterator();
	
	@Override
	public abstract AddressComponentSpliterator<? extends Address> prefixBlockSpliterator();

	@Override
	public abstract Stream<? extends Address> prefixBlockStream();

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
	 * Returns whether this address is an IP address
	 * 
	 * @return whether this address is an IP address
	 */
	public boolean isIPAddress() {
		return false;
	}

	/**
	 * Returns whether this address is a MAC address
	 * 
	 * @return whether this address is a MAC address
	 */
	public boolean isMACAddress() {
		return false;
	}

	/**
	 * If this address is an IP address, returns that {@link IPAddress}.  Otherwise, returns null.
	 * 
	 * @return the IP address
	 */
	public IPAddress toIPAddress() {
		return null;
	}

	/**
	 * If this address is a MAC address, returns that {@link MACAddress}.  Otherwise, returns null.
	 * 
	 * @return the MAC address
	 */
	public MACAddress toMACAddress() {
		return null;
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
	 * Returns a prefix length for which the range of this address subnet matches the block of addresses for that prefix.
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
	 * Returns whether this is same type and version of the given address and whether it overlaps with the values in the given address or subnet
	 * 
	 * @param other
	 * @return
	 */
	public boolean overlaps(Address other) {
		if(other == this) {
			return true;
		}
		return getSection().overlaps(other.getSection());
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

	/**
	 * Indicates where an address sits relative to the subnet ordering.
	 * <p>
	 * Determines how many address elements of a subnet precede the given address element, if the address is in the subnet.
	 * If above the subnet range, it is the distance to the upper boundary added to the subnet address count, and if below the subnet range, the distance to the lower boundary.
	 * <p>
	 * In other words, if the given address is not in the subnet but above it, returns the number of addresses preceding the address from the upper subnet boundary, 
	 * added to the total number of subnet addresses.  If the given address is not in the subnet but below it, returns the number of addresses following the address to the lower subnet boundary.
	 * <p>
	 * enumerate returns null when the argument is a multi-valued subnet. The argument must be an individual address.
	 * <p>
	 * When this address is also single-valued, the returned value is the distance (difference) between this address and the argument address.
	 * <p>
	 * enumerate is the inverse of the increment method:
	 * <ul><li>subnet.enumerate(subnet.increment(inc)) = inc</li>
	 * <li>subnet.increment(subnet.enumerate(newAddr)) = newAddr</li></ul>
	 *
	 * If the given address does not have the same version or type as this subnet or address, then null is returned.
	 */
	public abstract BigInteger enumerate(Address other);

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
	public String toHexString(boolean with0xPrefix) throws IncompatibleAddressException {
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
	
	@Override @Deprecated
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
	
	@Deprecated
	@Override
	public abstract Address applyPrefixLength(int networkPrefixLength);
	
	/** 
	 * Checks if the two arrays share the same list of addresses, subnets, or address collections, in any order, using address equality.
	 * The function can handle duplicates, ignoring them.
	 * @param addrs1
	 * @param addrs2
	 * @return
	 */
	public static boolean matchUnordered(Address addrs1[], Address addrs2[]) {
		int len1 = addrs1 == null ? 0 : addrs1.length;
		int len2 = addrs2 == null ? 0 : addrs2.length;
		boolean sameLen = len1 == len2;
		boolean result;
		if(len1 == 0 || len2 == 0) {
			result = sameLen;
		} else if(len1 == 1 && sameLen) {
			result = addrs1[0].equals(addrs2[0]);
		} else if(len1 == 2 && sameLen) {
			if(addrs1[0].equals(addrs2[0])) {
				result = addrs1[1].equals(addrs2[1]);
			} else if(result = addrs1[0].equals(addrs2[1])) {
				result = addrs1[1].equals(addrs2[0]);
			}
		} else {
			result = Objects.equals(asSet(addrs1), asSet(addrs2));
		}
		return result;
	}
	
	private static HashSet<Address> asSet(Address addrs[])  {
		int addrLen = addrs.length;
		if(addrLen > 0) {
			HashSet<Address> result = new HashSet<>();
			for(int i = 0; i < addrs.length; i++) {
				Address addr = addrs[i];
				result.add(addr);
			}
			return result;
		}
		return null;
	}
	
	/**
	 * Checks if the two arrays share the same ordered list of addresses, subnets, or address collections, using address equality.
	 * Duplicates are allowed, but must match their counterpart in the other array with each occurrence.
	 * @param addrs1
	 * @param addrs2
	 * @return
	 */
	public static boolean matchOrdered(Address addrs1[], Address addrs2[]) {
		int len1 = addrs1 == null ? 0 : addrs1.length;
		int len2 = addrs2 == null ? 0 : addrs2.length;
		if(len1 != len2) {
			return false;
		}
		for(int i = 0; i < addrs1.length; i++) {
			if(!addrs1[i].equals(addrs2[i])) {
				return false;
			}
		}
		return true;
	}
}
