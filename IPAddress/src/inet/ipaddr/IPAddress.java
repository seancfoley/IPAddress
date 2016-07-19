package inet.ipaddr;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.NoSuchElementException;

import inet.ipaddr.IPAddressComparator.CountComparator;
import inet.ipaddr.IPAddressConverter.DefaultAddressConverter;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.StringOptions;
import inet.ipaddr.IPAddressTypeNetwork.IPAddressCreator;
import inet.ipaddr.IPAddressTypeNetwork.IPAddressSegmentCreator;
import inet.ipaddr.format.IPAddressPart;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.sql.IPAddressSQLTranslator;
import inet.ipaddr.format.validate.AddressProvider;
import inet.ipaddr.format.validate.ParsedHost;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSegment;

/**
 * A single IP address, or a subnet of multiple addresses.  Subnets have one or more segments that are a range of values.
 * <p>
 * IPAddress objects are immutable and cannot change values.  This also makes them thread-safe.
 * <p>
 *
 * String creation:
 * <p>
 * There are several public classes used to customize IP address strings.
 * For single strings from an address or address section, you use {@link StringOptions} or {@link inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions} along with {@link #toNormalizedString(IPAddressSection.StringOptions)}.
 * Or you use one of the methods like {@link #toCanonicalString()} which does the same.
 * <p>
 * For string collections from an address or address section, use {@link inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringBuilderOptions}, {@link inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringBuilderOptions}, {@link IPStringBuilderOptions} along with {@link #toStringCollection(IPAddressSection.IPStringBuilderOptions)} or {@link #toStrings(IPAddressSection.IPStringBuilderOptions)}.
 * Or you use one of the methods {@link #toStandardStringCollection()}, {@link #toAllStringCollection()}, {@link #toStandardStrings()}, {@link #toAllStrings()} which does the same.
 * <p>
 * @custom.core
 * @author sfoley
 * 
 */
/*
 * Internal details of how this works:
 * 
 * 1. Building single strings steps:
 * StringOptions, IPv6StringOptions provides options for a user to specify a single string to be produced for a given address or section of an address.
 *  When calling toNormalizedString, each is mapped to a single IPv4StringParams/IPv6StringParams/StringParams object used to construct the string.
 *  Each IPv4StringParams/IPv6StringParams/StringParams constructs a single string with its toString method
 *  
 * 
 * 2. Building string collection steps:
 *  IPv4StringBuilderOptions, IPv6StringBuilderOptions, IPStringBuilderOptions provides options to create a set of multiple strings from a single IP Address or section of an address.
 * 	toStringCollection constructs a IPv6StringBuilder/IPv4StringBuilder/IPAddressStringBuilder for that address section
 *  The builder translates the options to a series of IPv4StringParams/IPv6StringParams/StringParams in addAllVariations
 *  When the set is being created, it will use each IPv4StringParams/IPv6StringParams/StringParams object to construct each unique string, using their toString method
 * 
 * 
 * Non-public classes:
 * IPv6StringParams, IPv4StringParams and the base classes StringParams and IPAddressPartStringParams: 
 * 	Used by both single string creation or creating collections of strings, these are not public.
 * IPv6StringBuilder/IPv4StringBuilder/IPAddressStringBuilder, used to create collections of strings, are not public either
 *
 */
public abstract class IPAddress implements Comparable<IPAddress>, Serializable {
	
	private static final long serialVersionUID = 1L;

	/**
	 * @author sfoley
	 */
	public enum IPVersion {
		IPV4,
		IPV6;
		
		public boolean isIPv4() {
			return this == IPV4;
		}
		
		public boolean isIPv6() {
			return this == IPV6;
		}
	};
	
	public static final char RANGE_SEPARATOR = '-';
	public static final String RANGE_SEPARATOR_STR = String.valueOf(RANGE_SEPARATOR);
	public static final char SEGMENT_WILDCARD = '*';
	public static final String SEGMENT_WILDCARD_STR = String.valueOf(SEGMENT_WILDCARD);
	public static final char SEGMENT_SQL_WILDCARD = '%';
	public static final String SEGMENT_SQL_WILDCARD_STR = String.valueOf(SEGMENT_SQL_WILDCARD);
	public static final char SEGMENT_SQL_SINGLE_WILDCARD = '_';
	public static final String SEGMENT_SQL_SINGLE_WILDCARD_STR = String.valueOf(SEGMENT_SQL_SINGLE_WILDCARD);
	public static final char PREFIX_LEN_SEPARATOR = '/';
	
	//The default way addresses are converted
	public static final IPAddressConverter addressConverter = new DefaultAddressConverter();
	
	//The default way addresses are compared
	public static final IPAddressComparator addressComparator = new CountComparator();
	
	/* the segments.  For IPv4, each element is actually just 1 byte and the array has 4 elements, while for IPv6, each element is 2 bytes and the array has 8 elements. */
	final IPAddressSection addressSection;
	
	/* an IPAddressString representing the address, which is the one used to construct the address if the address was constructed from a IPAddressString */
	protected IPAddressString fromString;
	
	/* a Host representing the address, which is the one used to construct the address if the address was resolved from a Host */
	HostName fromHost;
	
	/* a Host representing the canonical host for this address */
	private HostName canonicalHost;
	
	/* the associated InetAddress */
	protected transient InetAddress inetAddress;
	
	/**
	 * Represents an IP address or a set of addresses.
	 * @param section the address segments
	 */
	protected IPAddress(IPAddressSection section) {
		this.addressSection = section;
	}
	
	/**
	 * If this address was resolved from a host, returns that host.  Otherwise, does a reverse name lookup.
	 */
	public HostName toHostName() {
		HostName host = fromHost;
		if(host == null) {
			fromHost = host = toCanonicalHostName();
		}
		return host;
	}
	
	/**
	 * Does a reverse name lookup to get the canonical host name.
	 */
	public HostName toCanonicalHostName() {
		HostName host = canonicalHost;
		if(host == null) {
			if(isMultiple()) {
				throw new IPAddressTypeException(this, "ipaddress.error.unavailable.numeric");
			}
			InetAddress inetAddress = toInetAddress();
			//String hostStr1 = inetAddress.getHostName();
			String hostStr = inetAddress.getCanonicalHostName();//note: this does not return ipv6 addresses enclosed in brackets []
			if(hostStr.equals(inetAddress.getHostAddress())) {
				//we got back the address, so the host is me
				host = new HostName(hostStr, new ParsedHost(hostStr, AddressProvider.getProviderFor(this)));
				host.resolvedAddress = this;
			} else {
				//the reverse lookup succeeded in finding a host string
				//we might not be the default resolved address for the host, so we don't set that field
				host = new HostName(hostStr);
			}
		}
		return host;
	}
	
	protected static <T extends IPAddressSegment> T[] toSegments(
			byte bytes[],
			int segmentCount,
			int bytesPerSegment,
			int bitsPerSegment,
			IPAddressSegmentCreator<T> creator,
			Integer networkPrefixLength) {
		int cidrByteIndex = getByteIndex(networkPrefixLength, bytes.length);
		T segments[] = creator.createAddressSegmentArray(segmentCount);
		for(int i = 0; i < bytes.length; i += bytesPerSegment) {
			int value = 0;
			int k = bytesPerSegment + i;
			for(int j = i; j < k; j++) {
				int byteValue;
				if(j >= bytes.length) {
					byteValue = 0;
				} else if(j >= cidrByteIndex) {
					//apply the CIDR to the bytes
					if(j == cidrByteIndex) {
						int startBits = networkPrefixLength % 8;
						if(startBits != 0) {
							byte mask = (byte) (0xff << (8 - startBits));
							byteValue = (byte) (mask & bytes[j]);
						} else {
							byteValue = bytes[j];
						}
					} else {
						byteValue = 0;
					}
				} else {
					byteValue = bytes[j];
				}
				value <<= 8;
				value |= 0xff & byteValue;
			}
			int segmentIndex = i / bytesPerSegment;
			Integer prefix = IPAddressSection.getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, segmentIndex);
			segments[segmentIndex] = creator.createAddressSegment(value, prefix);
		}
		return segments;
	}
	
	public abstract IPAddressNetwork getNetwork();
	
	public static IPAddressNetwork network(IPVersion version) {
		return version.isIPv4() ? IPv4Address.network() : IPv6Address.network();
	}
	
	public static IPAddress getLoopback(IPVersion version) {
		return network(version).getLoopback();
	}
	
	public static IPAddress getLocalHost() throws UnknownHostException {
		return from(InetAddress.getLocalHost().getAddress());
	}
	
	public static String[] getStandardLoopbackStrings(IPVersion version) {
		return network(version).getStandardLoopbackStrings();
	}
	
	/**
	 * Breaks the address down into the standard segment arrangement.
	 * @return
	 */
	public IPAddressSection getSegments() {
		return addressSection;
	}
	
	/**
	 * Returns all the ways of breaking this address down into segments, as selected.
	 * @return
	 */
	public IPAddressPart[] getParts(IPStringBuilderOptions options) {
		return new IPAddressPart[] { getSegments() };
	}
	
	public int getMaxSegmentValue() {
		return IPAddressSegment.getMaxSegmentValue(getIPVersion());
	}
	
	public static int maxSegmentValue(IPVersion version) {
		return IPAddressSegment.getMaxSegmentValue(version);
	}
	
	public int getBytesPerSegment() {
		return IPAddressSegment.getByteCount(getIPVersion());
	}
	
	public int getBitsPerSegment() {
		return IPAddressSegment.getBitCount(getIPVersion());
	}
	
	public static int bitsPerSegment(IPVersion version) {
		return IPAddressSegment.getBitCount(version);
	}
	
	public abstract int getByteCount();
	
	public static int byteCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BYTE_COUNT : IPv6Address.BYTE_COUNT;
	}
	
	public abstract int getSegmentCount();
	
	public int getSegmentIndex(Integer networkPrefixLength) {
		return addressSection.getSegmentIndex(networkPrefixLength);
	}
	
	static int getSegmentIndex(Integer networkPrefixLength, int byteLength, int bytesPerSegment) {
		return IPAddressSection.getSegmentIndex(networkPrefixLength, byteLength, bytesPerSegment);
	}
	
	public int getByteIndex(Integer networkPrefixLength) {
		return addressSection.getByteIndex(networkPrefixLength);
	}
	
	static int getByteIndex(Integer networkPrefixLength, int byteLength) {
		return IPAddressSection.getByteIndex(networkPrefixLength, byteLength);
	}
	
	public static int segmentCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.SEGMENT_COUNT : IPv6Address.SEGMENT_COUNT;
	}
	
	public abstract int getBitCount();
	
	public static int bitCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BIT_COUNT : IPv6Address.BIT_COUNT;
	}
	
	public boolean isMultipleByNetworkPrefix() {
		return addressSection.isMultipleByNetworkPrefix();
	}
	
	/**
	 * @return whether this address represents more than one address.
	 * Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
	 */
	public boolean isMultiple() {
		return addressSection.isMultiple();
	}

	/**
	 * @return whether this address represents a network prefix or the set of all addresses with the same network prefix
	 */
	public boolean isPrefixed() {
		return addressSection.isPrefixed();
	}
	
	public Integer getNetworkPrefixLength() {
		return addressSection.getNetworkPrefixLength();
	}
	
	public IPAddressSegment getSegment(int index) {
		return addressSection.getSegment(index);
	}
	
	/**
	 * Gets the count of addresses that this address may represent.
	 * 
	 * If this address is not a CIDR network prefix and it has no range, then there is only one such address.
	 * 
	 * @return
	 */
	public BigInteger getCount() {
		if(!isMultiple()) {
			return BigInteger.ONE;
		}
		return addressSection.getCount();
	}
	
	/**
	 * If this represents a range of addresses, returns the lowest in the range.
	 * If this represents a single address, returns this.
	 * 
	 * @return
	 */
	public abstract IPAddress getLowest();
	
	/**
	 * If this represents a range of addresses, returns the highest in the range
	 * If this represents a single address, returns this.
	 * 
	 * @return
	 */
	public abstract IPAddress getHighest();
	
	protected <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> T getLowestOrHighest(IPAddressCreator<T, R, S> creator, boolean lowest) {
		if(!isMultiple() && !isPrefixed()) {
			return IPAddressSection.cast(this);
		}
		S[] segs = IPAddressSection.cast(addressSection.createLowestOrHighest(creator, lowest));
    	T result = creator.createAddressInternal(segs);
    	return result;
	}
	
	public abstract Iterator<? extends IPAddress> iterator();
	
	/**
	 * @return an object to iterate over the individual addresses represented by this object.
	 */
	public Iterable<? extends IPAddress> getAddresses() {
		return IPAddressSection.cast(this);
	}
	
	protected <T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> Iterator<T> iterator(final IPAddressCreator<T, R, S> creator) {
		return new Iterator<T>() {
			private boolean doThis = !isPrefixed() && !isMultiple(); //note that a non-multiple address can have a prefix (either /32 or /128)
			private Iterator<S[]> iterator = IPAddressSection.cast(addressSection.iterator(addressSection.getSegmentCreator(), doThis));
			
			@Override
			public boolean hasNext() {
				return iterator.hasNext() || doThis;
			}

		    @Override
			public T next() {
		    	if(!hasNext()) {
		    		throw new NoSuchElementException();
		    	}
		    	if(doThis) {
		    		doThis = false;
			    	return IPAddressSection.cast(IPAddress.this);
		    	}
		    	S[] next = iterator.next();
		    	return creator.createAddressInternal(next);
		    }

		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}
	
	public boolean isIPv4() {
		return addressSection.isIPv4();
	}
	
	public boolean isIPv6() {
		return addressSection.isIPv6();
	}
	
	public IPVersion getIPVersion() {
		return addressSection.getIPVersion();
	}
	
	/**
	 * If this address is IPv4, or can be converted to IPv4, returns that {@link IPv4Address}.  Otherwise, returns null.
	 * 
	 * @see #isIPv4Convertible()
	 * @return the address
	 */
	public IPv4Address toIPv4() {
		return null;
	}
	
	/**
	 * 
	 * @return If this address is IPv6, or can be converted to IPv6, returns that {@link IPv6Address}.  Otherwise, returns null.
	 */
	public IPv6Address toIPv6() {
		return null;
	}
	
	/**
	 * Determines whether this address can be converted to IPv4, if not IPv4 already.  
	 * Override this method to convert in your own way, or call setAddressConverter with your own converter object.
	 * 
	 * You should also override {@link #toIPv4()} to match the conversion.
	 * 
	 * This method returns true for all IPv4 addresses.
	 * 
	 * @return
	 */
	public abstract boolean isIPv4Convertible();

	/**
	 * Determines whether an address can be converted to IPv6, if not IPv6 already. 
	 * Override this method to convert in your own way, or call setAddressConverter with your own converter object.
	 * 
	 * You should also override {@link #toIPv6()} to match the conversion.
	 * 
	 * This method returns true for all IPv6 addresses.
	 * 
	 * @return
	 */
	public abstract boolean isIPv6Convertible();
	
	public static IPAddress from(byte bytes[]) {
		return from(bytes, null);
	}
	
	public static IPAddress from(byte bytes[], Integer prefixLength) {
		if(bytes.length == IPv4Address.BYTE_COUNT) {
			IPAddressCreator<IPv4Address, ?, IPv4AddressSegment> addressCreator = IPv4Address.network().getAddressCreator();
			IPv4AddressSegment segments[] = toSegments(bytes, IPv4Address.SEGMENT_COUNT, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT, addressCreator, prefixLength);
			return addressCreator.createAddressInternal(segments);
		}
		if(bytes.length == IPv6Address.BYTE_COUNT) {
			IPAddressCreator<IPv6Address, ?, IPv6AddressSegment> addressCreator = IPv6Address.network().getAddressCreator();
			IPv6AddressSegment segments[] = toSegments(bytes, IPv6Address.SEGMENT_COUNT, IPv6Address.BYTES_PER_SEGMENT, IPv6Address.BITS_PER_SEGMENT, addressCreator, prefixLength);
			return addressCreator.createAddressInternal(segments);
		}
		throw new IllegalArgumentException();
	}

	/**
	 * @see java.net.InetAddress#isLinkLocalAddress()
	 */
	public abstract boolean isLinkLocal();
	
	/**
	 * @see java.net.InetAddress#isSiteLocalAddress()
	 */
	public abstract boolean isSiteLocal();
	
	/**
	 * @see java.net.InetAddress#isMulticastAddress()
	 */
	public abstract boolean isMulticast();
	
	/**
	 * @see java.net.InetAddress#isAnyLocalAddress()
	 */
	public boolean isAnyLocal() {
		return isZero();
	}

	/**
	 * @see java.net.InetAddress#isLoopbackAddress()
	 */
	public abstract boolean isLoopback();
	
	
	public boolean isReachable(int timeout) throws IOException {
		return toInetAddress().isReachable(timeout);
	}
	
	public boolean isReachable(NetworkInterface netif, int ttl, int timeout) throws IOException {
		return toInetAddress().isReachable(netif, ttl, timeout);
	}
	
	/**
	 * @throws IPAddressTypeException if this address does not map to a single address.
	 * If you want to get subnet bytes or mask bytes, call getLowestBytes
	 */
	public byte[] getBytes() {
		if(isMultiple()) {
			throw new IPAddressTypeException(this, "ipaddress.error.unavailable.numeric");
		}
		return getLowestBytes();
	}
	
	/**
	 * Gets the bytes for the lowest address in the range represented by this address.
	 * 
	 * @return
	 */
	public byte[] getLowestBytes() {
		return addressSection.getLowestBytes();
	}
	
	/**
	 * @throws IPAddressTypeException if this address does not map to a single address, ie it is a subnet
	 */
	public InetAddress toInetAddress() {
		if(inetAddress == null) {
			synchronized(this) {
				if(inetAddress == null) {
					byte bytes[] = getBytes();
					try {
						inetAddress = InetAddress.getByAddress(bytes);
					} catch(UnknownHostException e) { /* will never reach here */ }
				}
			}
		}
		return inetAddress;
	}
	
	public boolean isZero() {
		if(isMultipleByNetworkPrefix()) {
			return false;
		}
		return addressSection.isZero();
	}
	
	@Override
	public int hashCode() {
		return addressSection.hashCode();
	}
	
	@Override
	public int compareTo(IPAddress other) {
		if(this == other) {
			return 0;
		}
		return addressComparator.compare(this, other);
	}

	public boolean matches(IPAddressString otherString) {
		//before converting otherString to an address object, check if the strings match
		if(isFromSameString(otherString)) {
			return true;
		}
		IPAddress otherAddr = otherString.getAddress();
		return otherAddr != null && isSameAddress(otherAddr);
	}
	
	protected boolean isFromSameString(IPAddressString otherString) {
		return fromString != null && otherString != null &&
				(fromString == otherString || fromString.fullAddr.equals(otherString.fullAddr)) &&
				fromString.validationOptions == otherString.validationOptions;//we could do equals here but 99% of the time this gives the right answer in less time because the validation options are not expected to change
	}
	
	public boolean isSameAddress(IPAddress other) {
		return other == this || getSegments().equals(other.getSegments());
	}
	
	/**
	 * Two IPAddress objects are equal if they represent the same set of addresses.
	 * Whether one or the other has an associated network prefix length is not considered.
	 * 
	 * Also, an IPAddressString and IPAddress are considered equal if they represent the same set of addresses.
	 */
	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof IPAddress) {
			IPAddress other = (IPAddress) o;
			if(isFromSameString(other.fromString)) {
				return true;
			}
			return isSameAddress(other);
		}
		return false;
	}
	
	/**
	 * 
	 * @param other
	 * @return whether this subnet contains the given address
	 */
	public boolean contains(IPAddress other) {
		if(other == this) {
			return true;
		}
		return addressSection.contains(other.addressSection);
	}
	
	public static IPAddress from(InetAddress inetAddress) {
		byte bytes[] = inetAddress.getAddress();
		if(bytes.length == IPv6Address.BYTE_COUNT) {
			Inet6Address inet6Address = (Inet6Address) inetAddress;
			NetworkInterface networkInterface = inet6Address.getScopedInterface();
			String zone = null;
			if(networkInterface == null) {
				int scopeId = inet6Address.getScopeId();
				if(scopeId != 0) {
					zone = Integer.toString(scopeId);
				}
			} else {
				zone = networkInterface.getName();
			}
			IPv6AddressCreator ipv6Creator = IPv6Address.network().getAddressCreator();
			IPAddressCreator<IPv6Address, IPv6AddressSection, ?> creator = ipv6Creator;
			return ipv6Creator.createAddress(creator.createSectionInternal(bytes), zone);
		} else {
			IPAddressCreator<IPv4Address, IPv4AddressSection, ?> creator = IPv4Address.network().getAddressCreator();
			return creator.createAddress(creator.createSectionInternal(bytes));
		}
	}
	
	//////////////// string creation below ///////////////////////////////////////////////////////////////////////////////////////////
	
	public String[] getSegmentStrings() {
		return addressSection.getSegmentStrings();
	}
	
	@Override
	public String toString() {
		return toCanonicalString();
	}

	/**
	 * This produces a canonical string.
	 * 
	 * RFC 5952 describes canonical representations.
	 * http://en.wikipedia.org/wiki/IPv6_address#Recommended_representation_as_text
	 * http://tools.ietf.org/html/rfc5952
	 * 
	 * Each address has a unique canonical string, not counting the prefix, which can give two equal addresses different strings.
	 */
	public String toCanonicalString() {
		return addressSection.toCanonicalString();
	}

	/**
	 * This produces a string with no compressed segments and all segments of full length,
	 * which is 4 characters for IPv6 segments and 3 characters for IPv4 segments.
	 * 
	 * Each address has a unique full string, not counting CIDR the prefix, which can give two equal addresses different strings.
	 */
	public String toFullString() {
		return addressSection.toFullString();
	}
	
	/**
	 * The normalized string returned by this method is consistent with java.net.Inet4Address and java.net.Inet6Address.
	 * IPs are not compressed nor mixed in this representation.
	 * 
	 * The string returned by this method is unique for each address, not counting CIDR the prefix, which can give two equal addresses different strings.
	 */
	public String toNormalizedString() {
		return addressSection.toNormalizedString();
	}
	
	/**
	 * This produces the shortest valid string for the address.
	 * 
	 * Each address has a unique compressed string, not counting the prefix, which can give two equal addresses different strings.
	 * 
	 * For subnets the string will not have wildcards in host segments (there will be zeros instead), only in network segments.
	 */
	public String toCompressedString() {
		return addressSection.toCompressedString();
	}
	
	/**
	 * Produces a consistent subnet string that looks like 1.2.*.* or 1:2::/16
	 * 
	 * In the case of IPv4, this means that wildcards are used instead of a network prefix when a network prefix has been supplied.
	 * In the case of IPv6, when a network prefix has been supplied, the prefix will be shown and the host section will be compressed with ::.
	 */
	public String toSubnetString() {
		return addressSection.toSubnetString();
	}
	
	/**
	 * This produces a string similar to the normalized string but avoids the CIDR prefix.
	 * CIDR addresses will be shown with wildcards and ranges instead of using the CIDR prefix notation.
	 */
	public String toNormalizedWildcardString() {
		return addressSection.toNormalizedWildcardString();
	}
	
	/**
	 * This produces a string similar to the canonical string but avoids the CIDR prefix.
	 * Addresses with a network prefix length will be shown with wildcards and ranges instead of using the CIDR prefix length notation.
	 * IPv6 addresses will be compressed according to the canonical representation.
	 */
	public String toCanonicalWildcardString() {
		return addressSection.toCanonicalWildcardString();
	}
	
	/**
	 * This is similar to toNormalizedWildcardString, avoiding the CIDR prefix, but with compression as well.
	 */
	public String toCompressedWildcardString() {
		return addressSection.toCompressedWildcardString();
	}
	
	/**
	 * This is the same as the string from toNormalizedWildcardString except that 
	 * it uses IPAddress.SEGMENT_SQL_WILDCARD instead of IPAddress.SEGMENT_WILDCARD and also uses IPAddress.SEGMENT_SQL_SINGLE_WILDCARD
	 */
	public String toSQLWildcardString() {
		 return addressSection.toSQLWildcardString();
	}
	
	/**
	 * Returns a string with a CIDR network prefix length if this address has a network prefix length.
	 * For IPv6, the host section will be compressed with ::, for IPv4 the host section will be zeros.
	 * @return
	 */
	public String toNetworkPrefixLengthString() {
		return addressSection.toNetworkPrefixLengthString();
	}
	
	/**
	 * Returns a mixed string if it represents a convertible IPv4 address, returns the normalized string otherwise.
	 * @return
	 */
	public String toConvertedString() {
		return toNormalizedString();
	}
	
	/**
	 * Constructs a string representing this address according to the given parameters
	 * 
	 * @param params the parameters for the address string
	 */
	public String toNormalizedString(StringOptions params) {
		return addressSection.toNormalizedString(params);
	}
	
	/**
	 * Returns at most a few dozen string representations:
	 * 
	 * -mixed (1:2:3:4:5:6:1.2.3.4)
	 * -full compressions (a:0:b:c:d:0:e:f or a::b:c:d:0:e:f or a:0:b:c:d::e:f)
	 * -full leading zeros (000a:0000:000b:000c:000d:0000:000e:000f)
	 * -all uppercase and all lowercase (a::a can be A::A)
	 * -combinations thereof
	 * 
	 * @return
	 */
	public String[] toStandardStrings() {
		return toStandardStringCollection().toStrings();
	}
	
	/**
	 * Produces almost all possible string variations
	 * <p>
	 * Use this method with care...  a single IPv6 address can have thousands of string representations.
	 * <p>
	 * Examples:
	 * <ul>
	 * <li>"::" has 1297 such variations, but only 9 are considered standard</li>
	 * <li>"a:b:c:0:d:e:f:1" has 1920 variations, but only 12 are standard</li>
	 * </ul>
	 * <p>
	 * Variations included in this method:
	 * <ul>
	 * <li>all standard variations from {@link #toStandardStrings()}</li>
	 * <li>adding a variable number of leading zeros (::a can be ::0a, ::00a, ::000a)</li>
	 * <li>choosing any number of zero-segments to compress (:: can be 0:0:0::0:0)</li>
	 * <li>mixed representation of all variations (1:2:3:4:5:6:1.2.3.4)</li>
	 * <li>all uppercase and all lowercase (a::a can be A::A)</li>
	 * <li>all combinations of such variations</li>
	 * </ul>
	 * Variations omitted from this method: mixed case of a-f, which you can easily handle yourself with String.equalsIgnoreCase
	 * <p>
	 * @return the strings
	 */
	public String[] toAllStrings() {
		return toAllStringCollection().toStrings();
	}
	
	/**
	 * Rather than using toAllStrings or StandardStrings, 
	 * you can use this method to customize the list of strings produced for this address
	 */
	public String[] toStrings(IPStringBuilderOptions options) {
		return toStringCollection(options).toStrings();
	}
	
	public IPAddressPartStringCollection toStandardStringCollection() {
		return addressSection.toStandardStringCollection();
	}

	public IPAddressPartStringCollection toAllStringCollection() {
		return addressSection.toAllStringCollection();
	}
	
	public IPAddressPartStringCollection toStringCollection(IPStringBuilderOptions options) {
		return addressSection.toStringCollection(options);
	}
	
	/**
	 * Generates an IPAddressString object for this IPAddress object.
	 *   
	 * This same IPAddress object can be retrieved from the resulting IPAddressString object using {@link IPAddressString#getAddress()}
	 * 
	 * In general, users are intended to create IPAddress objects from IPAddressString objects, 
	 * while the reverse direction is generally not all that useful.
	 * 
	 * However, the reverse direction can be useful under certain circumstances.
	 * 
	 * Not all IPAddressString objects can be converted to IPAddress objects, 
	 * as is the case with IPAddressString objects corresponding to the types IPType.INVALID and IPType.EMPTY.
	 * 
	 * Not all IPAddressString objects can be converted to IPAddress objects without specifying the IP version, 
	 * as is the case with IPAddressString objects corresponding to the types IPType.PREFIX and  IPType.ALL.
	 * 
	 * So in the event you wish to store a collection of IPAddress objects with a collection of IPAddressString objects,
	 * and not all the IPAddressString objects can be converted to IPAddress objects, then you may wish to use a collection
	 * of only IPAddressString objects, in which case this method is useful.
	 * 
	 * @return an IPAddressString object for this IPAddress.
	 */
	public IPAddressString toAddressString() {
		if(fromString == null) {
			fromString = new IPAddressString(this);
		}
		return fromString;
	}
	
	public static String toDelimitedSQLStrs(String strs[]) {
		if(strs.length == 0) {
			return "";
		}
		StringBuilder builder = new StringBuilder();
		for(String str : strs) {
			builder.append('\'').append(str).append('\'').append(',');
		}
		return builder.substring(0, builder.length() - 1);
	}
	
	///////////////////// masks and subnets below ///////////////////////
	
	/**
	 * @return whether this address represents more than one address and the set of addresses is determined entirely by the prefix length.
	 */
	public boolean isRangeEquivalentToPrefix() {
		return addressSection.isRangeEquivalentToPrefix();
	}
	
	/**
	 * Returns the smallest CIDR prefix possible (largest network),
	 * such that this address paired with that prefix represents the exact same range of addresses.
	 *
	 * @see inet.ipaddr.format.IPAddressDivision#getMaskPrefixLength(boolean)
	 * 
	 * @return
	 */
	public int getMinPrefix() {
		return addressSection.getMinPrefix();
	}
		
	/**
	 * Returns the smallest CIDR prefix possible (largest network),
	 * such that this address paired with that prefix represents the exact same range of addresses.
	 * 
	 * Examples:
	 * 1.2.3.4 returns 32
	 * 1.2.*.* returns 16
	 * 1.2.*.0/24 returns 16 
	 * 1.2.*.4 returns 32
	 * 1.2.252-255.* returns 22
	 * 1.2.3.4/x returns x
	 * 
	 * @return
	 */
	public Integer getEquivalentPrefix() {
		return addressSection.getEquivalentPrefix();
	}
	
	/**
	 * Returns the equivalent CIDR address for which the range of addresses represented 
	 * is specified using just a single value and a prefix length in the returned section.
	 * 
	 * Otherwise, returns null.
	 * 
	 * If this address represents just a single address, this object is returned.
	 * 
	 * Examples:
	 * 1.2.3.4 returns 1.2.3.4/32
	 * 1.2.*.* returns 1.2.0.0/16
	 * 1.2.*.0/24 returns 1.2.0.0/16 
	 * 1.2.*.4 returns null
	 * 1.2.252-255.* returns 1.2.252.0/22
	 * 1.2.3.4/x returns the same address
	 * 
	 * @return
	 */
	public IPAddress toPrefixedEquivalent() {
		if(!isMultiple()) {
			return this;
		}
		Integer newPrefix = getEquivalentPrefix();
		return newPrefix == null ? null : toSubnet(newPrefix);
	}
	
	/**
	 * Constructs an equivalent address with the smallest CIDR prefix possible (largest network),
	 * such that the address represents the exact same range of addresses.
	 * 
	 * @return
	 */
	public IPAddress toPrefixedMin() {
		return toSubnet(getMinPrefix());
	}
	
	/**
	 * If this address is equivalent to the mask for a CIDR prefix, it returns that prefix length.
	 * Otherwise, it returns null.
	 * A CIDR network mask is all 1s in the network section and then all 0s in the host section.
	 * A CIDR host mask is all 0s in the network section and then all 1s in the host section.
	 * The prefix is the length of the network section.
	 * 
	 * Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length used to construct this object.
	 * The prefix length used to construct indicates the network and host portion of this address.  
	 * The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host
	 * portion of any other address.  Therefore the two values can be different values, or one can be null while the other is not.
	 *
	 * @param network whether to check if we are a network mask or a host mask
	 * @return the prefix length corresponding to this mask, or null if this address is not a CIDR prefix mask
	 */
	public Integer getMaskPrefixLength(boolean network) {
		return addressSection.getMaskPrefixLength(network);
	}

	/**
	 * Check that the range in each segment resulting from the mask is contiguous, otherwise we cannot represent it.
	 * 
	 * For instance, for the range 0 to 3 (bits are 00 to 11), if we mask all 4 numbers from 0 to 3 with 2 (ie bits are 10), 
	 * then we are left with 1 and 3.  2 is not included.  So we cannot represent 1 and 3 as a contiguous range.
	 * 
	 * The underlying rule is that mask bits that are 0 must be above the resulting range in each segment.
	 * 
	 * Any bit in the mask that is 0 must not fall below any bit in the masked segment range that is different between low and high
	 * 
	 * Any network mask must eliminate each entire segment range.  Any host mask is fine.
	 * 
	 * @param mask
	 * @param networkPrefixLength
	 * @return
	 */
	public boolean isMaskCompatibleWithRange(IPAddress mask, Integer networkPrefixLength) {
		return getSegments().isMaskCompatibleWithRange(mask.getSegments(), networkPrefixLength);
	}
	
	/**
	 * Creates a subnet address using the given mask.
	 * Any existing prefix is removed as the mask is applied to all individual addresses.
	 * 
	 * If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
	 * that cannot be represented as a contiguous range, then IPAddressTypeException is thrown.
	 * 
	 * See {@link #isMaskCompatibleWithRange(IPAddress, Integer)}
	 */
	public abstract IPAddress toSubnet(IPAddress mask) throws IPAddressTypeException;
	
	/**
	 * Creates a subnet address using the given mask.  
	 * Any existing prefix is removed as the mask is applied to all individual addresses.
	 * If networkPrefixLength is non-null, applies that prefix after the mask has been applied.
	 * 
	 * If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
	 * that cannot be represented as a contiguous range, then IPAddressTypeException is thrown.
	 * 
	 * See {@link #isMaskCompatibleWithRange(IPAddress, Integer)}
	 */
	public abstract IPAddress toSubnet(IPAddress mask, Integer networkPrefixLength) throws IPAddressTypeException;
	
	/**
	 * Creates a subnet address using the given CIDR prefix bits.
	 * 
	 * Since no mask is applied to all of the addresses represented (as with the other toSubnet methods), 
	 * any existing prefix or range remains the same before applying the additional prefix.
	 */
	public abstract IPAddress toSubnet(int networkPrefixLength);
	
	/**
	 * Generates the network section of the address.  The returned section will have only as many segments as needed
	 * to hold the network as indicated by networkPrefixLength.  If withPrefixLength is true, it will have networkPrefixLength as its associated prefix length,
	 * unless this address already has a smaller prefix length, in which case the existing prefix length is retained.
	 * 
	 * @param networkPrefixLength
	 * @param withPrefixLength whether the resulting section will have networkPrefixLength as the associated prefix length or not
	 * @return
	 */
	public abstract IPAddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength);
	
	/**
	 * Generates the network section of the address.  The returned section will have only as many segments as needed
	 * to hold the network as indicated by networkPrefixLength.  It will have networkPrefixLength as its associated prefix length,
	 * unless this address already has a smaller prefix length, in which case the existing prefix length is retained.
	 * 
	 * @param networkPrefixLength
	 * @return
	 */
	public IPAddressSection getNetworkSection(int networkPrefixLength) {
		return addressSection.getNetworkSection(networkPrefixLength);
	}
	
	/**
	 * Generates the network section of the address if the address is a CIDR prefix, otherwise it generates the entire address as a prefixed address with prefix matching the address bit length.
	 * @return
	 */
	public IPAddressSection getNetworkSection() {
		if(isPrefixed()) {
			return getNetworkSection(getNetworkPrefixLength());
		}
		return getNetworkSection(getBitCount());
	}
	
	/**
	 * Generates the host section of the address.  The returned section will have only as many segments as needed
	 * to hold the host as indicated by cidrBits.
	 * 
	 * @param networkPrefixLength
	 * @return
	 */
	public abstract IPAddressSection getHostSection(int networkPrefixLength);
	
	/**
	 * Generates the host section of the address.  The returned section will have only as many segments as needed
	 * as determined by the existing CIDR prefix length.  If there is no CIDR prefix length, the host section will have 0 segments.
	 * 
	 * @return
	 */
	public IPAddressSection getHostSection() {
		if(isPrefixed()) {
			return getHostSection(getNetworkPrefixLength());
		}
		return getHostSection(0);
	}

	/**
	 * Return an address for the network encompassing this address.  
	 * The bits indicate the number of additional network bits in the network address in comparison to this address.
	 * 
	 * @param prefixLengthDecrement the number to reduce the network bits in order to create a larger network.  
	 * 	If null, then this method has the same behaviour as toSupernet()
	 * @return
	 */
	public IPAddress toSupernet(Integer prefixLengthDecrement) {
		int newPrefix = addressSection.getSupernetPrefix(prefixLengthDecrement);
		return toSubnet(newPrefix);
	}
	
	/**
	 * Return an address for the network encompassing this address,
	 * with the network portion of the returned address extending to the furthest segment boundary
	 * located entirely within but not matching the network portion of this address,
	 * unless the network portion has no bits in which case the same address is returned.  
	 * 
	 * @return the encompassing network
	 */
	public IPAddress toSupernet() {
		return toSupernet(null);
	}
	
	/**
	 * returns a clause for matching this address.
	 * 
	 * If this address is a subnet, this method will attempt to match every address in the subnet.
	 * Therefore it is much more efficient to use getNetworkSection().getStartsWithSQLClause() for a CIDR subnet.
	 * 
	 * @param builder
	 * @param sqlExpression
	 */
	public void getMatchesSQLClause(StringBuilder builder, String sqlExpression) {
		addressSection.getStartsWithSQLClause(builder, sqlExpression);
	}
	
	/**
	 * returns a clause for matching this address.
	 * 
	 * Similar to getMatchesSQLClause(StringBuilder builder, String sqlExpression) but allows you to tailor the SQL produced.
	 * 
	 * @param builder
	 * @param sqlExpression
	 * @param translator
	 */
	public void getMatchesSQLClause(StringBuilder builder, String sqlExpression, IPAddressSQLTranslator translator) {
		addressSection.getStartsWithSQLClause(builder, sqlExpression, translator);
	}
}
