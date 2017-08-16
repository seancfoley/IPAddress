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
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.Objects;

import inet.ipaddr.IPAddressConverter.DefaultAddressConverter;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.IPAddressTypeNetwork.IPAddressCreator;
import inet.ipaddr.format.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.sql.IPAddressSQLTranslator;
import inet.ipaddr.format.validate.IPAddressProvider;
import inet.ipaddr.format.validate.ParsedHost;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
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
 * For single strings from an address or address section, you use {@link IPStringOptions} or {@link inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions} along with {@link #toNormalizedString(IPAddressSection.IPStringOptions)}.
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
public abstract class IPAddress extends Address {
	
	private static final long serialVersionUID = 3L;

	/**
	 * @author sfoley
	 *
	 */
	public static enum IPVersion {
		IPV4,
		IPV6;
		
		public boolean isIPv4() {
			return this == IPV4;
		}
		
		public boolean isIPv6() {
			return this == IPV6;
		}
		
		/**
		 * @throws IllegalArgumentException if not the byte length of IPv4 or IPv6 (4 or 16)
		 * @param length
		 * @return
		 */
		public static IPVersion fromByteLength(int length) {
			switch(length) {
				case IPv4Address.BYTE_COUNT:
					return IPV4;
				case IPv6Address.BYTE_COUNT:
					return IPV6;
			}
			throw new IllegalArgumentException();
		}
	};
	
	public static final char PREFIX_LEN_SEPARATOR = '/';
	
	//The default way by which addresses are converted
	public static final IPAddressConverter addressConverter = new DefaultAddressConverter();
	
	/* a Host representing the address, which is the one used to construct the address if the address was resolved from a Host.  
	 * Note this is different than if the Host was an address itself, in which case the Host holds a reference to the address
	 * but there is no backwards reference to the Host.
	 */
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
		super(section);
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
	
	void cache(HostIdentifierString string) {
		if(string instanceof HostName) {
			fromHost = (HostName) string;
		} else if(string instanceof IPAddressString) {
			fromString = (IPAddressString) string;
		}
	}

	protected IPAddressProvider getProvider() {
		if(isPrefixed()) {
			return IPAddressProvider.getProviderFor(this, removePrefixLength(true, true));
		}
		return IPAddressProvider.getProviderFor(this, this);
	}
	
	/**
	 * Does a reverse name lookup to get the canonical host name.
	 */
	public HostName toCanonicalHostName() {
		HostName host = canonicalHost;
		if(host == null) {
			if(isMultiple()) {
				throw new AddressTypeException(this, "ipaddress.error.unavailable.numeric");
			}
			InetAddress inetAddress = toInetAddress();
			//String hostStr1 = inetAddress.getHostName();
			String hostStr = inetAddress.getCanonicalHostName();//note: this does not return ipv6 addresses enclosed in brackets []
			if(hostStr.equals(inetAddress.getHostAddress())) {
				//we got back the address, so the host is me
				host = new HostName(hostStr, new ParsedHost(hostStr, getProvider()));
				host.resolvedAddress = this;
			} else {
				//the reverse lookup succeeded in finding a host string
				//we might not be the default resolved address for the host, so we don't set that field
				host = new HostName(hostStr);
			}
		}
		return host;
	}
	
	public static IPAddress from(byte bytes[]) {
		return from(bytes, null, null);
	}
	
	public static IPAddress from(byte bytes[], Integer prefixLength) {
		return from(bytes, prefixLength, null);
	}
	
	public static IPAddress from(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength) {
		return from(version, lowerValueProvider, upperValueProvider, prefixLength, null);
	}
	
	protected static IPAddress from(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
		if(version == IPVersion.IPV4) {
			if(zone != null) {
				throw new IllegalArgumentException();
			}
			IPAddressCreator<IPv4Address, ?, ?, IPv4AddressSegment> addressCreator = IPv4Address.network().getAddressCreator();
			return addressCreator.createAddressInternal(lowerValueProvider, upperValueProvider, prefixLength);
		}
		if(version == IPVersion.IPV6) {
			IPAddressCreator<IPv6Address, ?, ?, IPv6AddressSegment> addressCreator = IPv6Address.network().getAddressCreator();
			return addressCreator.createAddressInternal(lowerValueProvider, upperValueProvider, prefixLength, zone);
		}
		throw new IllegalArgumentException();
	}
	
	protected static IPAddress from(byte lowerBytes[], Integer prefixLength, CharSequence zone) {
		if(lowerBytes.length == IPv4Address.BYTE_COUNT) {
			if(zone != null) {
				throw new IllegalArgumentException();
			}
			IPAddressCreator<IPv4Address, ?, ?, IPv4AddressSegment> addressCreator = IPv4Address.network().getAddressCreator();
			return addressCreator.createAddressInternal(lowerBytes, prefixLength);
		}
		if(lowerBytes.length == IPv6Address.BYTE_COUNT) {
			IPAddressCreator<IPv6Address, ?, ?, IPv6AddressSegment> addressCreator = IPv6Address.network().getAddressCreator();
			return addressCreator.createAddressInternal(lowerBytes, prefixLength, zone);
		}
		throw new IllegalArgumentException();
	}

	/**
	 * Creates the normalized string for an address without having to create the address objects first.
	 * 
	 * @param lowerValueProvider
	 * @param upperValueProvider
	 * @param prefixLength
	 * @param zone
	 * @return
	 */
	protected static String toNormalizedString(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
		if(version == IPVersion.IPV4) {
			return toNormalizedString(lowerValueProvider, upperValueProvider, prefixLength, 
					IPv4Address.SEGMENT_COUNT, IPv4Address.BYTES_PER_SEGMENT, IPv4Address.BITS_PER_SEGMENT, IPv4Address.MAX_VALUE_PER_SEGMENT, IPv4Address.SEGMENT_SEPARATOR, IPv4Address.DEFAULT_TEXTUAL_RADIX,
					null, IPv4Address.network());
		}
		if(version == IPVersion.IPV6) {
			return toNormalizedString(lowerValueProvider, upperValueProvider, prefixLength, 
					IPv6Address.SEGMENT_COUNT, IPv6Address.BYTES_PER_SEGMENT, IPv6Address.BITS_PER_SEGMENT, IPv6Address.MAX_VALUE_PER_SEGMENT, IPv6Address.SEGMENT_SEPARATOR, IPv6Address.DEFAULT_TEXTUAL_RADIX,
					zone, IPv6Address.network());
		}
		throw new IllegalArgumentException();
	}
	
	private static String toNormalizedString(
			SegmentValueProvider lowerValueProvider,
			SegmentValueProvider upperValueProvider,
			Integer prefixLength,
			int segmentCount,
			int bytesPerSegment,
			int bitsPerSegment,
			int segmentMaxValue,
			char separator,
			int radix,
			CharSequence zone,
			IPAddressNetwork network) {
		int length = toNormalizedString(
				lowerValueProvider,
				upperValueProvider,
				prefixLength,
				segmentCount,
				bytesPerSegment,
				bitsPerSegment,
				segmentMaxValue,
				separator,
				radix,
				zone,
				network,
				null);
		StringBuilder builder = new StringBuilder(length);
		toNormalizedString(
				lowerValueProvider,
				upperValueProvider,
				prefixLength,
				segmentCount,
				bytesPerSegment,
				bitsPerSegment,
				segmentMaxValue,
				separator,
				radix,
				zone,
				network,
				builder);
		IPAddressSection.checkLengths(length, builder);
		return builder.toString();
	}
	
	private static int toNormalizedString(
			SegmentValueProvider lowerValueProvider,
			SegmentValueProvider upperValueProvider,
			Integer prefixLength,
			int segmentCount,
			int bytesPerSegment,
			int bitsPerSegment,
			int segmentMaxValue,
			char separator,
			int radix,
			CharSequence zone,
			IPAddressNetwork network,
			StringBuilder builder) {
		int segmentIndex = 0, count = 0;
		while(true) {
			Integer segmentPrefixLength = IPAddressSection.getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
			if(segmentPrefixLength != null && segmentPrefixLength == 0) {
				if(builder == null) {
					count++;
				} else {
					builder.append('0');//.append(separator);
				}
			} else {
				int value = 0, value2 = 0;
				if(lowerValueProvider == null) {
					value = upperValueProvider.getValue(segmentIndex, bytesPerSegment);
				} else {
					value = lowerValueProvider.getValue(segmentIndex, bytesPerSegment);
					if(upperValueProvider != null) {
						value2 = upperValueProvider.getValue(segmentIndex, bytesPerSegment);
					}
				}
				
				if(lowerValueProvider == null || upperValueProvider == null) {
					if(segmentPrefixLength != null) {
						value &= network.getSegmentNetworkMask(segmentPrefixLength);
					}
					if(builder == null) {
						count += IPAddressSegment.toUnsignedStringLength(value, radix);
					} else {
						IPAddressSegment.toUnsignedString(value, radix, builder);
					}
				} else {
					if(segmentPrefixLength != null) {
						int mask = network.getSegmentNetworkMask(segmentPrefixLength);
						value &= mask;
						value2 &= mask;
					}
					if(value == value2) {
						if(builder == null) {
							count += IPAddressSegment.toUnsignedStringLength(value, radix);
						} else {
							IPAddressSegment.toUnsignedString(value, radix, builder);
						}
					} else {
						if(value > value2) {
							int tmp = value2;
							value2 = value;
							value = tmp;
						} 
						if(value == 0 && value2 == segmentMaxValue) {
							if(builder == null) {
								count += IPAddress.SEGMENT_WILDCARD_STR.length();
							} else {
								builder.append(IPAddress.SEGMENT_WILDCARD_STR);
							}
						} else {
							if(builder == null) {
								count += IPAddressSegment.toUnsignedStringLength(value, radix) + 
										IPAddressSegment.toUnsignedStringLength(value2, radix) + 
										IPAddress.RANGE_SEPARATOR_STR.length();
							} else {
								IPAddressSegment.toUnsignedString(value2, radix, IPAddressSegment.toUnsignedString(value, radix, builder).append(IPAddress.RANGE_SEPARATOR_STR));
							}
						}
					}
				}
			}
			if(++segmentIndex >= segmentCount) {
				break;
			}
			if(builder != null) {
				builder.append(separator);
			}
		}
		if(builder == null) {
			count += segmentCount - 1;//separators
		}
		if(zone != null && zone.length() > 0) {
			if(builder == null) {
				count += zone.length() + 1;
			} else {
				builder.append(IPv6Address.ZONE_SEPARATOR).append(zone);
			}
		}
		if(prefixLength != null) {
			if(builder == null) {
				count += IPAddressSegment.toUnsignedStringLength(prefixLength, 10) + 1;
			} else {
				builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(prefixLength);
			}
		} 
		return count;
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
	 * Returns the address as an address section comprising all segments in the address.
	 * @return
	 */
	@Override
	public IPAddressSection getSection() {
		return (IPAddressSection) super.getSection();
	}

	@Override
	public IPAddressSection getSection(int index) {
		return getSection().getSection(index);
	}

	@Override
	public IPAddressSection getSection(int index, int endIndex) {
		return getSection().getSection(index, endIndex);
	}
	
	/**
	 * Returns all the ways of breaking this address down into segments, as selected.
	 * @return
	 */
	public IPAddressStringDivisionSeries[] getParts(IPStringBuilderOptions options) {
		return new IPAddressStringDivisionSeries[] { getSection() };
	}
	
	@Override
	public int getMaxSegmentValue() {
		return IPAddressSegment.getMaxSegmentValue(getIPVersion());
	}
	
	public static int maxSegmentValue(IPVersion version) {
		return IPAddressSegment.getMaxSegmentValue(version);
	}
	
	@Override
	public int getBytesPerSegment() {
		return IPAddressSegment.getByteCount(getIPVersion());
	}
	
	@Override
	public int getBitsPerSegment() {
		return IPAddressSegment.getBitCount(getIPVersion());
	}
	
	public static int bitsPerSegment(IPVersion version) {
		return IPAddressSegment.getBitCount(version);
	}
	
	@Override
	public int getByteCount() {
		return getSection().getByteCount();
	}
	
	public static int byteCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BYTE_COUNT : IPv6Address.BYTE_COUNT;
	}
	
	public static int segmentCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.SEGMENT_COUNT : IPv6Address.SEGMENT_COUNT;
	}
	
	public static int bitCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BIT_COUNT : IPv6Address.BIT_COUNT;
	}
	
	public boolean isMultipleByNetworkPrefix() {
		return getSection().isMultipleByNetworkPrefix();
	}
	
	public Integer getNetworkPrefixLength() {
		return getSection().getNetworkPrefixLength();
	}
	
	@Override
	public IPAddressSegment getSegment(int index) {
		return (IPAddressSegment) super.getSegment(index);
	}
	
	@Override
	public IPAddressSegment[] getSegments() {
		return getSection().getSegments();
	}
	
	/**
	 * If this represents an address with ranging values, returns an address representing the lower values of the range.
	 * If this represents an address with a single value in each segment, returns this.
	 * 
	 * @return
	 */
	@Override
	public abstract IPAddress getLower();
	
	/**
	 * If this represents an address with ranging values, returns an address representing the upper values of the range
	 * If this represents an address with a single value in each segment, returns this.
	 * 
	 * @return
	 */
	@Override
	public abstract IPAddress getUpper();
	
	/**
	 * 
	 * If this address has an associated prefix length, then the prefix length is dropped for the reversed address.
	 */
	/**
	 * Returns a new IPAddress which has the bits reversed.
	 * 
	 * If this represents a range of values that cannot be reversed, then this throws AddressTypeException.
	 * 
	 * In such cases where isMultiple() is true, call iterator(), getLower(), getUpper() or some other methods to transform the address 
	 * into an address representing a single value.
	 * 
	 * @param perByte if true, only the bits in each byte are reversed, if false, then all bits in the address are reversed
	 * @throw AddressTypeException if isMultiple() returns true
	 * @return
	 */
	@Override
	public abstract IPAddress reverseBits(boolean perByte);
	
	@Override
	public abstract IPAddress reverseBytes();
	
	@Override
	public abstract IPAddress reverseBytesPerSegment();
	
	@Override
	public abstract IPAddress reverseSegments();
	
	@Override
	public abstract Iterator<? extends IPAddress> iterator();
	
	@Override
	public Iterator<? extends IPAddressSegment[]> segmentsIterator() {
		return getSection().segmentsIterator();
	}
	
	/**
	 * @return an object to iterate over the individual addresses represented by this object.
	 */
	@Override
	public abstract Iterable<? extends IPAddress> getIterable();
	
	public boolean isIPv4() {
		return getSection().isIPv4();
	}
	
	public boolean isIPv6() {
		return getSection().isIPv6();
	}
	
	public IPVersion getIPVersion() {
		return getSection().getIPVersion();
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
	
	/**
	 * @see java.net.InetAddress#isLinkLocalAddress()
	 */
	public abstract boolean isLinkLocal();
	
	/**
	 * @see java.net.InetAddress#isSiteLocalAddress()
	 */
	public abstract boolean isSiteLocal();

	@Override
	public boolean isLocal() {
		return isLinkLocal() || isSiteLocal() || isAnyLocal();
	}
	
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
	
	/**
	 * @throws AddressTypeException if this address does not map to a single address, ie it is a subnet
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

	public boolean matches(IPAddressString otherString) {
		//before converting otherString to an address object, check if the strings match
		if(isFromSameString(otherString)) {
			return true;
		}
		IPAddress otherAddr = otherString.getAddress();
		return otherAddr != null && isSameAddress(otherAddr);
	}
	
	@Override
	protected boolean isFromSameString(HostIdentifierString other) {
		if(fromString != null && other instanceof IPAddressString) {
			IPAddressString fromString = (IPAddressString) this.fromString;
			IPAddressString otherString = (IPAddressString) other;
			return (fromString == otherString || 
					(fromString.fullAddr.equals(otherString.fullAddr)) &&
					Objects.equals(fromString.validationOptions, otherString.validationOptions));
		}
		return false;
	}
	
	public boolean isSameAddress(IPAddress other) {
		return other == this || getSection().equals(other.getSection());
	}

	@Override
	public boolean contains(Address other) {
		if(other instanceof IPAddress) {
			return contains((IPAddress) other);
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
		return getSection().contains(other.getSection());
	}
	
	/**
	 * Subtract the give subnet from this subnet, returning an array of subnets for the result (the subnets will not be contiguous so an array is required).
	 * 
	 * Computes the subnet difference, the set of addresses in this address subnet but not in the provided subnet.
	 * 
	 * If the address is not the same version, the default conversion will be applied, and it that fails, AddressTypeException will be thrown.
	 * 
	 * @param other
	 * @throws AddressTypeException if the two sections are not comparable
	 * @return the difference
	 */
	public abstract IPAddress[] subtract(IPAddress other);

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
			return ipv6Creator.createAddressInternal(bytes, null, zone); /* address creation */
		} else {
			IPv4AddressCreator creator = IPv4Address.network().getAddressCreator();
			return creator.createAddressInternal(bytes, null); /* address creation */
		}
	}
	
	//////////////// string creation below ///////////////////////////////////////////////////////////////////////////////////////////
	
	public String[] getSegmentStrings() {
		return getSection().getSegmentStrings();
	}

	/**
	 * This produces a string with no compressed segments and all segments of full length,
	 * which is 4 characters for IPv6 segments and 3 characters for IPv4 segments.
	 * 
	 * Each address has a unique full string, not counting CIDR the prefix, which can give two equal addresses different strings.
	 */
	public String toFullString() {
		return getSection().toFullString();
	}
	
	protected void cacheNormalizedString(String str) {
		getSection().cacheNormalizedString(str);
	}
	
	/**
	 * Produces a consistent subnet string that looks like 1.2.*.* or 1:2::/16
	 * 
	 * In the case of IPv4, this means that wildcards are used instead of a network prefix when a network prefix has been supplied.
	 * In the case of IPv6, when a network prefix has been supplied, the prefix will be shown and the host section will be compressed with ::.
	 */
	public String toSubnetString() {
		return getSection().toSubnetString();
	}
	
	/**
	 * This produces a string similar to the normalized string but avoids the CIDR prefix.
	 * CIDR addresses will be shown with wildcards and ranges instead of using the CIDR prefix notation.
	 */
	public String toNormalizedWildcardString() {
		return getSection().toNormalizedWildcardString();
	}
	
	/**
	 * This produces a string similar to the canonical string but avoids the CIDR prefix.
	 * Addresses with a network prefix length will be shown with wildcards and ranges instead of using the CIDR prefix length notation.
	 * IPv6 addresses will be compressed according to the canonical representation.
	 */
	public String toCanonicalWildcardString() {
		return getSection().toCanonicalWildcardString();
	}
	
	/**
	 * This is similar to toNormalizedWildcardString, avoiding the CIDR prefix, but with compression as well.
	 */
	public String toCompressedWildcardString() {
		return getSection().toCompressedWildcardString();
	}
	
	/**
	 * This is the same as the string from toNormalizedWildcardString except that 
	 * it uses IPAddress.SEGMENT_SQL_WILDCARD instead of IPAddress.SEGMENT_WILDCARD and also uses IPAddress.SEGMENT_SQL_SINGLE_WILDCARD
	 */
	public String toSQLWildcardString() {
		 return getSection().toSQLWildcardString();
	}
	
	/**
	 * Returns a string with a CIDR network prefix length if this address has a network prefix length.
	 * For IPv6, the host section will be compressed with ::, for IPv4 the host section will be zeros.
	 * @return
	 */
	public String toPrefixLengthString() {
		return getSection().toPrefixLengthString();
	}
	
	/**
	 * Returns a mixed string if it represents a convertible IPv4 address, returns the normalized string otherwise.
	 * @return
	 */
	public String toConvertedString() {
		return toNormalizedString();
	}
	
	/**
	 * Generates the Microsoft UNC path component for this address
	 * 
	 * @return
	 */
	public abstract String toUNCHostName();
	
	/**
	 * Generates the reverse DNS lookup string
	 * For 8.255.4.4 it is 4.4.255.8.in-addr.arpa
	 * For 2001:db8::567:89ab it is b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
	 * 
	 *
	 * @throw {@link AddressTypeException} if this address is a subnet of multiple addresses
	 * @return
	 */
	public String toReverseDNSLookupString() {
		return getSection().toReverseDNSLookupString();
	}
	
	/**
	 * Writes this address as a single binary value with always the exact same number of characters
	 * 
	 * If this section represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 */
	public String toBinaryString() {
		return getSection().toBinaryString();
	}
	
	/**
	 * Writes this address as a single octal value with always the exact same number of characters, with or without a preceding 0 prefix.
	 * 
	 * If this section represents a range of values outside of the network prefix length, then this is printed as a range of two hex values.
	 */
	public String toOctalString(boolean with0Prefix) {
		return getSection().toOctalString(with0Prefix);
	}
	
	/**
	 * Constructs a string representing this address according to the given parameters
	 * 
	 * @throw {@link AddressTypeException} if this address is a subnet of multiple addresses, you have selected splitDigits, and the address range cannot be represented in split digits
	 * 
	 * @param params the parameters for the address string
	 */
	public String toNormalizedString(IPStringOptions params) {
		return getSection().toNormalizedString(params);
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
		return getSection().toStandardStringCollection();
	}

	public IPAddressPartStringCollection toAllStringCollection() {
		return getSection().toAllStringCollection();
	}
	
	public IPAddressPartStringCollection toStringCollection(IPStringBuilderOptions options) {
		return getSection().toStringCollection(options);
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
	@Override
	public IPAddressString toAddressString() {
		if(fromString == null) {
			fromString = new IPAddressString(this); /* address string creation */
		}
		return getAddressfromString();
	}
	
	protected IPAddressString getAddressfromString() {
		return (IPAddressString) fromString;
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
	 * Returns the equivalent CIDR address for which the range of addresses represented 
	 * is specified using just a single value and a prefix length.
	 * 
	 * Otherwise, returns null.
	 * 
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
		Integer newPrefix = getEquivalentPrefix();
		return newPrefix == null ? null : applyPrefixLength(newPrefix);
	}

	/**
	 * Returns the equivalent BigInteger address.
	 *
	 * Examples:
	 * 1.2.3.4 returns 16909060
	 * 1:2:3:4:5:6:7:8 returns 5192455318486707404433266433261576
	 *
	 * @return
	 */
	public BigInteger toBigInteger() {
		BigInteger value = BigInteger.valueOf(0);
		for (IPAddressSegment seg : this.getSegments()) {
			value = value.shiftLeft(this.getBitsPerSegment()).add(BigInteger.valueOf(seg.getLowerValue()));
		}
		return value;
	}

	/**
	 * Constructs an equivalent address with the smallest CIDR prefix possible (largest network),
	 * such that the address represents the exact same range of addresses.
	 * 
	 * @return
	 */
	public IPAddress toMinPrefixedEquivalent() {
		return applyPrefixLength(getMinPrefix());
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
		return getSection().getMaskPrefixLength(network);
	}
	
	/**
	 * Applies the given mask to all addresses represented by this IPAddress.
	 * 
	 * Any existing prefix is removed as the mask is applied to all individual addresses.
	 * 
	 * If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
	 * that cannot be represented as a contiguous range within each segment, then {@link AddressTypeException} is thrown.
	 * 
	 */
	public abstract IPAddress mask(IPAddress mask) throws AddressTypeException;
	
	/**
	 * Applies the given mask up until the given prefix length to all addresses represented by this IPAddress.
	 * 
	 * Any existing prefix length is removed as the mask is applied to all individual addresses.
	 * If networkPrefixLength is non-null, it is applied after the mask has been applied.
	 * 
	 * If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
	 * that cannot be represented as a contiguous range within each segment, then {@link AddressTypeException} is thrown.
	 * 
	 */
	public abstract IPAddress maskNetwork(IPAddress mask, int networkPrefixLength) throws AddressTypeException;
	
	/**
	 * Applies the given prefix length to create a new address.
	 * 
	 * If this address has a prefix length that is smaller than the given one, 
	 * then the method has no effect and simply returns this address.
	 */
	@Override
	public abstract IPAddress applyPrefixLength(int networkPrefixLength);
	
	/**
	 * Does the bitwise disjunction with this address.  Useful when subnetting.
	 * @param mask
	 * @return
	 * @throws AddressTypeException
	 */
	public abstract IPAddress bitwiseOr(IPAddress mask) throws AddressTypeException;
	
	/**
	 * Does the bitwise disjunction with this address.  Useful when subnetting.
	 * 
	 * Any existing prefix length is dropped for the new prefix length and the mask is applied up to the end the new prefix length.
	 * 
	 * @param mask
	 * @param networkPrefixLength the new prefix length for the address
	 * @return
	 * @throws AddressTypeException
	 */
	public abstract IPAddress bitwiseOrNetwork(IPAddress mask, int networkPrefixLength) throws AddressTypeException;
	
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
	public abstract IPAddressSection getNetworkSection(int networkPrefixLength);
	
	/**
	 * Generates the network section of the address if the address is a CIDR prefix, otherwise it generates the entire address as a prefixed address with prefix matching the address bit length.
	 * @return
	 */
	public abstract IPAddressSection getNetworkSection();
	
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
	public abstract IPAddressSection getHostSection();
	
	@Override
	public abstract IPAddress removePrefixLength();
	
	public abstract IPAddress removePrefixLength(boolean zeroed);
	
	protected abstract IPAddress removePrefixLength(boolean zeroed, boolean onlyPrefixZeroed);
	
	@Override
	public abstract IPAddress adjustPrefixBySegment(boolean nextSegment);

	@Override
	public abstract IPAddress adjustPrefixLength(int adjustment);

	@Override
	public abstract IPAddress setPrefixLength(int prefixLength);

	public abstract IPAddress setPrefixLength(int prefixLength, boolean zeroed);
	
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
		getSection().getStartsWithSQLClause(builder, sqlExpression);
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
		getSection().getStartsWithSQLClause(builder, sqlExpression, translator);
	}
}
