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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.Objects;
import java.util.function.Function;

import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.IPAddressConverter.DefaultAddressConverter;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.format.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.util.sql.IPAddressSQLTranslator;
import inet.ipaddr.format.validate.IPAddressProvider;
import inet.ipaddr.format.validate.ParsedHost;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;


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
public abstract class IPAddress extends Address implements IPAddressSegmentSeries {
	
	private static final long serialVersionUID = 4L;

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
	}
	
	public static final char PREFIX_LEN_SEPARATOR = '/';
	
	/**
	 * The default way by which addresses are converted, initialized to an instance of {@link DefaultAddressConverter}
	 */
	public static final IPAddressConverter DEFAULT_ADDRESS_CONVERTER = new DefaultAddressConverter();
	
	/* a Host representing the address, which is the one used to construct the address if the address was resolved from a Host.  
	 * Note this is different than if the Host was an address itself, in which case the Host holds a reference to the address
	 * but there is no backwards reference to the Host.
	 */
	HostName fromHost;
	
	/* a Host representing the canonical host for this address */
	private HostName canonicalHost;
	
	/**
	 * Represents an IP address or a set of addresses.
	 * @param section the address segments
	 */
	protected IPAddress(IPAddressSection section) {
		super(section);
	}
	
	protected IPAddress(Function<Address, AddressSection> supplier) {
		super(supplier);
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
			return IPAddressProvider.getProviderFor(this, removePrefixLength(true));
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
				throw new IncompatibleAddressException(this, "ipaddress.error.unavailable.numeric");
			}
			InetAddress inetAddress = toInetAddress();
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
	
	@Override
	public abstract IPAddressNetwork<?, ?, ?, ?, ?> getNetwork();

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
	
	public static int getMaxSegmentValue(IPVersion version) {
		return IPAddressSegment.getMaxSegmentValue(version);
	}
	
	@Override
	public BigInteger getNonZeroHostCount() {
		return getSection().getNonZeroHostCount();
	}
	
	@Override
	public int getBytesPerSegment() {
		return IPAddressSegment.getByteCount(getIPVersion());
	}
	
	@Override
	public int getBitsPerSegment() {
		return IPAddressSegment.getBitCount(getIPVersion());
	}
	
	public static int getBitsPerSegment(IPVersion version) {
		return IPAddressSegment.getBitCount(version);
	}
	
	@Override
	public int getByteCount() {
		return getSection().getByteCount();
	}
	
	public static int getByteCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BYTE_COUNT : IPv6Address.BYTE_COUNT;
	}
	
	public static int getSegmentCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.SEGMENT_COUNT : IPv6Address.SEGMENT_COUNT;
	}
	
	public static int getBitCount(IPVersion version) {
		return version.isIPv4() ? IPv4Address.BIT_COUNT : IPv6Address.BIT_COUNT;
	}
	
	@Override
	public IPAddressSegment getSegment(int index) {
		return (IPAddressSegment) super.getSegment(index);
	}
	
	@Override
	public IPAddressSegment[] getSegments() {
		return getSection().getSegments();
	}

	@Override
	public abstract IPAddress getLowerNonZeroHost();

	@Override
	public abstract IPAddress getLower();
	
	@Override
	public abstract IPAddress getUpper();
	
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
	public abstract Iterator<? extends IPAddress> nonZeroHostIterator();
	
	@Override
	public abstract Iterator<? extends IPAddressSegment[]> segmentsIterator();
	
	@Override
	public abstract Iterator<? extends IPAddressSegment[]> segmentsNonZeroHostIterator();

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
	
	@Override
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
	 * Override this method to convert in your own way.
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
	 * Override this method to convert in your own way.
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
	 * Converts the lowest value of this address to an InetAddress.
	 * If this consists of just a single address, this is equivalent to {@link #toInetAddress()}
	 */
	public InetAddress toUpperInetAddress() {
		return getSection().toUpperInetAddress(this);
	}
	
	/**
	 * Converts the lowest value of this address to an InetAddress
	 */
	public InetAddress toInetAddress() {
		return getSection().toInetAddress(this);
	}

	protected InetAddress toInetAddressImpl(byte bytes[]) {
		try {
			return InetAddress.getByAddress(bytes);
		} catch(UnknownHostException e) { /* will never reach here */ return null; }
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
	
	
	//////////////// string creation below ///////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Creates the normalized string for an address without having to create the address objects first.
	 *
	 */
	protected static String toNormalizedString(
			PrefixConfiguration prefixConfiguration,
			SegmentValueProvider lowerValueProvider,
			SegmentValueProvider upperValueProvider,
			Integer prefixLength,
			int segmentCount,
			int bytesPerSegment,
			int bitsPerSegment,
			int segmentMaxValue,
			char separator,
			int radix,
			CharSequence zone) {
		int length = toNormalizedString(
				prefixConfiguration,
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
				null);
		StringBuilder builder = new StringBuilder(length);
		toNormalizedString(
				prefixConfiguration,
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
				builder);
		IPAddressSection.checkLengths(length, builder);
		return builder.toString();
	}
	
	private static int toNormalizedString(
			PrefixConfiguration prefixConfiguration,
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
			StringBuilder builder) {
		int segmentIndex, count;
		segmentIndex = count = 0;
		boolean isPrefixSubnet = IPAddressSection.isPrefixSubnet(
				lowerValueProvider,
				upperValueProvider,
				segmentCount,
				bytesPerSegment,
				bitsPerSegment,
				segmentMaxValue,
				prefixLength,
				prefixConfiguration,
				false);
		while(true) {
			Integer segmentPrefixLength = IPAddressSection.getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
			if(isPrefixSubnet && segmentPrefixLength != null && segmentPrefixLength == 0) {
				if(builder == null) {
					count++;
				} else {
					builder.append('0');
				}
			} else {
				int value = 0, value2 = 0;
				if(lowerValueProvider == null) {
					value = upperValueProvider.getValue(segmentIndex);
				} else {
					value = lowerValueProvider.getValue(segmentIndex);
					if(upperValueProvider != null) {
						value2 = upperValueProvider.getValue(segmentIndex);
					}
				}
				if(lowerValueProvider == null || upperValueProvider == null) {
					if(isPrefixSubnet && segmentPrefixLength != null) {
						value &= ~0 << (segmentPrefixLength - bitsPerSegment);
					}
					if(builder == null) {
						count += IPAddressSegment.toUnsignedStringLength(value, radix);
					} else {
						IPAddressSegment.toUnsignedString(value, radix, builder);
					}
				} else {
					if(isPrefixSubnet && segmentPrefixLength != null) {
						int mask = ~0 << (segmentPrefixLength - bitsPerSegment);
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
	
	/**
	 * This produces a string with no compressed segments and all segments of full length,
	 * which is 4 characters for IPv6 segments and 3 characters for IPv4 segments.
	 * 
	 * Each address has a unique full string, not counting CIDR the prefix, which can give two equal addresses different strings.
	 */
	@Override
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
	@Override
	public String toSubnetString() {
		return getSection().toSubnetString();
	}
	
	/**
	 * This produces a string similar to the normalized string but avoids the CIDR prefix.
	 * CIDR addresses will be shown with wildcards and ranges instead of using the CIDR prefix notation.
	 */
	@Override
	public String toNormalizedWildcardString() {
		return getSection().toNormalizedWildcardString();
	}
	
	/**
	 * This produces a string similar to the canonical string but avoids the CIDR prefix.
	 * Addresses with a network prefix length will be shown with wildcards and ranges instead of using the CIDR prefix length notation.
	 * IPv6 addresses will be compressed according to the canonical representation.
	 */
	@Override
	public String toCanonicalWildcardString() {
		return getSection().toCanonicalWildcardString();
	}
	
	/**
	 * This is similar to toNormalizedWildcardString, avoiding the CIDR prefix, but with compression as well.
	 */
	@Override
	public String toCompressedWildcardString() {
		return getSection().toCompressedWildcardString();
	}
	
	
	/**
	 * This is the same as the string from toNormalizedWildcardString except that 
	 * it uses {@link IPAddress#SEGMENT_SQL_WILDCARD} instead of {@link IPAddress#SEGMENT_WILDCARD} and also uses {@link IPAddress#SEGMENT_SQL_SINGLE_WILDCARD}
	 */
	@Override
	public String toSQLWildcardString() {
		 return getSection().toSQLWildcardString();
	}
	
	/**
	 * Returns a string with a CIDR network prefix length if this address has a network prefix length.
	 * For IPv6, the host section will be compressed with ::, for IPv4 the host section will be zeros.
	 * @return
	 */
	@Override
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
	 * Generates the reverse DNS lookup string<p>
	 * For 8.255.4.4 it is 4.4.255.8.in-addr.arpa<br>
	 * For 2001:db8::567:89ab it is b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
	 * 
	 *
	 * @throws IncompatibleAddressException if this address is a subnet
	 * @return
	 */
	@Override
	public String toReverseDNSLookupString() {
		return getSection().toReverseDNSLookupString();
	}
	
	/**
	 * Writes this address as a single binary value with always the exact same number of characters
	 * <p>
	 * If this section represents a range of values not corresponding to a prefix, then this is printed as a range of two hex values.
	 */
	@Override
	public String toBinaryString() {
		return getSection().toBinaryString();
	}
	
	/**
	 * Writes this address as a single octal value with always the exact same number of characters, with or without a preceding 0 prefix.
	 * <p>
	 * If this section represents a range of values not corresponding to a prefix, then this is printed as a range of two hex values.
	 */
	@Override
	public String toOctalString(boolean with0Prefix) {
		return getSection().toOctalString(with0Prefix);
	}
	
	/**
	 * Constructs a string representing this address according to the given parameters
	 * 
	 * @throws IncompatibleAddressException for cases in which the requested string cannot be produced, which can generally only occur with specific strings from specific subnets.
	 * 
	 * @param params the parameters for the address string
	 */
	@Override
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
	
	@Override
	public IPAddressPartStringCollection toStringCollection(IPStringBuilderOptions options) {
		return getSection().toStringCollection(options);
	}
	
	/**
	 * Generates an IPAddressString object for this IPAddress object.
	 * <p>
	 * This same IPAddress object can be retrieved from the resulting IPAddressString object using {@link IPAddressString#getAddress()}
	 * <p>
	 * In general, users are intended to create IPAddress objects from IPAddressString objects, 
	 * while the reverse direction is generally not all that useful.
	 * <p>
	 * However, the reverse direction can be useful under certain circumstances.
	 * <p>
	 * Not all IPAddressString objects can be converted to IPAddress objects, 
	 * as is the case with IPAddressString objects corresponding to the types IPType.INVALID and IPType.EMPTY.
	 * <p>
	 * Not all IPAddressString objects can be converted to IPAddress objects without specifying the IP version, 
	 * as is the case with IPAddressString objects corresponding to the types IPType.PREFIX and  IPType.ALL.
	 * <p>
	 * So in the event you wish to store a collection of IPAddress objects with a collection of IPAddressString objects,
	 * and not all the IPAddressString objects can be converted to IPAddress objects, then you may wish to use a collection
	 * of only IPAddressString objects, in which case this method is useful.
	 * 
	 * @return an IPAddressString object for this IPAddress.
	 */
	@Override
	public IPAddressString toAddressString() {
		if(fromString == null) {
			IPAddressStringParameters params = createFromStringParams();
			fromString = new IPAddressString(this, params); /* address string creation */
		}
		return getAddressfromString();
	}
	
	protected abstract IPAddressStringParameters createFromStringParams();
	
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
	
	@Override
	public Integer getNetworkPrefixLength() {
		return getSection().getNetworkPrefixLength();
	}

	public boolean includesZeroHost() {
		return getSection().includesZeroHost();
	}

	@Override
	public abstract IPAddress toPrefixBlock();

	@Override
	public abstract IPAddress toPrefixBlock(int networkPrefixLength) throws PrefixLenException;

	/**
	 * Returns the equivalent CIDR address with a prefix length for which the address subnet block matches the range of values in this address.
	 * <p>
	 * If no such prefix length exists, returns null.
	 * <p>
	 * 
	 * Examples:<br>
	 * 1.2.3.4 returns 1.2.3.4/32<br>
	 * 1.2.*.* returns 1.2.0.0/16<br>
	 * 1.2.*.0/24 returns 1.2.0.0/16 <br>
	 * 1.2.*.4 returns null<br>
	 * 1.2.252-255.* returns 1.2.252.0/22<br>
	 * 1.2.3.4/x returns the same address<br>
	 * 
	 * @return
	 */
	@Override
	public IPAddress assignPrefixForSingleBlock() {
		Integer newPrefix = getPrefixLengthForSingleBlock();
		return newPrefix == null ? null : setPrefixLength(newPrefix, false);
	}

	/**
	 * Constructs an equivalent address with the smallest CIDR prefix possible (largest network),
	 * such that the range of values are a set of subnet blocks for that prefix.
	 * 
	 * @return
	 */
	@Override
	public IPAddress assignMinPrefixForBlock() {
		return setPrefixLength(getMinPrefixLengthForBlock(), false);
	}

	/**
	 * If this address is equivalent to the mask for a CIDR prefix block, it returns that prefix length.
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
	 * @return the prefix length corresponding to this mask, or null if there is no such prefix length
	 */
	public Integer getBlockMaskPrefixLength(boolean network) {
		return getSection().getBlockMaskPrefixLength(network);
	}
	
	/**
	 * Produces the subnet whose addresses are found in both this and the given subnet argument.
	 * <p>
	 * This is also known as the conjunction of the two sets of addresses.
	 * <p>
	 * If the address is not the same version, the default conversion will be applied using ({@link #toIPv4()} or {@link #toIPv6()}, and it that fails, {@link AddressConversionException} will be thrown.
	 * <p>
	 * @param other
	 * @throws AddressConversionException if the address argument could not be converted to the same address version as this
	 * @return the subnet containing the addresses found in both this and the given subnet
	 */
	public abstract IPAddress intersect(IPAddress other);
	
	/**
	 * Subtract the given subnet from this subnet, returning an array of subnets for the result (the subnets will not be contiguous so an array is required).
	 * <p>
	 * Computes the subnet difference, the set of addresses in this address subnet but not in the provided subnet.  This is also known as the relative complement of the given argument in this subnet.
	 * <p>
	 * If the address is not the same version, the default conversion will be applied using ({@link #toIPv4()} or {@link #toIPv6()}, and it that fails, {@link AddressConversionException} will be thrown.
	 * <p>
	 * @param other
	 * @throws AddressConversionException if the address argument could not be converted to the same address version as this
	 * @return the difference
	 */
	public abstract IPAddress[] subtract(IPAddress other);

	/**
	 * Equivalent to calling {@link #mask(IPAddress, boolean)} with the second argument as false.
	 *<p>
	 * If the mask is a different version than this, then the default conversion is applied first using ({@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * @param mask
	 * @return
	 * @throws IncompatibleAddressException if this is a range of addresses and applying the mask results in an address that cannot be represented as a contiguous range within each segment
	 * @throws AddressConversionException if the address argument could not be converted to the same address version as this
	 */
	public abstract IPAddress mask(IPAddress mask) throws AddressConversionException, IncompatibleAddressException;
	
	/**
	 * Applies the given mask to all addresses represented by this IPAddress.
	 * The mask is applied to all individual addresses.
	 * If the retainPrefix argument is true, then any existing prefix length is removed beforehand.
	 * <p>
	 * If the mask is a different version than this, then the default conversion is applied first using ({@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
	 * that cannot be represented as a contiguous range within each segment, then {@link IncompatibleAddressException} is thrown.
	 * <p>
	 * @param mask
	 * @return
	 * @throws IncompatibleAddressException if this is a range of addresses and applying the mask results in an address that cannot be represented as a contiguous range within each segment
	 * @throws AddressConversionException if the address argument could not be converted to the same address version as this
	 */
	public abstract IPAddress mask(IPAddress mask, boolean retainPrefix) throws AddressConversionException, IncompatibleAddressException;
	
	/**
	 * Applies the given mask to all addresses represented by this IPAddress while also applying the given prefix length at the same time.
	 * <p>
	 * Any existing prefix length is removed as the mask and new prefix length is applied to all individual addresses.
	 * <p>
	 * If the mask is a different version than this, then the default conversion is applied first using ({@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
	 * that cannot be represented as a contiguous range within each segment, then {@link IncompatibleAddressException} is thrown.
	 * 
	 * @throws IncompatibleAddressException if this is a range of addresses and applying the mask results in an address that cannot be represented as a contiguous range within each segment
	 * @throws AddressConversionException if the address argument could not be converted to the same address version as this
	 */
	public abstract IPAddress maskNetwork(IPAddress mask, int networkPrefixLength) throws AddressConversionException, IncompatibleAddressException;

	/**
	 * Equivalent to calling {@link #bitwiseOr(IPAddress, boolean)} with the second argument as false.
	 * <p>
	 * If the mask is a different version than this, then the default conversion is applied first using ({@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 @param mask
	 * @return
	 * @throws AddressConversionException if the address argument could not be converted to the same address version as this
	 * @throws IncompatibleAddressException if this is a range of addresses and applying the mask results in an address that cannot be represented as a contiguous range within each segment
	 */
	public abstract IPAddress bitwiseOr(IPAddress mask) throws AddressConversionException, IncompatibleAddressException;
	
	/**
	 * Does the bitwise disjunction with this address.  Useful when subnetting.
	 * <p>
	 * The mask is applied to all individual addresses, similar to how the {@link #mask(IPAddress)} method which does the bitwise conjunction.
	 * If the retainPrefix argument is true, then any existing prefix length is removed beforehand.
	 * <p>
	 * If the mask is a different version than this, then the default conversion is applied first using ({@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * If you wish to mask a portion of the network, use {@link #bitwiseOrNetwork(IPAddress, int)}
	 * <p>
	 * For instance, you can get the broadcast address for a subnet as follows:
	 * <code>
	 * String addrStr = "1.2.3.4/16";
	 * IPAddress address = new IPAddressString(addrStr).getAddress();
	 * IPAddress hostMask = address.getNetwork().getHostMask(address.getNetworkPrefixLength());//0.0.255.255
	 * IPAddress broadcastAddress = address.bitwiseOr(hostMask); //1.2.255.255
	 * </code>
	 * 
	 * @param mask
	 * @param retainPrefix
	 * @return
	 * @throws AddressConversionException if the address argument could not be converted to the same address version as this
	 * @throws IncompatibleAddressException if this is a range of addresses and applying the mask results in an address that cannot be represented as a contiguous range within each segment
	 */
	public abstract IPAddress bitwiseOr(IPAddress mask, boolean retainPrefix) throws AddressConversionException, IncompatibleAddressException;
	
	/**
	 * Does the bitwise disjunction with this address.  Useful when subnetting.
	 * <p>
	 * If the mask is a different version than this, then the default conversion is applied first using ({@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * Any existing prefix length is dropped for the new prefix length and the mask is applied up to the end the new prefix length.
	 * It is similar to how the {@link #maskNetwork(IPAddress, int)} method does the bitwise conjunction.
	 * 
	 * @param mask
	 * @param networkPrefixLength the new prefix length for the address
	 * @return
	 * @throws IncompatibleAddressException if this is a range of addresses and applying the mask results in an address that cannot be represented as a contiguous range within each segment
	 * @throws AddressConversionException if the address argument could not be converted to the same address version as this
	 */
	public abstract IPAddress bitwiseOrNetwork(IPAddress mask, int networkPrefixLength) throws AddressConversionException, IncompatibleAddressException;
	
	@Override
	public abstract IPAddress removePrefixLength();
	
	@Override
	public abstract IPAddress removePrefixLength(boolean zeroed);
	
	@Override
	public abstract IPAddress adjustPrefixBySegment(boolean nextSegment);

	@Override
	public abstract IPAddress adjustPrefixLength(int adjustment);

	@Override
	public abstract IPAddress setPrefixLength(int prefixLength);

	@Override
	public abstract IPAddress setPrefixLength(int prefixLength, boolean zeroed);
	
	@Override
	public abstract IPAddress applyPrefixLength(int networkPrefixLength);

	/**
	 * Returns a clause for matching this address.
	 * <p>
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
	 * Returns a clause for matching this address.
	 * <p>
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
