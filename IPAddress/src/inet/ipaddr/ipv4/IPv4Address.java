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

package inet.ipaddr.ipv4;

import java.net.Inet4Address;
import java.util.Iterator;

import inet.ipaddr.AddressTypeException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressConverter;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.format.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection.AddressCache;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringBuilderOptions;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringCollection;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6Address.IPv6AddressConverter;


/**
 * An IPv4 address, or a subnet of multiple IPv4 addresses.
 * 
 * @custom.core
 * @author sfoley
 *
 */
public class IPv4Address extends IPAddress implements Iterable<IPv4Address> {

	private static final long serialVersionUID = 3L;
	
	public static final char SEGMENT_SEPARATOR = '.';
	public static final int BITS_PER_SEGMENT = 8;
	public static final int BYTES_PER_SEGMENT = 1;
	public static final int SEGMENT_COUNT = 4;
	public static final int BYTE_COUNT = 4;
	public static final int BIT_COUNT = 32;
	public static final int DEFAULT_TEXTUAL_RADIX = 10;
	public static final int MAX_VALUE_PER_SEGMENT = 0xff;
	public static final String REVERSE_DNS_SUFFIX = ".in-addr.arpa";
	
	protected static IPv4AddressNetwork network = new IPv4AddressNetwork();
	
	transient AddressCache sectionCache;

	/**
	 * Constructs an IPv4 address or subnet.
	 * When networkPrefixLength is non-null, this object represents a network prefix or the set of addresses with the same network prefix (a network or subnet, in other words).
	 * @param segments the address segments
	 * @param networkPrefixLength
	 * @throws IllegalArgumentException if segments is not length 4
	 */
	public IPv4Address(IPv4AddressSegment[] segments, Integer networkPrefixLength) {
		this(network().getAddressCreator().createSection(segments, networkPrefixLength));
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * @param segments the address segments
	 * @throws IllegalArgumentException if segments is not length 4
	 */
	public IPv4Address(IPv4AddressSegment[] segments) {
		this(network().getAddressCreator().createSection(segments));
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * @param section the address segments
	 * @throws IllegalArgumentException if section does not have 4 segments
	 */
	public IPv4Address(IPv4AddressSection section) {
		super(section);
		if(section.getSegmentCount() != SEGMENT_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.ipv4.invalid.segment.count") + ' ' + section.getSegmentCount());
		}
	}
	
	/**
	 * Constructs an IPv4 address.
	 * 
	 * @param address the 4 byte IPv4 address
	 */
	public IPv4Address(int address) {
		this(address, null);
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * When networkPrefixLength is non-null, this object represents a network prefix or the set of addresses with the same network prefix (a network or subnet, in other words).
	 * 
	 * @param address the 4 byte IPv4 address
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv4Address(int address, Integer networkPrefixLength) {
		super(getAddressCreator().createSectionInternal(address, networkPrefixLength));
	}
	
	/**
	 * Constructs an IPv4 address.
	 * 
	 * @param bytes must be a 4 byte IPv4 address
	 * @throws IllegalArgumentException if bytes is not length 4
	 */
	public IPv4Address(byte[] bytes) {
		this(bytes, null);
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * When networkPrefixLength is non-null, this object represents a network prefix or the set of addresses with the same network prefix (a network or subnet, in other words).
	 * 
	 * @param bytes must be a 4 byte IPv4 address
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv4Address(byte[] bytes, Integer networkPrefixLength) {
		super(getAddressCreator().createSection(bytes, networkPrefixLength));
		if(bytes.length != BYTE_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.ipv4.invalid.byte.count") + ' ' + bytes.length);
		}
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * When networkPrefixLength is non-null, this object represents a network prefix or the set of addresses with the same network prefix (a network or subnet, in other words).
	 * 
	 * @param lowerValueProvider supplies the 1 byte lower values for each segment
	 * @param upperValueProvider supplies the 1 byte upper values for each segment
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv4Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer networkPrefixLength) {
		super(getAddressCreator().createSection(lowerValueProvider, upperValueProvider, networkPrefixLength));
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * 
	 * @param lowerValueProvider supplies the 1 byte lower values for each segment
	 * @param upperValueProvider supplies the 1 byte upper values for each segment
	 */
	public IPv4Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider) {
		this(lowerValueProvider, upperValueProvider, null);
	}

	@Override
	public IPv4AddressSection getSection() {
		return (IPv4AddressSection) super.getSection();
	}

	@Override
	public IPv4AddressSection getSection(int index) {
		return getSection().getSection(index);
	}

	@Override
	public IPv4AddressSection getSection(int index, int endIndex) {
		return getSection().getSection(index, endIndex);
	}
	
	@Override
	public IPv4AddressSegment getSegment(int index) {
		return getSection().getSegment(index);
	}
	
	@Override
	public IPv4AddressSegment[] getSegments() {
		return getSection().getSegments();
	}

	@Override
	public IPAddressStringDivisionSeries[] getParts(IPStringBuilderOptions options) {
		return getParts(IPv4StringBuilderOptions.from(options));
	}
	
	public IPAddressStringDivisionSeries[] getParts(IPv4StringBuilderOptions options) {
		IPAddressStringDivisionSeries parts[] = getSection().getParts(options);
		IPv6Address ipv6Addr = getConverted(options);
		if(ipv6Addr != null) {
			IPAddressStringDivisionSeries ipv6Parts[] = ipv6Addr.getParts(options.ipv6ConverterOptions);
			IPAddressStringDivisionSeries tmp[] = parts;
			parts = new IPAddressStringDivisionSeries[tmp.length + ipv6Parts.length];
			System.arraycopy(tmp, 0, parts, 0, tmp.length);
			System.arraycopy(ipv6Parts,  0, parts, tmp.length, ipv6Parts.length);
		}
		return parts;
	}
	
	@Override
	public int getSegmentCount() {
		return SEGMENT_COUNT;
	}
	
	@Override
	public int getByteCount() {
		return BYTE_COUNT;
	}
	
	@Override
	public int getBitCount() {
		return BIT_COUNT;
	}
	
	@Override
	public IPv4Address toIPv4() {
		return this;
	}
	
	@Override
	public boolean isIPv4Convertible() {
		return true;
	}
	
	public IPv6Address getIPv4MappedAddress() {
		return IPv6Address.toIPv4Mapped(this);
	}
	
	/**
	 * @see IPv4Address#toIPv6()
	 */
	@Override
	public boolean isIPv6Convertible() {
		IPAddressConverter conv = addressConverter;
		return conv != null && conv.isIPv6Convertible(this);
	}
	
	/**
	 * Returns this address converted to IPv6.
	 * <p>
	 * This uses {@link #isIPv6Convertible()} to determine convertibility, and that uses an instance of {@link IPAddressConverter.DefaultAddressConverter} which uses IPv4-mapped address mappings from rfc 4038.
	 * <p>
	 * Override this method and {@link IPv6Address#isIPv4Convertible()} if you wish to map IPv4 to IPv6 according to the mappings defined by
	 * in {@link IPv6Address#isIPv4Compatible()}, {@link IPv6Address#isIPv4Mapped()}, {@link IPv6Address#is6To4()} or some other mapping.
	 * <p>
	 * If you override this method, you should also override the {@link IPv4Address#isIPv6Convertible()} method to match this behaviour, 
	 * and potentially also override the reverse conversion {@link IPv6Address#toIPv4()} in your {@link IPv6Address} subclass.
	 */
	@Override
	public IPv6Address toIPv6() {
		IPAddressConverter conv = addressConverter;
		if(conv != null) {
			return conv.toIPv6(this);
		}
		return null;
	}

	private IPv4Address getLowestOrHighest(boolean lowest) {
		return getSection().getLowestOrHighest(this, lowest);
	}
	
	@Override
	public IPv4Address getLower() {
		return getLowestOrHighest(true);
	}
	
	@Override
	public IPv4Address getUpper() {
		return getLowestOrHighest(false);
	}
	
	@Override
	public IPv4Address reverseBits(boolean perByte) {
		return checkIdentity(getSection().reverseBits(perByte));
	}
	
	@Override
	public IPv4Address reverseBytes() {
		return checkIdentity(getSection().reverseBytes());
	}
	
	@Override
	public IPv4Address reverseBytesPerSegment() {
		return this;
	}
	
	@Override
	public IPv4Address reverseSegments() {
		return checkIdentity(getSection().reverseSegments());
	}
	
	private IPv4Address checkIdentity(IPv4AddressSection newSection) {
		IPv4AddressSection section = getSection();
		if(newSection == section) {
			return this;
		}
		return getAddressCreator().createAddress(newSection);
	}
	
	@Override
	public IPv4Address adjustPrefixBySegment(boolean nextSegment) {
		return checkIdentity(getSection().adjustPrefixBySegment(nextSegment));
	}

	@Override
	public IPv4Address adjustPrefixLength(int adjustment) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment));
	}

	@Override
	public IPv4Address setPrefixLength(int prefixLength) {
		return setPrefixLength(prefixLength, true);
	}

	@Override
	public IPv4Address setPrefixLength(int prefixLength, boolean zeroed) {
		return checkIdentity(getSection().setPrefixLength(prefixLength, zeroed));
	}

	@Override
	public Iterator<IPv4Address> iterator() {
		IPv4AddressCreator creator = getAddressCreator();
		return getSection().iterator(this, creator);
	}

	@Override
	public Iterable<IPv4Address> getIterable() {
		return this;
	}
	
	public static IPv4AddressNetwork network() {
		return network;
	}
	
	private static IPv4AddressCreator getAddressCreator() {
		return network().getAddressCreator();
	}
	
	@Override
	public IPv4AddressNetwork getNetwork() {
		return network();
	}
	
	public static IPv4Address getLoopback() {
		return network().getLoopback();
	}
	
	public static String[] getStandardLoopbackStrings() {
		return network().getStandardLoopbackStrings();
	}
	
	private IPv4Address convertArg(IPAddress arg) {
		IPv4Address converted = arg.toIPv4();
		if(converted == null) {
			throw new AddressTypeException(this, "ipaddress.error.prefix.mask.mismatch");
		}
		return converted;
	}
	
	@Override
	public IPv4Address[] subtract(IPAddress other) {
		IPv4AddressSection thisSection = getSection();
		IPv4AddressSection sections[] = thisSection.subtract(convertArg(other).getSection());
		if(sections == null) {
			return null;
		}
		IPv4AddressCreator creator = getAddressCreator();
		IPv4Address result[] = new IPv4Address[sections.length];
		for(int i = 0; i < result.length; i++) {
			result[i] = creator.createAddress(sections[i]); /* address creation */ 
		}
		return result;
	}
	
	@Override
	public IPv4Address applyPrefixLength(int networkPrefixLength) throws AddressTypeException {
		return checkIdentity(getSection().applyPrefixLength(networkPrefixLength));
	}
	
	@Override
	protected IPAddress removePrefixLength(boolean zeroed, boolean onlyPrefixZeroed) {
		return checkIdentity(getSection().removePrefixLength(zeroed, onlyPrefixZeroed));
	}
	
	@Override
	public IPv4Address removePrefixLength(boolean zeroed) {
		return checkIdentity(getSection().removePrefixLength(zeroed));
	}
	
	@Override
	public IPv4Address removePrefixLength() {
		return removePrefixLength(true);
	}
	
	@Override
	public IPv4Address mask(IPAddress mask) throws AddressTypeException {
		return checkIdentity(getSection().mask(convertArg(mask).getSection()));
	}
	
	@Override
	public IPv4Address maskNetwork(IPAddress mask, int networkPrefixLength) throws AddressTypeException {
		return checkIdentity(getSection().maskNetwork(convertArg(mask).getSection(), networkPrefixLength));
	}
	
	@Override
	public IPv4Address bitwiseOr(IPAddress mask) throws AddressTypeException {
		return checkIdentity(getSection().bitwiseOr(convertArg(mask).getSection()));
	}
	
	@Override
	public IPv4Address bitwiseOrNetwork(IPAddress mask, int networkPrefixLength) throws AddressTypeException {
		return checkIdentity(getSection().bitwiseOrNetwork(convertArg(mask).getSection(), networkPrefixLength));
	}
	
	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength) {
		return getSection().getNetworkSection(networkPrefixLength);
	}
	
	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		return getSection().getNetworkSection(networkPrefixLength, withPrefixLength);
	}
	
	@Override
	public IPv4AddressSection getNetworkSection() {
		if(isPrefixed()) {
			return getNetworkSection(getNetworkPrefixLength(), true);
		}
		return getNetworkSection(getBitCount(), true);
	}
	
	@Override
	public IPv4AddressSection getHostSection(int networkPrefixLength) {
		return getSection().getHostSection(networkPrefixLength);
	}
	
	@Override
	public IPv4AddressSection getHostSection() {
		if(isPrefixed()) {
			return getHostSection(getNetworkPrefixLength());
		}
		return getHostSection(0);
	}

	@Override
	public Inet4Address toInetAddress() {
		return (Inet4Address) super.toInetAddress();
	}
	
	/**
	 * @see java.net.InetAddress#isLinkLocalAddress()
	 */
	@Override
	public boolean isLinkLocal() {
		return getSegment(0).matches(169) && getSegment(1).matches(254);
	}
	
	/**
	 * @see java.net.InetAddress#isSiteLocalAddress()
	 */
	@Override
	public boolean isSiteLocal() {
		IPv4AddressSegment seg0 = getSegment(0);
		IPv4AddressSegment seg1 = getSegment(1);
		return seg0.matches(10)
			|| seg0.matches(172) && seg1.matchesWithPrefix(16, 4)
			|| seg0.matches(192) && seg1.matches(168);
	}
	
	@Override
	public boolean isMulticast() {
		// 1110...
		return getSegment(0).matchesWithPrefix(0xff, 4);
	}
	
	/**
	 * @see java.net.InetAddress#isLoopbackAddress()
	 */
	@Override
	public boolean isLoopback() {
		return getSegment(0).matches(127);
	}

	/**
	 * Returns a string like the inet_aton style string
	 * @return
	 */
	public String toInetAtonString(IPv4Address.inet_aton_radix radix) {
		return getSection().toInetAtonString(radix);
	}
	
	public String toInetAtonString(IPv4Address.inet_aton_radix radix, int joinedCount) {
		return getSection().toInetAtonString(radix, joinedCount);
	}
	
	@Override
	public String toUNCHostName() {
		return super.toCanonicalString();
	}
	
	@Override
	public IPAddressPartStringCollection toStandardStringCollection() {
		return toStringCollection(IPv4StringBuilderOptions.STANDARD_OPTS);
	}

	@Override
	public IPAddressPartStringCollection toAllStringCollection() {
		return toStringCollection(IPv4StringBuilderOptions.ALL_OPTS);
	}
	
	@Override
	public IPAddressPartStringCollection toStringCollection(IPStringBuilderOptions opts) {
		return toStringCollection(IPv4StringBuilderOptions.from(opts));
	}
	
	private IPv6Address getConverted(IPv4StringBuilderOptions opts) {
		if(opts.includes(IPv4StringBuilderOptions.IPV6_CONVERSIONS)) {
			IPv6AddressConverter converter = opts.converter;
			return converter.toIPv6(this);
		}
		return null;
	}
	
	public IPAddressPartStringCollection toStringCollection(IPv4StringBuilderOptions opts) {
		IPv4StringCollection coll = new IPv4StringCollection();
		IPAddressPartStringCollection sectionColl = getSection().toStringCollection(opts);
		coll.addAll(sectionColl);
		IPv6Address ipv6Addr = getConverted(opts);
		if(ipv6Addr != null) {
			IPAddressPartStringCollection ipv6StringCollection = ipv6Addr.toStringCollection(opts.ipv6ConverterOptions);
			coll.addAll(ipv6StringCollection);
		}
		return coll;
	}
	
	/**
	 * @custom.core
	 * @author sfoley
	 *
	 */
	public interface IPv4AddressConverter {
		/**
		 * If the given address is IPv4, or can be converted to IPv4, returns that {@link IPv4Address}.  Otherwise, returns null.
		 */
		IPv4Address toIPv4(IPAddress address);
	}
	
	/**
	 * @author sfoley
	 *
	 */
	public static enum inet_aton_radix { OCTAL, HEX, DECIMAL;
		int getRadix() {
			if(this == OCTAL) {
				return 8;
			} else if(this == HEX) {
				return 16;
			}
			return 10;
		}
		
		String getSegmentStrPrefix() {
			if(this == OCTAL) {
				return "0";
			} else if(this == HEX) {
				return "0x";
			}
			return null;
		}
	}
	
	@Override
	public Iterator<IPv4AddressSegment[]> segmentsIterator() {
		return getSection().segmentsIterator();
	};
}
