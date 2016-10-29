package inet.ipaddr.ipv4;

import java.net.Inet4Address;
import java.util.Iterator;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressConverter;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.format.IPAddressPart;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringBuilderOptions;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringCache;
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

	private static final long serialVersionUID = 1L;
	
	public static final char SEGMENT_SEPARATOR = '.';
	public static final int BITS_PER_SEGMENT = 8;
	public static final int BYTES_PER_SEGMENT = 1;
	public static final int SEGMENT_COUNT = 4;
	public static final int BYTE_COUNT = 4;
	public static final int BIT_COUNT = 32;
	public static final int DEFAULT_TEXTUAL_RADIX = 10;
	public static final int MAX_STRING_LEN = 15;
	public static final int MAX_VALUE_PER_SEGMENT = 0xff;
	
	private static IPv4AddressNetwork network = new IPv4AddressNetwork();
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * When networkPrefixLength is non-null, this object represents a network prefix or the set of addresses with the same network prefix (a network or subnet, in other words).
	 * @param segments the address segments
	 * @param networkPrefixLength
	 * @throws IllegalArgumentException if segments is not length 4
	 */
	public IPv4Address(IPv4AddressSegment[] segments, Integer networkPrefixLength) {
		this(network.getAddressCreator().createSection(segments, networkPrefixLength));
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * @param segments the address segments
	 * @throws IllegalArgumentException if segments is not length 4
	 */
	public IPv4Address(IPv4AddressSegment[] segments) {
		this(network.getAddressCreator().createSection(segments));
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * @param section the address segments
	 * @throws IllegalArgumentException if section does not have 4 segments
	 */
	public IPv4Address(IPv4AddressSection section) {
		super(section);
		if(section.getSegmentCount() != SEGMENT_COUNT) {
			throw new IllegalArgumentException();
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
		super(getAddressCreator().createSectionInternal(new byte[] {
				(byte) (address >> 24),
				(byte) ((address >> 16) & 0xff),
				(byte) ((address >> 8) & 0xff),
				(byte) (address & 0xff),
			}, networkPrefixLength));
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
	 * @throws IllegalArgumentException if bytes is not length 4
	 */
	public IPv4Address(byte[] bytes, Integer networkPrefixLength) {
		super(getAddressCreator().createSection(bytes, networkPrefixLength));
		if(bytes.length != BYTE_COUNT) {
			throw new IllegalArgumentException();
		}
	}

	@Override
	public IPv4AddressSection getSegments() {
		return (IPv4AddressSection) super.getSegments();
	}

	@Override
	public IPv4AddressSegment getSegment(int index) {
		return getSegments().getSegment(index);
	}

	@Override
	public IPAddressPart[] getParts(IPStringBuilderOptions options) {
		return getParts(IPv4StringBuilderOptions.from(options));
	}
	
	public IPAddressPart[] getParts(IPv4StringBuilderOptions options) {
		IPAddressPart parts[] = getSegments().getParts(options);
		IPv6Address ipv6Addr = getConverted(options);
		if(ipv6Addr != null) {
			IPAddressPart ipv6Parts[] = ipv6Addr.getParts(options.ipv6ConverterOptions);
			IPAddressPart tmp[] = parts;
			parts = new IPAddressPart[tmp.length + ipv6Parts.length];
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
		if(conv != null && conv.isIPv6Convertible(this)) {
			return conv.toIPv6(this);
		}
		return null;
	}
	
	private IPv4Address getLowestOrHighest(boolean lowest) {
		IPv4AddressCreator creator = getAddressCreator();
		return getSingle(this, () -> {
			IPv4AddressSection section = getSegments();
			IPv4AddressSegment[] segs = createSingle(section, creator, i -> {
				IPv4AddressSegment seg = getSegment(i);
				return lowest ? seg.getLowest() : seg.getHighest();
			});
			return creator.createAddressInternal(segs);
		});
	}
	
	@Override
	public IPv4Address getLowest() {
		return getLowestOrHighest(true);
	}
	
	@Override
	public IPv4Address getHighest() {
		return getLowestOrHighest(false);
	}
	
	@Override
	public Iterator<IPv4Address> iterator() {
		return iterator(this, getAddressCreator(), () -> getSegments().getLowestSegments(), index -> getSegment(index).iterator());
	}
	
	@Override
	public Iterable<IPv4Address> getAddresses() {
		return this;
	}
	
	public static IPv4AddressNetwork network() {
		return network;
	}
	
	private static IPv4AddressCreator getAddressCreator() {
		return network.getAddressCreator();
	}
	
	@Override
	public IPv4AddressNetwork getNetwork() {
		return network;
	}
	
	public static IPv4Address getLoopback() {
		return network.getLoopback();
	}
	
	public static String[] getStandardLoopbackStrings() {
		return network.getStandardLoopbackStrings();
	}
	
	@Override
	public IPv4Address[] subtract(IPAddress other) {
		IPv4AddressSection thisSection = getSegments();
		IPv4AddressSection sections[] = thisSection.subtract(other.getSegments());
		if(sections == null) {
			return null;
		}
		IPv4AddressCreator creator = getAddressCreator();
		IPv4Address result[] = new IPv4Address[sections.length];
		for(int i = 0; i < result.length; i++) {
			result[i] = creator.createAddress(sections[i]);
		}
		return result;
	}
	
	@Override
	public IPv4Address toSubnet(int networkPrefixLength) throws IPAddressTypeException {
		IPv4AddressSection thisSection = getSegments();
		IPv4AddressSection subnetSection = thisSection.toSubnet(networkPrefixLength);
		if(thisSection == subnetSection) {
			return this;
		}
		return getAddressCreator().createAddress(subnetSection);
	}
		
	/**
	 * Creates a subnet address using the given mask. 
	 */
	@Override
	public IPv4Address toSubnet(IPAddress mask) throws IPAddressTypeException {
		return toSubnet(mask, null);
	}
	
	/**
	 * Creates a subnet address using the given mask.  If networkPrefixLength is non-null, applies the prefix length as well.
	 */
	@Override
	public IPv4Address toSubnet(IPAddress mask, Integer networkPrefixLength) throws IPAddressTypeException {
		IPv4AddressSection thisSection = getSegments();
		IPv4AddressSection subnetSection = thisSection.toSubnet(mask.getSegments(), networkPrefixLength);
		if(thisSection == subnetSection) {
			return this;
		}
		return getAddressCreator().createAddress(subnetSection);
	}
	
	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		return getSegments().getNetworkSection(networkPrefixLength, withPrefixLength);
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
		return getSegments().getHostSection(networkPrefixLength);
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
		return getSegments().toInetAtonString(radix);
	}
	
	public String toInetAtonString(IPv4Address.inet_aton_radix radix, int joinedCount) {
		return getSegments().toInetAtonString(radix, joinedCount);
	}
	
	@Override
	public String toUNCHostName() {
		return super.toCanonicalString();
	}
	
	@Override
	public String toReverseDNSLookupString() {
		String result;
		IPv4AddressSection section = getSegments();
		if(section.hasNoCache() || (result = section.stringCache.reverseDNSString) == null) {
			section.stringCache.reverseDNSString = result = toNormalizedString(IPv4StringCache.reverseDNSParams);
		}
		return result;
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
		IPAddressPartStringCollection sectionColl = getSegments().toStringCollection(opts);
		coll.addAll(sectionColl);
		IPv6Address ipv6Addr = getConverted(opts);
		if(ipv6Addr != null) {
			IPAddressPartStringCollection ipv6StringCollection = ipv6Addr.toStringCollection(opts.ipv6ConverterOptions);
			coll.addAll(ipv6StringCollection);
		}
		return coll;
	}
	
	public interface IPv4AddressConverter {
		/**
		 * If the given address is IPv4, or can be converted to IPv4, returns that {@link IPv4Address}.  Otherwise, returns null.
		 */
		IPv4Address toIPv4(IPAddress address);
	}
	
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
	};
}
