package inet.ipaddr.ipv6;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressConverter;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.StringOptions;
import inet.ipaddr.IPAddressTypeException;
import inet.ipaddr.format.IPAddressPart;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4Address.IPv4AddressConverter;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringBuilderOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCache;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCollection;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions;

/**
 * An IPv6 address, or a subnet of multiple IPv6 addresses.
 * 
 * @custom.core
 * @author sfoley
 */
/*
 * rfc 6890 and the earlier 5156 has details on some of the special addresses
 * 
 * For some of the various pre-specified IPv6 address formats (IPv4 mapped, IPv4 translated, IPv4 compatible, etc), 
 * see gestioip.net/docu/ipv6_address_examples.html
 * 
 * A nice summary of IPV6 formats at https://technet.microsoft.com/en-us/library/cc757359(v=ws.10).aspx
 * https://technet.microsoft.com/en-us/library/dd379548(v=ws.10).aspx
 */
public class IPv6Address extends IPAddress implements Iterable<IPv6Address> {

	private static final long serialVersionUID = 1L;
	
	public static final char SEGMENT_SEPARATOR = ':';
	public static final char ZONE_SEPARATOR = '%';
	
	public static final int BITS_PER_SEGMENT = 16;
	public static final int BYTES_PER_SEGMENT = 2;
	public static final int SEGMENT_COUNT = 8;
	public static final int MIXED_REPLACED_SEGMENT_COUNT = 2; //IPv4Address.BYTE_COUNT / BYTES_PER_SEGMENT;
	public static final int MIXED_ORIGINAL_SEGMENT_COUNT = 6; //SEGMENT_COUNT - MIXED_REPLACED_SEGMENT_COUNT
	public static final int BYTE_COUNT = 16;
	public static final int BIT_COUNT = 128;
	public static final int DEFAULT_TEXTUAL_RADIX = 16;
	public static final int MAX_STRING_LEN = 50;
	public static final int MAX_VALUE_PER_SEGMENT = 0xffff;
	
	private static IPv6AddressNetwork network = new IPv6AddressNetwork();
	
	/* An IPv6 zone distinguishes two IPv6 addresses that are the same.
	 * They are used with link-local addresses fe80::/10 and distinguishes two interfaces to the link-local network, this is known as the zone id.
	 * They are used with site-local addresses to distinguish sites, using the site id, also known as the scope id.
	 * 
	 * A zone that consists of a scope id is called a scoped zone.
	 */
	private final String zone;
	
	private transient IPv6StringCache stringCache;
	private transient IPv6AddressCreator addressCreator;
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * @param segments the address segments
	 */
	public IPv6Address(IPv6AddressSegment[] segments) {
		this(network.getAddressCreator().createSection(segments));
	}
	
	/**
	 * Constructs an IPv6 address or a set of addresses.
	 * When networkPrefixLength is non-null, this object represents a network prefix or the set of addresses with the same network prefix (a network or subnet, in other words).
	 * @param segments the address segments
	 * @param networkPrefixLength
	 */
	public IPv6Address(IPv6AddressSegment[] segments, Integer networkPrefixLength) {
		this(network.getAddressCreator().createSection(segments, networkPrefixLength));
	}
	
	/**
	 * Constructs an IPv6 address or a set of addresses.
	 * @param segments the address segments
	 * @param zone the zone
	 */
	public IPv6Address(IPv6AddressSegment[] segments, CharSequence zone) {
		this(network.getAddressCreator().createSection(segments), zone);
	}
	
	public IPv6Address(IPv6AddressSection section, CharSequence zone) {
		super(section);
		if(section.getSegmentCount() != SEGMENT_COUNT) {
			throw new IllegalArgumentException();
		}
		this.zone = (zone == null) ? "" : zone.toString();
	}
	
	public IPv6Address(IPv6AddressSection section) throws IPAddressTypeException {
		super(section);
		if(section.getSegmentCount() != SEGMENT_COUNT) {
			throw new IllegalArgumentException();
		}
		this.zone = "";
	}
	
	/**
	 * Constructs an IPv6 address.
	 *
	 * @param bytes must be a 16 byte IPv6 address
	 */
	public IPv6Address(byte[] bytes, CharSequence zone) {
		super(network.getAddressCreator().createSection(bytes, null));
		if(bytes.length != BYTE_COUNT) {
			throw new IllegalArgumentException();
		}
		this.zone = (zone == null) ? "" : zone.toString();
	}
	
	/**
	 * Constructs an IPv6 address.
	 *
	 * @param bytes must be a 16 byte IPv6 address
	 */
	public IPv6Address(byte[] bytes) {
		this(bytes, (Integer) null);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * When networkPrefixLength is non-null, this object represents a network prefix or the set of addresses with the same network prefix (a network or subnet, in other words).
	 * 
	 * @param bytes must be a 16 byte IPv6 address
	 * @param networkPrefixLength the CIDR prefix, which can be null for no prefix length
	 * @throws IllegalArgumentException if bytes is not length 16
	 */
	public IPv6Address(byte[] bytes, Integer networkPrefixLength) {
		super(network.getAddressCreator().createSection(bytes, networkPrefixLength));
		if(bytes.length != BYTE_COUNT) {
			throw new IllegalArgumentException();
		}
		zone = "";
	}
	
	public static IPv6AddressNetwork network() {
		return network;
	}
	
	@Override
	public IPv6AddressNetwork getNetwork() {
		return network;
	}
	
	public static IPv6Address getLoopback() {
		return network.getLoopback();
	}
	
	public static String[] getStandardLoopbackStrings() {
		return network.getStandardLoopbackStrings();
	}
	
	@Override
	public IPv6AddressSection getSegments() {
		return (IPv6AddressSection) super.getSegments();
	}
	
	@Override
	public IPv6AddressSegment getSegment(int index) {
		return getSegments().getSegment(index);
	}

	@Override
	public IPAddressPart[] getParts(IPStringBuilderOptions options) {
		return getParts(IPv6StringBuilderOptions.from(options));
	}
	
	public IPAddressPart[] getParts(IPv6StringBuilderOptions options) {
		IPAddressPart parts[] = getSegments().getParts(options);
		IPv4Address ipv4Addr = getConverted(options);
		if(ipv4Addr != null) {
			IPAddressPart ipv4Parts[] = ipv4Addr.getParts(options.ipv4ConverterOptions);
			IPAddressPart tmp[] = parts;
			parts = new IPAddressPart[tmp.length + ipv4Parts.length];
			System.arraycopy(tmp, 0, parts, 0, tmp.length);
			System.arraycopy(ipv4Parts,  0, parts, tmp.length, ipv4Parts.length);
		}
		return parts;
	}
	
	private static IPv6AddressSection createSection(IPv6AddressSegment nonMixedSection[], IPv4Address mixedSection) throws IPAddressTypeException {
		IPv4AddressSection ipv4Section = mixedSection.getSegments();
		IPv6AddressCreator creator = network.getAddressCreator();
		IPv6AddressSegment newSegs[] = creator.createAddressSegmentArray(SEGMENT_COUNT);
		newSegs[0] = nonMixedSection[0];
		newSegs[1] = nonMixedSection[1];
		newSegs[2] = nonMixedSection[2];
		newSegs[3] = nonMixedSection[3];
		newSegs[4] = nonMixedSection[4];
		newSegs[5] = nonMixedSection[5];
		newSegs[6] = IPv6AddressSegment.join(ipv4Section.getSegment(0), ipv4Section.getSegment(1));
		newSegs[7] = IPv6AddressSegment.join(ipv4Section.getSegment(2), ipv4Section.getSegment(3));
		IPv6AddressSection result = creator.createSectionInternal(newSegs);
		result.mixedSection = ipv4Section;
		return result;
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
	
	private IPv6Address getLowestOrHighest(boolean lowest) {
		IPv6AddressCreator creator = getAddressCreator();
		return getSingle(this, () -> {
			IPv6AddressSection section = getSegments();
			IPv6AddressSegment[] segs = createSingle(section, creator, i -> {
				IPv6AddressSegment seg = getSegment(i);
				return lowest ? seg.getLowest() : seg.getHighest();
			});
			return creator.createAddressInternal(segs);
		});
	}
	
	@Override
	public IPv6Address getLowest() {
		return getLowestOrHighest(true);
	}
	
	@Override
	public IPv6Address getHighest() {
		return getLowestOrHighest(false);
	}
	
	@Override
	public Iterator<IPv6Address> iterator() {
		return iterator(this, getAddressCreator(), () -> getSegments().getLowestSegments(), index -> getSegment(index).iterator());
	}
	
	@Override
	public Iterable<IPv6Address> getAddresses() {
		return this;
	}

	protected IPv6AddressCreator getAddressCreator() {
		IPv6AddressCreator creator = addressCreator;
		if(creator == null) {
			if(hasZone()) {
				creator = new IPv6AddressCreator() {
					@Override
					protected IPv6Address createAddressInternal(IPv6AddressSegment segments[]) {
						IPv6AddressCreator creator = network.getAddressCreator();
						return creator.createAddressInternal(segments, zone);
					}
				};
			} else {
				creator = network.getAddressCreator();
			}
			addressCreator = creator;
		}
		return creator;
	}
	
	public static IPAddress from(byte bytes[], String zone) {
		if(bytes.length != BYTE_COUNT) {
			throw new IllegalArgumentException();
		}
		IPv6AddressCreator addressCreator = network().getAddressCreator();
		IPv6AddressSegment segments[] = toSegments(bytes, SEGMENT_COUNT, BYTES_PER_SEGMENT, BITS_PER_SEGMENT, addressCreator, null);
		return addressCreator.createAddressInternal(segments, zone);
	}

	/**
	 * If this address is IPv4 convertible, returns that address.
	 * Otherwise, returns null.
	 * 
	 * This uses {@link #isIPv4Convertible()} to determine convertibility, and that uses an instance of {@link IPAddressConverter.DefaultAddressConverter} which uses IPv4-mapped address mappings from rfc 4038.
	 * 
	 * Override this method and {@link IPv6Address#isIPv4Convertible()} if you wish to map IPv6 to IPv4 according to the mappings defined by
	 * in {@link IPv6Address#isIPv4Compatible()}, {@link IPv6Address#isIPv4Mapped()}, {@link IPv6Address#is6To4()} or by some other mapping.
	 * 
	 * For the reverse mapping, see {@link IPv4Address#toIPv6()} 
	 */
	@Override
	public IPv4Address toIPv4() {
		IPAddressConverter conv = addressConverter;
		if(conv != null && conv.isIPv4Convertible(this)) {
			return conv.toIPv4(this);
		}
		return null;
	}
	
	@Override
	public IPv6Address toIPv6() {
		return this;
	}
	
	/**
	 * Determines whether this address can be converted to IPv4. 
	 * Override this method to convert in your own way, or call setAddressConverter with your own converter object.
	 * The default behaviour is to use isIPv4Mapped()
	 * 
	 * You should also override {@link #toIPv4()} to match the conversion.
	 * 
	 * @return
	 */
	@Override
	public boolean isIPv4Convertible() {
		IPAddressConverter conv = addressConverter;
		return conv != null && conv.isIPv4Convertible(this);
	}
	
	@Override
	public boolean isIPv6Convertible() {
		return true;
	}

	/**
	 * 
	 * @param addr
	 * @return
	 * @throws IPAddressTypeException if the IPv4 address segments cannot be converted to IPv6 segments because of one or more incompatible segment ranges.
	 */
	public static IPv6Address toIPv4Mapped(IPv4Address addr) throws IPAddressTypeException {
		IPv6AddressSegment zero = IPv6AddressSegment.ZERO_SEGMENT;
		IPv6AddressCreator creator = network.getAddressCreator();
		IPv6AddressSegment segs[] = creator.createAddressSegmentArray(MIXED_ORIGINAL_SEGMENT_COUNT);
		segs[0] = segs[1] = segs[2] = segs[3] = segs[4] = zero;
		segs[5] = IPv6AddressSegment.ALL_SEGMENT;
		return creator.createAddress(createSection(segs, addr));
	}
	
	/**
	 * ::ffff:x:x/96 indicates IPv6 address mapped to IPv4
	 */
	public IPv4AddressSection toMappedIPv4Segments() {
		if(isIPv4Mapped()) {
			return getSegments().getMixedSection();
		}
		return null;
	}
	
	/**
	 * Returns the embedded {@link IPv4Address} in the lowest (least-significant) two segments.
	 * This is used by IPv4-mapped, IPv4-compatible, ISATAP addresses and 6over4 addresses
	 * 
	 * @return the embedded {@link IPv4Address}
	 */
	public IPv4Address getLowerIPv4Address() {
		IPv4AddressCreator creator = IPv4Address.network().getAddressCreator();
		return creator.createAddress(getSegments().getMixedSection());
	}
	
	/**
	 * Returns the second and third bytes as an {@link IPv4Address}.
	 * 
	 * This can be used for IPv4 or for IPv6 6to4 addresses convertible to IPv4.
	 * 
	 * @return the address
	 */
	public IPv4Address get6to4IPv4Address() {
		return getEmbeddedIPv4Address(2);
	}
	
	/**
	 * Produces an IPv4 address from any sequence of 4 bytes in this IPv6 address.
	 * 
	 * @param byteIndex the byte index to start
	 * @throws IndexOutOfBoundsException if the index is less than zero or bigger than 7
	 * @return
	 */
	public IPv4Address getEmbeddedIPv4Address(int byteIndex) {
		if(byteIndex == IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT * IPv6Address.BYTES_PER_SEGMENT) {
			return getLowerIPv4Address();
		}
		IPv4AddressCreator creator = IPv4Address.network().getAddressCreator();
		return creator.createAddress(getSegments().getEmbeddedIPv4AddressSection(byteIndex, byteIndex + IPv4Address.BYTE_COUNT));
	}
	
	/**
	 * @see java.net.InetAddress#isLinkLocalAddress()
	 */
	@Override
	public boolean isLinkLocal() {
		//1111 1110 10 .... fe8x currently only in use
		return getSegment(0).matchesWithPrefix(0xfe80, 10);
	}
	
	/**
	 * @see java.net.InetAddress#isSiteLocalAddress()
	 */
	@Override
	public boolean isSiteLocal() {
		//1111 1110 11 ...
		return getSegment(0).matchesWithPrefix(0xfec0, 10);
	}
	
	public boolean isUniqueLocal() {
		return getSegment(0).matchesWithPrefix(0xfc00, 7);
	}
	
	/**
	 * Whether the address is IPv4-mapped
	 * 
	 * ::ffff:x:x/96 indicates IPv6 address mapped to IPv4
	 */
	public boolean isIPv4Mapped() {
		//::ffff:x:x/96 indicates IPv6 address mapped to IPv4
		if(getSegment(5).matches(IPv6AddressSegment.ALL_SEGMENT.getLowerSegmentValue())) {
			for(int i = 0; i < 5; i++) {
				if(!getSegment(i).isZero()) {
					return false;
				}
			}
			return true;
		}
		return false;
	}
	
	/**
	 * Whether the address is IPv4-compatible
	 * 
	 * @see java.net.Inet6Address#isIPv4CompatibleAddress()
	 */
	public boolean isIPv4Compatible() {
		return getSegment(0).isZero() && getSegment(1).isZero() && getSegment(2).isZero() &&
				getSegment(3).isZero() && getSegment(4).isZero() && getSegment(5).isZero();
	}
	
	/**
	 * Whether the address is IPv6 to IPv4 relay
	 */
	public boolean is6To4() {
		//2002::/16
		return getSegment(0).matches(0x2002);
	}
	
	/**
	 * Whether the address is 6over4
	 */
	public boolean is6Over4() {
		return getSegment(4).isZero() && getSegment(5).isZero();
	}
	
	/**
	 * Whether the address is Teredo
	 */
	public boolean isTeredo() {
		//2001::/32
		return getSegment(0).matches(0x2001) && getSegment(1).isZero();
	}

	/**
	 * Whether the address is ISATAP
	 */
	public boolean isIsatap() {
		return getSegment(4).isZero() && getSegment(5).matches(0x5efe);
	}
	
	/**
	 * 
	 * @return Whether the address is IPv4 translatable as in rfc 2765
	 */
	public boolean isIPv4Translatable() { //rfc 2765  
		//::ffff:0:x:x/96 indicates IPv6 addresses translated from IPv4
		if(getSegment(4).matches(0xffff) && getSegment(5).isZero()) {
			for(int i = 0; i < 3; i++) {
				if(!getSegment(i).isZero()) {
					return false;
				}
			}
			return true;
		}
		return false;
	}
	
	/**
	 * Whether the address has the well-known prefix for IPv4 translatable addresses as in rfc 6052 and 6144
	 * @return
	 */
	public boolean isWellKnownIPv4Translatable() { //rfc 6052 rfc 6144
		//64:ff9b::/96 prefix for auto ipv4/ipv6 translation
		if(getSegment(0).matches(0x64) && getSegment(1).matches(0xff9b)) {
			for(int i=2; i<=5; i++) {
				if(!getSegment(i).isZero()) {
					return false;
				}
			}
			return true;
		}
		return false;
	}
	
	@Override
	public boolean isMulticast() {
		// 11111111...
		return getSegment(0).matchesWithPrefix(0xff, 8);
	}

	/**
	 * @see java.net.InetAddress#isLoopbackAddress()
	 */
	@Override
	public boolean isLoopback() {
		//::1
		int i=0;
		for(; i < getSegmentCount() - 1; i++) {
			if(!getSegment(i).isZero()) {
				return false;
			}
		}
		return getSegment(i).matches(1);
	}
	
	@Override
	public IPv6Address[] subtract(IPAddress other) {
		IPv6AddressSection thisSection = getSegments();
		IPv6AddressSection sections[] = thisSection.subtract(other.getSegments());
		if(sections == null) {
			return null;
		}
		IPv6AddressCreator creator = getAddressCreator();
		IPv6Address result[] = new IPv6Address[sections.length];
		for(int i = 0; i < result.length; i++) {
			result[i] = creator.createAddress(sections[i]);
		}
		return result;
	}

	@Override
	public IPv6Address toSubnet(int networkPrefixLength) throws IPAddressTypeException {
		IPv6AddressSection thisSection = getSegments();
		IPv6AddressSection subnetSection = thisSection.toSubnet(networkPrefixLength);
		if(thisSection == subnetSection) {
			return this;
		}
		IPv6AddressCreator creator = network.getAddressCreator();
		return creator.createAddress(subnetSection);
	}

	/**
	 * Creates a subnet address using the given mask.
	 * The mask can be a subnet itself, in which case the lowest value of the mask's range is used.
	 */
	@Override
	public IPv6Address toSubnet(IPAddress mask) throws IPAddressTypeException {
		return toSubnet(mask, null);
	}
	
	/**
	 * Creates a subnet address using the given mask.  If networkPrefixLength is non-null, applies the prefix length as well.
	 * The mask can be a subnet itself, in which case the lowest value of the mask's range is used.
	 */
	@Override
	public IPv6Address toSubnet(IPAddress mask, Integer networkPrefixLength) throws IPAddressTypeException {
		IPv6AddressSection thisSection = getSegments();
		IPv6AddressSection subnetSection = thisSection.toSubnet(mask.getSegments(), networkPrefixLength);
		if(thisSection == subnetSection) {
			return this;
		}
		IPv6AddressCreator creator = network.getAddressCreator();
		return creator.createAddress(subnetSection);
	}

	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		return getSegments().getNetworkSection(networkPrefixLength, withPrefixLength);
	}
	
	@Override
	public IPv6AddressSection getNetworkSection() {
		if(isPrefixed()) {
			return getNetworkSection(getNetworkPrefixLength(), true);
		}
		return getNetworkSection(getBitCount(), true);
	}
	
	@Override
	public IPv6AddressSection getHostSection(int networkPrefixLength) {
		return getSegments().getHostSection(networkPrefixLength);
	}
	
	@Override
	public IPv6AddressSection getHostSection() {
		if(isPrefixed()) {
			return getHostSection(getNetworkPrefixLength());
		}
		return getHostSection(0);
	}

	public boolean hasZone() {
		return zone.length() > 0;
	}
	
	public String getZone() {
		return zone;
	}
	
	public IPv6Address removeZone() {
		return network.getAddressCreator().createAddress(getSegments());
	}

	@Override
	public Inet6Address toInetAddress() {
		Inet6Address result = (Inet6Address) inetAddress;
		if(result == null) {
			synchronized(this) {
				result = (Inet6Address) inetAddress;
				if(result == null) {
					byte bytes[] = getBytes();
					try {
						if(hasZone()) {
							try {
								int scopeId = Integer.valueOf(zone);
								result = Inet6Address.getByAddress(null, bytes, scopeId);
							} catch(NumberFormatException e) {
								//there is no related function that takes a string as third arg. Only other one takes a NetworkInterface.  we don't want to be looking up network interface objects.
								//public static Inet6Address getByAddress(String host, byte[] addr, NetworkInterface nif) 
							
								//so we must go back to a string, even though we have the bytes available to us.  There appears to be no other alternative.
								result = (Inet6Address) InetAddress.getByName(toNormalizedString());
							}
						} else {
							result = (Inet6Address) InetAddress.getByAddress(bytes);
						}
					} catch(UnknownHostException e) {
						result = null;
					}
					inetAddress = result;
				}
			}
		}
		return result;
	}
	
	@Override
	public int hashCode() {
		int result = super.hashCode();
		if(hasZone()) {
			result *= zone.hashCode();
		}
		return result;
	}
	
	@Override
	public boolean isSameAddress(IPAddress other) {
		if(super.isSameAddress(other)) {
			//must check the zone too
			IPv6Address otherIPv6Address = other.toIPv6();
			String otherZone = otherIPv6Address.zone;
			return zone.equals(otherZone);
		}
		return false;
	}
	
	/**
	 * 
	 * @param other
	 * @return whether this subnet contains the given address
	 */
	@Override
	public boolean contains(IPAddress other) {
		if(super.contains(other)) {
			//must check the zone too
			if(other != this) {
				IPv6Address otherIPv6Address = other.toIPv6();
				String otherZone = otherIPv6Address.zone;
				return zone.equals(otherZone);
			}
			return true;
		}
		return false;
	}
	
	//////////////// string creation below ///////////////////////////////////////////////////////////////////////////////////////////
	
	private boolean hasNoCache() {
		if(stringCache == null) {
			synchronized(this) {
				if(stringCache == null) {
					if(hasZone()) {
						stringCache = new IPv6StringCache();
					} else {
						//when there is no zone, the section and address strings are the same, so we use the same cache
						IPv6AddressSection section = getSegments();
						boolean result = section.hasNoCache();
						stringCache = section.stringCache;
						return result;
					}
					return true;
				}
			}
		}
		return false;
	}
	
	public String toMixedString() {
		String result;
		if(hasNoCache() || (result = stringCache.mixedString) == null) {
			if(hasZone()) {
				stringCache.mixedString = result = toNormalizedString(IPv6StringCache.mixedParams);
			} else {
				result = getSegments().toMixedString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toCanonicalString() {
		String result;
		if(hasNoCache() || (result = stringCache.canonicalString) == null) {
			if(hasZone()) {
				stringCache.canonicalString = result = toNormalizedString(IPv6StringCache.canonicalParams);
			} else {
				result = getSegments().toCanonicalString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}

	@Override
	public String toFullString() {
		String result;
		if(hasNoCache() || (result = stringCache.fullString) == null) {
			if(hasZone()) {
				stringCache.fullString = result = toNormalizedString(IPv6StringCache.fullParams);
			} else {
				result = getSegments().toFullString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toNormalizedString() {
		String result;
		if(hasNoCache() || (result = stringCache.normalizedString) == null) {
			if(hasZone()) {
				stringCache.normalizedString = result = toNormalizedString(IPv6StringCache.normalizedParams);
			} else {
				result = getSegments().toNormalizedString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toCompressedString() {
		String result;
		if(hasNoCache() || (result = stringCache.compressedString) == null) {
			if(hasZone()) {
				stringCache.compressedString = result = toNormalizedString(IPv6StringCache.compressedParams);
			} else {
				result = getSegments().toCompressedString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toSubnetString() {
		return toNetworkPrefixLengthString();
	}
	
	//note this string is used by hashCode
	@Override
	public String toNormalizedWildcardString() {
		String result;
		if(hasNoCache() || (result = stringCache.normalizedWildcardString) == null) {
			if(hasZone()) {
				stringCache.normalizedWildcardString = result = toNormalizedString(IPv6StringCache.wildcardNormalizedParams);
			} else {
				result = getSegments().toNormalizedWildcardString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toCanonicalWildcardString() {
		String result;
		if(hasNoCache() || (result = stringCache.canonicalWildcardString) == null) {
			if(hasZone()) {
				stringCache.canonicalWildcardString = result = toNormalizedString(IPv6StringCache.wildcardCanonicalParams);
			} else {
				result = getSegments().toCanonicalWildcardString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toCompressedWildcardString() {
		String result;
		if(hasNoCache() || (result = stringCache.compressedWildcardString) == null) {
			if(hasZone()) {
				stringCache.compressedWildcardString = result = toNormalizedString(IPv6StringCache.wildcardCompressedParams);
			} else {
				result = getSegments().toCompressedWildcardString();//the cache is shared with the section, so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toSQLWildcardString() {
		String result;
		if(hasNoCache() || (result = stringCache.sqlWildcardString) == null) {
			if(hasZone()) {
				stringCache.sqlWildcardString = result = toNormalizedString(IPv6StringCache.sqlWildcardParams);
			} else {
				result = getSegments().toSQLWildcardString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toNetworkPrefixLengthString() {
		String result;
		if(hasNoCache() || (result = stringCache.networkPrefixLengthString) == null) {
			if(hasZone()) {
				stringCache.networkPrefixLengthString = result = toNormalizedString(IPv6StringCache.networkPrefixLengthParams);
			} else {
				result = getSegments().toNetworkPrefixLengthString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toConvertedString() {
		if(isIPv4Convertible()) {
			return toMixedString();
		}
		return toNormalizedString();
	}
	
	@Override
	public String toNormalizedString(StringOptions params) {
		return toNormalizedString(IPv6StringOptions.from(params));
	}
	
	public String toNormalizedString(IPv6StringOptions params) {
		return getSegments().toNormalizedString(params, zone);
	}

	/**
	 * Constructs a string representing this address according to the given parameters
	 * 
	 * @param keepMixed if this address was constructed from a string with mixed representation (a:b:c:d:e:f:1.2.3.4), whether to keep it that way (ignored if makeMixed is true in the params argument)
	 * @param params the parameters for the address string
	 */
	public String toNormalizedString(boolean keepMixed, IPv6StringOptions params) {
		if(keepMixed && fromString != null && fromString.isMixedIPv6() && !params.makeMixed()) {
			params = new IPv6StringOptions(
					params.base,
					params.expandSegments,
					params.wildcardOptions,
					params.segmentStrPrefix,
					true,
					params.ipv4Opts,
					params.compressOptions,
					params.separator,
					params.zoneSeparator,
					params.addrSuffix,
					params.reverse,
					params.splitDigits);
		}
		return toNormalizedString(params);
	}
	
	@Override
	public String toUNCHostName() {
		String result;
		if(hasNoCache() || (result = stringCache.uncString) == null) {
			stringCache.uncString = result = toNormalizedString(IPv6StringCache.uncParams);
		}
		return result;
	}
	
	@Override
	public String toReverseDNSLookupString() {
		String result;
		if(hasNoCache() || (result = stringCache.reverseDNSString) == null) {
			stringCache.reverseDNSString = result = getSegments().toNormalizedString(IPv6StringCache.reverseDNSParams, "");//the zone is dropped
		}
		return result;
	}
	
	@Override
	public IPAddressPartStringCollection toStandardStringCollection() {
		return toStringCollection(IPv6StringBuilderOptions.STANDARD_OPTS);
	}

	@Override
	public IPAddressPartStringCollection toAllStringCollection() {
		return toStringCollection(IPv6StringBuilderOptions.ALL_OPTS);
	}
	
	@Override
	public IPAddressPartStringCollection toStringCollection(IPStringBuilderOptions opts) {
		return toStringCollection(IPv6StringBuilderOptions.from(opts));
	}

	private IPv4Address getConverted(IPv6StringBuilderOptions opts) {
		if(!hasZone() && opts.includes(IPv6StringBuilderOptions.IPV4_CONVERSIONS)) {//we cannot convert to ipv4 if there is a zone
			IPv4AddressConverter converter = opts.converter;
			return converter.toIPv4(this);
		}
		return null;
	}
	
	public IPAddressPartStringCollection toStringCollection(IPv6StringBuilderOptions opts) {
		IPv6StringCollection coll = getSegments().toStringCollection(opts, zone);
		IPv4Address ipv4Addr = getConverted(opts);
		if(ipv4Addr != null) {
			IPAddressPartStringCollection ipv4StringCollection = ipv4Addr.toStringCollection(opts.ipv4ConverterOptions);
			coll.addAll(ipv4StringCollection);
		}
		return coll;
	}
	
	public interface IPv6AddressConverter {
		/**
		 * If the given address is IPv6, or can be converted to IPv6, returns that {@link IPv6Address}.  Otherwise, returns null.
		 */
		IPv6Address toIPv6(IPAddress address);
	}
}
