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

package inet.ipaddr.ipv6;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;

import inet.ipaddr.AddressTypeException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressConverter;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.format.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4Address.IPv4AddressConverter;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection.AddressCache;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringBuilderOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCache;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCollection;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSegment;

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

	private static final long serialVersionUID = 3L;
	
	public static final char SEGMENT_SEPARATOR = ':';
	public static final char ZONE_SEPARATOR = '%';
	public static final char ALTERNATIVE_ZONE_SEPARATOR = '§';
	
	public static final char UNC_SEGMENT_SEPARATOR = '-';
	public static final char UNC_ZONE_SEPARATOR = 's';
	public static final char UNC_RANGE_SEPARATOR = ALTERNATIVE_RANGE_SEPARATOR;
	public static final String UNC_RANGE_SEPARATOR_STR = String.valueOf(UNC_RANGE_SEPARATOR);
	
	public static final String UNC_SUFFIX = ".ipv6-literal.net";
	
	public static final String REVERSE_DNS_SUFFIX = ".ip6.arpa";
	public static final String REVERSE_DNS_SUFFIX_DEPRECATED = ".ip6.int";
	
	public static final int BITS_PER_SEGMENT = 16;
	public static final int BYTES_PER_SEGMENT = 2;
	public static final int SEGMENT_COUNT = 8;
	public static final int MIXED_REPLACED_SEGMENT_COUNT = 2; //IPv4Address.BYTE_COUNT / BYTES_PER_SEGMENT;
	public static final int MIXED_ORIGINAL_SEGMENT_COUNT = 6; //SEGMENT_COUNT - MIXED_REPLACED_SEGMENT_COUNT
	public static final int BYTE_COUNT = 16;
	public static final int BIT_COUNT = 128;
	public static final int DEFAULT_TEXTUAL_RADIX = 16;
	public static final int MAX_VALUE_PER_SEGMENT = 0xffff;
	
	protected static IPv6AddressNetwork network = new IPv6AddressNetwork();
	
	/* 
	 * An IPv6 zone distinguishes two IPv6 addresses that are the same.
	 * They are used with link-local addresses fe80::/10 and distinguishes two interfaces to the link-local network, this is known as the zone id.
	 * They are used with site-local addresses to distinguish sites, using the site id, also known as the scope id.
	 * 
	 * A zone that consists of a scope id is called a scoped zone.
	 */
	private final String zone;

	private transient IPv6StringCache stringCache;
	
	transient AddressCache sectionCache;

	private transient IPv6AddressCreator creator;
	
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * @param segments the address segments
	 */
	public IPv6Address(IPv6AddressSegment[] segments) {
		this(network().getAddressCreator().createSection(segments));
	}

	/**
	 * Constructs an IPv6 address or a set of addresses.
	 * When networkPrefixLength is non-null, this object represents a network prefix or the set of addresses with the same network prefix (a network or subnet, in other words).
	 * @param segments the address segments
	 * @param networkPrefixLength
	 */
	public IPv6Address(IPv6AddressSegment[] segments, Integer networkPrefixLength) {
		this(network().getAddressCreator().createSection(segments, networkPrefixLength));
	}
	
	/**
	 * Constructs an IPv6 address or a set of addresses.
	 * @param segments the address segments
	 * @param zone the zone
	 */
	public IPv6Address(IPv6AddressSegment[] segments, CharSequence zone) {
		this(network().getAddressCreator().createSection(segments), zone);
	}
	
	public IPv6Address(IPv6AddressSection section, CharSequence zone) {
		super(section);
		if(section.getSegmentCount() != SEGMENT_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.ipv6.invalid.segment.count") + ' ' + section.getSegmentCount());
		}
		this.zone = (zone == null) ? "" : zone.toString();
	}
	
	public IPv6Address(IPv6AddressSection section) throws AddressTypeException {
		super(section);
		if(section.getSegmentCount() != SEGMENT_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.ipv6.invalid.segment.count") + ' ' + section.getSegmentCount());
		}
		this.zone = "";
	}
	
	/**
	 * Constructs an IPv6 address.
	 *
	 * @param bytes must be a 16 byte IPv6 address
	 */
	public IPv6Address(byte[] bytes, CharSequence zone) {
		super(network().getAddressCreator().createSection(bytes, null));
		if(bytes.length != BYTE_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.ipv6.invalid.byte.count") + ' ' + bytes.length);
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
		super(network().getAddressCreator().createSection(bytes, networkPrefixLength));
		if(bytes.length != BYTE_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.ipv6.invalid.byte.count") + ' ' + bytes.length);
		}
		zone = "";
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * When networkPrefixLength is non-null, this object represents a network prefix or the set of addresses with the same network prefix (a network or subnet, in other words).
	 * 
	 * @param lowerValueProvider supplies the 2 byte lower values for each segment
	 * @param upperValueProvider supplies the 2 byte upper values for each segment
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer networkPrefixLength) {
		super(network().getAddressCreator().createSection(lowerValueProvider, upperValueProvider, networkPrefixLength));
		zone = "";
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * 
	 * @param lowerValueProvider supplies the 2 byte lower values for each segment
	 * @param upperValueProvider supplies the 2 byte upper values for each segment
	 */
	public IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider) {
		this(lowerValueProvider, upperValueProvider, (Integer) null);
	}
	
	/**
	 * Constructs an IPv6 address.
	 *
	 * @param lowerValueProvider supplies the 2 byte lower values for each segment
	 * @param upperValueProvider supplies the 2 byte upper values for each segment
	 */
	public IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, CharSequence zone) {
		super(network().getAddressCreator().createSection(lowerValueProvider, upperValueProvider, null));
		this.zone = (zone == null) ? "" : zone.toString();
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address section and an IPv6 address section network prefix.
	 * 
	 * If the supplied MAC section is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied section is a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * 
	 * If the supplied section neither 6 nor 8 bytes, or if the 8-byte section does not have required EUI-64 format of xx-xx-ff-fe-xx-xx,
	 * AddressTypeException will be thrown.
	 *
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * 
	 * Only the first 8 bytes (4 segments) of the IPv6Address are used to construct the address.
	 * 
	 * @param section
	 * @param eui
	 */
	public IPv6Address(IPv6Address prefix, MACAddress eui) {
		this(prefix.getSection(), eui.getSection());
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address section and an IPv6 address section network prefix.
	 * 
	 * If the supplied MAC section is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied section is a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * 
	 * If the supplied section neither 6 nor 8 bytes, or if the 8-byte section does not have required EUI-64 format of xx-xx-ff-fe-xx-xx,
	 * AddressTypeException will be thrown.
	 *
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * 
	 * The IPv6 address section must be 8 bytes.
	 * 
	 * @param section
	 * @param eui
	 */
	public IPv6Address(IPv6AddressSection section, MACAddress eui) {
		this(section, eui.getSection());
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address and an IPv6 address section network prefix.
	 * 
	 * If the supplied address is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied address is a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * 
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * 
	 * The IPv6 address section must be 8 bytes.
	 * 
	 * @param section
	 * @param eui
	 */
	public IPv6Address(IPv6AddressSection section, MACAddressSection eui) {
		this(section, eui, "");
	}
	
	public IPv6Address(IPv6AddressSection section, MACAddressSection eui, CharSequence zone) {
		super(toEUI64Segments(section, eui));
		this.zone = zone.toString();
	}

	private static IPv6AddressSection toEUI64Segments(IPv6AddressSection section, MACAddressSection eui) {
		boolean euiIsExtended = eui.isExtended();
		if(eui.startIndex != 0 || section.startIndex != 0 || section.getSegmentCount() < 4 ||
				eui.getSegmentCount() != (euiIsExtended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT)) {
			throw new AddressTypeException(eui, "ipaddress.mac.error.not.eui.convertible");
		}
		if(section.isPrefixed()) {  
			section = section.removePrefixLength();
		}
		IPv6AddressCreator creator = network().getAddressCreator();
		IPv6AddressSegment segments[] = creator.createSegmentArray(8);
		section.getSegments(0, 4, segments, 0);
		return creator.createSectionInternal(toEUI64Segments(segments, 4, eui, 0, eui.isExtended()));
	}
	
	static IPv6AddressSegment[] toEUI64Segments(IPv6AddressSegment segments[], int ipv6StartIndex, MACAddressSection eui, int euiStartIndex, boolean isExtended) {
		IPv6AddressCreator creator = network().getAddressCreator();
		int euiSegmentIndex = 0;
		int euiSegmentCount = eui.getSegmentCount();
		MACAddressSegment seg0, seg1, seg2, seg3, seg4, seg5, seg6, seg7;
		seg0 = (euiStartIndex == 0 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg1 = (euiStartIndex <= 1 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg2 = (euiStartIndex <= 2 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg3 = (euiStartIndex <= 3 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg4 = (euiStartIndex <= 4 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg5 = (euiStartIndex <= 5 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg6 = (euiStartIndex <= 6 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex++) : null;
		seg7 = (euiStartIndex <= 7 && euiSegmentIndex < euiSegmentCount) ? eui.getSegment(euiSegmentIndex) : null;
		boolean isNotNull;
		MACAddressSegment ZERO_SEGMENT = MACAddressSegment.ZERO_SEGMENT;
		MACAddressSegment FF_SEGMENT = MACAddressSegment.FF_SEGMENT;
		MACAddressSegment FE_SEGMENT = MACAddressSegment.FE_SEGMENT;
		if((isNotNull = (seg0 != null)) || seg1 != null) {
			if(isNotNull) {
				if(seg1 == null) {
					seg1 = ZERO_SEGMENT;
				}
			} else {
				seg0 = ZERO_SEGMENT;
			}
			segments[ipv6StartIndex++] = join(creator, seg0, seg1, true /* only this first one gets the flipped bit */);
		}
		
		//join 2 and 3 
		if(isExtended) {
			if((isNotNull = (seg2 != null)) || seg3 != null) {
				if(!isNotNull) {
					seg2 = ZERO_SEGMENT;
					if(!seg3.matches(0xff)) {
						throw new AddressTypeException(eui, "ipaddress.mac.error.not.eui.convertible");
					}
				}
				segments[ipv6StartIndex++] = join(creator, seg2, FF_SEGMENT);
			}
			if((isNotNull = (seg4 != null)) || seg5 != null) {
				if(isNotNull) {
					if(!seg4.matches(0xfe)) {
						throw new AddressTypeException(eui, "ipaddress.mac.error.not.eui.convertible");
					}
					if(seg5 == null) {
						seg5 = ZERO_SEGMENT;
					}
				}
				segments[ipv6StartIndex++] = join(creator, FE_SEGMENT, seg5);
			}
		} else {
			if(seg2 != null) {
				segments[ipv6StartIndex++] = join(creator, seg2, FF_SEGMENT);
			}
			if(seg3 != null) {
				segments[ipv6StartIndex++] = join(creator, FE_SEGMENT, seg3);
			}
			if((isNotNull = (seg4 != null)) || seg5 != null) {
				if(isNotNull) {
					if(seg5 == null) {
						seg5 = ZERO_SEGMENT;
					}
				} else {
					seg4 = ZERO_SEGMENT;
				}
				segments[ipv6StartIndex++] = join(creator, seg4, seg5);
			}
		}
		if((isNotNull = (seg6 != null)) || seg7 != null) {
			if(isNotNull) {
				if(seg7 == null) {
					seg7 = ZERO_SEGMENT;
				}
			} else {
				seg6 = ZERO_SEGMENT;
			}
			segments[ipv6StartIndex] = join(creator, seg6, seg7);
		}
		return segments;
	} 
	
	private static IPv6AddressSegment join(IPv6AddressCreator creator, MACAddressSegment macSegment0, MACAddressSegment macSegment1) {
		return join(creator, macSegment0, macSegment1, false);
	}
	
	private static IPv6AddressSegment join(IPv6AddressCreator creator, MACAddressSegment macSegment0, MACAddressSegment macSegment1, boolean flip) {
		int lower0 = macSegment0.getLowerSegmentValue();
		int upper0 = macSegment0.getUpperSegmentValue();
		if(flip) {
			int mask2ndBit = 0x2;
			if(!macSegment0.matchesWithMask(mask2ndBit & lower0, mask2ndBit)) {
				throw new AddressTypeException(macSegment0, "ipaddress.mac.error.not.eui.convertible");
			}
			lower0 ^= mask2ndBit;//flip the universal/local bit
			upper0 ^= mask2ndBit;
		}
		return creator.createSegment(
				(lower0 << 8) | macSegment1.getLowerSegmentValue(), 
				(upper0 << 8) | macSegment1.getUpperSegmentValue(),
				null);
	}

	public static IPv6AddressNetwork network() {
		return network;
	}

	@Override
	public IPv6AddressNetwork getNetwork() {
		return network();
	}
	
	public static IPv6Address getLoopback() {
		return network().getLoopback();
	}
	
	public static String[] getStandardLoopbackStrings() {
		return network().getStandardLoopbackStrings();
	}

	@Override
	public IPv6AddressSection getSection() {
		return (IPv6AddressSection) super.getSection();
	}

	@Override
	public IPv6AddressSection getSection(int index) {
		return getSection().getSection(index);
	}

	@Override
	public IPv6AddressSection getSection(int index, int endIndex) {
		return getSection().getSection(index, endIndex);
	}
	
	@Override
	public IPv6AddressSegment getSegment(int index) {
		return getSection().getSegment(index);
	}
	
	@Override
	public IPv6AddressSegment[] getSegments() {
		return getSection().getSegments();
	}

	public boolean isEUI64() {
		return getSection().isEUI64();
	}

	public MACAddress toEUI(boolean extended) {
		MACAddressSection section = getSection().toEUI(extended);
		if(section == null) {
			return null;
		}
		MACAddressCreator creator = MACAddress.getAddressCreator();
		return creator.createAddress(section);
	}

	@Override
	public IPAddressStringDivisionSeries[] getParts(IPStringBuilderOptions options) {
		return getParts(IPv6StringBuilderOptions.from(options));
	}
	
	public IPAddressStringDivisionSeries[] getParts(IPv6StringBuilderOptions options) {
		IPAddressStringDivisionSeries parts[] = getSection().getParts(options);
		IPv4Address ipv4Addr = getConverted(options);
		if(ipv4Addr != null) {
			IPAddressStringDivisionSeries ipv4Parts[] = ipv4Addr.getParts(options.ipv4ConverterOptions);
			IPAddressStringDivisionSeries tmp[] = parts;
			parts = new IPAddressStringDivisionSeries[tmp.length + ipv4Parts.length];
			System.arraycopy(tmp, 0, parts, 0, tmp.length);
			System.arraycopy(ipv4Parts,  0, parts, tmp.length, ipv4Parts.length);
		}
		return parts;
	}
	
	private static IPv6AddressSection createSection(IPv6AddressSegment nonMixedSection[], IPv4Address mixedSection) throws AddressTypeException {
		IPv4AddressSection ipv4Section = mixedSection.getSection();
		IPv6AddressCreator creator = network().getAddressCreator();
		IPv6AddressSegment newSegs[] = creator.createSegmentArray(SEGMENT_COUNT);
		newSegs[0] = nonMixedSection[0];
		newSegs[1] = nonMixedSection[1];
		newSegs[2] = nonMixedSection[2];
		newSegs[3] = nonMixedSection[3];
		newSegs[4] = nonMixedSection[4];
		newSegs[5] = nonMixedSection[5];
		newSegs[6] = IPv6AddressSegment.join(ipv4Section.getSegment(0), ipv4Section.getSegment(1));
		newSegs[7] = IPv6AddressSegment.join(ipv4Section.getSegment(2), ipv4Section.getSegment(3));
		IPv6AddressSection result = creator.createSectionInternal(newSegs);
		result.embeddedIPv4Section = ipv4Section;
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
		return getSection().getLowestOrHighest(getCreator(), this, lowest);
	}

	@Override
	public IPv6Address getLower() {
		return getLowestOrHighest(true);
	}
	
	@Override
	public IPv6Address getUpper() {
		return getLowestOrHighest(false);
	}
	
	@Override
	public IPv6Address reverseBits(boolean perByte) {
		IPv6AddressCreator creator = getCreator();
		return creator.createAddress(getSection().reverseBits(perByte));
	}
	
	@Override
	public IPv6Address reverseBytes() {
		return checkIdentity(getSection().reverseBytes());
	}
	
	@Override
	public IPv6Address reverseBytesPerSegment() {
		return checkIdentity(getSection().reverseBytesPerSegment());
	}
	
	@Override
	public IPv6Address reverseSegments() {
		return checkIdentity(getSection().reverseSegments());
	}
	
	private IPv6AddressCreator getCreator() {
		IPv6AddressCreator result = creator;
		if(result == null) {
			synchronized(this) {
				result = creator;
				if(result == null) {
					result = !hasZone() ? network().getAddressCreator() : new IPv6AddressCreator() {//using a lambda for this one results in a big performance hit, so we use anonymous class
						@Override
						protected IPv6Address createAddressInternal(IPv6AddressSegment segments[]) {
							IPv6AddressCreator creator = network().getAddressCreator();
							return creator.createAddressInternal(segments, zone); /* address creation */
						}

						@Override
						public IPv6Address createAddress(IPv6AddressSection section) {
							IPv6AddressCreator creator = network().getAddressCreator();
							return creator.createAddress(section, zone); /* address creation */
						}
					};
				}
			}
		}
		return result;
	}
	
	@Override
	public Iterator<IPv6Address> iterator() {
		return getSection().iterator(this, getCreator());
	}
	
	@Override
	public Iterable<IPv6Address> getIterable() {
		return this;
	}
	
	public static IPv6Address from(byte bytes[], Integer prefix, CharSequence zone) {
		if(bytes.length != BYTE_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.ipv6.invalid.byte.count") + ' ' + bytes.length);
		}
		return (IPv6Address) IPAddress.from(bytes, prefix, zone);
	}
	
	public static IPv6Address from(byte bytes[], CharSequence zone) {
		return from(bytes, null, zone);
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
		if(conv != null) {
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
	 * @throws AddressTypeException if the IPv4 address segments cannot be converted to IPv6 segments because of one or more incompatible segment ranges.
	 */
	public static IPv6Address toIPv4Mapped(IPv4Address addr) throws AddressTypeException {
		IPv6AddressSegment zero = IPv6AddressSegment.ZERO_SEGMENT;
		IPv6AddressCreator creator = network().getAddressCreator();
		IPv6AddressSegment segs[] = creator.createSegmentArray(MIXED_ORIGINAL_SEGMENT_COUNT);
		segs[0] = segs[1] = segs[2] = segs[3] = segs[4] = zero;
		segs[5] = IPv6AddressSegment.ALL_SEGMENT;
		return creator.createAddress(createSection(segs, addr)); /* address creation */
	}
	
	/**
	 * ::ffff:x:x/96 indicates IPv6 address mapped to IPv4
	 */
	public IPv4AddressSection toMappedIPv4Segments() {
		if(isIPv4Mapped()) {
			return getSection().getEmbeddedIPv4AddressSection();
		}
		return null;
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
	 * Returns the embedded {@link IPv4Address} in the lowest (least-significant) two segments.
	 * This is used by IPv4-mapped, IPv4-compatible, ISATAP addresses and 6over4 addresses
	 * 
	 * @return the embedded {@link IPv4Address}
	 */
	public IPv4Address getEmbeddedIPv4Address() {
		IPv4AddressCreator creator = IPv4Address.network().getAddressCreator();
		return creator.createAddress(getSection().getEmbeddedIPv4AddressSection()); /* address creation */
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
			return getEmbeddedIPv4Address();
		}
		IPv4AddressCreator creator = IPv4Address.network().getAddressCreator();
		return creator.createAddress(getSection().getEmbeddedIPv4AddressSection(byteIndex, byteIndex + IPv4Address.BYTE_COUNT)); /* address creation */
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
	 * @see #get6to4IPv4Address()
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
		IPv6AddressSection thisSection = getSection();
		IPv6AddressSection sections[] = thisSection.subtract(convertArg(other).getSection());
		if(sections == null) {
			return null;
		}
		IPv6Address result[] = new IPv6Address[sections.length];
		for(int i = 0; i < result.length; i++) {
			result[i] = network().getAddressCreator().createAddress(sections[i], zone); /* address creation */
		}
		return result;
	}

	private IPv6Address checkIdentity(IPv6AddressSection newSection) {
		if(newSection == getSection()) {
			return this;
		}
		return getCreator().createAddress(newSection);
	}
	
	@Override
	public IPv6Address adjustPrefixBySegment(boolean nextSegment) {
		return checkIdentity(getSection().adjustPrefixBySegment(nextSegment));
	}

	@Override
	public IPv6Address adjustPrefixLength(int adjustment) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment));
	}

	@Override
	public IPv6Address setPrefixLength(int prefixLength) {
		return setPrefixLength(prefixLength, true);
	}

	@Override
	public IPv6Address setPrefixLength(int prefixLength, boolean zeroed) {
		return checkIdentity(getSection().setPrefixLength(prefixLength, zeroed));
	}

	@Override
	public IPv6Address applyPrefixLength(int networkPrefixLength) throws AddressTypeException {
		return checkIdentity(getSection().applyPrefixLength(networkPrefixLength));
	}

	private IPv6Address convertArg(IPAddress arg) {
		IPv6Address converted = arg.toIPv6();
		if(converted == null) {
			throw new AddressTypeException(this, "ipaddress.error.prefix.mask.mismatch");
		}
		return converted;
	}
	
	@Override
	public IPv6Address removePrefixLength() {
		return removePrefixLength(true);
	}
	
	@Override
	public IPv6Address removePrefixLength(boolean zeroed) {
		return checkIdentity(getSection().removePrefixLength(zeroed));
	}
	
	@Override
	protected IPAddress removePrefixLength(boolean zeroed, boolean onlyPrefixZeroed) {
		return checkIdentity(getSection().removePrefixLength(zeroed, onlyPrefixZeroed));
	}
	
	@Override
	public IPv6Address mask(IPAddress mask) throws AddressTypeException {
		return checkIdentity(getSection().mask(convertArg(mask).getSection()));
	}

	@Override
	public IPv6Address maskNetwork(IPAddress mask, int networkPrefixLength) throws AddressTypeException {
		return checkIdentity(getSection().maskNetwork(convertArg(mask).getSection(), networkPrefixLength));
	}
	
	@Override
	public IPv6Address bitwiseOr(IPAddress mask) throws AddressTypeException {
		return checkIdentity(getSection().bitwiseOr(convertArg(mask).getSection()));
	}
	
	@Override
	public IPv6Address bitwiseOrNetwork(IPAddress mask, int networkPrefixLength) throws AddressTypeException {
		return checkIdentity(getSection().bitwiseOrNetwork(convertArg(mask).getSection(), networkPrefixLength));
	}

	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength) {
		return getSection().getNetworkSection(networkPrefixLength);
	}
	
	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) {
		return getSection().getNetworkSection(networkPrefixLength, withPrefixLength);
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
		return getSection().getHostSection(networkPrefixLength);
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
		if(hasZone()) {
			return zone;
		}
		return null;
	}
	
	public IPv6Address removeZone() {
		return network().getAddressCreator().createAddress(getSection()); /* address creation */
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
	
	private boolean hasNoStringCache() {
		if(stringCache == null) {
			synchronized(this) {
				if(stringCache == null) {
					if(hasZone()) {
						stringCache = new IPv6StringCache();
					} else {
						//when there is no zone, the section and address strings are the same, so we use the same cache
						IPv6AddressSection section = getSection();
						boolean result = section.hasNoStringCache();
						stringCache = section.getStringCache();
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
		if(hasNoStringCache() || (result = stringCache.mixedString) == null) {
			if(hasZone()) {
				stringCache.mixedString = result = toNormalizedString(IPv6StringCache.mixedParams);
			} else {
				result = getSection().toMixedString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	/**
	 * This produces a canonical string.
	 * 
	 * RFC 5952 describes canonical representations.
	 * http://en.wikipedia.org/wiki/IPv6_address#Recommended_representation_as_text
	 * http://tools.ietf.org/html/rfc5952
	 */
	@Override
	public String toCanonicalString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.canonicalString) == null) {
			if(hasZone()) {
				stringCache.canonicalString = result = toNormalizedString(IPv6StringCache.canonicalParams);
			} else {
				result = getSection().toCanonicalString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}

	@Override
	public String toFullString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.fullString) == null) {
			if(hasZone()) {
				stringCache.fullString = result = toNormalizedString(IPv6StringCache.fullParams);
			} else {
				result = getSection().toFullString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	/**
	 * The normalized string returned by this method is consistent with java.net.Inet6address.
	 * IPs are not compressed nor mixed in this representation.
	 */
	@Override
	public String toNormalizedString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.normalizedString) == null) {
			if(hasZone()) {
				stringCache.normalizedString = result = toNormalizedString(IPv6StringCache.normalizedParams);
			} else {
				result = getSection().toNormalizedString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toCompressedString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.compressedString) == null) {
			if(hasZone()) {
				stringCache.compressedString = result = toNormalizedString(IPv6StringCache.compressedParams);
			} else {
				result = getSection().toCompressedString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toSubnetString() {
		return toPrefixLengthString();
	}
	
	//note this string is used by hashCode
	@Override
	public String toNormalizedWildcardString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.normalizedWildcardString) == null) {
			if(hasZone()) {
				stringCache.normalizedWildcardString = result = toNormalizedString(IPv6StringCache.wildcardNormalizedParams);
			} else {
				result = getSection().toNormalizedWildcardString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	/**
	 * The base 85 string is described by RFC 1924
	 * @return
	 */
	public String toBase85String() {
		//first we see if we obtained this address from a base 85 string
		//in the case of a prefix, applying the prefix changes the value
		IPAddressString originator = getAddressfromString();
		if(originator != null && (!isPrefixed() || getNetworkPrefixLength() == IPv6Address.BIT_COUNT) && originator.isBase85IPv6()) {
			return originator.toString();
		}
		String result;
		if(hasNoStringCache() || (result = stringCache.base85String) == null) {
			if(hasZone()) {
				stringCache.base85String = result = getSection().toBase85String(getZone());
			} else {
				result = getSection().toBase85String();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toCanonicalWildcardString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.canonicalWildcardString) == null) {
			if(hasZone()) {
				stringCache.canonicalWildcardString = result = toNormalizedString(IPv6StringCache.wildcardCanonicalParams);
			} else {
				result = getSection().toCanonicalWildcardString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toCompressedWildcardString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.compressedWildcardString) == null) {
			if(hasZone()) {
				stringCache.compressedWildcardString = result = toNormalizedString(IPv6StringCache.wildcardCompressedParams);
			} else {
				result = getSection().toCompressedWildcardString();//the cache is shared with the section, so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toSQLWildcardString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.sqlWildcardString) == null) {
			if(hasZone()) {
				stringCache.sqlWildcardString = result = toNormalizedString(IPv6StringCache.sqlWildcardParams);
			} else {
				result = getSection().toSQLWildcardString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toHexString(boolean with0xPrefix) {
		String result;
		if(hasNoStringCache() || (result = (with0xPrefix ? stringCache.hexStringPrefixed : stringCache.hexString)) == null) {
			if(hasZone()) {
				result = getSection().toHexString(with0xPrefix, zone);
				if(with0xPrefix) {
					stringCache.hexStringPrefixed = result;
				} else {
					stringCache.hexString = result;
				}
			} else {
				result = getSection().toHexString(with0xPrefix);//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toBinaryString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.binaryString) == null) {
			if(hasZone()) {
				result = getSection().toBinaryString(zone);
				stringCache.binaryString = result;
			} else {
				result = getSection().toBinaryString();//the cache is shared so no need to update it here
			}
		}
		return result;
	}
	
	@Override
	public String toOctalString(boolean with0Prefix) {
		String result;
		if(hasNoStringCache() || (result = (with0Prefix ? stringCache.octalStringPrefixed : stringCache.octalString)) == null) {
			if(hasZone()) {
				result = getSection().toOctalString(with0Prefix, zone);
				if(with0Prefix) {
					stringCache.octalStringPrefixed = result;
				} else {
					stringCache.octalString = result;
				}
			} else {
				result = getSection().toOctalString(with0Prefix);//the cache is shared so no need to update it here
			}
		}
		return result;
	}

	@Override
	public String toPrefixLengthString() {
		String result;
		if(hasNoStringCache() || (result = stringCache.networkPrefixLengthString) == null) {
			if(hasZone()) {
				stringCache.networkPrefixLengthString = result = toNormalizedString(IPv6StringCache.networkPrefixLengthParams);
			} else {
				result = getSection().toPrefixLengthString();//the cache is shared so no need to update it here
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
	public String toNormalizedString(IPStringOptions params) {
		return getSection().toNormalizedString(params, zone);
	}
	
	public String toNormalizedString(IPv6StringOptions params) {
		return getSection().toNormalizedString(params, zone);
	}

	/**
	 * Constructs a string representing this address according to the given parameters
	 * 
	 * @param keepMixed if this address was constructed from a string with mixed representation (a:b:c:d:e:f:1.2.3.4), whether to keep it that way (ignored if makeMixed is true in the params argument)
	 * @param params the parameters for the address string
	 */
	public String toNormalizedString(boolean keepMixed, IPv6StringOptions params) {
		if(keepMixed && fromString != null && getAddressfromString().isMixedIPv6() && !params.makeMixed()) {
			params = new IPv6StringOptions(
					params.base,
					params.expandSegments,
					params.wildcardOption,
					params.wildcards,
					params.segmentStrPrefix,
					true,
					params.ipv4Opts,
					params.compressOptions,
					params.separator,
					params.zoneSeparator,
					params.addrLabel,
					params.addrSuffix,
					params.reverse,
					params.splitDigits,
					params.uppercase);
		}
		return toNormalizedString(params);
	}
	
	@Override
	public String toUNCHostName() {
		String result;
		if(hasNoStringCache() || (result = stringCache.uncString) == null) {
			//it seems for unc hosts we not only replace the zone character % with s and the segment separator : with -,
			//we do the same for any such characters appearing in the zone itself as well
			//see https://blogs.msdn.microsoft.com/oldnewthing/20100915-00/?p=12863/
			stringCache.uncString = result = getSection().toNormalizedString(IPv6StringCache.uncParams, 
					zone.replace(IPv6Address.ZONE_SEPARATOR, IPv6Address.UNC_ZONE_SEPARATOR).replace(IPv6Address.SEGMENT_SEPARATOR, IPv6Address.UNC_SEGMENT_SEPARATOR));
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
		IPv6StringCollection coll = getSection().toStringCollection(opts, zone);
		IPv4Address ipv4Addr = getConverted(opts);
		if(ipv4Addr != null) {
			IPAddressPartStringCollection ipv4StringCollection = ipv4Addr.toStringCollection(opts.ipv4ConverterOptions);
			coll.addAll(ipv4StringCollection);
		}
		return coll;
	}
	
	/**
	 * @custom.core
	 * @author sfoley
	 *
	 */
	public interface IPv6AddressConverter {
		/**
		 * If the given address is IPv6, or can be converted to IPv6, returns that {@link IPv6Address}.  Otherwise, returns null.
		 */
		IPv6Address toIPv6(IPAddress address);
	}

	@Override
	public Iterator<IPv6AddressSegment[]> segmentsIterator() {
		return getSection().segmentsIterator();
	}
}
