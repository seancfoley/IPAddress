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

package inet.ipaddr.mac;

import java.util.Iterator;

import inet.ipaddr.Address;
import inet.ipaddr.AddressTypeException;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.format.AddressDivisionGrouping;
import inet.ipaddr.format.AddressDivisionGrouping.StringOptions;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;
import inet.ipaddr.mac.MACAddressSection.AddressCache;

/**
 * @custom.core
 * @author sfoley
 *
 */
public class MACAddress extends Address implements Iterable<MACAddress> {

	private static final long serialVersionUID = 3L;
	
	public static final char COLON_SEGMENT_SEPARATOR = ':';
	public static final char DASH_SEGMENT_SEPARATOR = '-';
	public static final char SPACE_SEGMENT_SEPARATOR = ' ';
	public static final char DOTTED_SEGMENT_SEPARATOR = '.';
	public static final char DASHED_SEGMENT_RANGE_SEPARATOR = '|';
	public static final String DASHED_SEGMENT_RANGE_SEPARATOR_STR = String.valueOf(DASHED_SEGMENT_RANGE_SEPARATOR);
	public static final int BITS_PER_SEGMENT = 8;
	public static final int BYTES_PER_SEGMENT = 1;
	public static final int MEDIA_ACCESS_CONTROL_SEGMENT_COUNT = 6;
	public static final int MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT = 3;
	public static final int MEDIA_ACCESS_CONTROL_DOTTED_64_SEGMENT_COUNT = 4;
	public static final int MEDIA_ACCESS_CONTROL_DOTTED_BITS_PER_SEGMENT = 16;
	public static final int MEDIA_ACCESS_CONTROL_SINGLE_DASHED_SEGMENT_COUNT = 2;
	public static final int EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT = MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
	public static final int EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT = 8;
	public static final int DEFAULT_TEXTUAL_RADIX = 16;
	public static final int MAX_VALUE_PER_SEGMENT = 0xff;
	public static final int MAX_VALUE_PER_DOTTED_SEGMENT = 0xffff;
	public static final int ORGANIZATIONAL_UNIQUE_IDENTIFIER_SEGMENT_COUNT = 3;
	public static final int ORGANIZATIONAL_UNIQUE_IDENTIFIER_BIT_COUNT = ORGANIZATIONAL_UNIQUE_IDENTIFIER_SEGMENT_COUNT * BITS_PER_SEGMENT;
	
	protected static MACAddressNetwork network = new MACAddressNetwork();
	
	transient AddressCache sectionCache;
	
	/**
	 * Constructs a MAC address.
	 * @param segments the address segments
	 */
	public MACAddress(MACAddressSegment[] segments) {
		this(segments, null);
	}
	
	/**
	 * Constructs a MAC address.
	 * @param segments the address segments
	 */
	public MACAddress(MACAddressSegment[] segments, Integer prefixLength) {
		this(getAddressCreator().createSection(segments, segments.length == EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT, prefixLength));
	}
	
	/**
	 * Constructs a MAC address.
	 * @param section the address segments
	 */
	public MACAddress(MACAddressSection section) {
		super(section);
		int segCount = section.getSegmentCount();
		if(segCount != MEDIA_ACCESS_CONTROL_SEGMENT_COUNT && segCount != EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mac.invalid.segment.count") + ' ' + segCount);
		}
	}

	/**
	 * Constructs a MAC address.
	 */
	public MACAddress(long address) {
		this(address, false, null);
	}
	
	/**
	 * Constructs a MAC address.
	 */
	public MACAddress(long address, boolean extended) {
		this(address, extended, null);
	}
	
	/**
	 * Constructs a MAC address.
	 */
	public MACAddress(long address, Integer prefixLength) {
		this(address, false, prefixLength);
	}
	
	/**
	 * Constructs a MAC address.
	 * 
	 * @param address the bytes
	 * @param prefixLength the length for which the address represents all addresses with the same prefix identifier such as the 24 bit Organizational Unique Identifier (OUI)
	 * @param extended if true, treated as an 8-byte EUI-64 address, otherwise treated as a 6-byte MAC or EUI-48
	 */
	public MACAddress(long address, boolean extended, Integer prefixLength) {
		super(getAddressCreator().createSection(address, 0, extended, prefixLength));
	}

	/**
	 * Constructs a MAC address.
	 */
	public MACAddress(byte[] bytes) {
		this(bytes, null);
	}
	
	/**
	 * Constructs a MAC address.
	 */
	public MACAddress(byte[] bytes, Integer prefixLength) {
		super(getAddressCreator().createSection(bytes, 0, bytes.length == EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT, prefixLength));
		if(bytes.length != MEDIA_ACCESS_CONTROL_SEGMENT_COUNT && bytes.length != EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
			throw new IllegalArgumentException(getMessage("ipaddress.error.mac.invalid.byte.count") + ' ' + bytes.length);
		}
	}
	
	/**
	 * Constructs a MAC address
	  * 
	 * @param lowerValueProvider supplies the 1 byte lower values for each segment
	 * @param upperValueProvider supplies the 1 byte upper values for each segment
	 */
	public MACAddress(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, boolean extended, Integer prefixLength) {
		super(getAddressCreator().createSection(lowerValueProvider, upperValueProvider, 0, extended, prefixLength));
	}
	
	/**
	 * Constructs a MAC address
	  * 
	 * @param lowerValueProvider supplies the 1 byte lower values for each segment
	 * @param upperValueProvider supplies the 1 byte upper values for each segment
	 */
	public MACAddress(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength) {
		super(getAddressCreator().createSection(lowerValueProvider, upperValueProvider, 0, false, prefixLength));
	}
	
	/**
	 * Constructs a MAC address
	  * 
	 * @param lowerValueProvider supplies the 1 byte lower values for each segment
	 * @param upperValueProvider supplies the 1 byte upper values for each segment
	 */
	public MACAddress(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, boolean extended) {
		super(getAddressCreator().createSection(lowerValueProvider, upperValueProvider, 0, extended, null));
	}
	
	/**
	 * Constructs a MAC address
	 * 
	 * @param lowerValueProvider supplies the 1 byte lower values for each segment
	 * @param upperValueProvider supplies the 1 byte upper values for each segment
	 */
	public MACAddress(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider) {
		this(lowerValueProvider, upperValueProvider, null);
	}
	
	protected static String getMessage(String key) {
		return Address.getMessage(key);
	}
	
	public static MACAddressNetwork network() {
		return network;
	}
	
	public static MACAddressCreator getAddressCreator() {
		return network().getAddressCreator();
	}
	
	public boolean isExtended() {
		return getSection().isExtended();
	}
	
	public boolean isAllAddresses() {
		return getSection().isFullRange();
	}

	@Override
	public MACAddressSection getSection() {
		return (MACAddressSection) super.getSection();
	}

	@Override
	public MACAddressSegment getSegment(int index) {
		return (MACAddressSegment) super.getSegment(index);
	}
	
	@Override
	public MACAddressSegment[] getSegments() {
		return getSection().getSegments();
	}
	
	public static int maxSegmentValue() {
		return MAX_VALUE_PER_SEGMENT;
	}
	
	@Override
	public int getMaxSegmentValue() {
		return MAX_VALUE_PER_SEGMENT;
	}
	
	@Override
	public int getByteCount() {
		return getSection().getByteCount();
	}
	
	@Override
	public int getBitCount() {
		return getSection().getBitCount();
	}
	
	@Override
	public int getBytesPerSegment() {
		return BYTES_PER_SEGMENT;
	}
	
	@Override
	public int getBitsPerSegment() {
		return BITS_PER_SEGMENT;
	}
	
	@Override
	protected boolean isFromSameString(HostIdentifierString other) {
		if(fromString != null && other instanceof MACAddressString) {
			MACAddressString fromString = (MACAddressString) this.fromString;
			MACAddressString otherString = (MACAddressString) other;
			return (fromString == otherString || 
					(fromString.toString().equals(otherString.toString())) &&
					fromString.getValidationOptions().equals(otherString.getValidationOptions()));
		}
		return false;
	}
	
	@Override
	public boolean contains(Address other) {
		if(other instanceof MACAddress) {
			return contains((MACAddress) other);
		}
		return false;
	}
	
	/**
	 * 
	 * @param other
	 * @return whether this address contains the given address
	 */
	public boolean contains(MACAddress other) {
		if(other == this) {
			return true;
		}
		return getSection().contains(other.getSection());
	}
	
	@Override
	public Iterable<MACAddress> getIterable() {
		return this;
	}
	
	@Override
	public Iterator<MACAddress> iterator() {
		return getSection().iterator(this);
	}
	
	@Override
	public Iterator<MACAddressSegment[]> segmentsIterator() {
		return getSection().segmentsIterator();
	}
	
	@Override
	public MACAddress getLower() {
		return getLowestOrHighest(true);
	}

	@Override
	public MACAddress getUpper() {
		return getLowestOrHighest(false);
	}
	
	private MACAddress getLowestOrHighest(boolean lowest) {
		return getSection().getLowestOrHighest(this, lowest);
	}
	
	/**
	 * Use to produce:
	 * "MSB format", "IBM format", "Token-Ring format", and "non-canonical form"
	 * 
	 * See RFC 2469 section 2
	 * 
	 * Also see https://en.wikipedia.org/wiki/MAC_address
	 * 
	 * @return
	 */
	@Override
	public MACAddress reverseBits(boolean perByte) {
		return checkIdentity(getSection().reverseBits(perByte));
	}
	
	@Override
	public MACAddress reverseBytes() {
		return checkIdentity(getSection().reverseBytes());
	}
	
	@Override
	public MACAddress reverseBytesPerSegment() {
		return this;
	}
	
	@Override
	public MACAddress reverseSegments() {
		return checkIdentity(getSection().reverseSegments());
	}

	private MACAddress checkIdentity(MACAddressSection newSection) {
		MACAddressSection section = getSection();
		if(newSection == section) {
			return this;
		}
		return getAddressCreator().createAddress(newSection);
	}
	
	@Override
	public MACAddress removePrefixLength() {
		return checkIdentity(getSection().removePrefixLength());
	}
	
	@Override
	public MACAddress applyPrefixLength(int networkPrefixLength) {
		return checkIdentity(getSection().applyPrefixLength(networkPrefixLength));
	}
	
	@Override
	public MACAddress adjustPrefixBySegment(boolean nextSegment) {
		return checkIdentity(getSection().adjustPrefixBySegment(nextSegment));
	}

	@Override
	public MACAddress adjustPrefixLength(int adjustment) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment));
	}

	@Override
	public MACAddress setPrefixLength(int prefixLength) {
		return checkIdentity(getSection().setPrefixLength(prefixLength));
	}
	
	@Override
	public MACAddressSection getSection(int index) {
		return getSection().getSection(index);
	}

	@Override
	public MACAddressSection getSection(int index, int endIndex) {
		return getSection().getSection(index, endIndex);
	}

	public MACAddressSection getODISection() {
		return getSection().getODISection();
	}
	
	public MACAddressSection getOUISection() {
		return getSection().getOUISection();
	}
	
	public MACAddress toOUIPrefixed() {
		return getAddressCreator().createAddress(getSection().toOUIPrefixed());
	}

	public IPv6Address toLinkLocalIPv6() {
		return IPv6Address.network().getAddressCreator().createAddress(IPv6AddressSection.LINK_LOCAL_PREFIX.append(toEUI64IPv6()));
	}
	
	public IPv6AddressSection toEUI64IPv6() {
		return IPv6Address.network().getAddressCreator().createSection(this);
	}
	
	/**
	 * Whether this section is consistent with an IPv6 EUI64 section,
	 * which means it came from an extended 8 byte address,
	 * and the corresponding segments in the middle match 0xff and 0xff/fe for MAC/not-MAC
	 * 
	 * @param asMAC
	 * @return
	 */
	public boolean isEUI64(boolean asMAC) {
		if(isExtended()) {//getSegmentCount() == EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT
			MACAddressSection section = getSection();
			MACAddressSegment seg3 = section.getSegment(3);
			MACAddressSegment seg4 = section.getSegment(4);
			return seg3.matches(0xff) && seg4.matches(asMAC ? 0xff : 0xfe);
		}
		return false;
	}

	/**
	 * Convert to IPv6 EUI-64 section
	 * 
	 * http://standards.ieee.org/develop/regauth/tut/eui64.pdf
	 * 
	 * @param asMAC if true, this address is considered MAC and the EUI-64 is extended using ff-ff, otherwise this address is considered EUI-48 and extended using ff-fe
	 * 	Note that IPv6 treats MAC as EUI-48 and extends MAC to IPv6 addresses using ff-fe
	 * @return
	 */
	public MACAddress toEUI64(boolean asMAC) {
		if(!isExtended()) {//getSegmentCount() == EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT
			MACAddressCreator creator = getAddressCreator();
			MACAddressSegment segs[] = creator.createSegmentArray(EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT);
			MACAddressSection section = getSection();
			section.getSegments(0,  3, segs, 0);
			segs[3] = MACAddressSegment.FF_SEGMENT;
			segs[4] = asMAC ? MACAddressSegment.FF_SEGMENT : MACAddressSegment.FE_SEGMENT;
			section.getSegments(3,  6, segs, 5);
			return creator.createAddressInternal(segs);
		} else {
			MACAddressSection section = getSection();
			MACAddressSegment seg3 = section.getSegment(3);
			MACAddressSegment seg4 = section.getSegment(4);
			if(seg3.matches(0xff) && seg4.matches(asMAC ? 0xff : 0xfe)) {
				return this;
			}
		}
		throw new AddressTypeException(this, "ipaddress.mac.error.not.eui.convertible");
	}
	
	public AddressDivisionGrouping getDottedAddress() {
		return getSection().getDottedGrouping();
	}

	void cache(HostIdentifierString string) {
		if(fromString instanceof MACAddressString) {
			fromString = string;
		}
	}
	
	@Override
	public MACAddressString toAddressString() {
		if(fromString == null) {
			fromString = new MACAddressString(this); /* address string creation */
		}
		return (MACAddressString) fromString;
	}
	
	public String toNormalizedString(StringOptions stringOptions) {
		return getSection().toNormalizedString(stringOptions);
	}
	
	public String toDottedString() {
		return getSection().toDottedString();
	}
	
	public String toDashedString() {
		return toCanonicalString();
	}
	
	public String toColonDelimitedString() {
		return toNormalizedString();
	}
	
	public String toSpaceDelimitedString() {
		return getSection().toSpaceDelimitedString();
	}
	
	@Override
	public boolean isMulticast() {
		return getSegment(0).matchesWithMask(1, 0x1);
	}
	
	public boolean isUniversal() {
		return getSegment(0).matchesWithMask(0, 0x2);
	}
	
	@Override
	public boolean isLocal() {
		return getSegment(0).matchesWithMask(1, 0x2);
	}
}
