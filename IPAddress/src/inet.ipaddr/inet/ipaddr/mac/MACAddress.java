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

package inet.ipaddr.mac;

import java.net.NetworkInterface;
import java.util.Iterator;

import inet.ipaddr.Address;
import inet.ipaddr.AddressPositionException;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.HostIdentifierString;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.format.standard.AddressDivisionGrouping;
import inet.ipaddr.format.standard.AddressDivisionGrouping.StringOptions;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;
import inet.ipaddr.mac.MACAddressSection.AddressCache;

/**
 * A MAC address, or a collection of multiple MAC addresses.  Each segment can represent a single value or a range of values.
 * <p>
 * You can construct a MAC address from a byte array, from a long, from a {@link inet.ipaddr.Address.SegmentValueProvider}, 
 * from a {@link java.net.NetworkInterface}, from a {@link MACAddressSection} of 6 or 8 segments, or from an array of 6 or 8 {@link MACAddressSegment} objects.
 * <p>
 * To construct one from a {@link java.lang.String} use 
 * {@link inet.ipaddr.MACAddressString#toAddress()} or  {@link inet.ipaddr.MACAddressString#getAddress()}
 * 
 * @custom.core
 * @author sfoley
 *
 */
public class MACAddress extends Address implements Iterable<MACAddress> {
	
	private static final long serialVersionUID = 4L;
	
	public static final char COLON_SEGMENT_SEPARATOR = ':';
	public static final char DASH_SEGMENT_SEPARATOR = '-';
	public static final char SPACE_SEGMENT_SEPARATOR = ' ';
	public static final char DOTTED_SEGMENT_SEPARATOR = '.';
	public static final char DASHED_SEGMENT_RANGE_SEPARATOR = '|';
	public static final String DASHED_SEGMENT_RANGE_SEPARATOR_STR = String.valueOf(DASHED_SEGMENT_RANGE_SEPARATOR);
	public static final int BITS_PER_SEGMENT = 8;
	public static final int BYTES_PER_SEGMENT = 1;
	public static final int MEDIA_ACCESS_CONTROL_SEGMENT_COUNT = 6;
	public static final int MEDIA_ACCESS_CONTROL_BIT_COUNT = 48;
	public static final int MEDIA_ACCESS_CONTROL_DOTTED_SEGMENT_COUNT = 3;
	public static final int MEDIA_ACCESS_CONTROL_DOTTED_64_SEGMENT_COUNT = 4;
	public static final int MEDIA_ACCESS_CONTROL_DOTTED_BITS_PER_SEGMENT = 16;
	public static final int MEDIA_ACCESS_CONTROL_SINGLE_DASHED_SEGMENT_COUNT = 2;
	public static final int EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT = MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
	public static final int EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT = 8;
	public static final int EXTENDED_UNIQUE_IDENTIFIER_48_BIT_COUNT = MEDIA_ACCESS_CONTROL_BIT_COUNT;
	public static final int EXTENDED_UNIQUE_IDENTIFIER_64_BIT_COUNT = 64;
	public static final int DEFAULT_TEXTUAL_RADIX = 16;
	public static final int MAX_VALUE_PER_SEGMENT = 0xff;
	public static final int MAX_VALUE_PER_DOTTED_SEGMENT = 0xffff;
	public static final int ORGANIZATIONAL_UNIQUE_IDENTIFIER_SEGMENT_COUNT = 3;
	public static final int ORGANIZATIONAL_UNIQUE_IDENTIFIER_BIT_COUNT = ORGANIZATIONAL_UNIQUE_IDENTIFIER_SEGMENT_COUNT * BITS_PER_SEGMENT;
	
	transient AddressCache sectionCache;
	
	/**
	 * Constructs a MAC address.
	 * @param segments the address segments
	 */
	public MACAddress(MACAddressSegment[] segments) throws AddressValueException {
		super(thisAddress -> ((MACAddress) thisAddress).getAddressCreator().createSection(segments, segments.length == EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT));
		int segCount = segments.length;
		if(segCount != MEDIA_ACCESS_CONTROL_SEGMENT_COUNT && segCount != EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
			throw new AddressValueException("ipaddress.error.mac.invalid.segment.count", segCount);
		}
	}
	
	/**
	 * Constructs a MAC address.
	 * @param section the address segments
	 */
	public MACAddress(MACAddressSection section) throws AddressValueException {
		super(section);
		int segCount = section.getSegmentCount();
		if(segCount != MEDIA_ACCESS_CONTROL_SEGMENT_COUNT && segCount != EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
			throw new AddressValueException("ipaddress.error.mac.invalid.segment.count", segCount);
		}
		if(section.addressSegmentIndex != 0) {
			throw new AddressPositionException(section.addressSegmentIndex);
		}
	}

	/**
	 * Constructs a MAC address.
	 */
	public MACAddress(long address) throws AddressValueException {
		this(address, false);
	}

	/**
	 * Constructs a MAC address for a network interface.
	 */
	public MACAddress(NetworkInterface ni) throws java.net.SocketException {
		this(ni.getHardwareAddress());
	}

	/**
	 * Constructs a MAC address.
	 */
	public MACAddress(long address, boolean extended) throws AddressValueException {
		super(thisAddress -> ((MACAddress) thisAddress).getAddressCreator().createSection(address, 0, extended));
	}

	/**
	 * Constructs a MAC address.
	 */
	public MACAddress(byte[] bytes) throws AddressValueException {
		super(thisAddress -> createSection((MACAddress) thisAddress, bytes));
	}
	
	/**
	 * Constructs a MAC address
	  * 
	 * @param lowerValueProvider supplies the 1 byte lower values for each segment
	 * @param upperValueProvider supplies the 1 byte upper values for each segment
	 */
	public MACAddress(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, boolean extended) {
		super(thisAddress -> ((MACAddress) thisAddress).getAddressCreator().createSection(lowerValueProvider, upperValueProvider, 0, extended));
	}
	
	/**
	 * Constructs a MAC address
	 * 
	 * @param lowerValueProvider supplies the 1 byte lower values for each segment
	 * @param upperValueProvider supplies the 1 byte upper values for each segment
	 */
	public MACAddress(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider) {
		this(lowerValueProvider, upperValueProvider, false);
	}
	
	/**
	 * Constructs a MAC address
	 * 
	 * @param valueProvider supplies the 1 byte value for each segment
	 */
	public MACAddress(SegmentValueProvider valueProvider, boolean extended) throws AddressValueException {
		this(valueProvider, valueProvider, extended);
	}
	
	/**
	 * Constructs a MAC address
	 * 
	 * @param valueProvider supplies the 1 byte value for each segment
	 */
	public MACAddress(SegmentValueProvider valueProvider) {
		this(valueProvider, false);
	}
	
	private static MACAddressSection createSection(MACAddress addr, byte[] bytes) {
		int segCount;
		int len = bytes.length;
		//We round down the bytes to 6 bytes if we can.  Otherwise, we round up.
		if(len < EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT) {
			segCount = MEDIA_ACCESS_CONTROL_SEGMENT_COUNT;
			if(len > MEDIA_ACCESS_CONTROL_SEGMENT_COUNT) {
				int i = 0;
				do {
					if(bytes[i++] != 0) {
						segCount = EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT;
						break;
					}
				} while(--len > MEDIA_ACCESS_CONTROL_SEGMENT_COUNT);
			}
		} else {
			segCount = EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT;
		}
		return addr.getAddressCreator().createSection(bytes, 0, segCount, segCount == EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT);
	}
	
	protected static String getMessage(String key) {
		return Address.getMessage(key);
	}
	
	@Override
	public MACAddressNetwork getNetwork() {
		return defaultMACNetwork();
	}
	
	public IPv6AddressNetwork getIPv6Network() {
		return defaultIpv6Network();
	}
	
	public MACAddressCreator getAddressCreator() {
		return getNetwork().getAddressCreator();
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
	public MACAddressSegment getDivision(int index) {
		return getSegment(index);
	}

	@Override
	public MACAddressSegment getSegment(int index) {
		return getSection().getSegment(index);
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
					(fromString.toString().equals(otherString.toString()) &&
					// We do not call equals() on the validation options, this is intended as an optimization,
					// and probably better to avoid going through all the validation options here
					fromString.getValidationOptions() == otherString.getValidationOptions()));
		}
		return false;
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
	public Iterator<MACAddress> prefixBlockIterator() {
		return getSection().prefixIterator(this, true);
	}
	
	@Override
	public Iterator<MACAddress> prefixIterator() {
		return getSection().prefixIterator(this, false);
	}

	@Override
	public Iterator<MACAddressSegment[]> segmentsIterator() {
		return getSection().segmentsIterator();
	}

	@Override
	public MACAddress increment(long increment) {
		return checkIdentity(getSection().increment(increment));
	}

	@Override
	public MACAddress incrementBoundary(long increment) {
		return checkIdentity(getSection().incrementBoundary(increment));
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
	
	public long longValue() {
		return getSection().longValue();
	}
	
	public long upperLongValue() {
		return getSection().upperLongValue();
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
		return removePrefixLength(true);
	}
	
	@Override
	public MACAddress withoutPrefixLength() {
		return removePrefixLength(false);
	}
	
	@Override @Deprecated
	public MACAddress removePrefixLength(boolean zeroed) {
		return checkIdentity(getSection().removePrefixLength(zeroed));
	}
	
	@Override
	public MACAddress applyPrefixLength(int prefixLength) {
		return checkIdentity(getSection().applyPrefixLength(prefixLength));
	}
	
	@Override
	public MACAddress adjustPrefixBySegment(boolean nextSegment) {
		return checkIdentity(getSection().adjustPrefixBySegment(nextSegment));
	}
	
	@Override
	public MACAddress adjustPrefixBySegment(boolean nextSegment, boolean zeroed) {
		return checkIdentity(getSection().adjustPrefixBySegment(nextSegment, zeroed));
	}

	@Override
	public MACAddress adjustPrefixLength(int adjustment) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment));
	}
	
	@Override
	public MACAddress adjustPrefixLength(int adjustment, boolean zeroed) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment, zeroed));
	}

	@Override
	public MACAddress setPrefixLength(int prefixLength) {
		return checkIdentity(getSection().setPrefixLength(prefixLength));
	}

	@Override
	public MACAddress setPrefixLength(int prefixLength, boolean zeroed) {
		return checkIdentity(getSection().setPrefixLength(prefixLength, zeroed));
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

	/**
	 * Returns an address in which the range of values match the block for the OUI (organizationally unique identifier)
	 * 
	 * @return
	 */
	public MACAddress toOUIPrefixBlock() {
		return checkIdentity(getSection().toOUIPrefixBlock());
	}

	@Override
	public MACAddress toPrefixBlock() {
		return checkIdentity(getSection().toPrefixBlock());
	}

	/**
	 * Converts to a link-local Ipv6 address.  Any MAC prefix length is ignored.  Other elements of this address section are incorporated into the conversion.
	 * This will provide the latter 4 segments of an IPv6 address, to be paired with the link-local IPv6 prefix of 4 segments.
	 * 
	 * @return
	 */
	public IPv6Address toLinkLocalIPv6() {
		IPv6AddressNetwork network = getIPv6Network();
		IPv6AddressSection linkLocalPrefix = network.getLinkLocalPrefix();
		IPv6AddressCreator creator = network.getAddressCreator();
		return creator.createAddress(linkLocalPrefix.append(toEUI64IPv6()));
	}
	
	/**
	 * Converts to an Ipv6 address section.  Any MAC prefix length is ignored.  Other elements of this address section are incorporated into the conversion.
	 * This will provide the latter 4 segments of an IPv6 address, to be paired with an IPv6 prefix of 4 segments.
	 * 
	 * @return
	 */
	public IPv6AddressSection toEUI64IPv6() {
		return getIPv6Network().getAddressCreator().createSection(this);
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
			MACAddressSegment ffSegment = creator.createSegment(0xff);
			segs[3] = ffSegment;
			segs[4] = asMAC ? ffSegment : creator.createSegment(0xfe);
			section.getSegments(3,  6, segs, 5);
			Integer prefLength = getPrefixLength();
			if(prefLength != null) {
				MACAddressSection resultSection = creator.createSectionInternal(segs, true);
				if(prefLength >= 24) {
					prefLength += MACAddress.BITS_PER_SEGMENT << 1; //two segments
				}
				resultSection.assignPrefixLength(prefLength);
			}
			return creator.createAddressInternal(segs);
		} else {
			MACAddressSection section = getSection();
			MACAddressSegment seg3 = section.getSegment(3);
			MACAddressSegment seg4 = section.getSegment(4);
			if(seg3.matches(0xff) && seg4.matches(asMAC ? 0xff : 0xfe)) {
				return this;
			}
		}
		throw new IncompatibleAddressException(this, "ipaddress.mac.error.not.eui.convertible");
	}

	/**
	 * Replaces segments starting from startIndex and ending before endIndex with the same number of segments starting at replacementStartIndex from the replacement section
	 * 
	 * @param startIndex
	 * @param endIndex
	 * @param replacement
	 * @param replacementIndex
	 * @throws IndexOutOfBoundsException
	 * @return
	 */
	public MACAddress replace(int startIndex, int endIndex, MACAddress replacement, int replacementIndex) {
		return checkIdentity(getSection().replace(startIndex, endIndex, replacement.getSection(), replacementIndex, replacementIndex + (endIndex - startIndex)));
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
	public String toString() {
		return toNormalizedString();
	}
	
	public boolean isUnicast() {
		return !isMulticast();
	}

	/**
	 * Multicast MAC addresses have the least significant bit of the first octet set to 1.
	 */
	@Override
	public boolean isMulticast() {
		return getSegment(0).matchesWithMask(1, 0x1);
	}
	
	/**
	 * Universal MAC addresses have second the least significant bit of the first octet set to 0.
	 */
	public boolean isUniversal() {
		return !isLocal();
	}
	
	/**
	 * Local MAC addresses have the second least significant bit of the first octet set to 1.
	 */
	@Override
	public boolean isLocal() {
		return getSegment(0).matchesWithMask(2, 0x2);
	}
}
