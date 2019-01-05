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

package inet.ipaddr.ipv6;

import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import inet.ipaddr.Address;
import inet.ipaddr.AddressConversionException;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.AddressPositionException;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressConverter;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.IPAddressSegmentSeries;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.format.validate.Validator;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4Address.IPv4AddressConverter;
import inet.ipaddr.ipv4.IPv4AddressNetwork;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection.AddressCache;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringBuilderOptions;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCache;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringCollection;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions;
import inet.ipaddr.mac.MACAddress;
import inet.ipaddr.mac.MACAddressNetwork;
import inet.ipaddr.mac.MACAddressNetwork.MACAddressCreator;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSegment;

/**
 * An IPv6 address, or a subnet of multiple IPv6 addresses.  Each segment can represent a single value or a range of values.
 * <p>
 * You can construct an IPv6 address from a byte array, from a BigInteger, from a {@link inet.ipaddr.Address.SegmentValueProvider}, 
 * from Inet6Address, from MACAddress, from an {@link IPv6AddressSection} of 8 segments, or from an array of 8  {@link IPv6AddressSegment} objects.
 * <p>
 * To construct one from a {@link java.lang.String} use 
 * {@link inet.ipaddr.IPAddressString#toAddress()} or  {@link inet.ipaddr.IPAddressString#getAddress()}, {@link inet.ipaddr.IPAddressString#toHostAddress()} or {@link inet.ipaddr.IPAddressString#getHostAddress()}
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

	private static final long serialVersionUID = 4L;

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

	/* 
	 * An IPv6 zone distinguishes two IPv6 addresses that are the same.
	 * They are used with link-local addresses fe80::/10 and distinguishes two interfaces to the link-local network, this is known as the zone id.
	 * They are used with site-local addresses to distinguish sites, using the site id, also known as the scope id.
	 * 
	 * A zone that consists of a scope id is called a scoped zone.
	 */
	private final String zone;

	protected static class ValueCache {
		public Inet6Address inetAddress, upperInetAddress;
	}
	
	private transient ValueCache valueCache;
	
	private transient IPv6StringCache stringCache;
	
	transient AddressCache sectionCache;

	IPv6Address(IPv6AddressSection section, CharSequence zone, boolean checkZone) throws AddressValueException {
		super(section);
		if(section.getSegmentCount() != SEGMENT_COUNT) {
			throw new AddressValueException("ipaddress.error.ipv6.invalid.segment.count", section.getSegmentCount());
		}
		if(section.addressSegmentIndex != 0) {
			throw new AddressPositionException(section.addressSegmentIndex);
		}
		if(checkZone) {
			this.zone = checkZone(zone);
		} else if(zone != null && zone.length() > 0) {
			this.zone = zone.toString();
		} else {
			this.zone = null;
		}
	}
	
	/**
	 * @throws AddressValueException if segment count is not 8 or zone is invalid
	 * @param section
	 * @param zone
	 */
	public IPv6Address(IPv6AddressSection section, CharSequence zone) throws AddressValueException {
		this(section, zone, true);
	}
	
	public IPv6Address(IPv6AddressSection section) throws AddressValueException {
		this(section, (CharSequence) null);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * @throws AddressValueException if segment count is not 8
	 * @param segments the address segments
	 */
	public IPv6Address(IPv6AddressSegment[] segments) throws AddressValueException {
		this(segments, null, null);
	}

	/**
	 * Constructs an IPv6 address or a set of addresses.
	 * 
	 * @throws AddressValueException if segment count is not 8
	 * @param segments the address segments
	 * @param networkPrefixLength
	 * @throws AddressValueException if network prefix length invalid
	 */
	public IPv6Address(IPv6AddressSegment[] segments, Integer networkPrefixLength) throws AddressValueException {
		this(segments, networkPrefixLength, null);
	}

	/**
	 * Constructs an IPv6 address or a set of addresses.
	 * @param segments the address segments
	 * @param zone the zone or scope id
	 * 
	 * @throws AddressValueException if segment count is not 8 or the zone invalid
	 */
	public IPv6Address(IPv6AddressSegment[] segments, CharSequence zone) throws AddressValueException {
		this(segments, null, zone);
	}

	private IPv6Address(IPv6AddressSegment[] segments, Integer networkPrefixLength, CharSequence zone) throws AddressValueException {
		super(thisAddress -> ((IPv6Address) thisAddress).getDefaultCreator().createSection(segments, networkPrefixLength));
		if(segments.length != SEGMENT_COUNT) {
			throw new AddressValueException("ipaddress.error.ipv6.invalid.segment.count", segments.length);
		}
		this.zone = checkZone(zone);
	}

	/**
	 * Constructs an IPv6 address.
	 *
	 * @param inet6Address the java.net address object
	 */
	public IPv6Address(Inet6Address inet6Address) {
		this(inet6Address.getAddress(), getZone(inet6Address));
	}

	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * The byte array can be a 16 byte IPv6 address, but may have additional zero-valued bytes, or it may be fewer than 16 bytes.
	 *
	 * @throws AddressValueException if bytes not equivalent to a 16 byte address
	 * @param bytes the 16 byte IPv6 address in network byte order - if longer than 16 bytes the additional bytes must be zero (and are ignored), if shorter than 16 bytes then the bytes are sign-extended to 16 bytes.
	 * @throws AddressValueException if byte range invalid or zone invalid
	 */
	public IPv6Address(byte[] bytes, CharSequence zone) throws AddressValueException {
		this(bytes, null, zone);
	}
	
	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * The byte array can be a 16 byte IPv6 address, but may have additional zero-valued bytes, or it may be fewer than 16 bytes.
	 *
	 * @throws AddressValueException if bytes not equivalent to a 16 byte address
	 * @param bytes the 16 byte IPv6 address in network byte order - if longer than 16 bytes the additional bytes must be zero (and are ignored), if shorter than 16 bytes then the bytes are sign-extended to 16 bytes.
	 */
	public IPv6Address(byte[] bytes) throws AddressValueException {
		this(bytes, null, null);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * Similar to {@link #IPv6Address(byte[])} except that you can specify the start and end of the address in the given byte array.
	 * @throws AddressValueException if byte range invalid
	 */
	public IPv6Address(byte[] bytes, int byteStartIndex, int byteEndIndex) throws AddressValueException {
		this(bytes, byteStartIndex, byteEndIndex, null, null);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * The byte array can be a 16 byte IPv6 address, but may have additional zero-valued bytes, or it may be fewer than 16 bytes.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * @param bytes the 16 byte IPv6 address in network byte order - if longer than 16 bytes the additional bytes must be zero (and are ignored), if shorter than 16 bytes then the bytes are sign-extended to 16 bytes.
	 * @param networkPrefixLength the CIDR prefix, which can be null for no prefix length
	 * @throws AddressValueException if bytes not equivalent to a 16 byte address
	 */
	public IPv6Address(byte[] bytes, Integer networkPrefixLength) throws AddressValueException {
		this(bytes, networkPrefixLength, null);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * Similar to {@link #IPv6Address(byte[], Integer)} except that you can specify the start and end of the address in the given byte array.
	 */
	public IPv6Address(byte[] bytes, int byteStartIndex, int byteEndIndex, Integer networkPrefixLength) throws AddressValueException {
		this(bytes, byteStartIndex, byteEndIndex, networkPrefixLength, null);
	}
	
	/**
	 * Constructs an IPv6 address.  
	 * <p>
	 * The byte representation from {@link BigInteger#toByteArray()} is used, and the byte array follows the rules according to {@link #IPv6Address(byte[])}.
	 * Either it must be exactly 16 bytes, or if larger then any extra bytes must be significant leading zeros, 
	 * or if smaller it is sign-extended to the required 16 byte length.
	 * <p>
	 * This means that you can end up with the same address from two different values of BigInteger, one positive and one negative.
	 * For instance, -1 and ffffffffffffffffffffffffffffffff are represented by the two's complement byte arrays [ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff] 
	 * and [0,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff] respectively.
	 * Both create the address ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
	 * <p>
	 * In fact, the two's complement byte array [ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff] can be shortened to [ff], the former being the sign-extension of the latter.
	 * So the byte array [ff] also creates the address ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff.
	 * <p>
	 * When using positive integers you end up with the results you expect, the magnitude of the big integer becomes the address.
	 * <p>
	 * When ranging over all 16-byte arrays and constructing BigInteger from those arrays, you range over all possible addresses.
	 * <p>
	 * @throws AddressValueException if value is outside the range of potential values
	 * @param val must be an IPv6 address value.
	 * @throws AddressValueException if val is invalid
	 */
	public IPv6Address(BigInteger val) throws AddressValueException {
		this(val, null, null);
	}
	
	/**
	 * Constructs an IPv6 address.  
	 * <p>
	 * The byte representation from {@link BigInteger#toByteArray()} is used, and the byte array follows the rules according to {@link #IPv6Address(byte[])}.
	 * Either it must be exactly 16 bytes, or if larger then any extra bytes must be significant leading zeros, 
	 * or if smaller it is sign-extended to the required 16 byte length.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * 
	 * @param val
	 * @param networkPrefixLength
	 * @throws AddressValueException if val is invalid
	 */
	public IPv6Address(BigInteger val, Integer networkPrefixLength) throws AddressValueException {
		this(val, networkPrefixLength, null);
	}
	
	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * The byte representation from {@link BigInteger#toByteArray()} is used, and the byte array follows the rules according to {@link #IPv6Address(byte[])}.
	 * Either it must be exactly 16 bytes, or if larger then any extra bytes must be significant leading zeros, 
	 * or if smaller it is sign-extended to the required 16 byte length.
	 * <p>
	 * @param val
	 * @param zone
	 * @throws AddressValueException if val is invalid or if zone is invalid
	 */
	public IPv6Address(BigInteger val, CharSequence zone) throws AddressValueException {
		this(val, null, zone);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param val must be an IPv6 address value
	 * @param networkPrefixLength the CIDR prefix length, which can be null for no prefix length
	 * @param zone the zone or scope id
	 * @throws AddressValueException if value is outside the range of potential values, or if zone is invalid
	 */
	public IPv6Address(BigInteger val, Integer networkPrefixLength, CharSequence zone) throws AddressValueException {	
		super(thisAddress -> ((IPv6Address) thisAddress).getDefaultCreator().createSectionInternal(val.toByteArray(), IPv6Address.SEGMENT_COUNT, networkPrefixLength));
		this.zone = checkZone(zone);
	}
	
	private IPv6Address(byte[] bytes, Integer networkPrefixLength, CharSequence zone) throws AddressValueException {
		this(bytes, 0, bytes.length, networkPrefixLength, zone);
	}
	
	private IPv6Address(byte[] bytes, int byteStartIndex, int byteEndIndex, Integer networkPrefixLength, CharSequence zone) throws AddressValueException {
		super(thisAddress -> ((IPv6Address) thisAddress).getDefaultCreator().createSection(bytes, byteStartIndex, byteEndIndex, IPv6Address.SEGMENT_COUNT, networkPrefixLength));
		this.zone = checkZone(zone);
	}

	/**
	 * Constructs an IPv6 address or subnet.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param lowerValueProvider supplies the 2 byte lower values for each segment
	 * @param upperValueProvider supplies the 2 byte upper values for each segment
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer networkPrefixLength) throws AddressValueException {
		this(lowerValueProvider, upperValueProvider, networkPrefixLength, null);
	}
	
	/**
	 * Constructs an IPv6 address or subnet.
	 * 
	 * @param lowerValueProvider supplies the 2 byte lower values for each segment
	 * @param upperValueProvider supplies the 2 byte upper values for each segment
	 */
	public IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider) {
		this(lowerValueProvider, upperValueProvider, null, null);
	}
	
	/**
	 * Constructs an IPv6 address.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param valueProvider supplies the 2 byte value for each segment
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv6Address(SegmentValueProvider valueProvider, Integer networkPrefixLength) throws AddressValueException {
		this(valueProvider, valueProvider, networkPrefixLength);
	}
	
	/**
	 * Constructs an IPv6 address.
	 * 
	 * @param valueProvider supplies the 2 byte value for each segment
	 */
	public IPv6Address(SegmentValueProvider valueProvider) {
		this(valueProvider, (Integer) null);
	}
	
	/**
	 * Constructs an IPv6 address.
	 *
	 * @param lowerValueProvider supplies the 2 byte lower values for each segment
	 * @param upperValueProvider supplies the 2 byte upper values for each segment
	 * @throws AddressValueException if zone is invalid
	 */
	public IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, CharSequence zone) throws AddressValueException {
		this(lowerValueProvider, upperValueProvider, null, zone);
	}
	
	private IPv6Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer networkPrefixLength, CharSequence zone) throws AddressValueException {
		super(thisAddress -> ((IPv6Address) thisAddress).getDefaultCreator().createFullSectionInternal(lowerValueProvider, upperValueProvider, networkPrefixLength));
		this.zone = checkZone(zone);
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address section and an IPv6 address section network prefix.
	 * <p>
	 * If the supplied MAC section is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied section is a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * <p>
	 * If the supplied section neither 6 nor 8 bytes, or if the 8-byte section does not have required EUI-64 format of xx-xx-ff-fe-xx-xx,
	 * {@link IncompatibleAddressException} will be thrown.
	 * <p>
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * <p>
	 * Only the first 8 bytes (4 segments) of the IPv6Address are used to construct the address.
	 * <p>
	 * Any prefix length in the MAC address is ignored, while a prefix length in the IPv6 address is preserved but only up to the first 4 segments.
	 * 
	 * @throws IncompatibleAddressException if the MACAddress is an 8 byte MAC address incompatible with EUI-64 IPv6 format
	 * @param prefix an address from which the first four segments will be used as the same initial segments in the returned address
	 * @param eui
	 */
	public IPv6Address(IPv6Address prefix, MACAddress eui) throws IncompatibleAddressException {
		this(prefix.getSection(), eui.getSection());
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address section and an IPv6 address section network prefix.
	 * <p>
	 * If the supplied MAC section is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied section is a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * <p>
	 * If the supplied section neither 6 nor 8 bytes, or if the 8-byte section does not have required EUI-64 format of xx-xx-ff-fe-xx-xx,
	 * {@link IncompatibleAddressException} will be thrown.
	 * <p>
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * <p>
	 * The IPv6 address section must be 8 bytes.
	 * <p>
	 * Any prefix length in the MAC address is ignored, while a prefix length in the IPv6 address is preserved but only up to the first 4 segments.
	 * @throws IncompatibleAddressException if the MACAddress is an 8 byte MAC address incompatible with EUI-64 IPv6 format
	 * @throws AddressValueException  if the IPv6 section is the wrong size or structure
	 * @param section
	 * @param eui
	 */
	public IPv6Address(IPv6AddressSection section, MACAddress eui) throws IncompatibleAddressException, AddressValueException  {
		this(section, eui.getSection());
	}
	
	/**
	 * Constructs an IPv6 address from a modified EUI-64 (Extended Unique Identifier) address and an IPv6 address section network prefix.
	 * <p>
	 * If the supplied address is an 8 byte EUI-64, then it must match the required EUI-64 format of xx-xx-ff-fe-xx-xx
	 * with the ff-fe section in the middle.
	 * 
	 * If the supplied address is a 6 byte MAC-48 or EUI-48, then the ff-fe pattern will be inserted.
	 * <p>
	 * The constructor will toggle the MAC U/L (universal/local) bit as required with EUI-64.
	 * <p>
	 * The IPv6 address section must be 8 bytes.
	 * <p>
	 * Any prefix length in the MAC address is ignored, while a prefix length in the IPv6 address is preserved but only up to the first 4 segments.
	 * @throws IncompatibleAddressException if the MACAddress is an 8 byte MAC address incompatible with EUI-64 IPv6 format
	 * @throws AddressValueException  if the MACAddress or IPv6 sections are the wrong size or structure
	 * @param section
	 * @param eui
	 */
	public IPv6Address(IPv6AddressSection section, MACAddressSection eui) throws IncompatibleAddressException, AddressValueException  {
		this(section, eui, null);
	}
	
	/**
	 * 
	 * @param section
	 * @param eui
	 * @param zone
	 * @throws IncompatibleAddressException  if the MACAddress is an 8 byte MAC address incompatible with EUI-64 IPv6 format
	 * @throws AddressValueException  if the MACAddress or IPv6 sections are the wrong size or structure, or if zone is invalid
	 */
	public IPv6Address(IPv6AddressSection section, MACAddressSection eui, CharSequence zone) throws IncompatibleAddressException, AddressValueException  {
		super(thisAddress -> toFullEUI64Section(section, eui, ((IPv6Address) thisAddress).getDefaultCreator(), ((IPv6Address) thisAddress).getMACNetwork().getAddressCreator()));
		this.zone = checkZone(zone);
	}
	
	private static String checkZone(CharSequence zone) throws AddressValueException {
		if(zone == null || zone.length() == 0) {
			return null;
		}
		int invalidIndex = Validator.validateZone(zone);
		if(invalidIndex >= 0) {
			throw new AddressValueException("ipaddress.error.invalid.zone", invalidIndex);
		}
		return zone.toString();
	}

	IPv6AddressCreator getDefaultCreator() {
		return getNetwork().getAddressCreator();
	}
	
	private IPv6AddressCreator getCreator() {
		if(!hasZone()) {
			return getDefaultCreator();
		}
		return new IPv6AddressCreator(getNetwork()) {// using a lambda for this one results in a big performance hit, so we use anonymous class

			private static final long serialVersionUID = 4L;

			@Override
			protected IPv6Address createAddressInternal(IPv6AddressSegment segments[]) {
				IPv6AddressCreator creator = getDefaultCreator();
				return creator.createAddressInternal(segments, zone); /* address creation */
			}

			@Override
			public IPv6Address createAddress(IPv6AddressSection section) {
				IPv6AddressCreator creator = getDefaultCreator();
				return creator.createAddressInternal(section, zone); /* address creation */
			}
		};
	}
	
	private static CharSequence getZone(Inet6Address inet6Address) {
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
		return zone;
	}

	private static IPv6AddressSection toFullEUI64Section(IPv6AddressSection section, MACAddressSection eui, IPv6AddressCreator creator, MACAddressCreator macCreator) throws AddressValueException, IncompatibleAddressException {
		boolean euiIsExtended = eui.isExtended();
		
		if(eui.addressSegmentIndex != 0) {
			throw new AddressPositionException(eui, eui.addressSegmentIndex);
		}
		if(section.addressSegmentIndex != 0) {
			throw new AddressPositionException(section, section.addressSegmentIndex);
		}
		if(section.getSegmentCount() < 4) {
			throw new AddressValueException(section, "ipaddress.mac.error.not.eui.convertible");
		}
		if(eui.getSegmentCount() != (euiIsExtended ? MACAddress.EXTENDED_UNIQUE_IDENTIFIER_64_SEGMENT_COUNT : MACAddress.EXTENDED_UNIQUE_IDENTIFIER_48_SEGMENT_COUNT)) {
			throw new AddressValueException(eui, "ipaddress.mac.error.not.eui.convertible");
		}
		IPv6AddressSegment segments[] = creator.createSegmentArray(8);
		section.getSegments(0, 4, segments, 0);
		Integer prefLength = section.getNetworkPrefixLength();
		Integer prefixLength = prefLength != null && (prefLength <= 64) ? prefLength : null;
		toEUI64Segments(segments, 4, eui, 0, eui.isExtended(), creator, macCreator, prefixLength);
		return creator.createSectionInternal(segments);
	}
	
	static IPv6AddressSegment[] toEUI64Segments(
			IPv6AddressSegment segments[],
			int ipv6StartIndex,
			MACAddressSection eui,
			int euiStartIndex,
			boolean isExtended,
			IPv6AddressCreator creator,
			MACAddressCreator macCreator,
			Integer prefixLength) 
					throws IncompatibleAddressException {
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

		MACAddressSegment zeroSegment = macCreator.createSegment(0);
		MACAddressSegment ffSegment = macCreator.createSegment(0xff);
		MACAddressSegment feSegment = macCreator.createSegment(0xfe);

		Integer currentPrefix = null;
		if(prefixLength != null) {
			//since the prefix comes from the ipv6 section and not the MAC section, any segment prefix for the MAC section is 0 or null
			//prefixes across segments have the pattern: null, null, ..., null, 0-16, 0, 0, ..., 0
			//So if the overall prefix is 0, then the prefix of every segment is 0
			currentPrefix = 0;
		}
		if((isNotNull = (seg0 != null)) || seg1 != null) {
			if(isNotNull) {
				if(seg1 == null) {
					seg1 = zeroSegment;
				}
			} else {
				seg0 = zeroSegment;
			}
			segments[ipv6StartIndex++] = join(creator, seg0, seg1, true /* only this first one gets the flipped bit */, currentPrefix);
		}
		
		//join 2 and 3 
		if(isExtended) {
			if((isNotNull = (seg2 != null)) || seg3 != null) {
				if(!isNotNull) {
					seg2 = zeroSegment;
					if(!seg3.matches(0xff)) {
						throw new IncompatibleAddressException(eui, "ipaddress.mac.error.not.eui.convertible");
					}
				}
				segments[ipv6StartIndex++] = join(creator, seg2, ffSegment, currentPrefix);
			}
			if((isNotNull = (seg4 != null)) || seg5 != null) {
				if(isNotNull) {
					if(!seg4.matches(0xfe)) {
						throw new IncompatibleAddressException(eui, "ipaddress.mac.error.not.eui.convertible");
					}
					if(seg5 == null) {
						seg5 = zeroSegment;
					}
				}
				segments[ipv6StartIndex++] = join(creator, feSegment, seg5, currentPrefix);
			}
		} else {
			if(seg2 != null) {
				segments[ipv6StartIndex++] = join(creator, seg2, ffSegment, currentPrefix);
			}
			if(seg3 != null) {
				segments[ipv6StartIndex++] = join(creator, feSegment, seg3, currentPrefix);
			}
			if((isNotNull = (seg4 != null)) || seg5 != null) {
				if(isNotNull) {
					if(seg5 == null) {
						seg5 = zeroSegment;
					}
				} else {
					seg4 = zeroSegment;
				}
				segments[ipv6StartIndex++] = join(creator, seg4, seg5, currentPrefix);
			}
		}
		if((isNotNull = (seg6 != null)) || seg7 != null) {
			if(isNotNull) {
				if(seg7 == null) {
					seg7 = zeroSegment;
				}
			} else {
				seg6 = zeroSegment;
			}
			segments[ipv6StartIndex] = join(creator, seg6, seg7, currentPrefix);
		}
		return segments;
	} 
	
	private static IPv6AddressSegment join(IPv6AddressCreator creator, MACAddressSegment macSegment0, MACAddressSegment macSegment1, Integer prefixLength) {
		return join(creator, macSegment0, macSegment1, false, prefixLength);
	}
	
	private static IPv6AddressSegment join(IPv6AddressCreator creator, MACAddressSegment macSegment0, MACAddressSegment macSegment1, boolean flip, Integer prefixLength) {
		int lower0 = macSegment0.getSegmentValue();
		int upper0 = macSegment0.getUpperSegmentValue();
		if(flip) {
			int mask2ndBit = 0x2;
			if(!macSegment0.matchesWithMask(mask2ndBit & lower0, mask2ndBit)) {
				throw new IncompatibleAddressException(macSegment0, "ipaddress.mac.error.not.eui.convertible");
			}
			lower0 ^= mask2ndBit;//flip the universal/local bit
			upper0 ^= mask2ndBit;
		}
		return creator.createSegment(
				(lower0 << 8) | macSegment1.getSegmentValue(), 
				(upper0 << 8) | macSegment1.getUpperSegmentValue(),
				prefixLength);
	}

	@Override
	public IPv6AddressNetwork getNetwork() {
		return defaultIpv6Network();
	}
	
	public MACAddressNetwork getMACNetwork() {
		return defaultMACNetwork();
	}
	
	public IPv4AddressNetwork getIPv4Network() {
		return defaultIpv4Network();
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
	public IPv6AddressSegment getDivision(int index) {
		return getSegment(index);
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
		MACAddressCreator creator = getMACNetwork().getAddressCreator();
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
	
	private IPv6Address getLowestOrHighest(boolean lowest, boolean excludeZeroHost) {
		IPv6AddressSection currentSection = getSection();
		IPv6AddressSection sectionResult = currentSection.getLowestOrHighestSection(lowest, excludeZeroHost);
		if(sectionResult == currentSection) {
			return this;
		} else if(sectionResult == null) {
			return null;
		}
		IPv6Address result = null;
		AddressCache cache = sectionCache;
		if(cache == null || 
			(result = lowest ? (excludeZeroHost ? cache.lowerNonZeroHost : cache.lower) : cache.upper) == null) {
			synchronized(this) {
				cache = sectionCache;
				boolean create = (cache == null);
				if(create) {
					sectionCache = cache = new AddressCache();
				} else {
					if(lowest) {
						if(excludeZeroHost) {
							create = (result = cache.lowerNonZeroHost) == null;
						} else {
							create = (result = cache.lower) == null;
						}
					} else {
						create = (result = cache.upper) == null;
					}
				}
				if(create) {
					result = getCreator().createAddress(sectionResult);
					if(lowest) {
						if(excludeZeroHost) {
							 cache.lowerNonZeroHost = result;
						} else {
							cache.lower = result;
						}
					} else {
						cache.upper = result;
					}
				}
			}
		}
		return result;
	}
	
	@Override
	public IPv6Address getLowerNonZeroHost() {
		return getLowestOrHighest(true, true);
	}
	
	@Override
	public IPv6Address getLower() {
		return getLowestOrHighest(true, false);
	}
	
	@Override
	public IPv6Address getUpper() {
		return getLowestOrHighest(false, false);
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
	public IPv6Address replace(int startIndex, int endIndex, IPv6Address replacement, int replacementIndex) {
		return checkIdentity(getSection().replace(startIndex, endIndex, replacement.getSection(), replacementIndex, replacementIndex + (endIndex - startIndex)));
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
	
	@Override
	public Iterator<IPv6AddressSegment[]> segmentsNonZeroHostIterator() {
		return getSection().segmentsNonZeroHostIterator();
	}
	
	@Override
	public Iterator<IPv6AddressSegment[]> segmentsIterator() {
		return getSection().segmentsIterator();
	}
	
	@Override
	public Iterator<IPv6Address> prefixBlockIterator() {
		return getSection().prefixBlockIterator(this, getCreator(), true);
	}

	@Override
	public Iterator<IPv6Address> prefixBlockIterator(int prefixLength) {
		return getSection().prefixBlockIterator(this, getCreator(), true, prefixLength);
	}
	
	@Override
	public Iterator<IPv6Address> prefixIterator() {
		return getSection().prefixBlockIterator(this, getCreator(), false);
	}

	@Override
	public Iterator<IPv6Address> prefixIterator(int prefixLength) {
		return getSection().prefixBlockIterator(this, getCreator(), false, prefixLength);
	}

	@Override
	public Iterator<IPv6Address> blockIterator(int segmentCount) {
		return getSection().blockIterator(this, getCreator(), segmentCount);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv6Address> sequentialBlockIterator() {
		return (Iterator<IPv6Address>) super.sequentialBlockIterator();
	}

	@Override
	public Iterator<IPv6Address> iterator() {
		return getSection().iterator(this, getCreator(), false);
	}
	
	@Override
	public Iterator<IPv6Address> nonZeroHostIterator() {
		return getSection().iterator(this, getCreator(), true);
	}
	
	@Override
	public Iterable<IPv6Address> getIterable() {
		return this;
	}

	@Override
	public IPv6Address increment(long increment) {
		return checkIdentity(getSection().increment(increment));
	}
	
	@Override
	public IPv6Address incrementBoundary(long increment) {
		return checkIdentity(getSection().incrementBoundary(increment));
	}

	/**
	 * If this address is IPv4 convertible, returns that address.
	 * Otherwise, returns null.
	 * <p>
	 * This uses {@link #isIPv4Convertible()} to determine convertibility, and that uses an instance of {@link IPAddressConverter.DefaultAddressConverter} which uses IPv4-mapped address mappings from rfc 4038.
	 * <p>
	 * Override this method and {@link IPv6Address#isIPv4Convertible()} if you wish to map IPv6 to IPv4 according to the mappings defined by
	 * in {@link IPv6Address#isIPv4Compatible()}, {@link IPv6Address#isIPv4Mapped()}, {@link IPv6Address#is6To4()} or by some other mapping.
	 * <p>
	 * For the reverse mapping, see {@link IPv4Address#toIPv6()} 
	 */
	@Override
	public IPv4Address toIPv4() {
		IPAddressConverter conv = DEFAULT_ADDRESS_CONVERTER;
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
	 * Override this method to convert in your own way.
	 * The default behaviour is to use isIPv4Mapped()
	 * 
	 * You should also override {@link #toIPv4()} to match the conversion.
	 * 
	 * @return
	 */
	@Override
	public boolean isIPv4Convertible() {
		IPAddressConverter conv = DEFAULT_ADDRESS_CONVERTER;
		return conv != null && conv.isIPv4Convertible(this);
	}
	
	@Override
	public boolean isIPv6Convertible() {
		return true;
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
		IPv4AddressCreator creator = getIPv4Network().getAddressCreator();
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
		IPv4AddressCreator creator = getIPv4Network().getAddressCreator();
		return creator.createAddress(getSection().getEmbeddedIPv4AddressSection(byteIndex, byteIndex + IPv4Address.BYTE_COUNT)); /* address creation */
	}
	
	@Override
	public boolean isLocal() {
		if(isMulticast()) {
			/*
			 [RFC4291][RFC7346]
			 11111111|flgs|scop 
				scope 4 bits
				 1  Interface-Local scope
		         2  Link-Local scope
		         3  Realm-Local scope
		         4  Admin-Local scope
		         5  Site-Local scope
		         8  Organization-Local scope
		         E  Global scope
			 */
			IPv6AddressSegment firstSeg = getSegment(0);
			if(firstSeg.matchesWithMask(8, 0xf)) {
				return true;
			}
			if(firstSeg.getValueCount() <= 5 && 
					(firstSeg.getSegmentValue() & 0xf) >= 1 && (firstSeg.getUpperSegmentValue() & 0xf) <= 5) {
				//all values fall within the range from interface local to site local
				return true;
			}
			
			//source specific multicast
			//rfc4607 and https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
			//FF3X::8000:0 - FF3X::FFFF:FFFF	Reserved for local host allocation	[RFC4607]
			if(firstSeg.matchesWithPrefixMask(0xff30, 12) && getSegment(6).matchesWithPrefixMask(0x8000, 1)) {
				return true;
			}
		}
		return isLinkLocal() || isSiteLocal() || isUniqueLocal() || isAnyLocal();
	}
	
	/**
	 * @see java.net.InetAddress#isLinkLocalAddress()
	 */
	@Override
	public boolean isLinkLocal() {
		IPv6AddressSegment firstSeg = getSegment(0);
		return (isMulticast() && firstSeg.matchesWithMask(2, 0xf)) ||
				//1111 1110 10 .... fe8x currently only in use
				firstSeg.matchesWithPrefixMask(0xfe80, 10);
	}
	
	/**
	 * @see java.net.InetAddress#isSiteLocalAddress()
	 */
	public boolean isSiteLocal() {
		IPv6AddressSegment firstSeg = getSegment(0);
		return (isMulticast() && firstSeg.matchesWithMask(5, 0xf)) || 
				//1111 1110 11 ...
				firstSeg.matchesWithPrefixMask(0xfec0, 10); //deprecated RFC 3879
	}
	
	public boolean isUniqueLocal() {
		//RFC 4193
		return getSegment(0).matchesWithPrefixMask(0xfc00, 7);
	}
	
	/**
	 * Whether the address is IPv4-mapped
	 * 
	 * ::ffff:x:x/96 indicates IPv6 address mapped to IPv4
	 */
	public boolean isIPv4Mapped() {
		//::ffff:x:x/96 indicates IPv6 address mapped to IPv4
		if(getSegment(5).matches(IPv6Address.MAX_VALUE_PER_SEGMENT)) {
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
		return getSegment(0).matchesWithPrefixMask(0xff, 8);
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
	public IPv6Address intersect(IPAddress other) throws AddressConversionException {
		IPv6AddressSection thisSection = getSection();
		IPv6Address otherAddr = convertArg(other);
		IPv6AddressSection section = thisSection.intersect(otherAddr.getSection());
		if(section == null) {
			return null;
		}
		//if they have the same zone, then use it in the intersection, otherwise ignore the zones
		IPv6AddressCreator creator = Objects.equals(zone, otherAddr.zone) ? getCreator() : getDefaultCreator();
		IPv6Address result = creator.createAddress(section);
		return result;
	}
	
	@Override
	public IPv6Address[] subtract(IPAddress other) throws AddressConversionException {
		IPv6AddressSection thisSection = getSection();
		IPv6AddressSection sections[] = thisSection.subtract(convertArg(other).getSection());
		if(sections == null) {
			return null;
		}
		IPv6Address result[] = new IPv6Address[sections.length];
		for(int i = 0; i < result.length; i++) {
			result[i] = getCreator().createAddress(sections[i]); /* address creation */
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
	public IPv6Address adjustPrefixBySegment(boolean nextSegment, boolean zeroed) {
		return checkIdentity(getSection().adjustPrefixBySegment(nextSegment, zeroed));
	}

	@Override
	public IPv6Address adjustPrefixLength(int adjustment) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment));
	}

	@Override
	public IPv6Address adjustPrefixLength(int adjustment, boolean zeroed) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment, zeroed));
	}

	@Override
	public IPv6Address setPrefixLength(int prefixLength) throws PrefixLenException {
		return setPrefixLength(prefixLength, true);
	}

	@Override
	public IPv6Address setPrefixLength(int prefixLength, boolean zeroed) throws PrefixLenException {
		return checkIdentity(getSection().setPrefixLength(prefixLength, zeroed));
	}

	@Override
	public IPv6Address applyPrefixLength(int networkPrefixLength) throws PrefixLenException {
		return checkIdentity(getSection().applyPrefixLength(networkPrefixLength));
	}
	
	@Override
	public IPv6Address removePrefixLength() {
		return removePrefixLength(true);
	}
	
	@Override
	public IPv6Address withoutPrefixLength() {
		return removePrefixLength(false);
	}
	
	@Override @Deprecated
	public IPv6Address removePrefixLength(boolean zeroed) {
		return checkIdentity(getSection().removePrefixLength(zeroed));
	}

	private IPv6Address convertArg(IPAddress arg) throws AddressConversionException{
		IPv6Address converted = arg.toIPv6();
		if(converted == null) {
			throw new AddressConversionException(this, arg);
		}
		return converted;
	}
	
	@Override
	public IPv6Address toZeroHost() {
		if(!isPrefixed()) {
			PrefixConfiguration config = getNetwork().getPrefixConfiguration();
			IPv6Address addr = getNetwork().getNetworkMask(0, !config.allPrefixedAddressesAreSubnets());
			if(config.zeroHostsAreSubnets()) {
				addr = addr.getLower();
			}
			return addr;
		}
		if(includesZeroHost() && isSingleNetwork()) {
			return getLower();//cached
		}
		return checkIdentity(getSection().createZeroHost());
	}

	@Override
	public IPv6Address toZeroHost(int prefixLength) {
		if(isPrefixed() && prefixLength == getNetworkPrefixLength()) {
			return toZeroHost();
		}
		return checkIdentity(getSection().toZeroHost(prefixLength));
	}

	@Override
	public IPv6Address toMaxHost() {
		if(!isPrefixed()) {
			IPv6Address resultNoPrefix = getNetwork().getHostMask(0);
			if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
				return resultNoPrefix;
			}
			return resultNoPrefix.setPrefixLength(0);
		}
		if(includesMaxHost() && isSingleNetwork()) {
			return getUpper();
		}
		return checkIdentity(getSection().createMaxHost());
	}
	
	@Override
	public IPv6Address toMaxHost(int prefixLength) {
		if(isPrefixed() && prefixLength == getNetworkPrefixLength()) {
			return toMaxHost();
		}
		return checkIdentity(getSection().toMaxHost(prefixLength));
	}
	
	@Override
	public IPv6Address mask(IPAddress mask, boolean retainPrefix) throws IncompatibleAddressException, AddressConversionException {
		return checkIdentity(getSection().mask(convertArg(mask).getSection(), retainPrefix));
	}

	@Override
	public IPv6Address mask(IPAddress mask) throws IncompatibleAddressException, AddressConversionException {
		return mask(mask, false);
	}

	@Override
	public IPv6Address maskNetwork(IPAddress mask, int networkPrefixLength) throws IncompatibleAddressException, PrefixLenException, AddressConversionException {
		return checkIdentity(getSection().maskNetwork(convertArg(mask).getSection(), networkPrefixLength));
	}
	
	@Override
	public IPv6Address bitwiseOr(IPAddress mask, boolean retainPrefix) throws IncompatibleAddressException, AddressConversionException {
		return checkIdentity(getSection().bitwiseOr(convertArg(mask).getSection(), retainPrefix));
	}
	
	@Override
	public IPv6Address bitwiseOr(IPAddress mask) throws IncompatibleAddressException, AddressConversionException {
		return bitwiseOr(mask, false);
	}
	
	@Override
	public IPv6Address bitwiseOrNetwork(IPAddress mask, int networkPrefixLength) throws IncompatibleAddressException, PrefixLenException, AddressConversionException {
		return checkIdentity(getSection().bitwiseOrNetwork(convertArg(mask).getSection(), networkPrefixLength));
	}

	@Override
	public IPv6AddressSection getNetworkSection() {
		return getSection().getNetworkSection();
	}
	
	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength) throws PrefixLenException {
		return getSection().getNetworkSection(networkPrefixLength);
	}
	
	@Override
	public IPv6AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) throws PrefixLenException {
		return getSection().getNetworkSection(networkPrefixLength, withPrefixLength);
	}
	
	@Override
	public IPv6AddressSection getHostSection(int networkPrefixLength) throws PrefixLenException {
		return getSection().getHostSection(networkPrefixLength);
	}
	
	@Override
	public IPv6AddressSection getHostSection() {
		return getSection().getHostSection();
	}
	
	@Override
	public IPv6Address toPrefixBlock() {
		Integer prefixLength = getNetworkPrefixLength();
		if(prefixLength == null || getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			return this;
		}
		return toPrefixBlock(prefixLength);
	}

	@Override
	public IPv6Address toPrefixBlock(int networkPrefixLength) throws PrefixLenException {
		return checkIdentity(getSection().toPrefixBlock(networkPrefixLength));
	}

	@Override
	public IPv6Address assignPrefixForSingleBlock() {
		return (IPv6Address) super.assignPrefixForSingleBlock();
	}

	@Override
	public IPv6Address assignMinPrefixForBlock() {
		return (IPv6Address) super.assignMinPrefixForBlock();
	}

	/**
	 * Produces an array of prefix blocks that cover the same set of addresses as this.
	 * <p>
	 * Unlike {@link #spanWithPrefixBlocks(IPAddress)} this method only includes addresses that are a part of this subnet.
	 */
	@Override
	public IPv6Address[] spanWithPrefixBlocks() {
		if(isSequential()) {
			return spanWithPrefixBlocks(this);
		}
		@SuppressWarnings("unchecked")
		ArrayList<IPv6Address> list = (ArrayList<IPv6Address>) spanWithBlocks(true);
		return list.toArray(new IPv6Address[list.size()]);
	}
	
	@Override
	public IPv6Address[] spanWithPrefixBlocks(IPAddress other) throws AddressConversionException {
		return IPAddress.getSpanningPrefixBlocks(
				this,
				convertArg(other),
				IPv6Address::getLower,
				IPv6Address::getUpper,
				Address.ADDRESS_LOW_VALUE_COMPARATOR::compare,
				IPv6Address::assignPrefixForSingleBlock,
				IPv6Address::withoutPrefixLength,
				getCreator()::createAddressArray);
	}
	
	/**
	 * Produces an array of blocks that are sequential that cover the same set of addresses as this.
	 * <p>
	 * This array can be shorter than that produced by {@link #spanWithPrefixBlocks()} and is never longer.
	 * <p>
	 * Unlike {@link #spanWithSequentialBlocks(IPAddress)} this method only includes addresses that are a part of this subnet.
	 */
	@Override
	public IPv6Address[] spanWithSequentialBlocks() throws AddressConversionException {
		if(isSequential()) {
			return new IPv6Address[] { withoutPrefixLength() };
		}
		@SuppressWarnings("unchecked")
		ArrayList<IPv6Address> list = (ArrayList<IPv6Address>) spanWithBlocks(false);
		return list.toArray(new IPv6Address[list.size()]);
	}
	
	@Override
	public IPv6Address[] spanWithSequentialBlocks(IPAddress other) throws AddressConversionException {
		return IPAddress.getSpanningSequentialBlocks(
				this,
				convertArg(other),
				IPv6Address::getLower,
				IPv6Address::getUpper,
				Address.ADDRESS_LOW_VALUE_COMPARATOR::compare,
				IPv6Address::withoutPrefixLength,
				getDefaultCreator());
	}
	
	@Override
	public IPv6AddressSeqRange spanWithRange(IPAddress other) throws AddressConversionException {
		return new IPv6AddressSeqRange(this, convertArg(other));
	}
	
	@Override
	public IPv6Address[] mergeToPrefixBlocks(IPAddress ...addresses) throws AddressConversionException {
		for(int i = 0; i < addresses.length; i++) {
			addresses[i] = convertArg(addresses[i]);
		}
		List<IPAddressSegmentSeries> blocks = getMergedPrefixBlocks(this, addresses);
		return blocks.toArray(new IPv6Address[blocks.size()]);
	}
	
	@Override
	public IPv6Address[] mergeToSequentialBlocks(IPAddress ...addresses) throws AddressConversionException {
		for(int i = 0; i < addresses.length; i++) {
			addresses[i] = convertArg(addresses[i]);
		}
		List<IPAddressSegmentSeries> blocks = getMergedSequentialBlocks(this, addresses, getDefaultCreator());
		return blocks.toArray(new IPv6Address[blocks.size()]);
	}

	/**
	 * Returns whether {@link #getZone()} returns a non-null value
	 * 
	 * @return
	 */
	public boolean hasZone() {
		return zone != null;
	}

	/**
	 * The zone or scope id, which is typically appended to an address with a '%', eg fe80::71a3:2b00:ddd3:753f%16
	 * 
	 * If there is no zone or scope id, returns null
	 * 
	 * @return
	 */
	public String getZone() {
		return zone;
	}
	
	/**
	 * Returns the equivalent address but with no zone.
	 * 
	 * @return
	 */
	public IPv6Address removeZone() {
		if(hasZone()) {
			return getDefaultCreator().createAddress(getSection()); /* address creation */
		}
		return this;
	}

	protected boolean hasNoValueCache() {
		if(valueCache == null) {
			synchronized(this) {
				if(valueCache == null) {
					valueCache = new ValueCache();
					return true;
				}
			}
		}
		return false;
	}
	
	//we need to cache the address in here and not in the address section if there is a zone
	@Override
	public Inet6Address toInetAddress() {
		if(hasZone()) {
			Inet6Address result;
			if(hasNoValueCache() || (result = valueCache.inetAddress) == null) {
				valueCache.inetAddress = result = (Inet6Address) toInetAddressImpl(getBytes());
			}
			return result;
		}
		return (Inet6Address) super.toUpperInetAddress();
	}
	
	@Override
	public Inet6Address toUpperInetAddress() {
		if(hasZone()) {
			Inet6Address result;
			if(hasNoValueCache() || (result = valueCache.upperInetAddress) == null) {
				valueCache.upperInetAddress = result = toInetAddressImpl(getUpperBytes());
			}
			return result;
		}
		return (Inet6Address) super.toInetAddress();
	}
	
	@Override
	protected Inet6Address toInetAddressImpl(byte bytes[]) {
		InetAddress result;
		try {
			if(hasZone()) {
				try {
					int scopeId = Integer.valueOf(zone);
					result = Inet6Address.getByAddress(null, bytes, scopeId);
				} catch(NumberFormatException e) {
					//there is no related function that takes a string as third arg. Only other one takes a NetworkInterface.  we don't want to be looking up network interface objects.
					//public static Inet6Address getByAddress(String host, byte[] addr, NetworkInterface nif) 
				
					//so we must go back to a string, even though we have the bytes available to us.  There appears to be no other alternative.
					result = InetAddress.getByName(toNormalizedString());
				}
			} else {
				result = InetAddress.getByAddress(bytes);
			}
		} catch(UnknownHostException e) {
			result = null;
		}
		return (Inet6Address) result;
	}
	
	@Override
	public IPv6AddressSeqRange toSequentialRange(IPAddress other) {
		return new IPv6AddressSeqRange(this, convertArg(other));
	}

	@Override
	public IPv6AddressSeqRange toSequentialRange() {
		return new IPv6AddressSeqRange(getLower(), getUpper());
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
	public boolean isSameAddress(Address other) {
		if(other instanceof IPv6Address && super.isSameAddress(other)) {
			//must check the zone too
			IPv6Address otherIPv6Address = (IPv6Address) other;
			String otherZone = otherIPv6Address.zone;
			return Objects.equals(zone, otherZone);
		}
		return false;
	}
	
	/**
	 * 
	 * @param other
	 * @return whether this subnet contains the given address
	 */
	@Override
	public boolean contains(Address other) {
		if(super.contains(other)) {
			//must check the zone too
			if(other != this) {
				if(zone != null) {
					//if it has a zone, then it does not contain addresses from other zones
					IPv6Address otherIPv6Address = (IPv6Address) other;
					String otherZone = otherIPv6Address.zone;
					return Objects.equals(zone, otherZone);
				}
			}
			return true;
		}
		return false;
	}

	//////////////// string creation below ///////////////////////////////////////////////////////////////////////////////////////////

	@Override
	protected IPAddressStringParameters createFromStringParams() {
		return new IPAddressStringParameters.Builder().
				getIPv4AddressParametersBuilder().setNetwork(getIPv4Network()).getParentBuilder().
				getIPv6AddressParametersBuilder().setNetwork(getNetwork()).getParentBuilder().toParams();
	}
	
	private boolean hasNoStringCache() {
		if(stringCache == null) {
			synchronized(this) {
				if(stringCache == null) {
					if(hasZone()) {
						stringCache = new IPv6StringCache();
						return true;
					} else {
						//when there is no zone, the section and address strings are the same, so we use the same cache
						IPv6AddressSection section = getSection();
						boolean result = section.hasNoStringCache();
						stringCache = section.getStringCache();
						return result;
					}
				}
			}
		}
		return false;
	}
	
	/**
	 * Produces a string in which the lower 4 bytes are expressed as an IPv4 address and the remaining upper bytes are expressed in IPv6 format.
	 * 
	 * This the mixed IPv6/IPv4 format described in RFC 1884 https://tools.ietf.org/html/rfc1884
	 * 
	 * @return
	 */
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
	 * 
	 * If this has a prefix length, that will be included in the string.
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
	 * Creates the normalized string for an address without having to create the address objects first.
	 * 
	 * @param lowerValueProvider
	 * @param upperValueProvider
	 * @param prefixLength
	 * @param zone
	 * @param network use {@link #defaultIpv6Network()} if there is no custom network in use
	 * @return
	 */
	public static String toNormalizedString(IPv6AddressNetwork network, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
		return toNormalizedString(network.getPrefixConfiguration(), lowerValueProvider, upperValueProvider, prefixLength, SEGMENT_COUNT, BYTES_PER_SEGMENT, BITS_PER_SEGMENT, MAX_VALUE_PER_SEGMENT, SEGMENT_SEPARATOR, DEFAULT_TEXTUAL_RADIX, zone);
	}

	/**
	 * The normalized string returned by this method is consistent with java.net.Inet6address.
	 * 
	 * IPs are not compressed nor mixed in this representation.  If this has a prefix length, that will be included in the string.
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
	
	/**
	 * This compresses the maximum number of zeros and/or host segments with the IPv6 compression notation '::'
	 */
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
			String newZone;
			if(zone != null) {
				newZone = zone.replace(IPv6Address.ZONE_SEPARATOR, IPv6Address.UNC_ZONE_SEPARATOR).replace(IPv6Address.SEGMENT_SEPARATOR, IPv6Address.UNC_SEGMENT_SEPARATOR);
			} else {
				newZone = null;
			}
			stringCache.uncString = result = getSection().toNormalizedString(IPv6StringCache.uncParams, newZone);
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
}
