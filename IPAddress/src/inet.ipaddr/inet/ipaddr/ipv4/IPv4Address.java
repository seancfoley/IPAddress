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

package inet.ipaddr.ipv4;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import inet.ipaddr.Address;
import inet.ipaddr.AddressConversionException;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressConverter;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSegmentSeries;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IncompatibleAddressException;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressPartStringCollection;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv4.IPv4AddressSection.AddressCache;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringBuilderOptions;
import inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringCollection;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6Address.IPv6AddressConverter;
import inet.ipaddr.ipv6.IPv6AddressNetwork;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSegment;


/**
 * An IPv4 address, or a subnet of multiple IPv4 addresses.  Each segment can represent a single value or a range of values.
 * <p>
 * You can construct an IPv4 address from a byte array, from an int, from a {@link inet.ipaddr.Address.SegmentValueProvider}, 
 * from Inet4Address, from an {@link IPv4AddressSection} of 4 segments, or from an array of 4 {@link IPv4AddressSegment} objects.
 * <p>
 * To construct one from a {@link java.lang.String} use 
 * {@link inet.ipaddr.IPAddressString#toAddress()} or  {@link inet.ipaddr.IPAddressString#getAddress()}, {@link inet.ipaddr.IPAddressString#toHostAddress()} or {@link inet.ipaddr.IPAddressString#getHostAddress()}
 * 
 * 
 * @custom.core
 * @author sfoley
 *
 */
public class IPv4Address extends IPAddress implements Iterable<IPv4Address> {

	private static final long serialVersionUID = 4L;
	
	public static final char SEGMENT_SEPARATOR = '.';
	public static final int BITS_PER_SEGMENT = 8;
	public static final int BYTES_PER_SEGMENT = 1;
	public static final int SEGMENT_COUNT = 4;
	public static final int BYTE_COUNT = 4;
	public static final int BIT_COUNT = 32;
	public static final int DEFAULT_TEXTUAL_RADIX = 10;
	public static final int MAX_VALUE_PER_SEGMENT = 0xff;
	public static final String REVERSE_DNS_SUFFIX = ".in-addr.arpa";
	
	transient AddressCache sectionCache;

	/**
	 * Constructs an IPv4 address or subnet.
	 * @param segments the address segments
	 * @throws AddressValueException if segments is not length 4
	 */
	public IPv4Address(IPv4AddressSegment[] segments) throws AddressValueException {
		this(segments, null);
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * @param segments the address segments
	 * @param networkPrefixLength
	 * @throws AddressValueException if segments is not length 4
	 */
	public IPv4Address(IPv4AddressSegment[] segments, Integer networkPrefixLength) throws AddressValueException {
		super(thisAddress -> ((IPv4Address) thisAddress).getAddressCreator().createSection(segments, networkPrefixLength));
		if(getSegmentCount() != SEGMENT_COUNT) {
			throw new AddressValueException("ipaddress.error.ipv4.invalid.segment.count", getSegmentCount());
		}
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * @param section the address segments
	 * @throws AddressValueException if section does not have 4 segments
	 */
	public IPv4Address(IPv4AddressSection section) throws AddressValueException {
		super(section);
		if(section.getSegmentCount() != SEGMENT_COUNT) {
			throw new AddressValueException("ipaddress.error.ipv4.invalid.segment.count", section.getSegmentCount());
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
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param address the 4 byte IPv4 address
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv4Address(int address, Integer networkPrefixLength) throws AddressValueException {
		super(thisAddress -> ((IPv4Address) thisAddress).getAddressCreator().createSectionInternal(address, networkPrefixLength));
	}
	
	/**
	 * Constructs an IPv4 address.
	 *
	 * @param inet4Address the java.net address object
	 */
	public IPv4Address(Inet4Address inet4Address) {
		this(inet4Address.getAddress());
	}
	
	/**
	 * Constructs an IPv4 address.
	 * 
	 * @param bytes the 4 byte IPv4 address in network byte order - if longer than 4 bytes the additional bytes must be zero, if shorter than 4 bytes then then the bytes are sign-extended to 4 bytes.
	 * @throws AddressValueException if bytes not equivalent to a 4 byte address
	 */
	public IPv4Address(byte[] bytes) throws AddressValueException {
		this(bytes, null);
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * <p>
	 * Similar to {@link #IPv4Address(byte[])} except that you can specify the start and end of the address in the given byte array.
	 * 
	 * @param bytes
	 * @throws AddressValueException
	 */
	public IPv4Address(byte[] bytes, int byteStartIndex, int byteEndIndex) throws AddressValueException {
		this(bytes, byteStartIndex, byteEndIndex, null);
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param bytes the 4 byte IPv4 address in network byte order - if longer than 4 bytes the additional bytes must be zero, if shorter than 4 bytes then the bytes are sign-extended to 4 bytes.
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 * @throws AddressValueException if bytes not equivalent to a 4 byte address
	 */
	public IPv4Address(byte[] bytes, Integer networkPrefixLength) throws AddressValueException {
		this(bytes, 0, bytes.length, networkPrefixLength);
	}

	/**
	 * Constructs an IPv4 address or subnet.
	 * <p>
	 * Similar to {@link #IPv4Address(byte[],Integer)} except that you can specify the start and end of the address in the given byte array.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param bytes the 4 byte IPv4 address - if longer than 4 bytes the additional bytes must be zero, if shorter than 4 bytes then the bytes are sign-extended to 4 bytes.
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 * @throws AddressValueException if bytes not equivalent to a 4 byte address
	 */
	public IPv4Address(byte[] bytes, int byteStartIndex, int byteEndIndex, Integer networkPrefixLength) throws AddressValueException {
		super(thisAddress -> ((IPv4Address) thisAddress).getAddressCreator().createSection(bytes, byteStartIndex, byteEndIndex, IPv4Address.SEGMENT_COUNT, networkPrefixLength));
	}
	
	/**
	 * Constructs an IPv4 address or subnet.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param lowerValueProvider supplies the 1 byte lower values for each segment
	 * @param upperValueProvider supplies the 1 byte upper values for each segment
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv4Address(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer networkPrefixLength) throws AddressValueException {
		super(thisAddress -> ((IPv4Address) thisAddress).getAddressCreator().createFullSectionInternal(lowerValueProvider, upperValueProvider, networkPrefixLength));
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
	
	/**
	 * Constructs an IPv4 address.
	 * <p>
	 * When networkPrefixLength is non-null, depending on the prefix configuration (see {@link inet.ipaddr.AddressNetwork#getPrefixConfiguration()},
	 * this object may represent either a single address with that network prefix length, or the prefix subnet block containing all addresses with the same network prefix.
	 * <p>
	 * 
	 * @param valueProvider supplies the 1 byte value for each segment
	 * @param networkPrefixLength the CIDR network prefix length, which can be null for no prefix
	 */
	public IPv4Address(SegmentValueProvider valueProvider, Integer networkPrefixLength) throws AddressValueException {
		this(valueProvider, valueProvider, networkPrefixLength);
	}
	
	/**
	 * Constructs an IPv4 address.
	 * 
	 * @param valueProvider supplies the 1 byte value for each segment
	 */
	public IPv4Address(SegmentValueProvider valueProvider) {
		this(valueProvider, (Integer) null);
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
	public IPv4AddressSegment getDivision(int index) {
		return getSegment(index);
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
	
	/**
	 * Create an IPv6 mixed address using the given ipv6 segments and using this address for the embedded IPv4 segments
	 * 
	 * @param segs
	 * @return
	 */
	public IPv6Address getIPv6Address(IPv6AddressSegment segs[]) {
		IPv6AddressCreator creator = getIPv6Network().getAddressCreator();
		return creator.createAddress(IPv6AddressSection.createSection(creator, segs, this)); /* address creation */
	}
	
	public IPv6Address getIPv4MappedAddress() {
		IPv6AddressCreator creator = getIPv6Network().getAddressCreator();
		IPv6AddressSegment zero = creator.createSegment(0);
		IPv6AddressSegment segs[] = creator.createSegmentArray(IPv6Address.MIXED_ORIGINAL_SEGMENT_COUNT);
		segs[0] = segs[1] = segs[2] = segs[3] = segs[4] = zero;
		segs[5] = creator.createSegment(IPv6Address.MAX_VALUE_PER_SEGMENT);
		return getIPv6Address(segs);
	}

	/**
	 * @see IPv4Address#toIPv6()
	 */
	@Override
	public boolean isIPv6Convertible() {
		IPAddressConverter conv = DEFAULT_ADDRESS_CONVERTER;
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
		IPAddressConverter conv = DEFAULT_ADDRESS_CONVERTER;
		if(conv != null) {
			return conv.toIPv6(this);
		}
		return null;
	}

	private IPv4Address getLowestOrHighest(boolean lowest, boolean excludeZeroHost) {
		return getSection().getLowestOrHighest(this, lowest, excludeZeroHost);
	}
	
	public IPv4Address toBroadcastAddress() {
		return toMaxHost();
	}
	
	public IPv4Address toNetworkAddress() {
		return toZeroHost();
	}
	
	@Override
	public IPv4Address getLowerNonZeroHost() {
		return getLowestOrHighest(true, true);
	}
	
	@Override
	public IPv4Address getLower() {
		return getLowestOrHighest(true, false);
	}
	
	@Override
	public IPv4Address getUpper() {
		return getLowestOrHighest(false, false);
	}
	
	/**
	 * Returns the address (or lowest value of the address if a subnet) as a signed integer
	 * @return the signed integer lower address value
	 */
	public int intValue() {
		return getSection().intValue();
	}
	
	/**
	 * Returns the address (or highest value of the address if a subnet) as a signed integer
	 * @return the signed integer upper address value
	 */
	public int upperIntValue() {
		return getSection().upperIntValue();
	}
	
	/**
	 * Returns the address (or lowest value of the address if a subnet) as a positive integer
	 * @return the positive integer lower address value
	 */
	public long longValue() {
		return getSection().longValue();
	}
	
	/**
	 * Returns the address (or highest value of the address if a subnet) as a positive integer
	 * @return the positive integer upper address value
	 */
	public long upperLongValue() {
		return getSection().upperLongValue();
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
	public IPv4Address replace(int startIndex, int endIndex, IPv4Address replacement, int replacementIndex) {
		return checkIdentity(getSection().replace(startIndex, endIndex, replacement.getSection(), replacementIndex, replacementIndex + (endIndex - startIndex)));
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
	public IPv4Address adjustPrefixBySegment(boolean nextSegment, boolean zeroed) {
		return checkIdentity(getSection().adjustPrefixBySegment(nextSegment, zeroed));
	}

	@Override
	public IPv4Address adjustPrefixLength(int adjustment) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment));
	}
	
	@Override
	public IPv4Address adjustPrefixLength(int adjustment, boolean zeroed) {
		return checkIdentity(getSection().adjustPrefixLength(adjustment, zeroed));
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
	public IPv4Address applyPrefixLength(int networkPrefixLength) throws PrefixLenException {
		return checkIdentity(getSection().applyPrefixLength(networkPrefixLength));
	}

	@Override @Deprecated
	public IPv4Address removePrefixLength(boolean zeroed) {
		return checkIdentity(getSection().removePrefixLength(zeroed));
	}
	
	@Override
	public IPv4Address withoutPrefixLength() {
		return removePrefixLength(false);
	}

	@Override
	public IPv4Address removePrefixLength() {
		return removePrefixLength(true);
	}

	@Override
	public Iterator<IPv4AddressSegment[]> segmentsNonZeroHostIterator() {
		return getSection().segmentsNonZeroHostIterator();
	}

	@Override
	public Iterator<IPv4AddressSegment[]> segmentsIterator() {
		return getSection().segmentsIterator();
	};
	
	@Override
	public Iterator<IPv4Address> iterator() {
		return getSection().iterator(this, getAddressCreator(), false);
	}
	
	@Override
	public Iterator<IPv4Address> nonZeroHostIterator() {
		return getSection().iterator(this, getAddressCreator(), true);
	}
	
	@Override
	public Iterator<IPv4Address> prefixBlockIterator() {
		return getSection().prefixBlockIterator(this, getAddressCreator(), true);
	}
	
	@Override
	public Iterator<IPv4Address> prefixBlockIterator(int prefixLength) {
		return getSection().prefixIterator(this, getAddressCreator(), true, prefixLength);
	}
	
	@Override
	public Iterator<IPv4Address> prefixIterator() {
		return getSection().prefixBlockIterator(this, getAddressCreator(), false);
	}
	
	@Override
	public Iterator<IPv4Address> prefixIterator(int prefixLength) {
		return getSection().prefixIterator(this, getAddressCreator(), false, prefixLength);
	}

	@Override
	public Iterator<IPv4Address> blockIterator(int segmentCount) {
		return getSection().blockIterator(this, getAddressCreator(), segmentCount);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Iterator<IPv4Address> sequentialBlockIterator() {
		return (Iterator<IPv4Address>) super.sequentialBlockIterator();
	}

	@Override
	public Iterable<IPv4Address> getIterable() {
		return this;
	}

	@Override
	public IPv4Address increment(long increment) {
		return checkIdentity(getSection().increment(increment));
	}
	
	@Override
	public IPv4Address incrementBoundary(long increment) {
		return checkIdentity(getSection().incrementBoundary(increment));
	}
	
	IPv4AddressCreator getAddressCreator() {
		return getNetwork().getAddressCreator();
	}

	@Override
	public IPv4AddressNetwork getNetwork() {
		return defaultIpv4Network();
	}
	
	public IPv6AddressNetwork getIPv6Network() {
		return defaultIpv6Network();
	}

	IPv4Address convertArg(IPAddress arg) throws AddressConversionException {
		IPv4Address converted = arg.toIPv4();
		if(converted == null) {
			throw new AddressConversionException(this, arg);
		}
		return converted;
	}

	@Override
	public IPv4Address intersect(IPAddress other) throws AddressConversionException {
		IPv4AddressSection thisSection = getSection();
		IPv4AddressSection section = thisSection.intersect(convertArg(other).getSection());
		if(section == null) {
			return null;
		}
		IPv4AddressCreator creator = getAddressCreator();
		IPv4Address result = creator.createAddress(section); /* address creation */
		return result;
	}
	
	@Override
	public IPv4Address[] subtract(IPAddress other)  throws AddressConversionException {
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
	public IPv4Address toZeroHost() {
		if(!isPrefixed()) {
			PrefixConfiguration config = getNetwork().getPrefixConfiguration();
			IPv4Address addr = getNetwork().getNetworkMask(0, !config.allPrefixedAddressesAreSubnets());
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
	public IPv4Address toZeroHost(int prefixLength) {
		if(isPrefixed() && prefixLength == getNetworkPrefixLength()) {
			return toZeroHost();
		}
		return checkIdentity(getSection().toZeroHost(prefixLength));
	}

	@Override
	public IPv4Address toMaxHost() {
		if(!isPrefixed()) {
			IPv4Address resultNoPrefix = getNetwork().getHostMask(0);
			if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
				return resultNoPrefix;
			}
			return resultNoPrefix.setPrefixLength(0);
		}
		if(includesMaxHost() && isSingleNetwork()) {
			return getUpper();//cached
		}
		return checkIdentity(getSection().createMaxHost());
	}
	
	@Override
	public IPv4Address toMaxHost(int prefixLength) {
		if(isPrefixed() && prefixLength == getNetworkPrefixLength()) {
			return toMaxHost();
		}
		return checkIdentity(getSection().toMaxHost(prefixLength));
	}

	@Override
	public IPv4Address mask(IPAddress mask, boolean retainPrefix) throws IncompatibleAddressException, AddressConversionException {
		return checkIdentity(getSection().mask(convertArg(mask).getSection(), retainPrefix));
	}
	
	@Override
	public IPv4Address mask(IPAddress mask) throws IncompatibleAddressException, AddressConversionException {
		return mask(mask, false);
	}
	
	@Override
	public IPv4Address maskNetwork(IPAddress mask, int networkPrefixLength) throws IncompatibleAddressException, PrefixLenException, AddressConversionException {
		return checkIdentity(getSection().maskNetwork(convertArg(mask).getSection(), networkPrefixLength));
	}

	@Override
	public IPv4Address bitwiseOr(IPAddress mask, boolean retainPrefix) throws IncompatibleAddressException, AddressConversionException {
		return checkIdentity(getSection().bitwiseOr(convertArg(mask).getSection(), retainPrefix));
	}
	
	@Override
	public IPv4Address bitwiseOr(IPAddress mask) throws IncompatibleAddressException, AddressConversionException {
		return bitwiseOr(mask, false);
	}
	
	@Override
	public IPv4Address bitwiseOrNetwork(IPAddress mask, int networkPrefixLength) throws IncompatibleAddressException, PrefixLenException, AddressConversionException {
		return checkIdentity(getSection().bitwiseOrNetwork(convertArg(mask).getSection(), networkPrefixLength));
	}
	
	@Override
	public IPv4AddressSection getNetworkSection() {
		return getSection().getNetworkSection();
	}

	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength) throws PrefixLenException {
		return getSection().getNetworkSection(networkPrefixLength);
	}

	@Override
	public IPv4AddressSection getNetworkSection(int networkPrefixLength, boolean withPrefixLength) throws PrefixLenException {
		return getSection().getNetworkSection(networkPrefixLength, withPrefixLength);
	}

	@Override
	public IPv4AddressSection getHostSection() {
		return getSection().getHostSection();
	}

	@Override
	public IPv4AddressSection getHostSection(int networkPrefixLength) throws PrefixLenException {
		return getSection().getHostSection(networkPrefixLength);
	}

	@Override
	public IPv4Address toPrefixBlock() {
		Integer prefixLength = getNetworkPrefixLength();
		if(prefixLength == null || getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			return this;
		}
		return toPrefixBlock(prefixLength);
	}

	@Override
	public IPv4Address toPrefixBlock(int networkPrefixLength) throws PrefixLenException {
		return checkIdentity(getSection().toPrefixBlock(networkPrefixLength));
	}

	@Override
	public IPv4Address assignPrefixForSingleBlock() {
		return (IPv4Address) super.assignPrefixForSingleBlock();
	}
	
	@Override
	public IPv4Address assignMinPrefixForBlock() {
		return (IPv4Address) super.assignMinPrefixForBlock();
	}

	/**
	 * Produces an array of prefix blocks that cover the same set of addresses as this.
	 * <p>
	 * Unlike {@link #spanWithPrefixBlocks(IPAddress)} this method only includes addresses that are a part of this subnet.
	 */
	@Override
	public IPv4Address[] spanWithPrefixBlocks() {
		if(isSequential()) {
			return spanWithPrefixBlocks(this);
		}
		@SuppressWarnings("unchecked")
		ArrayList<IPv4Address> list = (ArrayList<IPv4Address>) spanWithBlocks(true);
		return list.toArray(new IPv4Address[list.size()]);
	}
	
	@Override
	public IPv4Address[] spanWithPrefixBlocks(IPAddress other) throws AddressConversionException {
		return IPAddress.getSpanningPrefixBlocks(
				this,
				convertArg(other),
				IPv4Address::getLower,
				IPv4Address::getUpper,
				Address.ADDRESS_LOW_VALUE_COMPARATOR::compare,
				IPv4Address::assignPrefixForSingleBlock,
				IPv4Address::withoutPrefixLength,
				getAddressCreator()::createAddressArray);
	}
	
	/**
	 * Produces an array of blocks that are sequential that cover the same set of addresses as this.
	 * <p>
	 * This array can be shorter than that produced by {@link #spanWithPrefixBlocks()} and is never longer.
	 * <p>
	 * Unlike {@link #spanWithSequentialBlocks(IPAddress)} this method only includes addresses that are a part of this subnet.
	 */
	@Override
	public IPv4Address[] spanWithSequentialBlocks() throws AddressConversionException {
		if(isSequential()) {
			return new IPv4Address[] { withoutPrefixLength() };
		}
		@SuppressWarnings("unchecked")
		ArrayList<IPv4Address> list = (ArrayList<IPv4Address>) spanWithBlocks(false);
		return list.toArray(new IPv4Address[list.size()]);
	}
	
	@Override
	public IPv4Address[] spanWithSequentialBlocks(IPAddress other) throws AddressConversionException {
		return IPAddress.getSpanningSequentialBlocks(
				this,
				convertArg(other),
				IPv4Address::getLower,
				IPv4Address::getUpper,
				Address.ADDRESS_LOW_VALUE_COMPARATOR::compare,
				IPv4Address::withoutPrefixLength,
				getAddressCreator());
	}
	
	@Override
	public IPv4AddressSeqRange spanWithRange(IPAddress other) throws AddressConversionException {
		return new IPv4AddressSeqRange(this, convertArg(other));
	}

	@Override
	public IPv4Address[] mergeToPrefixBlocks(IPAddress ...addresses) throws AddressConversionException {
		for(int i = 0; i < addresses.length; i++) {
			addresses[i] = convertArg(addresses[i]);
		}
		List<IPAddressSegmentSeries> blocks = getMergedPrefixBlocks(this, addresses);
		return blocks.toArray(new IPv4Address[blocks.size()]);
	}
	
	@Override
	public IPv4Address[] mergeToSequentialBlocks(IPAddress ...addresses) throws AddressConversionException {
		for(int i = 0; i < addresses.length; i++) {
			addresses[i] = convertArg(addresses[i]);
		}
		List<IPAddressSegmentSeries> blocks = getMergedSequentialBlocks(this, addresses, getAddressCreator());
		return blocks.toArray(new IPv4Address[blocks.size()]);
	}

	@Override
	public Inet4Address toUpperInetAddress() {
		return (Inet4Address) super.toInetAddress();
	}
	
	@Override
	public Inet4Address toInetAddress() {
		return (Inet4Address) super.toInetAddress();
	}
	
	@Override
	public IPv4AddressSeqRange toSequentialRange(IPAddress other) {
		return new IPv4AddressSeqRange(this, convertArg(other));
	}
	
	@Override
	public IPv4AddressSeqRange toSequentialRange() {
		return new IPv4AddressSeqRange(getLower(), getUpper());
	}

	@Override
	public boolean isLocal() {
		if(isMulticast()) {
			//1110...
			IPv4AddressSegment seg0 = getSegment(0);
			//http://www.tcpipguide.com/free/t_IPMulticastAddressing.htm
			//rfc4607 and https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
			
			//239.0.0.0-239.255.255.255 organization local
			if(seg0.matches(239)) {
				return true;
			}
			IPv4AddressSegment seg1 = getSegment(1), seg2 = getSegment(2);
			
			return 
					// 224.0.0.0 to 224.0.0.255 local 
					// includes link local multicast name resolution https://tools.ietf.org/html/rfc4795 224.0.0.252
					(seg0.matches(224) && seg1.isZero() && seg2.isZero())
					
					//232.0.0.1 - 232.0.0.255	Reserved for IANA allocation	[RFC4607]			
					//232.0.1.0 - 232.255.255.255	Reserved for local host allocation	[RFC4607]
									
					|| (seg0.matches(232) && !(seg1.isZero() && seg2.isZero()));
		}
		return isLinkLocal() || isPrivate() || isAnyLocal();
	}
	
	/**
	 * @see java.net.InetAddress#isLinkLocalAddress()
	 */
	@Override
	public boolean isLinkLocal() {
		if(isMulticast()) {
			//224.0.0.252	Link-local Multicast Name Resolution	[RFC4795]
			return getSegment(0).matches(224) && getSegment(1).isZero() && getSegment(2).isZero() &&  getSegment(3).matches(252);
		}
		return getSegment(0).matches(169) && getSegment(1).matches(254);
	}

	/**
	 * Unicast addresses allocated for private use
	 * 
	 * @see java.net.InetAddress#isSiteLocalAddress()
	 */
	public boolean isPrivate() {
		// refer to RFC 1918
        // 10/8 prefix
        // 172.16/12 prefix
        // 192.168/16 prefix
		IPv4AddressSegment seg0 = getSegment(0);
		IPv4AddressSegment seg1 = getSegment(1);
		return seg0.matches(10)
			|| seg0.matches(172) && seg1.matchesWithPrefixMask(16, 4)
			|| seg0.matches(192) && seg1.matches(168);
	}
	
	@Override
	public boolean isMulticast() {
		// 1110...
		//224.0.0.0/4
		return getSegment(0).matchesWithPrefixMask(0xe0, 4);
	}
	
	/**
	 * @see java.net.InetAddress#isLoopbackAddress()
	 */
	@Override
	public boolean isLoopback() {
		return getSegment(0).matches(127);
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
	
	////////////////string creation below ///////////////////////////////////////////////////////////////////////////////////////////

	@Override
	protected IPAddressStringParameters createFromStringParams() {
		return new IPAddressStringParameters.Builder().
				getIPv4AddressParametersBuilder().setNetwork(getNetwork()).getParentBuilder().
				getIPv6AddressParametersBuilder().setNetwork(getIPv6Network()).getParentBuilder().toParams();
	}
	
	/**
	 * Creates the normalized string for an address without having to create the address objects first.
	 * 
	 * @param lowerValueProvider
	 * @param upperValueProvider
	 * @param prefixLength
	 * @param network use {@link #defaultIpv4Network()} if there is no custom network in use
	 * @return
	 */
	public static String toNormalizedString(IPv4AddressNetwork network, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength) {
		return toNormalizedString(network.getPrefixConfiguration(), lowerValueProvider, upperValueProvider, prefixLength, SEGMENT_COUNT, BYTES_PER_SEGMENT, BITS_PER_SEGMENT, MAX_VALUE_PER_SEGMENT, SEGMENT_SEPARATOR, DEFAULT_TEXTUAL_RADIX, null);
	}

	/**
	 * @author sfoley
	 *
	 */
	public static enum inet_aton_radix {
		OCTAL, HEX, DECIMAL;
		
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
}
