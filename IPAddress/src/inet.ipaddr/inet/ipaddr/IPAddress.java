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

package inet.ipaddr;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.IPAddressConverter.DefaultAddressConverter;
import inet.ipaddr.IPAddressNetwork.IPAddressCreator;
import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.IPAddressSection.SeriesCreator;
import inet.ipaddr.IPAddressSection.TriFunction;
import inet.ipaddr.format.IPAddressRange;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.AddressComponentSpliterator;
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
 * String creation:<br>
 * There are various methods used to construct standard address string such as {@link #toCanonicalString()} or {@link #toNormalizedString()}
 * <p>
 * There are also several public classes used to create customized IP address strings.
 * For single strings from an address or address section, you use {@link IPStringOptions} or {@link inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringOptions} along with {@link #toNormalizedString(IPAddressSection.IPStringOptions)}.
 * Or you use one of the methods like {@link #toCanonicalString()} which does the same.
 * <p>
 * For string collections from an address or address section, use {@link inet.ipaddr.ipv4.IPv4AddressSection.IPv4StringBuilderOptions}, {@link inet.ipaddr.ipv6.IPv6AddressSection.IPv6StringBuilderOptions}, {@link IPStringBuilderOptions} along with {@link #toStringCollection(IPAddressSection.IPStringBuilderOptions)} or {@link #toStrings(IPAddressSection.IPStringBuilderOptions)}.
 * Or you use one of the methods {@link #toStandardStringCollection()}, {@link #toAllStringCollection()}, {@link #toStandardStrings()}, {@link #toAllStrings()} which does the same.
 * <p>
 * To construct one from a {@link java.lang.String} use 
 * {@link inet.ipaddr.IPAddressString#toAddress()} or  {@link inet.ipaddr.IPAddressString#getAddress()}, {@link inet.ipaddr.IPAddressString#toHostAddress()} or {@link inet.ipaddr.IPAddressString#getHostAddress()}
 * 
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
public abstract class IPAddress extends Address implements IPAddressSegmentSeries, IPAddressRange {

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
		
		@Override
		public String toString() {
			return isIPv4() ? "IPv4" : "IPv6";
		}
	}

	/**
	 * @custom.core
	 * @author sfoley
	 *
	 */
	public static interface IPAddressValueProvider extends AddressValueProvider {

		IPVersion getIPVersion();
		
		default Integer getPrefixLength() {
			return null;
		}
		
		default String getZone() {
			return null;
		}
	}

	public static final char PREFIX_LEN_SEPARATOR = '/';
	public static final String BINARY_STR_PREFIX = "0b";
	
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
			fromString = new IPAddressString(toCanonicalString(), this, params); /* address string creation */
		}
		return getAddressfromString();
	}
	
	protected abstract IPAddressStringParameters createFromStringParams();
	
	protected IPAddressString getAddressfromString() {
		return (IPAddressString) fromString;
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
			fromString = new IPAddressString(fromHost.toString(), this, fromHost.validationOptions.addressOptions);
		} else if(string instanceof IPAddressString) {
			fromString = (IPAddressString) string;
		}
	}

	protected IPAddressProvider getProvider() {
		if(isPrefixed()) {
			if(getNetwork().getPrefixConfiguration().prefixedSubnetsAreExplicit() || !isPrefixBlock()) {
				return IPAddressProvider.getProviderFor(this, withoutPrefixLength()); 
			}
			return IPAddressProvider.getProviderFor(this, toZeroHost(true).withoutPrefixLength());
		}
		return IPAddressProvider.getProviderFor(this, this);
	}
	
	/**
	 * Does a reverse name lookup to get the canonical host name.
	 * Note that the canonical host name may differ on different systems, as it aligns with {@link InetAddress#getCanonicalHostName()}
	 * In particular, on some systems the loopback address has canonical host localhost and on others the canonical host is the same loopback address.
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
				host.resolvedAddresses = new IPAddress[] {this};
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
	
	static int getMaxSegmentValue(IPVersion version) {
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
	
	static int getBytesPerSegment(IPVersion version) {
		return IPAddressSegment.getByteCount(version);
	}
	
	@Override
	public int getBitsPerSegment() {
		return IPAddressSegment.getBitCount(getIPVersion());
	}
	
	static int getBitsPerSegment(IPVersion version) {
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

	protected abstract IPAddress convertArg(IPAddress arg) throws AddressConversionException;
	
	/**
	 * Finds the lowest and highest single-valued address from the given addresses and subnets and this one,
	 * calling the given BiFunction with the lowest as first argument and the highest as second.
	 * It returns the result returned from the call to the BiFunction.
	 * <p>
	 * For instance, given the IPv4 addresses 1.2.0.0/16 and 1.3.4.5, the lowest is 1.2.0.0 and the highest is 1.3.4.5.
	 * Given the addresses 1.2.0.0/16 and 1.1.4.5, the lowest is 1.1.4.5 and the highest is 1.2.255.255.
	 * <p>
	 * If one of the given addresses or subnets is a different version than this, 
	 * then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * This can be useful for methods that require a range as input, 
	 * like {@link IPAddress#spanWithPrefixBlocks(IPAddress)}, {@link IPAddress#spanWithSequentialBlocks(IPAddress)}, 
	 * {@link IPAddress#coverWithPrefixBlock(IPAddress)}, or {@link IPAddress#toSequentialRange(IPAddress)}.<p>
	 * For instance, to cover multiple addresses with a prefix block:<br><code>
	 * IPAddress coveringAddress = address0.applyToBounds(IPAddress::coverWithPrefixBlock, address1, address2, address3, ...);
	 * </code>
	 */
	public <V> V applyToBounds(BiFunction<? super IPAddress, ? super IPAddress, V> func, IPAddress ...series) {
		AddressComparator lowComparator = Address.ADDRESS_LOW_VALUE_COMPARATOR;
		AddressComparator highComparator = Address.ADDRESS_HIGH_VALUE_COMPARATOR;
		IPAddress lowest = this;
		IPAddress highest = this;
		for(int i = 0; i < series.length; i++) {
			IPAddress next = series[i];
			if(next == null) {
				continue;
			}
			next = convertArg(next);
			if(lowComparator.compare(next, lowest) < 0) {
				lowest = next;
			}
			if(highComparator.compare(next, highest) > 0) {
				highest = next;
			}
		}
		return func.apply(lowest.getLower(), highest.getUpper());
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
	public abstract AddressComponentSpliterator<? extends IPAddress> spliterator();

	@Override
	public abstract Stream<? extends IPAddress> stream();

	@Override
	public abstract Iterator<? extends IPAddress> nonZeroHostIterator();

	@Override
	public abstract Iterator<? extends IPAddress> prefixIterator();

	@Override
	public abstract AddressComponentSpliterator<? extends IPAddress> prefixSpliterator();

	@Override
	public abstract Stream<? extends IPAddress> prefixStream();
		
	@Override
	public abstract Iterator<? extends IPAddress> prefixBlockIterator();

	@Override
	public abstract AddressComponentSpliterator<? extends IPAddress> prefixBlockSpliterator();

	@Override
	public abstract Stream<? extends IPAddress> prefixBlockStream();
		
	@Override
	public abstract Iterator<? extends IPAddress> blockIterator(int segmentCount);

	@Override
	public abstract AddressComponentSpliterator<? extends IPAddress> blockSpliterator(int segmentCount);

	@Override
	public abstract Stream<? extends IPAddress> blockStream(int segmentCount);
	
	@Override
	public Iterator<? extends IPAddress> sequentialBlockIterator() {
		return blockIterator(getSequentialBlockIndex());
	}

	@Override
	public AddressComponentSpliterator<? extends IPAddress> sequentialBlockSpliterator() {
		return blockSpliterator(getSequentialBlockIndex());
	}

	@Override
	public Stream<? extends IPAddress> sequentialBlockStream() {
		return blockStream(getSequentialBlockIndex());
	}
		
	@Override
	public BigInteger getSequentialBlockCount() {
		return getSection().getSequentialBlockCount();
	}
	
	/**
	 * @return an object to iterate over the individual addresses represented by this object.
	 */
	@Override
	public abstract Iterable<? extends IPAddress> getIterable();

	@Override
	public abstract IPAddress increment(long increment) throws AddressValueException;

	@Override
	public abstract IPAddress incrementBoundary(long increment) throws AddressValueException;
	
	public abstract boolean isIPv4();
	
	public abstract boolean isIPv6();
	
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
	 * 
	 * @see #isIPv6Convertible()
	 * @return the address
	 */
	public IPv6Address toIPv6() {
		return null;
	}

	/**
	 * Determines whether this address can be converted to IPv4, if not IPv4 already.  
	 * Override this method to convert in your own way.  If IPv6, the default behaviour
	 * is to convert by IPv4 mapping, see {@link IPv6Address#isIPv4Mapped()}
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
	 * Override this method to convert in your own way.  The default behaviour
	 * is to convert by IPv4 mapping, see {@link IPv4Address#getIPv4MappedAddress()}
	 * 
	 * You should also override {@link #toIPv6()} to match the conversion.
	 * 
	 * This method returns true for all IPv6 addresses.
	 * 
	 * @return
	 */
	public abstract boolean isIPv6Convertible();
	
	/**
	 * Returns whether the address is link local, whether unicast or multicast.
	 * 
	 * @see java.net.InetAddress#isLinkLocalAddress()
	 */
	public abstract boolean isLinkLocal();

	/**
	 * Returns true if the address is link local, site local, organization local, administered locally, or unspecified.
	 * This includes both unicast and multicast.
	 */
	@Override
	public abstract boolean isLocal();
	
	/**
	 * The unspecified address is the address that is all zeros.
	 * 
	 * @return
	 */
	public boolean isUnspecified() {
		return isZero();
	}
	
	/**
	 * Returns whether this address is the address which binds to any address on the local host.
	 * This is the address that has the value of 0, aka the unspecified address.
	 * 
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
	 * Converts the highest value of this address to an InetAddress.
	 * If this consists of just a single address and not a subnet, this is equivalent to {@link #toInetAddress()}
	 */
	public InetAddress toUpperInetAddress() {
		return getUpper().toInetAddress();
	}
	
	/**
	 * Converts the lowest value of this address to an InetAddress
	 */
	public InetAddress toInetAddress() {
		return getSection().toInetAddress(this);
	}

	protected InetAddress toInetAddressImpl() {
		try {
			return InetAddress.getByAddress(getSection().getBytesInternal());
		} catch(UnknownHostException e) { /* will never reach here */ return null; }
	}
	
	/**
	 * Creates a sequential range instance from the lowest and highest addresses in this subnet
	 * <p>
	 * The two will represent the same set of individual addresses if and only if {@link #isSequential()} is true.
	 * To get a series of ranges that represent the same set of individual addresses use the {@link #sequentialBlockIterator()} (or {@link #prefixIterator()}),
	 * and apply this method to each iterated subnet.
	 * <p>
	 * If this represents just a single address then the returned instance covers just that single address as well.
	 * 
	 * @return
	 */
	@Override
	public abstract IPAddressSeqRange toSequentialRange();

	/**
	 * Creates a sequential range instance from this and the given address, 
	 * spanning from the lowest to the highest addresses in the two subnets
	 * <p>
	 * If the other address is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * When you have multiple subnets, create a range from lowest to highest with:<br>
	 * <code>
	 * IPAddressSeqRange range = subnet0.applyToBounds(IPAddress::toSequentialRange, subnet1, subnet2, ...);
	 * </code>
	 * <p>
	 * See {@link #applyToBounds(java.util.function.BiFunction, IPAddress...)}
	 * 
	 * @deprecated use {@link #spanWithRange(IPAddress)}
	 * @param other
	 * @return
	 */
	@Deprecated
	public abstract IPAddressSeqRange toSequentialRange(IPAddress other) throws AddressConversionException;
	
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
					(fromString.fullAddr.equals(otherString.fullAddr) &&
					// We do not call equals() on the validation options, this is intended as an optimization,
					// and probably better to avoid going through all the validation options here
					fromString.validationOptions == otherString.validationOptions));
		}
		return false;
	}
	
	/**
	 * Returns whether this contains all values of the given address or subnet
	 * 
	 * @param other
	 * @return
	 */
	@Override
	public boolean contains(IPAddress other) {
		return super.contains(other);
	}

	/**
	 * Returns whether this address contains the non-zero host addresses in the other address or subnet
	 * 
	 * @param other
	 * @return
	 */
	public boolean containsNonZeroHosts(IPAddress other) {
		if(other == this) {
			return true;
		}
		return getSection().containsNonZeroHosts(other.getSection());
	}
	
	/**
	 * Returns whether the prefix of this address contains all values of the same bits in the given address or subnet
	 * 
	 * @param other
	 * @return
	 */
	public boolean prefixContains(IPAddress other) {
		if(other == this) {
			return true;
		}
		return getSection().prefixContains(other.getSection());
	}
	
	/**
	 * Returns whether this address has a prefix length and if so, whether the host section is zero for this address or all addresses in this subnet.
	 * If the host section is zero length (there are no host bits at all), returns false.
	 * 
	 * @return
	 */
	public boolean isZeroHost() {
		return getSection().isZeroHost();
	}
	
	/**
	 * Returns whether the host is zero for the given prefix length for this address or all addresses in this subnet.
	 * If this address already has a prefix length, then that prefix length is ignored.
	 * If the host section is zero length (there are no host bits at all), returns false.
	 * 
	 * @return
	 */
	public boolean isZeroHost(int networkPrefixLength) {
		return getSection().isZeroHost(networkPrefixLength);
	}

	@Override
	public boolean contains(IPAddressSeqRange otherRange) {
		if(compareLowValues(otherRange.getLower(), getLower()) >= 0 && 
				compareLowValues(otherRange.getUpper(), getUpper()) <= 0) {
			if(isSequential()) {
				return true;
			}
			Iterator<? extends IPAddress> iterator = sequentialBlockIterator();
			while(iterator.hasNext()) {
				IPAddress sequential = iterator.next();
				if(sequential.contains(otherRange)) {
					return true;
				}
			}
		}
		return false;
	}

	static int compareLowValues(IPAddress one, IPAddress two) {
		return Address.ADDRESS_LOW_VALUE_COMPARATOR.compare(one, two);
	}

	/**
	 * Applies the mask to this address and then compares values with the given address
	 * 
	 * @param mask
	 * @param other
	 * @return
	 */
	public boolean matchesWithMask(IPAddress other, IPAddress mask) {
		return getSection().matchesWithMask(other.getSection(), mask.getSection());
	}

	//////////////// string creation below ///////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Allows for the creation of a normalized string without creating a full IP address object first.
	 * Instead you can implement the {@link IPAddressValueProvider} interface in whatever way is most efficient.
	 * The string is appended to the provided {@link StringBuilder} instance.
	 * 
	 * @param provider
	 * @param builder
	 */
	public static void toNormalizedString(IPAddressValueProvider provider, StringBuilder builder) {
		IPVersion version = provider.getIPVersion();
		if(version.isIPv4()) {
			toNormalizedString(defaultIpv4Network().getPrefixConfiguration(), provider.getValues(), provider.getUpperValues(), provider.getPrefixLength(), IPv4Address.SEGMENT_COUNT,  IPv4Address.BYTES_PER_SEGMENT,  IPv4Address.BITS_PER_SEGMENT,  IPv4Address.MAX_VALUE_PER_SEGMENT,  IPv4Address.SEGMENT_SEPARATOR,  IPv4Address.DEFAULT_TEXTUAL_RADIX, null, builder);
		} else if(version.isIPv6()) {
			toNormalizedString(defaultIpv6Network().getPrefixConfiguration(), provider.getValues(), provider.getUpperValues(), provider.getPrefixLength(), IPv6Address.SEGMENT_COUNT, IPv6Address.BYTES_PER_SEGMENT, IPv6Address.BITS_PER_SEGMENT, IPv6Address.MAX_VALUE_PER_SEGMENT, IPv6Address.SEGMENT_SEPARATOR, IPv6Address.DEFAULT_TEXTUAL_RADIX, provider.getZone(), builder);
		} else {
			throw new IllegalArgumentException();
		}
	}

	/**
	 * Allows for the creation of a normalized string without creating a full IP address object first.
	 * Instead you can implement the {@link IPAddressValueProvider} interface in whatever way is most efficient.
	 * 
	 * @param provider
	 */
	public static String toNormalizedString(IPAddressValueProvider provider) {
		IPVersion version = provider.getIPVersion();
		if(version.isIPv4()) {
			return IPv4Address.toNormalizedString(defaultIpv4Network(), provider.getValues(), provider.getUpperValues(), provider.getPrefixLength());
		} else if(version.isIPv6()) {
			return IPv6Address.toNormalizedString(defaultIpv6Network(), provider.getValues(), provider.getUpperValues(), provider.getPrefixLength(), provider.getZone());
		}
		throw new IllegalArgumentException();
	}

	/**
	 * Creates the normalized string for an address without having to create the address objects first.
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

	protected static int toNormalizedString(
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
		boolean adjustByPrefixLength;
		if(prefixLength != null && prefixConfiguration.allPrefixedAddressesAreSubnets()) {
			if(prefixLength <= 0) {
				adjustByPrefixLength = true;
			} else {
				int totalBitCount = (bitsPerSegment == 8) ? segmentCount << 3 : ((bitsPerSegment == 16) ? segmentCount << 4 : segmentCount * bitsPerSegment);
				adjustByPrefixLength = prefixLength < totalBitCount;
			}
		} else {
			adjustByPrefixLength = false;
		}
		while(true) {
			Integer segmentPrefixLength = IPAddressSection.getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
			if(adjustByPrefixLength && segmentPrefixLength != null && segmentPrefixLength == 0) {
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
					if(adjustByPrefixLength && segmentPrefixLength != null) {
						value &= ~0 << (bitsPerSegment - segmentPrefixLength);
					}
					if(builder == null) {
						count += IPAddressSegment.toUnsignedStringLength(value, radix);
					} else {
						IPAddressSegment.toUnsignedString(value, radix, builder);
					}
				} else {
					if(adjustByPrefixLength && segmentPrefixLength != null) {
						int mask = ~0 << (bitsPerSegment - segmentPrefixLength);
						value &= mask;
						value2 &= mask;//255, mask is -2147483648, segmentPrefixLength is 7, bitsPer
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
			} // else counting the separators happens just once outside the loop, just below
		}
		if(builder == null) {
			count += segmentCount; // separators
			--count; // no ending separator
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
	public String toBinaryString() throws IncompatibleAddressException {
		return getSection().toBinaryString();
	}
	
	/**
	 * Writes this address as a single octal value with always the exact same number of characters, with or without a preceding 0 prefix.
	 * <p>
	 * If this section represents a range of values not corresponding to a prefix, then this is printed as a range of two hex values.
	 */
	@Override
	public String toOctalString(boolean with0Prefix) throws IncompatibleAddressException {
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

	@Override
	public IPAddress getHostMask() {
		Integer prefLength = getNetworkPrefixLength();
		return getNetwork().getHostMask(prefLength == null ? 0 : prefLength);
	}

	@Override
	public IPAddress getNetworkMask() {
		Integer prefLength = getNetworkPrefixLength();
		return getNetwork().getNetworkMask(prefLength == null ? getBitCount() : prefLength);
	}
	
	@Override
	public boolean includesZeroHost() {
		return getSection().includesZeroHost();
	}
	
	@Override
	public boolean includesZeroHost(int networkPrefixLength) {
		return getSection().includesZeroHost(networkPrefixLength);
	}

	@Override
	public abstract IPAddress toZeroHost(int prefixLength);

	@Override
	public abstract IPAddress toZeroHost();
	
	protected abstract IPAddress toZeroHost(boolean boundariesOnly);
	
	@Override
	public abstract IPAddress toZeroNetwork();
	
	@Override
	public abstract IPAddress toMaxHost(int prefixLength);
	
	@Override
	public abstract IPAddress toMaxHost();
	
	@Override
	public boolean includesMaxHost() {
		return getSection().includesMaxHost();
	}
	
	@Override
	public boolean includesMaxHost(int networkPrefixLength) {
		return getSection().includesMaxHost(networkPrefixLength);
	}
	
	/** 
	 * Returns true if the network section of the address spans just a single value 
	 * <p>
	 * For example, return true for 1.2.3.4/16 and false for 1.2-3.3.4/16
	 */
	public boolean isSingleNetwork() {
		return getSection().isSingleNetwork();
	}

	/**
	 * Returns the smallest set of prefix blocks that spans both this and the supplied address or subnet.
	 * @param other
	 * @return
	 */
	protected static <T extends IPAddress> T[] getSpanningPrefixBlocks(
			T first,
			T other,
			UnaryOperator<T> getLower,
			UnaryOperator<T> getUpper,
			Comparator<T> comparator,
			UnaryOperator<T> prefixAdder,
			UnaryOperator<T> prefixRemover,
			IntFunction<T[]> arrayProducer) {
		T[] result = checkPrefixBlockContainment(first, other, prefixAdder, arrayProducer);
		if(result != null) {
			return result;
		}
		List<IPAddressSegmentSeries> blocks = 
				IPAddressSection.applyOperatorToLowerUpper(first, other, getLower, getUpper, comparator, prefixRemover, (orig, one, two) -> IPAddressSection.splitIntoPrefixBlocks(one, two));
		return blocks.toArray(arrayProducer.apply(blocks.size()));
	}
	
	private static <T extends IPAddress> T[] checkPrefixBlockContainment(
			T first,
			T other,
			UnaryOperator<T> prefixAdder,
			IntFunction<T[]> arrayProducer) {
		if(first.contains(other)) {
			return checkPrefixBlockFormat(first, other, true, prefixAdder, arrayProducer);
		} else if(other.contains(first)) {
			return checkPrefixBlockFormat(other, first, false, prefixAdder, arrayProducer);
		}
		return null;
	}
	
	static <T extends IPAddressSegmentSeries> T[] checkPrefixBlockFormat(
			T container,
			T contained,
			boolean checkEqual,
			UnaryOperator<T> prefixAdder,
			IntFunction<T[]> arrayProducer) {
		T result = null;
		if(container.isPrefixed()) {
			if(container.isSinglePrefixBlock()) {
				result = container;
			}
		} else if(checkEqual && contained.isPrefixed() && container.equals(contained) && contained.isSinglePrefixBlock()) {
			result = contained;
		} else {
			result = prefixAdder.apply(container); // returns null if cannot be a prefix block
		}
		if(result != null) {
			T resultArray[] = arrayProducer.apply(1);
			resultArray[0] = result;
			return resultArray;
		}
		return null;
	}
	
	protected static <T extends IPAddress, S extends IPAddressSegment> T[] getSpanningSequentialBlocks(
			T first,
			T other,
			UnaryOperator<T> getLower,
			UnaryOperator<T> getUpper,
			Comparator<T> comparator,
			UnaryOperator<T> prefixRemover,
			IPAddressCreator<T, ?, ?, S, ?> creator) {
		T[] result = checkSequentialBlockContainment(first, other, prefixRemover, creator::createAddressArray);
		if(result != null) {
			return result;
		}
		SeriesCreator seriesCreator = creator::createSequentialBlockAddress;
		TriFunction<T, List<IPAddressSegmentSeries>> operatorFunctor = (orig, one, two) -> IPAddressSection.splitIntoSequentialBlocks(one, two, seriesCreator);
		List<IPAddressSegmentSeries> blocks = IPAddressSection.applyOperatorToLowerUpper(first, other, getLower, getUpper, comparator, prefixRemover, operatorFunctor);
		return blocks.toArray(creator.createAddressArray(blocks.size()));
	}
	
	private static <T extends IPAddress> T[] checkSequentialBlockContainment(
			T first,
			T other,
			UnaryOperator<T> prefixRemover,
			IntFunction<T[]> arrayProducer) {
		if(first.contains(other)) {
			return checkSequentialBlockFormat(first, other, true, prefixRemover, arrayProducer);
		} else if(other.contains(first)) {
			return checkSequentialBlockFormat(other, first, false, prefixRemover, arrayProducer);
		}
		return null;
	}
	
	static <T extends IPAddressSegmentSeries> T[] checkSequentialBlockFormat(
			T container,
			T contained,
			boolean checkEqual,
			UnaryOperator<T> prefixRemover,
			IntFunction<T[]> arrayProducer) {
		T result = null;
		if(!container.isPrefixed()) {
			if(container.isSequential()) {
				result = container;
			}
		} else if(checkEqual && !contained.isPrefixed() && container.equals(contained)) {
			if(contained.isSequential()) {
				result = contained;
			}
		} else if(container.isSequential()) {
			result = prefixRemover.apply(container);
		}
		if(result != null) {
			T resultArray[] = arrayProducer.apply(1);
			resultArray[0] = result;
			return resultArray;
		}
		return null;
	}

	/**
	 * Returns the subnet associated with the prefix length of this address.  If this address has no prefix length, this address is returned.
	 * <p>
	 * For example, if the address is 1.2.3.4/16 it returns the subnet 1.2.*.* /16
	 */
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
	 * A CIDR network mask is all 1 bits in the network section and then all 0 bits in the host section.
	 * A CIDR host mask is all 0 bits in the network section and then all 1 bits in the host section.
	 * The prefix is the length of the network section.
	 * <p>
	 * Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length used to construct this object.
	 * The prefix length used to construct indicates the network and host section of this address.  
	 * The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host
	 * section of any other address.  Therefore the two values can be different values, or one can be null while the other is not.
	 * <p>
	 * Just like the mask methods which use the lower value for masking,
	 * this method applies only to the lower value of the range if this address represents multiple values.
	 *
	 * @param network whether to check if we are a network mask or a host mask
	 * @return the prefix length corresponding to this mask, or null if there is no such prefix length
	 */
	public Integer getBlockMaskPrefixLength(boolean network) {
		return getSection().getBlockMaskPrefixLength(network);
	}

	/**
	 * Returns the number of consecutive trailing one or zero bits.
	 * If network is true, returns the number of consecutive trailing zero bits.
	 * Otherwise, returns the number of consecutive trailing one bits.
	 * <p>
	 * This method applies only to the lower value of the range if this address represents multiple values.
	 * 
	 * @param network
	 * @return
	 */
	public int getTrailingBitCount(boolean network) {
		return getSection().getTrailingBitCount(network);
	}
	
	/**
	 * Returns the number of consecutive leading one or zero bits.
	 * If network is true, returns the number of consecutive leading one bits.
	 * Otherwise, returns the number of consecutive leading zero bits.
	 * <p>
	 * This method applies only to the lower value of the range if this address represents multiple values.
	 * 
	 * @param network
	 * @return
	 */
	public int getLeadingBitCount(boolean network) {
		return getSection().getLeadingBitCount(network);
	}
	
	/**
	 * Returns the minimal-size prefix block that covers all the addresses spanning from this subnet to the given subnet.
	 * <p>
	 * If the other address is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * When you have multiple subnets, cover with:<br>
	 * <code>
	 * IPAddress block = subnet0.applyToBounds(IPAddress::coverWithPrefixBlock, subnet1, subnet2, ...);
	 * </code><p>
	 * See {@link #applyToBounds(java.util.function.BiFunction, IPAddress...)}
	 */
	public abstract IPAddress coverWithPrefixBlock(IPAddress other) throws AddressConversionException;

	/**
	 * Produces the list of prefix block subnets that span from this subnet to the given subnet.
	 * <p>
	 * If the other address is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
	 * <p>
	 * From the list of returned subnets you can recover the original range (this to other) by converting each to IPAddressRange with {@link IPAddress#toSequentialRange()}
	 * and them joining them into a single range with {@link IPAddressSeqRange#join(IPAddressSeqRange...)}
	 * <p>
	 * When you have multiple subnets, span with:<br>
	 * <code>
	 * IPAddress blocks[] = subnet0.applyToBounds(IPAddress::spanWithPrefixBlocks, subnet1, subnet2, ...);
	 * </code><p>
	 * See {@link #applyToBounds(java.util.function.BiFunction, IPAddress...)}
	 * 
	 * @param other
	 * @return
	 */
	public abstract IPAddress[] spanWithPrefixBlocks(IPAddress other) throws AddressConversionException;
	
	/**
	 * Produces a list of sequential block subnets that span all values from this subnet to the given subnet.
	 * The span will cover the sequence of all addresses from the lowest address in both subnets to the highest address in both subnets.
	 * <p>
	 * Individual block subnets come in the form 1-3.1-4.5.6-8, however that particular subnet is not sequential since address 1.1.5.8 is in the subnet,
	 * the next sequential address 1.1.5.9 is not in the subnet, and a higher address 1.2.5.6 is in the subnet.
	 * Blocks are sequential when the first segment with a range of values is followed by segments that span all values.
	 * <p>
	 * If the other address is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
	 * <p>
	 * From the list of returned subnets you can recover the original range (this and other) by converting each to IPAddressRange with {@link IPAddress#toSequentialRange()}
	 * and them joining them into a single range with {@link IPAddressSeqRange#join(IPAddressSeqRange...)}
	 * <p>
	 * When you have multiple subnets, span with:<br>
	 * <code>
	 * IPAddress blocks[] = subnet0.applyToBounds(IPAddress::spanWithSequentialBlocks, subnet1, subnet2, ...);
	 * </code><p>
	 * See {@link #applyToBounds(java.util.function.BiFunction, IPAddress...)}
	 * 
	 * @param other
	 * @return
	 */
	public abstract IPAddress[] spanWithSequentialBlocks(IPAddress other) throws AddressConversionException;
	
	protected List<? extends IPAddressSegmentSeries> spanWithBlocks(boolean prefixBlocks) {
		return spanWithBlocks(this, prefixBlocks);
	}
	
	static List<? extends IPAddressSegmentSeries> spanWithBlocks(IPAddressSegmentSeries orig, boolean prefixBlocks) {
		ArrayList<IPAddressSegmentSeries> list = new ArrayList<IPAddressSegmentSeries>();
		Iterator<? extends IPAddressSegmentSeries> iterator = orig.sequentialBlockIterator();
		while(iterator.hasNext()) {
			IPAddressSegmentSeries sequential = iterator.next();
			if(prefixBlocks) {
				Collections.addAll(list, sequential.spanWithPrefixBlocks());	
			} else {
				Collections.addAll(list, sequential);
			}
		}
		return list;
	}
	
	/**
	 * Produces an IPAddressRange instance that spans this subnet to the given subnet.
	 * <p>
	 * If the other address is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * When you have multiple subnets, span with:<br>
	 * <code>
	 * IPAddressSeqRange range = subnet0.applyToBounds(IPAddress::spanWithRange, subnet1, subnet2, ...);
	 * </code><p>
	 * See {@link #applyToBounds(java.util.function.BiFunction, IPAddress...)}
	 * 
	 * @param other
	 * @return
	 */
	public abstract IPAddressSeqRange spanWithRange(IPAddress other) throws AddressConversionException;
	
	/**
	 * Merges this with the list of addresses to produce the smallest list of prefix blocks.
	 * <p>
	 * For the smallest list of subnets use {@link #mergeToSequentialBlocks(IPAddress...)}.
	 * <p>
	 * If any other address in the list is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()},
	 * which can result in AddressConversionException
	 * <p>
	 * The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
	 * <p>
	 * In version 5.3.1 and earlier, the result was sorted from single address to smallest blocks to largest blocks.
	 * For that ordering, sort with {@link IPAddressSegmentSeries#getPrefixLenComparator()}:<br>
	 * <code>Arrays.sort(result, IPAddressSegmentSeries.getPrefixLenComparator());</code>
	 * <p>
	 * The merging process works with sequential blocks.  
	 * CIDR prefix subnets have just a single sequential block, as does individual addresses.  
	 * So this method works efficiently for most conventionally-used subnets.
	 * <p>
	 * For example, the subnet ::*:*:*:1-ffff has 281474976710656 sequential blocks.
	 * Just like you should avoid iterating through such a large number of blocks, 
	 * you should avoid using this method to merge such a subnet, 
	 * rather than a subnet like ::1-ffff:*:*:*:* which has 1 sequential block, 
	 * or the subnet ::1-ffff:1-ffff:*:*:*:* which has 65535 sequential blocks.
	 * You can use {@link #getSequentialBlockCount()} to get the sequential block count.
	 * <p>
	 * There are alternatives ways to merge into prefix blocks available in this library.
	 * Typically this method is most efficient when merging CIDR prefix blocks and/or individual addresses,
	 * which is likely to be the case for most users most of the time.  
	 * It converts to CIDR prefix blocks prior to merging, if not CIDR prefix blocks or individual addresses already.
	 * <p>
	 * When merging a large number of blocks that are not prefix blocks nor individual addresses, 
	 * it may be more efficient to merge first and then convert to CIDR prefix blocks afterwards.
	 * You can use {@link #mergeToSequentialBlocks(IPAddress...)} to merge, 
	 * and then span each merged element in the result with {@link #spanWithPrefixBlocks()},
	 * giving the same result as this method.
	 * <p>
	 * Sequential ranges provide another option.
	 * You can convert to sequential blocks first with {@link #sequentialBlockIterator()}, 
	 * then convert each sequential block to {@link IPAddressSeqRange} with {@link #toSequentialRange()}, 
	 * then join those sequential ranges with {@link IPAddressSeqRange#join(IPAddressSeqRange...)}, 
	 * then convert them to CIDR prefix blocks with {@link IPAddressSeqRange#spanWithPrefixBlocks()},
	 * giving the same result as this method.
	 * <p>
	 * 
	 * @throws AddressConversionException
	 * @param addresses the addresses to merge with this
	 * @return
	 */
	public abstract IPAddress[] mergeToPrefixBlocks(IPAddress ...addresses) throws AddressConversionException;
	
	protected static <T extends IPAddress, S extends IPAddressSegment> List<IPAddressSegmentSeries> getMergedPrefixBlocks(IPAddressSegmentSeries sections[]) {
		return IPAddressSection.getMergedPrefixBlocks(sections);
	}

	/**
	 * Merges this with the list of subnets to produce the smallest list of block subnets that are sequential.
	 * <p>
	 * Block subnets come in the form 1-3.1-4.5.6-8, however that subnet is not sequential since address 1.1.5.8 is in the subnet,
	 * the next sequential address 1.1.5.9 is not in the subnet, and a higher address 1.2.5.6 is in the subnet.
	 * Blocks are sequential when the first segment with a range of values is followed by segments that span all values.
	 * <p>
	 * This list will eliminate overlaps to produce the smallest list of sequential block subnets, which is the same size or smaller than the list of prefix blocks produced by {@link #mergeToPrefixBlocks(IPAddress...)}
	 * <p>
	 * If the incoming blocks are not sequential, the result could be a longer list, since the list is divided into sequential blocks before merging.
	 * <p>
	 * If any other address in the list is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()},
	 * which can result in AddressConversionException
	 * <p>
	 * The resulting array is sorted by lower address, regardless of the size of each prefix block.
	 * <p>
	 * In version 5.3.1 and earlier, the result was sorted from single address to smallest blocks to largest blocks.
	 * For that ordering, sort with {@link IPAddressSegmentSeries#getPrefixLenComparator()}:<br>
	 * <code>Arrays.sort(result, IPAddressSegmentSeries.getPrefixLenComparator());</code>
	 * <p>
	 * See the javadoc for {@link #mergeToPrefixBlocks(IPAddress...)} for some alternatives for merging subnets.
	 * 
	 * 
	 * @throws AddressConversionException
	 * @param addresses the addresses to merge with this
	 * @return
	 */
	public abstract IPAddress[] mergeToSequentialBlocks(IPAddress ...addresses) throws AddressConversionException;
	
	protected static <T extends IPAddress, S extends IPAddressSegment> List<IPAddressSegmentSeries> getMergedSequentialBlocks(IPAddressSegmentSeries sections[], IPAddressCreator<T, ?, ?, S, ?> creator) {
		return IPAddressSection.getMergedSequentialBlocks(sections, creator::createSequentialBlockAddress);
	}
	
	/**
	 * Produces the subnet whose addresses are found in both this and the given subnet argument, or null if no such addresses.
	 * <p>
	 * This is also known as the conjunction of the two sets of addresses.
	 * <p>
	 * If the address is not the same version, the default conversion will be applied using {@link #toIPv4()} or {@link #toIPv6()}, and it that fails, {@link AddressConversionException} will be thrown.
	 * <p>
	 * @param other
	 * @throws AddressConversionException if the address argument could not be converted to the same address version as this
	 * @return the subnet containing the addresses found in both this and the given subnet
	 */
	public abstract IPAddress intersect(IPAddress other) throws AddressConversionException;
	
	/**
	 * Subtract the given subnet from this subnet, returning an array of subnets for the result (the subnets will not be contiguous so an array is required).
	 * <p>
	 * Computes the subnet difference, the set of addresses in this address subnet but not in the provided subnet.  This is also known as the relative complement of the given argument in this subnet.
	 * <p>
	 * If the address is not the same version, the default conversion will be applied using {@link #toIPv4()} or {@link #toIPv6()}, and it that fails, {@link AddressConversionException} will be thrown.
	 * <p>
	 * @param other
	 * @throws AddressConversionException if the address argument could not be converted to the same address version as this
	 * @return the difference
	 */
	public abstract IPAddress[] subtract(IPAddress other) throws AddressConversionException;

	/**
	 * Equivalent to calling {@link #mask(IPAddress, boolean)} with the second argument as false.
	 *<p>
	 * If the mask is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
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
	 * Any existing prefix length is removed beforehand.  If the retainPrefix argument is true, then the existing prefix length will be applied to the result.
	 * <p>
	 * If the mask is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
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
	 * If the mask is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
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
	 * If the mask is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
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
	 * The mask is applied to all individual addresses, similar to how the method {@link #mask(IPAddress, boolean)} applies the bitwise conjunction.
	 * Any existing prefix length is removed beforehand.  If the retainPrefix argument is true, then the existing prefix length will be applied to the result.
	 * <p>
	 * If the mask is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
	 * <p>
	 * If you wish to mask a section of the network, use {@link #bitwiseOrNetwork(IPAddress, int)}
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
	 * If the mask is a different version than this, then the default conversion is applied to the other address first using {@link #toIPv4()} or {@link #toIPv6()}
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
	
	@Override @Deprecated
	public abstract IPAddress removePrefixLength();
	
	@Override @Deprecated
	public abstract IPAddress removePrefixLength(boolean zeroed);
	
	@Override
	public abstract IPAddress withoutPrefixLength();
	
	@Override
	public abstract IPAddress adjustPrefixBySegment(boolean nextSegment);

	@Override
	public abstract IPAddress adjustPrefixBySegment(boolean nextSegment, boolean zeroed);

	/**
	 * Increases or decreases prefix length by the given increment.
	 * <p>
	 * When prefix length is increased, the bits moved within the prefix become zero.
	 * When the prefix is extended beyond the segment series boundary, it is removed.
	 * When a prefix length is decreased, the bits moved outside the prefix become zero,
	 * and if the entire host address contains the zero address, 
	 * then the resulting address is determined {@link IPAddressNetwork#getPrefixConfiguration()}.
	 * <p>
	 * For example, 1.2.0.0/16 adjusted by -8 becomes 1.0.0.0/8.<br>
	 * 1.2.0.0/16 adjusted by 8 becomes 1.2.0.0/24
	 * 
	 * @param adjustment
	 * @return
	 */
	@Override
	public abstract IPAddress adjustPrefixLength(int adjustment);

	@Override
	public abstract IPAddress adjustPrefixLength(int adjustment, boolean zeroed);

	@Override
	public abstract IPAddress setPrefixLength(int prefixLength);

	@Override
	public abstract IPAddress setPrefixLength(int prefixLength, boolean zeroed);
	
	/**
	 * Sets the prefix length while allowing the caller to control whether bits moved in or out of the prefix become zero, 
	 * and whether a zero host for the new prefix bits can be translated into a prefix block.  
	 * The latter behaviour only applies to the default prefix handling configuration,
	 * PREFIXED_ZERO_HOSTS_ARE_SUBNETS.  The methods  {@link #setPrefixLength(int, boolean)} and {@link #setPrefixLength(int)}
	 * use a value of true for zeroed and for zeroHostIsBlock.
	 * <p>
	 * For example, when zeroHostIsBlock is true, applying to 1.2.0.0 the prefix length 16 results in 1.2.*.*&#x2f;16 
	 * <p>
	 * Or if you start with 1.2.0.0&#x2f;24, setting the prefix length to 16 results in 
	 * a zero host followed by the existing prefix block, which is then converted to a full prefix block, 1.2.*.*&#x2f;16
	 * <p>
	 * When both zeroed and zeroHostIsBlock are true, applying the prefiix length of 16 to 1.2.4.0&#x2f;24 also results in 
	 * a zero host followed by the existing prefix block, which is then converted to a full prefix block, 1.2.*.*&#x2f;16.
	 * <p>
	 * When both zeroed and zeroHostIsBlock are false, the resulting address always encompasses the same set of addresses as the original,
	 * albeit with a different prefix length.
	 * 
	 * @param prefixLength
	 * @param zeroed
	 * @param zeroHostIsBlock
	 * @return
	 */
	public abstract IPAddress setPrefixLength(int prefixLength, boolean zeroed, boolean zeroHostIsBlock);
	
	@Deprecated
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
	
	/**
	 * Removes the prefix length from addresses with a prefix length extending to the end of the address.
	 * @return
	 */
	public IPAddress removeBitCountPrefixLength() {
		if(isPrefixed() && getNetworkPrefixLength() == getBitCount()) {
			return this.withoutPrefixLength();
		}
		return this;
	}
}
