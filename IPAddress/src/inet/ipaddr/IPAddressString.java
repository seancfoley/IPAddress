package inet.ipaddr;

import java.io.Serializable;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.validate.AddressProvider;
import inet.ipaddr.format.validate.HostIdentifierStringValidator;
import inet.ipaddr.format.validate.Validator;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * Parses the string representation of an IP address.  Such a string can represent just a single address or a subnet like 1.2.0.0/16 or 1.*.1-3.1-4.
 * <p>
 * This supports a much wider range of address string formats than InetAddress.getByName, supports subnet formats, provides specific error messages, and allows more specific configuration.
 * <p>
 * You can control all of the supported formats using {@link IPAddressStringParameters.Builder} to build a parameters instance of {@link IPAddressStringParameters}.
 * When not using the constructor that takes a {@link IPAddressStringParameters}, a default instance of {@link IPAddressStringParameters} is used that is generally permissive.
 * <p>
 * <h2>Supported formats</h2>
 * Both IPv4 and IPv6 are supported.
 * <p>
 * Subnets are supported:
 * <ul>
 * <li>wildcards '*' and ranges '-' (for example 1.*.2-3.4), useful for working with subnets</li>
 * <li>SQL wildcards '%" and "_", although '%' is considered an SQL wildcard only when it is not considered an IPv6 zone indicator</li>
 * <li>CIDR network prefix length addresses, like 1.2.3.4/16, which is equivalent to 1.2.*.*</li>
 * <li>address/mask pairs, in which the mask is applied to the address, like 1.2.3.4/255.255.0.0, which is also equivalent to 1.2.*.*</li>
 * </ul>
 * <p>
 * You can combine these variations, such as 1.*.2-3.4/255.255.255.0
 * <p>
 * IPv6 is fully supported:
 * <ul>
 * <li>IPv6 addresses like ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff</li>
 * <li>IPv6 zones or scope ids, like ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%zone</li>
 * <li>IPv6 mixed addresses are supported, which are addresses for which the last two IPv6 segments are represented as IPv4, like ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255</li>
 * <li>IPv6 compressed addresses like ::1</li>
 * </ul>
 * <p>
 * All of the above subnet variations also work for IPv6, whether network prefixes, masks, ranges or wildcards.
 * Similarly, all the the above subnet variations also work for any supported IPv4 format, such as the standard dotted-decimal IPv4 format as well as the inet_aton formats listed below.
 * <p>
 * This class support all address formats of the C routine inet_pton and the Java method java.net.InetAddress.getByName.
 * This class supports all IPv4 address formats of the C routine inet_aton as follows:
 * <ul>
 * <li>IPv4 hex: 0x1.0x2.0x3.0x4 (0x prefix)</li>
 * <li>IPv4 octal: 01.02.03.0234.  Note this clashes with the same address interpreted as dotted decimal</li>
 * <li>IPv4 3 part: 1.2.3 (which is interpreted as 1.2.0.3 (ie the third part covers the last two)</li>
 * <li>IPv4 2 part: 1.2 (which is interpreted as 1.0.0.2 (ie the 2nd part covers the last 3)</li>
 * <li>IPv4 1 part: 1 (which is interpreted as 0.0.0.1 (ie the number represents all 4 segments)</li>
 * </ul><br>
 * inet_aton (and this class) allows mixing octal, hex and decimal (e.g. 0xa.11.013.11 which is equivalent to 11.11.11.11).  String variations using prefixes, masks, ranges, and wildcards also work for inet_aton style.
 * <p>
 * Note that there is ambiguity when supporting both inet_aton octal and dotted-decimal leading zeros, like 010.010.010.010 which can 
 * be interpreted as octal or decimal, thus it can be either 8.8.8.8 or 10.10.10.10, with the default behaviour using the latter interpretation<p>
 * This behaviour can be controlled by {@link IPAddressStringParameters.Builder#getIPv4AddressParametersBuilder()} and 
 * {@link inet.ipaddr.ipv4.IPv4AddressStringParameters.Builder#allowLeadingZeros(boolean)} 
 * <p>
 * Some additional formats:
 * <ul>
 * <li>null or empty strings are interpreted as the loopback, in the same way as InetAddress.getByName interprets null or empty strings</li>
 * <li>the single wildcard address "*" which represents all addresses both ipv4 and ipv6</li>
 * <li>specifying CIDR prefix lengths with no corresponding addresses are interpreted as the corresponding network mask.  For instance,
 *  /64 is interpreted as the 64 bit network mask (ie 64 ones followed by 64 zeros)</li>
 * </ul>
 * <p>
 * Not supported:<br>
 * IPv6 dotted decimal: 1.2.3.4.1.2.3.4.1.2.3.4.1.2.3.4<br>
 * IPv6 base 85: RFC 1924<br>
 * <p>
 * <h2>Usage</h2>
 * Once you have constructed an IPAddressString object, you can convert it to an IPAddress object with various methods.  
 * It is as simple as:<br>
 * <pre><code>
 * {@link IPAddress} address = new {@link IPAddressString}("1.2.3.4").{@link #getAddress()};
 * </code></pre>
 * <p>
 * If your application takes user input IP addresses, you can validate with:
 * <pre><code>
 * try {
 *  {@link IPAddress} address = new IPAddressString("1.2.3.4").{@link #toAddress()};
 * } catch({@link IPAddressStringException} e) {
 *	//e.getMessage() provides description of validation failure
 * }
 * </code></pre>
 * Most address strings can be converted to an IPAddress object using {@link #getAddress()} or {@link #toAddress()}.  In most cases the IP version is determined by the string itself.
 * <p>
 * There are a few exceptions, cases in which the version is unknown or ambiguous, for which {@link #getAddress()} returns null:
 * <ul>
 * <li>strings which do not represent valid addresses (eg "bla")</li>
 * <li>ambiguous address strings (eg "/32" is a prefix that could be IPv4 or IPv6).  For such strings you can provide the IPv4/IPv6 version to {@link #getAddress(IPVersion)} to get an address.</li>
 * <li>the "all" address "*" which represents all IPv4 and IPv6 addresses.  For this string you can provide the IPv4/IPv6 version to {@link #getAddress(IPVersion)} to get an address representing either all IPv4 or all IPv6 addresses.</li>
 * <li>empty string "" is interpreted as the default loopback address.  You can provide the ipv4/ipv6 version to{@link #getAddress(IPVersion)}to get the loopback version of your choice.</li>
 * </ul>
 * <p>
 * The other exception is subnets in which the range of values in a segment of the subnet are not sequential, for which {@link #getAddress()} throws IPAddressTypeException because there is no single IPAddress value, there would be many.
 * An IPAddress instance requires that all segments can be represented as a range of values.
 * There are only two unusual circumstances when this can occur:
 * <ul>
 * <li>using masks on subnets specified with wildcard or range characters causing non-sequential segments such as the final IPv4 segment of 0.0.0.*\/0.0.0.128, 
 * this example translating to the two addresses 0.0.0.0 and 0.0.0.128, so the last IPv4 segment cannot be represented as a sequential range of values.</li>
 * <li>using wildcards or range characters in the IPv4 section of an IPv6 mixed address causing non-sequential segments such as the last IPv6 segment of ::ffff:0.0.*.0, 
 * this example translating to the addresses ::ffff:0:100, ::ffff:0:200, , ::ffff:0:300, ..., so the last IPv6 segment cannot be represented as a sequential range of values.</li>
 * </ul>
 * <p>
 * This class is thread-safe.  In fact, IPAddressString objects are immutable.  
 * An IPAddressString object represents a single IP address representation that cannot be changed after construction.
 * Some of the derived state is created upon demand and cached, such as the derived IPAddress instances.
 * <p>
 * 
 * @custom.core
 * @author sfoley
 *
 */
/*
 * The test class IPAddressTest and other test classes can be used to validate any changes to this class and others.
 * 
 * A nice summary exists at http://www.gestioip.net/docu/ipv6_address_examples.html
 * 
 * Some discussion of formats is https://tools.ietf.org/html/draft-main-ipaddr-text-rep-00
 * Discussion of theses formats: http://tools.ietf.org/html/draft-main-ipaddr-text-rep-02
 * RFCs of interest are 2732, 2373, 3986, 4291, 5952, 2765, 1918, 3513 (IPv4 rfcs 1123 0953) 1883 1884 (original spec of 3 string representations of IPv6), 4007 6874 for IPv6 zone identifier or scope id
 * 
 * Nice cheat sheet for IPv6: http://www.roesen.org/files/ipv6_cheat_sheet.pdf
 */
//TODO check http://www.deepspace6.net/projects/ipv6calc.html#idp5031248 this was linked from the cheat sheet
//Add the DNS ptr example to the docs ie in our case we get an address section and then we do the reverse addr string (make sure we have that)
//one is base 85 ha ha 
//TODO maybe treat 32 hex chars as ipv6?  And treat some smaller number as ipv4?  ipv4 hex byte reversed - network order has the d in a.b.c.d first?  Simple 0xaabbccdd as ipv4?  
//Yeah, I like this idea, maybe even with or without the 0x
//In fact, the way I do the parsing now might work well with this
//We go by the number of chars.  20 chars is base 85.  32 chars is ipv6.  8 chars or less is ipv4.  We treat as hex.  Maybe we even allow octal chars or decimal.
//bitstring labels arpa: https://www.ibm.com/support/knowledgecenter/SSLTBW_1.13.0/com.ibm.zos.r13.halz002/f1a1b3b1220.htm
//Document: sections: addresses can be broken up into sections, and reconstituted from sections, such as EUI-64 hosts, mac addresses, etc
//TODO treat 20 chars as base 85

//TODO could have methods that extract mac address EUI 64 as an IPV6AddressSection, or methods that reconstitute an IPV6AddressSection from a mac address
//https://supportforums.cisco.com/document/100566/understanding-ipv6-eui-64-bit-address
//But also, we could have a segment grouping that is a mac address, since MAC addresses group segments like ab-cd-ef 
//Once we have this new mac address class, easier to jump back and forth
//A segment grouping is a series of divisions, 
//TODO MAC address design: so we need a mac address division, and then we have a macaddresssection extending IPAddressSegmentGrouping like ipaddresssection does
//but I think we actually split into two, we keep IPAddressSegmentgrouping and we create SegmentGrouping, the former has anything prefix related which is address-section specific
//Once we have this, we can have methods that create IPV6Section from mac, and for vice versa maybe nice to create an address from two separate sections?
//We also do the same for IPAddressDivision, we spit off the prefix-related stuff.
//the method isRangeEquivalentToPrefix must become isRangeImplied or isRangeInString or isRangeVisible
//getNetworkPrefixLength is the only part of IPAddressPart that would not apply to the SegmentGrouping, so we split tht up too
//BUT mac addresses have prefix too, 24 bits worth of the 48 total - http://aruljohn.com/mac.pl

//In HostName
//TODO support parsing the reverse DNS lookup string which is structured as a host
		//Similar to UNC Host, when you see the arpa suffix, then reverse the address in both IPv4 and IPv6, in IPV6 join the digits, then parse with the usual machinery
		//If an exception occurs, store it in the parsedHost object in its own field, then make that available here
		//Either that, or just throw it as HostException, which in its own way makes sense
		//TODO support parsing the IPv6 UNC Host name 0-0-0-1-0-0-0-1.ipv6.literal.net here in HostName - parse it as a host and recognize as an address, maybe create a special addressProvider object for that, but you probably want to put this in Validator
		//In Validator, when you see the ipv6.literal.net, convert the dashes and then parse the address with the usual machinery
		

public class IPAddressString implements HostIdentifierString, Comparable<IPAddressString>, Serializable {
	
	private static final long serialVersionUID = 1L;

	/* Generally permissive, settings are the default constants in IPAddressStringParameters.  % denotes a zone, not an SQL wildcard (allowZone is true), and leading zeros are considered decimal, not octal (allow_inet_aton_octal is false). */
	private static final IPAddressStringParameters DEFAULT_BASIC_VALIDATION_OPTIONS = new IPAddressStringParameters.Builder().toParams();
	
	private static final IPAddressStringException IS_IPV6_EXCEPTION = new IPAddressStringException("ipaddress.error.address.is.ipv6");
	private static final IPAddressStringException IS_IPV4_EXCEPTION = new IPAddressStringException("ipaddress.error.address.is.ipv4");
	
	public static final IPAddressString EMPTY_ADDRESS = new IPAddressString(""); //represents a blank address which resolves to the loopback /* address string creation */
	public static final IPAddressString ALL_ADDRESSES = new IPAddressString(IPAddress.SEGMENT_WILDCARD_STR); //represents any IPv6 or IPv4 address /* address string creation */
	
	final IPAddressStringParameters validationOptions;
	
	/* the full original string address  */
	final String fullAddr;
	
	// fields for validation state
	
	/* exceptions and booleans for validation - for type INVALID both of ipv6Exception and ipv4Exception are non-null */
	private IPAddressStringException ipv6Exception, ipv4Exception;
	
	//an object created by parsing that will provide the associated IPAddress(es)
	private AddressProvider addressProvider = AddressProvider.NO_TYPE_PROVIDER;
	
	/**
	 * Constructs an IPAddressString instance using the given String instance.
	 * 
	 * @param addr the address in string format, either IPv4 like a.b.c.d or IPv6 like a:b:c:d:e:f:g:h or a:b:c:d:e:f:h.i.j.k or a::b or some other valid IPv4 or IPv6 form.
	 * 		IPv6 addresses are allowed to terminate with a scope id which starts with a % symbol.
	 *		Both types of addresses can terminate with a network prefix value like a.b.c.d/24 or ::/24
	 *  	Optionally, you can specify just a network prefix value like /24, which represents the associated masks 255.255.255.0/24 or ffff:ff00::/24.
	 * <p>
	 *		Both IPv4 and IPv6 addresses can terminate with a mask instead of a prefix length, like a.b.c.d/255.0.0.0 or ::/ffff::
	 *		If a terminating mask is equivalent to a network prefix, then it will be the same as specifying the prefix, so a.b.c.d/16 is the same as a.b.c.d/255.255.0.0
	 *		If a terminating mask is not equivalent to a network prefix, then the mask will simply be applied to the address to produce a single address.
	 * <p>
	 *		You can also alter the addresses to include ranges using the wildcards * and -, such as 1.*.1-2.3, although this behaviour is not allowed by default,
	 *		you must provide your own IPAddressStringParameters for this, or you can use DEFAULT_WILDCARD_OPTIONS or DEFAULT_WILDCARD_AND_RANGE_OPTIONS as the validation options supplied to the constructor.
	 */
	public IPAddressString(String addr) {
		this(addr, DEFAULT_BASIC_VALIDATION_OPTIONS);
	}
	
	/**
	 * @param addr the address in string format
	 * 
	 * 	This constructor allows you to alter the default validation options.
	 * 
	 *	For example, you can alter the validation options to allow ranges using the wildcards * and -, such as 1.*.1-2.3.  Wildcards are not allowed in trailing masks.
	 */
	public IPAddressString(String addr, IPAddressStringParameters valOptions) {
		if(addr == null) {
			fullAddr = addr = "";
		} else {
			addr = addr.trim();
			fullAddr = addr;
		}
		this.validationOptions = valOptions;
	}
	
	IPAddressString(IPAddress address) {
		validationOptions = null; //no validation required, already validated
		fullAddr = address.toNormalizedString();
		initByAddress(address);
	}

	void cacheAddress(IPAddress address) {
		if(addressProvider == AddressProvider.NO_TYPE_PROVIDER) {
			initByAddress(address);
		}
	}
	
	void initByAddress(IPAddress address) {
		AddressProvider provider = AddressProvider.getProviderFor(address);
		if(provider.isIPv4()) {
			ipv6Exception = IS_IPV4_EXCEPTION;
		} else if(provider.isIPv6()) {
			ipv4Exception = IS_IPV6_EXCEPTION;
		}
		addressProvider = provider;
	}
	
	public IPAddressStringParameters getValidationOptions() {
		return validationOptions;
	}
	
	/**
	 * @return whether this address represents a network prefix or the set of all addresses with the same network prefix
	 */
	public boolean isPrefixed() {
		return isValid() && addressProvider.isPrefixed();
	}
	
	/**
	 * @return if this address is a valid address with a network prefix then this returns that prefix, otherwise returns null
	 */
	public Integer getNetworkPrefixLength() {
		if(isValid()) {
			return addressProvider.getNetworkPrefixLength();
		}
		return null;
	}
	 
	/**
	 * @return whether the address represents one of the accepted IP address types, which are:
	 * an IPv4 address, an IPv6 address, a network prefix, the address representing all addresses of all types, or an empty string.
	 * If it does not, and you want more details, call validate() and examine the thrown exception.
	 */
	public boolean isValid() {
		if(addressProvider.isUninitialized()) {
			try {
				validate();
				return true;
			} catch(IPAddressStringException e) {
				return false;
			}
		}
		return !addressProvider.isInvalid();
	}
	
	/**
	 * @return whether the address represents a valid specific IP address, 
	 * as opposed to an empty string, the address representing all addresses of all types, a prefix length, or an invalid format.
	 */
	public boolean isIPAddress() {
		return isValid() && addressProvider.isIPAddress();
	}
	
	/**
	 * @return whether the address represents the set all all valid IP addresses (as opposed to an empty string, a specific address, a prefix length, or an invalid format).
	 */
	public boolean isAllAddresses() {
		return isValid() && addressProvider.isAllAddresses();
	}
	
	/**
	 * @return whether the address represents a valid IP address network prefix (as opposed to an empty string, an address with or without a prefix, or an invalid format).
	 */
	public boolean isPrefixOnly() {
		return isValid() && addressProvider.isPrefixOnly();
	}
	
	/**
	 * Returns true if the address is empty (zero-length).
	 * @return
	 */
	public boolean isEmpty() {
		return isValid() && addressProvider.isEmpty();
	}
	
	/**
	 * Returns true if the address is IPv4 (with or without a network prefix, with or without wildcard segments).
	 * @return
	 */
	public boolean isIPv4() {
		return isValid() && addressProvider.isIPv4();
	}

	/**
	 * Returns true if the address is IPv6 (with or without a network prefix, with or without wildcard segments).
	 * @return
	 */
	public boolean isIPv6() {
		return isValid() && addressProvider.isIPv6();
	}
	
	public boolean isMixedIPv6() {
		return isIPv6() && addressProvider.isMixedIPv6();
	}
	
	public IPVersion getIPVersion() {
		if(isValid()) {
			return addressProvider.getIPVersion();
		}
		return null;
	}
	
	/**
	 * @see java.net.InetAddress#isLoopbackAddress()
	 */
	public boolean isLoopback() {
		IPAddress val = getAddress();
		return val != null && val.isLoopback();
	}

	public boolean isZero() {
		IPAddress value = getAddress();
		return value != null && value.isZero();
	}

	/**
	 * Validates this string is a valid IPv4 address, and if not, throws an exception with a descriptive message indicating why it is not.
	 * @throws IPAddressStringException
	 */
	public void validateIPv4() throws IPAddressStringException {
		validate(IPVersion.IPV4);
		checkIPv4Exception();
	}

	/**
	 * Validates this string is a valid IPv6 address, and if not, throws an exception with a descriptive message indicating why it is not.
	 * @throws IPAddressStringException
	 */
	public void validateIPv6() throws IPAddressStringException {
		validate(IPVersion.IPV6);
		checkIPv6Exception();
	}
	
	/**
	 * Validates this string is a valid address, and if not, throws an exception with a descriptive message indicating why it is not.
	 * @throws IPAddressStringException
	 */
	public void validate() throws IPAddressStringException {
		validate(null);
	}
	
	private void checkIPv4Exception() throws IPAddressStringException {
		if(ipv4Exception != null) {
			if(ipv4Exception == IS_IPV6_EXCEPTION) {
				ipv4Exception = new IPAddressStringException("ipaddress.error.address.is.ipv6");
			}
			throw ipv4Exception;
		}
	}
	
	private void checkIPv6Exception() throws IPAddressStringException {
		if(ipv6Exception != null) {
			if(ipv6Exception == IS_IPV4_EXCEPTION) {
				ipv6Exception = new IPAddressStringException("ipaddress.error.address.is.ipv4");
			}
			throw ipv6Exception;
		}
	}
	
	private boolean isValidated(IPVersion version) throws IPAddressStringException {
		if(addressProvider != AddressProvider.NO_TYPE_PROVIDER) {
			if(version == null) {
				if(ipv6Exception != null && ipv4Exception != null) {
					throw ipv4Exception;//the two exceptions are the same, so no need to choose
				}
			} else if(version.isIPv4()) {
				checkIPv4Exception();
			} else if(version.isIPv6()) {
				checkIPv6Exception();
			}
			return true;
		}
		return false;
	}

	protected HostIdentifierStringValidator getValidator() {
		return Validator.VALIDATOR;
	}
	
	private void validate(IPVersion version) throws IPAddressStringException {
		if(isValidated(version)) {
			return;
		}
		synchronized(this) {
			if(isValidated(version)) {
				return;
			}
			//we know nothing about this address.  See what it is.
			try {
				AddressProvider valueCreator = getValidator().validateAddress(this);

				//either the address is ipv4, ipv6, or indeterminate, and we set the cached validation exception appropriately
				IPVersion createdVersion = valueCreator.getIPVersion();
				if(createdVersion != null) {
					if(createdVersion.isIPv4()) {
						ipv6Exception = IS_IPV4_EXCEPTION;
					} else if(createdVersion.isIPv6()) {
						ipv4Exception = IS_IPV6_EXCEPTION;
					}
				}
				this.addressProvider = valueCreator;
			} catch(IPAddressStringException e) {
				ipv6Exception = ipv4Exception = e;
				this.addressProvider = AddressProvider.INVALID_PROVIDER;
				throw e;
			}
		}
	}

	/**
	 * Validates that the string has the format "/x" for a valid prefix length x.
	 * @param ipVersion IPv4, IPv6, or null if you do not know in which case it will be assumed that it can be either
	 * @param networkPrefixLength the network prefix length integer as a string, eg "24"
	 * @return the network prefix length
	 * @throws IPAddressTypeException if invalid with an appropriate message
	 */
	public static int validateNetworkPrefixLength(IPVersion ipVersion, CharSequence networkPrefixLength) throws IPAddressTypeException {
		try {
			return Validator.VALIDATOR.validatePrefix(networkPrefixLength, ipVersion);
		} catch(IPAddressStringException e) {
			throw new IPAddressTypeException(networkPrefixLength, ipVersion, "ipaddress.error.invalidCIDRPrefix", e);
		}
	}
	
	public static void validateNetworkPrefix(IPVersion ipVersion, int networkPrefixLength, boolean allowPrefixesBeyondAddressSize) throws IPAddressTypeException {
		boolean asIPv4 = (ipVersion != null && ipVersion.isIPv4());
		if(networkPrefixLength > (asIPv4 ? IPv4Address.BIT_COUNT : IPv6Address.BIT_COUNT)) {
			throw new IPAddressTypeException(networkPrefixLength, ipVersion, "ipaddress.error.prefixSize");
		}
	}
	
	@Override
	public int hashCode() {
		if(isValid()) {
			return addressProvider.hashCode();
		}
		return toString().hashCode();
	}

	@Override
	public int compareTo(IPAddressString other) {
		if(this == other) {
			return 0;
		}
		boolean isValid = isValid();
		boolean otherIsValid = other.isValid();
		if(!isValid && !otherIsValid) {
			return toString().compareTo(other.toString());
		}
		return addressProvider.compareTo(other.addressProvider);
	}
	
	/**
	 * Two IPAddressString objects are equal if they represent the same set of addresses.
	 * Whether one or the other has an associated network prefix length is not considered.
	 * 
	 * Also, an IPAddressString and IPAddress are considered equal if they represent the same set of addresses.
	 * 
	 * If an IPAddressString is invalid, it is equal to another address only if the other address was constructed from the same string.
	 * 
	 */
	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof IPAddressString) {
			IPAddressString other = (IPAddressString) o;	
			//if they have the same string, they must be the same,
			//but the converse is not true, if they have different strings, they can
			//still be the same because IPv6 addresses have many representations
			//and additional things like leading zeros can have an effect for IPv4
			if(toString().equals(other.toString())) {
				return true;
			}
			if(isValid() && other.isValid()) {
				return addressProvider.equals(other.addressProvider);
			} //else we have already compared strings.  Two invalid addresses are not equal unless strings match
		}
		return false;
	}
	
	public IPAddress getAddress(IPVersion version) {
		if(!addressProvider.isInvalid()) { //Avoid the exception the second time with this check
			try {
				return toAddress(version);
			} catch(IPAddressStringException e) { /* note that this exception is cached, it is not lost forever */ }
		}
		return null;
	}
	
	public IPAddress getAddress() {
		if(!addressProvider.isInvalid()) { //Avoid the exception the second time with this check
			try {
				return toAddress();
			} catch(IPAddressStringException e) { /* note that this exception is cached, it is not lost forever */ }
		}
		return null;
	}

	/**
	 * Produces the {@link IPAddress} of the specified address version corresponding to this IPAddressString.
	 * <p>
	 * In most cases the string indicates the address version and calling {@link #toAddress()} is sufficient, with a few exceptions.
	 * <p>
	 * When this object represents only a network prefix length, 
	 * specifying the address version allows the conversion to take place to the associated mask for that prefix length.
	 * <p>
	 * When this object represents all addresses, specifying the address version allows the conversion to take place 
	 * to the associated representation of all IPv4 or all IPv6 addresses.
	 * <p>
	 * When this object represents the empty string and that string is interpreted as a loopback, then it returns
	 * the corresponding loopback address.  If empty strings are not interpreted as loopback, null is returned.
	 * <p>
	 * When this object represents an ipv4 or ipv6 address, it returns that address if and only if that address matches the provided version.
	 * <p>
	 * If the string used to construct this object is an invalid format, 
	 * or a format that does not match the provided version, then this method throws IPAddressException.
	 * <p>
	 * @param version the address version that this address should represent.
	 * @return
	 * @throws IPAddressStringException
	 * @throws IPAddressTypeException address in proper format cannot be converted to an address: for masks inconsistent with associated address range, or ipv4 mixed segments that cannot be joined into ipv6 segments
	 */
	public IPAddress toAddress(IPVersion version) throws IPAddressStringException, IPAddressTypeException {
		validate(); //call validate so that we throw consistently, cover type == INVALID, and ensure the addressProvider exists
		return addressProvider.getAddress(version);
	}
	
	/**
	 * Produces the {@link IPAddress} corresponding to this IPAddressString.  If this object does not represent a specific IPAddress or a ranged IPAddress, null is returned,
	 * which may be the case if this object represents a network prefix or if it represents the empty address string.
	 * 
	 * If the string used to construct this object is not a known format (empty string, address, range of addresses, or prefix) then this method throws IPAddressException.
	 * 
	 * As long as this object represents a valid address (but not necessarily a specific address), this method does not throw.
	 * 
	 * @throws IPAddressStringException if the address format is invalid
	 * @throws IPAddressTypeException address in proper format cannot be converted to an address: for masks inconsistent with associated address range, or ipv4 mixed segments that cannot be joined into ipv6 segments
	 * 
	 */
	public IPAddress toAddress() throws IPAddressStringException, IPAddressTypeException {
		validate(); //call validate so that we throw consistently, cover type == INVALID, and ensure the addressProvider exists
		return addressProvider.getAddress();
	}
	
	/**
	 * Return an address for the network encompassing this address.  
	 * The bits indicate the number of additional network bits in the network address in comparison to this address.
	 * 
	 * @param prefixLengthDecrement the number to reduce the network bits in order to create a larger network.  
	 * 	If null, then this method has the same behaviour as toSupernet()
	 * @return the encompassing network
	 */
	public IPAddressString toSupernet(Integer prefixLengthDecrement) {
		if(isPrefixOnly()) {
			int bits;
			if(prefixLengthDecrement == null) {
				//Use IPv4 segment boundaries
				int bitsPerSegment = IPv4Address.BITS_PER_SEGMENT;
				int adjustment = getNetworkPrefixLength() % bitsPerSegment;
				bits = (adjustment > 0) ? adjustment : bitsPerSegment;
			} else {
				bits = prefixLengthDecrement;
			}
			int newBits = Math.max(0, getNetworkPrefixLength() - bits);
			return IPAddressNetwork.getPrefix(newBits);
		}
		IPAddress address = getAddress();
		if(address == null) {
			return null;
		}
		Integer prefix = address.getNetworkPrefixLength();
		if(prefix != null && prefix == 0) {
			return ALL_ADDRESSES;
		}
		return address.toSupernet(prefixLengthDecrement).toAddressString();
	}
	
	/**
	 * Return an address for the network encompassing this address,
	 * with the network portion of the returned address extending to the furthest segment boundary
	 * located entirely within but not matching the network portion of this address.
	 * 
	 * If the network portion has no bits then {@link #ALL_ADDRESSES} is returned.
	 * If this object is equal to {@link #ALL_ADDRESSES} then null is returned.
	 * 
	 * @return the encompassing network
	 */
	public IPAddressString toSupernet() {
		return toSupernet(null);
	}
	
	/**
	 * Converts this address to a prefix length
	 * 
	 * @return the prefix of the indicated IP type represented by this address or null if this address is valid but cannot be represented by a network prefix length
	 * @throws IPAddressStringException if the address is invalid
	 */
	public String convertToPrefixLength() throws IPAddressStringException {
		IPAddress address = toAddress();
		Integer prefix;
		if(address == null) {
			if(isPrefixOnly()) {
				prefix = getNetworkPrefixLength();
			} else {
				return null;
			}
		} else {
			prefix = address.getMaskPrefixLength(true);
			if(prefix == null) {
				return null;
			}
		}
		StringBuilder builder = new StringBuilder(HostIdentifierStringValidator.MAX_PREFIX_CHARS + 1);
		return builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(prefix).toString();
	}

	static String toNormalizedString(AddressProvider addressProvider) {
		String result;
		if(addressProvider.isAllAddresses()) {
			result = IPAddress.SEGMENT_WILDCARD_STR;
		} else if(addressProvider.isEmpty()) {
			result = "";
		} else if(addressProvider.isPrefixOnly()) {
			result = IPAddressNetwork.getPrefix(addressProvider.getNetworkPrefixLength()).toString();
		} else if(addressProvider.isIPAddress()) {
			result = addressProvider.getAddress().toNormalizedString();
		} else {
			result = null;
		}
		return result;
	}
	
	@Override
	public String toNormalizedString() {
		String result;
		if(isValid()) {
			result = toNormalizedString(addressProvider);
		} else {
			result = toString();
		}
		return result;
	}
	
	/**
	 * Gives us the original string provided to the constructor.  For variations, call {@link #getAddress()}/{@link #toAddress()} and then use string methods on the address object.
	 */
	@Override
	public String toString() {
		return fullAddr;
	}
}
