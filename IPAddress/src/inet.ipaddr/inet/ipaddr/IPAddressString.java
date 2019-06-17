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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.validate.HostIdentifierStringValidator;
import inet.ipaddr.format.validate.IPAddressProvider;
import inet.ipaddr.format.validate.Validator;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.mac.MACAddress;

/**
 * Parses the string representation of an IP address.  Such a string can represent just a single address like 1.2.3.4 or 1:2:3:4:6:7:8, or a subnet like 1.2.0.0/16 or 1.*.1-3.1-4 or 1111:222::/64.
 * <p>
 * This supports a much wider range of address string formats than InetAddress.getByName.  It supports subnet formats, provides specific error messages, and allows more specific configuration.
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
 * <li>the wildcard '*' can span multiple segments, so you can represent all addresses with '*', all IPv4 with '*.*', or all IPv6 with '*:*'</li>
 * <li>SQL wildcards '%' and '_', although '%' is considered an SQL wildcard only when it is not considered an IPv6 zone indicator</li>
 * <li>CIDR network prefix length addresses, like 1.2.0.0/16, which is equivalent to 1.2.*.* (all-zero hosts are the full subnet, non-zero hosts are single addresses)</li>
 * <li>address/mask pairs, in which the mask is applied to the address, like 1.2.3.4/255.255.0.0, which is also equivalent to 1.2.*.*</li>
 * </ul>
 * <p>
 * You can combine these variations, such as 1.*.2-3.4/255.255.255.0
 * <p>
 * IPv6 is fully supported:
 * <ul>
 * <li>IPv6 addresses like ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff</li>
 * <li>IPv6 zones or scope identifiers, like ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%zone</li>
 * <li>IPv6 mixed addresses are supported, which are addresses for which the last two IPv6 segments are represented as IPv4, like ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255</li>
 * <li>IPv6 compressed addresses like ::1</li>
 * <li>A single value of 32 hex digits like 00aa00bb00cc00dd00ee00ff00aa00bb with or without a preceding hex delimiter 0x</li>
 * <li>A base 85 address comprising 20 base 85 digits like 4)+k&amp;C#VzJ4br&gt;0wv%Yp as in rfc 1924 https://tools.ietf.org/html/rfc1924</li>
 * </ul>
 * <p>
 * All of the above subnet variations work for IPv6, whether network prefix lengths, masks, ranges or wildcards.
 * Similarly, all the the above subnet variations work for any supported IPv4 format, such as the standard dotted-decimal IPv4 format as well as the inet_aton formats listed below.
 * <p>
 * This class support all address formats of the C routine inet_pton and the Java method java.net.InetAddress.getByName.
 * This class supports all IPv4 address formats of the C routine inet_aton as follows:
 * <ul>
 * <li>IPv4 hex: 0x1.0x2.0x3.0x4 (0x prefix)</li>
 * <li>IPv4 octal: 01.02.03.0234.  Note this clashes with the same address interpreted as dotted decimal</li>
 * <li>3-part IPv4: 1.2.3 (which is interpreted as 1.2.0.3 (ie the third part covers the last two)</li>
 * <li>2-part IPv4: 1.2 (which is interpreted as 1.0.0.2 (ie the 2nd part covers the last 3)</li>
 * <li>1-part IPv4: 1 (which is interpreted as 0.0.0.1 (ie the number represents all 4 segments, and can be any number of digits less than the 32 digits which would be interpreted as IPv6)</li>
 * <li>hex or octal variants of 1, 2, and 3 part, such as 0xffffffff (which is interpreted as 255.255.255.255)</li>
 * </ul><br>
 * inet_aton (and this class) allows mixing octal, hex and decimal (e.g. 0xa.11.013.11 which is equivalent to 11.11.11.11).  String variations using prefixes, masks, ranges, and wildcards also work for inet_aton style.
 * <p>
 * Note that there is ambiguity when supporting both inet_aton octal and dotted-decimal leading zeros, like 010.010.010.010 which can 
 * be interpreted as octal or decimal, thus it can be either 8.8.8.8 or 10.10.10.10, with the default behaviour using the former interpretation<p>
 * This behaviour can be controlled by {@link IPAddressStringParameters.Builder#getIPv4AddressParametersBuilder()} and 
 * {@link inet.ipaddr.ipv4.IPv4AddressStringParameters.Builder#allowLeadingZeros(boolean)} 
 * <p>
 * Some additional formats:
 * <ul>
 * <li>null or empty strings are interpreted as the loopback, in the same way as InetAddress.getByName interprets null or empty strings</li>
 * <li>as noted previously, the single wildcard address "*" represents all addresses both ipv4 and ipv6, 
 * although you need to give it some help when converting to IPAddress by specifying the IP version in {@link #getAddress(IPVersion)} or {@link #toAddress(IPVersion)}</li>
 * <li>specifying CIDR prefix lengths with no corresponding addresses are interpreted as the corresponding network mask.  For instance,
 *  /64 is interpreted as the 64 bit network mask (ie 64 ones followed by 64 zeros)</li>
 * </ul>
 * <p>
 * If you have an address in which segments have been delimited with commas, such as "1,2.3.4,5.6", you can parse this with {@link #parseDelimitedSegments(String)}
 * which gives an iterator of strings.  For "1,2.3.4,5.6" you will iterate through "1.3.4.6", "1.3.5.6", "2.3.4.6" and "2.3.5.6".
 * You can count the number of elements in such an iterator with {@link #countDelimitedAddresses(String)}.  
 * Each string can then be used to construct an IPAddressString.
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
 * } catch({@link AddressStringException} e) {
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
 * The other exception is a subnet in which the range of values in a segment of the subnet are not sequential, for which {@link #getAddress()} throws {@link IncompatibleAddressException} because there is no single IPAddress value, there would be many.
 * An IPAddress instance requires that all segments can be represented as a range of values.
 * There are only two unusual circumstances when this can occur:
 * <ul>
 * <li>using masks on subnets specified with wildcard or range characters causing non-sequential segments such as the final IPv4 segment of 0.0.0.* with mask 0.0.0.128, 
 * this example translating to the two addresses 0.0.0.0 and 0.0.0.128, so the last IPv4 segment cannot be represented as a sequential range of values.</li>
 * <li>using wildcards or range characters in the IPv4 section of an IPv6 mixed address causing non-sequential segments such as the last IPv6 segment of ::ffff:0.0.*.0, 
 * this example translating to the addresses ::ffff:0:100, ::ffff:0:200, , ::ffff:0:300, ..., so the last IPv6 segment cannot be represented as a sequential range of values.</li>
 * </ul>
 * These exceptions do not occur with non-subnets (ie individual addresses), nor can they occur with standard CIDR prefix-based subnets.
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
 * Early ones: 2460, 2553, 1122, 1812
 * 
 * Nice cheat sheet for IPv6: http://www.roesen.org/files/ipv6_cheat_sheet.pdf
 * 
 * Nice summary on zones and parsing http://veithen.github.io/2013/12/30/how-to-correctly-parse-ipv6-addresses.html
 * 
 * Nice resource on IPv6 vs IPv4 and lots of stuff including MAC: 
 * https://communities.bmc.com/docs/DOC-19235
 * Another: https://www.midnightfreddie.com/ipv6-ipv4-similar.html
 * 
 * Some parsing code for various languages: https://rosettacode.org/wiki/Parse_an_IP_Address
 * http://www.cisco.com/c/en/us/support/docs/ip/routing-information-protocol-rip/13788-3.html
 */
public class IPAddressString implements HostIdentifierString, Comparable<IPAddressString> {

	private static final long serialVersionUID = 4L;

	/* 
	 * Generally permissive, settings are the default constants in IPAddressStringParameters.  
	 * % denotes a zone, not an SQL wildcard (allowZone is true), 
	 * and leading zeros are considered decimal, not octal (allow_inet_aton_octal is false).
	 */
	public static final IPAddressStringParameters DEFAULT_VALIDATION_OPTIONS = new IPAddressStringParameters.Builder().toParams();

	final IPAddressStringParameters validationOptions;
	
	/* the full original string address */
	final String fullAddr;
	
	// fields for validation state
	
	/* exceptions and booleans for validation - for type INVALID both of ipv6Exception and ipv4Exception are non-null */
	private AddressStringException validateException;

	// an object created by parsing that will provide the associated IPAddress(es)
	private IPAddressProvider addressProvider = IPAddressProvider.NO_TYPE_PROVIDER;
	
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
	 *		You can also alter the addresses to include ranges using the wildcards * and -, such as 1.*.1-2.3.
	 */
	public IPAddressString(String addr) {
		this(addr, DEFAULT_VALIDATION_OPTIONS);
	}
	
	/**
	 * @param addr the address in string format
	 * 
	 * 	This constructor allows you to alter the default validation options.
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

	/**
	 * Provides an address string instance for an existing address.
	 * <p> 
	 * Not all valid address strings can be converted to address objects,
	 * such as the all address"*", or empty strings "", or prefix only addresses like "/32",
	 * so it can be useful to maintain a set of address strings instances.
	 * <p>
	 * Even though the address exists already, the options provide the networks in use by the address, as well as options for creating new addresses from this address.
	 * 
	 * @param address
	 * @param network
	 */
	IPAddressString(String addrString, IPAddress address, IPAddressStringParameters valOptions) {
		validationOptions = valOptions; 
		fullAddr = addrString;
		addressProvider = address.getProvider();
	}

	void cacheAddress(IPAddress address) {
		if(addressProvider.isUninitialized()) {
			addressProvider = address.getProvider();
		}
	}

	public IPAddressStringParameters getValidationOptions() {
		return validationOptions;
	}

	/**
	 * Returns whether this address string has an associated prefix length.
	 * If so, the prefix length is given by {@link #getNetworkPrefixLength()}
	 * 
	 * @return whether this address string has an associated prefix length
	 */
	public boolean isPrefixed() {
		return getNetworkPrefixLength() != null;
	}

	/**
	 * if this address is a valid address with an associated network prefix length then this returns that prefix length, otherwise returns null
	 * 
	 * @return the prefix length or null
	 */
	public Integer getNetworkPrefixLength() {
		if(isValid()) {
			return addressProvider.getProviderNetworkPrefixLength();
		}
		return null;
	}

	/**
	 * Returns whether the address represents a valid specific IP address or subnet, either IPv4 or IPv6, 
	 * as opposed to an empty string, the address representing all addresses of all types, a prefix length, or an invalid format.
	 * 
	 * @return whether the address represents a valid specific IP address.
	 */
	public boolean isIPAddress() {
		return isValid() && addressProvider.isProvidingIPAddress();
	}

	/**
	 * Returns true if the string represents all IP addresses, such as the string "*"
	 * You can denote all IPv4 addresses with *.*, or all IPv6 addresses with *:*
	 * 
	 * @return whether the address represents the set all all valid IP addresses (as opposed to an empty string, a specific address, a prefix length, or an invalid format).
	 */
	public boolean isAllAddresses() {
		return isValid() && addressProvider.isProvidingAllAddresses();
	}
	
	/**
	 * Returns whether this address string represents only a prefix length with no associated address value,
	 * as opposed to an empty string, an address with or without a prefix length, or an invalid format.
	 * 
	 * @return whether the address represents a valid IP address network prefix length
	 */
	public boolean isPrefixOnly() {
		return isValid() && addressProvider.isProvidingPrefixOnly();
	}
	
	/**
	 * Returns true if the address string is empty (zero-length).
	 * @return
	 */
	public boolean isEmpty() {
		return isValid() && addressProvider.isProvidingEmpty();
	}
	
	/**
	 * Returns true if the address is IPv4 (with or without a network prefix, with or without wildcard segments).
	 * @return
	 */
	public boolean isIPv4() {
		return isValid() && addressProvider.isProvidingIPv4();
	}

	/**
	 * Returns true if the address is IPv6 (with or without a network prefix, with or without wildcard segments).
	 * @return
	 */
	public boolean isIPv6() {
		return isValid() && addressProvider.isProvidingIPv6();
	}
	
	/**
	 * If this address string represents an IPv6 address, returns whether the lower 4 bytes were represented as IPv4
	 * @return
	 */
	public boolean isMixedIPv6() {
		return isIPv6() && addressProvider.isProvidingMixedIPv6();
	}
	
	/**
	 * If this address string represents an IPv6 address, returns whether the string was base 85
	 * @return
	 */
	public boolean isBase85IPv6() {
		return isIPv6() && addressProvider.isProvidingBase85IPv6();
	}
	
	/**
	 * Returns the IP address version if {@link #isIPAddress()} returns true, otherwise returns null
	 * 
	 * @return the version
	 */
	public IPVersion getIPVersion() {
		if(isValid()) {
			return addressProvider.getProviderIPVersion();// this can also be null
		}
		return null;
	}
	
	/**
	 * Returns whether this string represents a loopback IP address.
	 * 
	 * @see java.net.InetAddress#isLoopbackAddress()
	 */
	public boolean isLoopback() {
		IPAddress val = getAddress();
		return val != null && val.isLoopback();
	}

	/**
	 * Returns whether this string represents an IP address whose value is zero.
	 * 
	 */
	public boolean isZero() {
		IPAddress value = getAddress();
		return value != null && value.isZero();
	}

	/**
	 * Returns whether this is a valid address string format.
	 * 
	 * The accepted IP address formats are:
	 * an IPv4 address, an IPv6 address, a network prefix alone, the address representing all addresses of all types, or an empty string.
	 * If this method returns false, and you want more details, call validate() and examine the thrown exception.
	 * 
	 * @return whether this is a valid address string format
	 */
	public boolean isValid() {
		if(addressProvider.isUninitialized()) {
			try {
				validate();
				return true;
			} catch(AddressStringException e) {
				return false;
			}
		}
		return !addressProvider.isInvalid();
	}

	/**
	 * Validates that this string is a valid IPv4 address, and if not, throws an exception with a descriptive message indicating why it is not.
	 * @throws AddressStringException
	 */
	public void validateIPv4() throws AddressStringException {
		validate(IPVersion.IPV4);
		checkIPv4Exception();
	}

	/**
	 * Validates that this string is a valid IPv6 address, and if not, throws an exception with a descriptive message indicating why it is not.
	 * @throws AddressStringException
	 */
	public void validateIPv6() throws AddressStringException {
		validate(IPVersion.IPV6);
		checkIPv6Exception();
	}
	
	/**
	 * Validates that this string is a valid address, and if not, throws an exception with a descriptive message indicating why it is not.
	 * @throws AddressStringException
	 */
	@Override
	public void validate() throws AddressStringException {
		validate(null);
	}
	
	private void checkIPv4Exception() throws AddressStringException {
		IPVersion version = addressProvider.getProviderIPVersion();
		if(version != null && version.isIPv6()) {
			throw new AddressStringException("ipaddress.error.address.is.ipv6");
		} else if(validateException != null) {
			throw validateException;
		}
	}
	
	private void checkIPv6Exception() throws AddressStringException {
		IPVersion version = addressProvider.getProviderIPVersion();
		if(version != null && version.isIPv4()) {
			throw new AddressStringException("ipaddress.error.address.is.ipv4");
		} else if(validateException != null) {
			throw validateException;
		}
	}
	
	private boolean isValidated(IPVersion version) throws AddressStringException {
		if(!addressProvider.isUninitialized()) {
			if(version == null) {
				if(validateException != null) {
					throw validateException; // the two exceptions are the same, so we can choose either one
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
	
	private void validate(IPVersion version) throws AddressStringException {
		if(isValidated(version)) {
			return;
		}
		synchronized(this) {
			if(isValidated(version)) {
				return;
			}
			//we know nothing about this address.  See what it is.
			try {
				addressProvider = getValidator().validateAddress(this);
			} catch(AddressStringException e) {
				validateException = e;
				addressProvider = IPAddressProvider.INVALID_PROVIDER;
				throw e;
			} 
		}
	}


	/**
	 * Validates that the string has the format "/x" for a valid prefix length x.
	 * @param ipVersion IPv4, IPv6, or null if you do not know in which case it will be assumed that it can be either
	 * @param networkPrefixLength the network prefix length integer as a string, eg "24"
	 * @return the network prefix length
	 * @throws IncompatibleAddressException if invalid with an appropriate message
	 */
	public static int validateNetworkPrefixLength(IPVersion ipVersion, CharSequence networkPrefixLength) throws PrefixLenException {
		try {
			return Validator.VALIDATOR.validatePrefix(networkPrefixLength, ipVersion);
		} catch(AddressStringException e) {
			throw new PrefixLenException(networkPrefixLength, ipVersion, e);
		}
	}
	
	public static void validateNetworkPrefix(IPVersion ipVersion, int networkPrefixLength, boolean allowPrefixesBeyondAddressSize) throws PrefixLenException {
		boolean asIPv4 = (ipVersion != null && ipVersion.isIPv4());
		if(networkPrefixLength > (asIPv4 ? IPv4Address.BIT_COUNT : IPv6Address.BIT_COUNT)) {
			throw new PrefixLenException(networkPrefixLength, ipVersion);
		}
	}
	
	@Override
	public int hashCode() {
		if(isValid()) {
			try {
				return addressProvider.providerHashCode();
			} catch(IncompatibleAddressException e) {}
		}
		return toString().hashCode();
	}

	/**
	 * All address strings are comparable.  If two address strings are invalid, their strings are compared.
	 * Otherwise, address strings are compared according to which type or version of string, and then within each type or version
	 * they are compared using the comparison rules for addresses.
	 * 
	 * @param other
	 * @return
	 */
	@Override
	public int compareTo(IPAddressString other) {
		if(this == other) {
			return 0;
		}
		boolean isValid = isValid();
		boolean otherIsValid = other.isValid();
		if(isValid || otherIsValid) {
			try {
				return addressProvider.providerCompare(other.addressProvider);
			} catch(IncompatibleAddressException e) {}
		}
		return toString().compareTo(other.toString());
	}
	
	/**
	 * Similar to {@link #equals(Object)}, but instead returns whether the prefix of this address matches the same of the given address,
	 * using the prefix length of this address.
	 * <p>
	 * In other words, determines if the other address is in the same prefix subnet using the prefix length of this address.
	 * <p>
	 * It this address has no prefix length, returns false.  The other address need not have an associated prefix length for this method to return true.
	 * <p>
	 * If this address string or the given address string is invalid, returns false.
	 * 
	 * @param other
	 * @return
	 */
	public boolean prefixEquals(IPAddressString other) {
		// getting the prefix 
		Integer prefixLength = getNetworkPrefixLength(); // this returns null if not valid
		if(prefixLength == null) {
			return false;
		}
		if(other == this && !isPrefixOnly()) {
			return true;
		}
		if(other.addressProvider.isUninitialized()) { // other not yet validated - if other is validated no need for this quick contains
			// do the quick check that uses only the String of the other, matching til the end of the prefix length, for performance
			Boolean directResult = addressProvider.prefixEquals(other.fullAddr);
			if(directResult != null) {
				return directResult.booleanValue();
			}
		}
		if(other.isValid()) {
			Boolean directResult = addressProvider.prefixEquals(other.addressProvider); 
			if(directResult != null) {
				return directResult.booleanValue();
			}
			IPAddress thisAddress = getAddress();
			if(thisAddress != null) {
				IPAddress otherAddress = other.getAddress();
				if(otherAddress != null) {
					return prefixLength <= otherAddress.getBitCount() && thisAddress.prefixEquals(otherAddress);
				}
			}
			// one or both addresses are null, so there is no prefix to speak of
		}
		return false;
	}

	/**
	 * Two IPAddressString objects are equal if they represent the same set of addresses.
	 * Whether one or the other has an associated network prefix length is not considered.
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
			// if they have the same string, they must be the same,
			// but the converse is not true, if they have different strings, they can
			// still be the same because IPv6 addresses have many representations
			// and additional things like leading zeros can have an effect for IPv4
			
			// Also note that we do not call equals() on the validation options, this is intended as an optimization,
			// and probably better to avoid going through all the validation objects here
			boolean stringsMatch = toString().equals(other.toString());
			if(stringsMatch && validationOptions == other.validationOptions) {
				return true;
			}
			if(isValid()) {
				if(other.isValid()) {
					Boolean directResult = addressProvider.parsedEquals(other.addressProvider);
					if(directResult != null) {
						return directResult.booleanValue();
					}
					try {
						// When a value provider produces no value, equality and comparison are based on the enum IPType,
						// which can be null.
						return addressProvider.providerEquals(other.addressProvider);
					} catch(IncompatibleAddressException e) {
						return stringsMatch;
					}
				}
			} else if(!other.isValid()) {
				return stringsMatch; // Two invalid addresses are not equal unless strings match, regardless of validation options
			}
		}
		return false;
	}
	
	/**
	 * Returns whether the address subnet identified by this address string contains the address identified by the given string.
	 * <p>
	 * If this address string or the given address string is invalid then returns false.
	 * 
	 * @param other
	 * @return
	 */
	public boolean contains(IPAddressString other) {
		if(isValid()) {
			if(other == this) {
				return true;
			}
			if(other.addressProvider.isUninitialized()) { // other not yet validated - if other is validated no need for this quick contains
				//do the quick check that uses only the String of the other
				Boolean directResult = addressProvider.contains(other.fullAddr);
				if(directResult != null) {
					return directResult.booleanValue();
				}
			}
			if(other.isValid()) {
				// note the quick result also handles the case of "all addresses"
				Boolean directResult = addressProvider.contains(other.addressProvider);
				if(directResult != null) {
					return directResult.booleanValue();
				}
				IPAddress addr = getAddress();
				if(addr != null) {
					IPAddress otherAddress = other.getAddress();
					if(otherAddress != null) {
						return addr.contains(otherAddress);
					}
				}
			}
		}
		return false;
	}

	/**
	 * If this address string was constructed from a host address with prefix length, 
	 * then this provides just the host address, rather than the address 
	 * provided by {@link #getAddress()} that incorporates the prefix.
	 * <p>
	 * Otherwise this returns the same object as {@link #getAddress()}.
	 * <p>
	 * This method returns null for invalid formats, the equivalent method {@link #toHostAddress()} throws exceptions for invalid formats.
	 * 
	 * @return
	 */
	public IPAddress getHostAddress() {
		if(!addressProvider.isInvalid()) { // Avoid the exception the second time with this check
			try {
				return toHostAddress();
			} catch(AddressStringException e) { /* note that this exception is cached, it is not lost forever */
			} catch(IncompatibleAddressException e) { /* this will be rethrown each time attempting to construct address */ }
		}
		return null;
	}
	
	/**
	 * Similar to {@link #toAddress(inet.ipaddr.IPAddress.IPVersion)}, but returns null rather than throwing an exception with the address is invalid or does not match the supplied version.
	 * 
	 */
	public IPAddress getAddress(IPVersion version) {
		if(!addressProvider.isInvalid()) { // Avoid the exception the second time with this check
			try {
				return toAddress(version);
			} catch(AddressStringException e) { /* note that this exception is cached, it is not lost forever */
			} catch(IncompatibleAddressException e) { /* this will be rethrown each time attempting to construct address */ }
		}
		return null;
	}
	
	/**
	 * If this represents an ip address, returns that address.  Otherwise, returns null.
	 * <p>
	 * This method will return null for invalid formats.  Use {@link #toAddress()} for an equivalent method that throws exceptions for invalid formats.
	 * <p>
	 * If you have a prefix address and you wish to get only the host without the prefix, use {@link #getHostAddress()}
	 * 
	 * @return the address
	 */
	@Override
	public IPAddress getAddress() {
		if(!addressProvider.isInvalid()) { // Avoid the exception the second time with this check
			try {
				return toAddress();
			} catch(AddressStringException e) { /* note that this exception is cached, it is not lost forever */
			} catch(IncompatibleAddressException e) { /* this will be rethrown each time attempting to construct address */ }
		}
		return null;
	}

	/**
	 * If this address string was constructed from a host address with prefix, 
	 * then this provides just the host address, rather than the address with the prefix
	 * provided by {@link #toAddress()} that incorporates the prefix.
	 * 
	 *  Otherwise this returns the same object as {@link #toAddress()}
	 * 
	 * This method throws exceptions for invalid formats, the equivalent method {@link #getHostAddress()} will simply return null in such cases.
	 * 
	 * @return
	 */
	public IPAddress toHostAddress() throws AddressStringException, IncompatibleAddressException {
		validate(); // call validate so that we throw consistently, cover type == INVALID, and ensure the addressProvider exists
		return addressProvider.getProviderHostAddress();
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
	 * or a format that does not match the provided version, then this method throws {@link AddressStringException}.
	 * <p>
	 * @param version the address version that this address should represent.
	 * @return
	 * @throws AddressStringException
	 * @throws IncompatibleAddressException address in proper format cannot be converted to an address: for masks inconsistent with associated address range, or ipv4 mixed segments that cannot be joined into ipv6 segments
	 */
	public IPAddress toAddress(IPVersion version) throws AddressStringException, IncompatibleAddressException {
		validate(); // call validate so that we throw consistently, cover type == INVALID, and ensure the addressProvider exists
		return addressProvider.getProviderAddress(version);
	}

	/**
	 * Produces the {@link IPAddress} corresponding to this IPAddressString.  
	 * <p>
	 * If this object does not represent a specific IPAddress or a ranged IPAddress, null is returned,
	 * which may be the case if this object represents only a network prefix or if it represents the empty address string.
	 * <p>
	 * If the string used to construct this object is not a known format (empty string, address, range of addresses, or prefix) then this method throws {@link AddressStringException}.
	 * <p>
	 * An equivalent method that does not throw exception for invalid formats is {@link #getAddress()}
	 * <p>
	 * If you have a prefixed address and you wish to get only the host rather than the address with the prefix, use {@link #toHostAddress()}
	 * <p>
	 * 
	 * As long as this object represents a valid address (but not necessarily a specific address), this method does not throw.
	 * <p>
	 * @throws AddressStringException if the address format is invalid
	 * @throws IncompatibleAddressException if a valid address string representing multiple addresses cannot be represented<br>
	 * 	This happens only for masks inconsistent with the associated address ranges, or ranges in ipv4 mixed segments that cannot be joined into ipv6 segments
	 * 
	 */
	@Override
	public IPAddress toAddress() throws AddressStringException, IncompatibleAddressException {
		validate(); //call validate so that we throw consistently, cover type == INVALID, and ensure the addressProvider exists
		return addressProvider.getProviderAddress();
	}
	
	/**
	 * Increases or decreases prefix length to the next segment boundary of the given address version's standard segment boundaries.
	 * <p>
	 * This acts on address strings with an associated prefix length, whether or not there is also an associated address value, see {@link IPAddressString#isPrefixOnly()}.
	 * If there is no associated address value then the segment boundaries are considered to be at each byte, much like IPv4.
	 * <p>
	 * If the address string has prefix length 0 and represents all addresses of the same version,
	 * and the prefix length is being decreased, then the address representing all addresses of any version is returned.
	 * <p>
	 * Follows the same rules as {@link #adjustPrefixLength(int)} when there is an associated address value:<br>
	 * When prefix length is increased, the bits moved within the prefix become zero.
	 * When a prefix length is decreased, the bits moved outside the prefix become zero.
	 * 
	 * Also see {@link IPAddress#adjustPrefixBySegment(boolean)}
	 * @param nextSegment whether to move prefix to previous or following segment boundary
	 * @return
	 */
	public IPAddressString adjustPrefixBySegment(boolean nextSegment) {
		if(isPrefixOnly()) {
			// Use IPv4 segment boundaries
			int bitsPerSegment = IPv4Address.BITS_PER_SEGMENT;
			int existingPrefixLength = getNetworkPrefixLength();
			int newBits;
			if(nextSegment) {
				int adjustment = existingPrefixLength % bitsPerSegment;
				newBits = Math.min(IPv6Address.BIT_COUNT, existingPrefixLength + bitsPerSegment - adjustment);
			} else {
				int adjustment = ((existingPrefixLength - 1) % bitsPerSegment) + 1;
				newBits = Math.max(0, existingPrefixLength - adjustment);
			}
			return new IPAddressString(IPAddressNetwork.getPrefixString(newBits), validationOptions);
		}
		IPAddress address = getAddress();
		if(address == null) {
			return null;
		}
		Integer prefix = address.getNetworkPrefixLength();
		if(!nextSegment && prefix != null && prefix == 0 && address.isMultiple() && address.isPrefixBlock()) {
			return new IPAddressString(IPAddress.SEGMENT_WILDCARD_STR, validationOptions);
		}
		return address.adjustPrefixBySegment(nextSegment).toAddressString();
	}

	
	/**
	 * Increases or decreases prefix length by the given increment.
	 * <p>
	 * This acts on address strings with an associated prefix length, whether or not there is also an associated address value.
	 * <p>
	 * If the address string has prefix length 0 and represents all addresses of the same version,
	 * and the prefix length is being decreased, then the address representing all addresses of any version is returned.
	 * <p>
	 * When there is an associated address value and the prefix length is increased, the bits moved within the prefix become zero, 
	 * and if prefix lengthis extended beyond the segment series boundary, it is removed.
	 * When there is an associated address value 
	 * and the prefix length is decreased, the bits moved outside the prefix become zero.
	 * 
	 * Also see {@link IPAddress#adjustPrefixLength(int)}
	 * @param adjustment
	 * @return
	 */
	public IPAddressString adjustPrefixLength(int adjustment) {
		if(isPrefixOnly()) {
			int newBits = adjustment > 0 ? Math.min(IPv6Address.BIT_COUNT, getNetworkPrefixLength() + adjustment) : Math.max(0, getNetworkPrefixLength() + adjustment);
			return new IPAddressString(IPAddressNetwork.getPrefixString(newBits), validationOptions);
		}
		IPAddress address = getAddress();
		if(address == null) {
			return null;
		}
		if(adjustment == 0) {
			return this;
		}
		Integer prefix = address.getNetworkPrefixLength();
		if(prefix != null && prefix + adjustment < 0 && address.isPrefixBlock()) {
			return new IPAddressString(IPAddress.SEGMENT_WILDCARD_STR, validationOptions);
		}
		return address.adjustPrefixLength(adjustment).toAddressString();
	}
	
	/**
	 * Given a string with comma delimiters to denote segment elements, this method will count the possible combinations.
	 * <p>
	 * For example, given "1,2.3.4,5.6" this method will return 4 for the possible combinations: "1.3.4.6", "1.3.5.6", "2.3.4.6" and "2.3.5.6"
	 * <p>
	 * @param str
	 * @return
	 */
	public static int countDelimitedAddresses(String str) {
		int segDelimitedCount = 0;
		int result = 1;
		for(int i = 0; i < str.length(); i++) {
			char c = str.charAt(i);
			if(isDelimitedBoundary(c)) {
				if(segDelimitedCount > 0) {
					result *= segDelimitedCount + 1;
					segDelimitedCount = 0;
				}
			} else if(c == SEGMENT_VALUE_DELIMITER) {
				segDelimitedCount++;
			}
		}
		if(segDelimitedCount > 0) {
			result *= segDelimitedCount + 1;
		}
		return result;
	}
	
	private static boolean isDelimitedBoundary(char c) {
		return c == IPv4Address.SEGMENT_SEPARATOR ||
				c == IPv6Address.SEGMENT_SEPARATOR ||
				c == Address.RANGE_SEPARATOR ||
				c == MACAddress.DASHED_SEGMENT_RANGE_SEPARATOR;
	}
	
	/**
	 * Given a string with comma delimiters to denote segment elements, this method will provide an iterator to iterate through the possible combinations.
	 * <p>
	 * For example, given "1,2.3.4,5.6" this will iterate through "1.3.4.6", "1.3.5.6", "2.3.4.6" and "2.3.5.6"
	 * <p>
	 * Another example: "1-2,3.4.5.6" will iterate through "1-2.4.5.6" and "1-3.4.5.6".
	 * <p>
	 * This method will not validate strings.  Each string produced can be validated using an instance of IPAddressString.
	 * 
	 * @param str
	 * @return
	 */
	public static Iterator<String> parseDelimitedSegments(String str) { 
		List<List<String>> parts = null;
		int lastSegmentStartIndex = 0;
		int lastPartIndex = 0;
		int lastDelimiterIndex = 0;
		boolean anyDelimited = false;
		List<String> delimitedList = null;
		for(int i = 0; i < str.length(); i++) {
			char c = str.charAt(i);
			if(isDelimitedBoundary(c)) {
				if(delimitedList != null) {
					if(parts == null) {
						parts = new ArrayList<List<String>>(8);
					}
					addParts(str, parts, lastSegmentStartIndex, lastPartIndex, lastDelimiterIndex, delimitedList, i);
					lastPartIndex = i;
					delimitedList = null;
				}
				lastSegmentStartIndex = lastDelimiterIndex = i + 1; 
			} else if(c == SEGMENT_VALUE_DELIMITER) {
				anyDelimited = true;
				if(delimitedList == null) {
					delimitedList = new ArrayList<String>();
				}
				String sub = str.substring(lastDelimiterIndex, i);
				delimitedList.add(sub);
				lastDelimiterIndex = i + 1;
			}
		}
		if(anyDelimited) {
			if(delimitedList != null) {
				if(parts == null) {
					parts = new ArrayList<List<String>>(8);
				}
				addParts(str, parts, lastSegmentStartIndex, lastPartIndex, lastDelimiterIndex, delimitedList, str.length());
			} else {
				parts.add(Arrays.asList(new String[] {str.substring(lastPartIndex, str.length())}));
			}
			return iterator(parts);
		}
		return new Iterator<String>() {
			boolean done;
			
			@Override
			public boolean hasNext() {
				return !done;
			}

		    @Override
			public String next() {
		    	if(done) {
		    		throw new NoSuchElementException();
		    	}
		    	done = true;
		    	return str;
		    }

		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}
	
	private static Iterator<String> iterator(List<List<String>> parts) {
		return new Iterator<String>() {
			private boolean done;
			final int partCount = parts.size();
			
			@SuppressWarnings("unchecked")
			private final Iterator<String> variations[] = new Iterator[partCount];
			
			private String nextSet[] = new String[partCount];  {
				updateVariations(0);
			}
			
			private void updateVariations(int start) {
				for(int i = start; i < partCount; i++) {
					variations[i] = parts.get(i).iterator();
					nextSet[i] = variations[i].next();
				}
			}
			
			@Override
			public boolean hasNext() {
				return !done;
			}
			
		    @Override
			public String next() {
		    	if(done) {
		    		throw new NoSuchElementException();
		    	}
		    	StringBuilder result = new StringBuilder();
		    	for(int i = 0; i < partCount; i++) {
		    		result.append(nextSet[i]);
		    	}
		    	increment();
		    	return result.toString();
		    }
		    
		    private void increment() {
		    	for(int j = partCount - 1; j >= 0; j--) {
		    		if(variations[j].hasNext()) {
		    			nextSet[j] = variations[j].next();
		    			updateVariations(j + 1);
		    			return;
		    		}
		    	}
		    	done = true;
		    }

		    @Override
			public void remove() {
		    	throw new UnsupportedOperationException();
		    }
		};
	}

	private static void addParts(String str, List<List<String>> parts, int lastSegmentStartIndex, int lastPartIndex,
			int lastDelimiterIndex, List<String> delimitedList, int i) {
		String sub = str.substring(lastDelimiterIndex, i);
		delimitedList.add(sub);
		if(lastPartIndex != lastSegmentStartIndex) {
			parts.add(Arrays.asList(new String[] {str.substring(lastPartIndex, lastSegmentStartIndex)}));
		}
		parts.add(delimitedList);
	}

	/**
	 * Converts this address to a prefix length
	 * 
	 * @return the prefix of the indicated IP type represented by this address or null if this address is valid but cannot be represented by a network prefix length
	 * @throws AddressStringException if the address is invalid
	 */
	public String convertToPrefixLength() throws AddressStringException {
		IPAddress address = getAddress();
		Integer prefix;
		if(address == null) {
			prefix = getNetworkPrefixLength(); // handles prefix-only, but also handles cases of IncompatibleAddressException in which there is a prefix length
			if(prefix == null) {
				return null;
			}
		} else {
			prefix = address.getBlockMaskPrefixLength(true);
			if(prefix == null) {
				return null;
			}
		}
		return IPAddressSegment.toUnsignedString(prefix, 10, 
				new StringBuilder(IPAddressSegment.toUnsignedStringLength(prefix, 10) + 1).append(IPAddress.PREFIX_LEN_SEPARATOR)).toString();
	}

	private static String toNormalizedString(IPAddressProvider addressProvider) throws IncompatibleAddressException {
		String result;
		if(addressProvider.isProvidingAllAddresses()) {
			result = IPAddress.SEGMENT_WILDCARD_STR;
		} else if(addressProvider.isProvidingEmpty()) {
			result = "";
		} else if(addressProvider.isProvidingPrefixOnly()) {
			result = IPAddressNetwork.getPrefixString(addressProvider.getProviderNetworkPrefixLength());
		} else if(addressProvider.isProvidingIPAddress()) {
			result = addressProvider.getProviderAddress().toNormalizedString();
		} else {
			result = null;
		}
		return result;
	}
	
	@Override
	public String toNormalizedString() {
		if(isValid()) {
			try {
				return toNormalizedString(addressProvider);
			} catch(IncompatibleAddressException e) {}
		}
		return toString();
	}

	/**
	 * Gives us the original string provided to the constructor.  
	 * For variations on this string, call {@link #getAddress()}/{@link #toAddress()} and then use string methods on the address object.
	 */
	@Override
	public String toString() {
		return fullAddr;
	}
}
