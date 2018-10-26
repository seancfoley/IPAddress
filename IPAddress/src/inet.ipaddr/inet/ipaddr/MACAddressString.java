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

import java.util.Iterator;

import inet.ipaddr.format.validate.HostIdentifierStringValidator;
import inet.ipaddr.format.validate.MACAddressProvider;
import inet.ipaddr.format.validate.MACAddressProvider.ParsedMACAddressProvider;
import inet.ipaddr.format.validate.Validator;
import inet.ipaddr.mac.MACAddress;

/* 
 * Some MAC address resources:
 * https://supportforums.cisco.com/document/100566/understanding-ipv6-eui-64-bit-address
 * http://aruljohn.com/mac.pl
 * https://standards.ieee.org/events/automotive/2014/18_Looming_Ethernet_MAC_Address_Crisis.pdf
 * https://standards.ieee.org/develop/regauth/oui/index.html
 * 
 * https://en.wikipedia.org/wiki/IPv6_address#Modified_EUI-64
 * https://en.wikipedia.org/wiki/MAC_address
 * http://packetlife.net/blog/2008/aug/4/eui-64-ipv6/
 * 
 * Nice resource on IPv6 vs IPv4 and lots of stuff including MAC: https://communities.bmc.com/docs/DOC-19235
 * 
 */
/**
 * Parses the string representation of a MAC address.  Such a string can represent just a single address or a set of addresses like 1:*:1-3:1-4:5:6
 * <p>
 * This supports a wide range of address formats and provides specific error messages, and allows specific configuration.
 * <p>
 * You can control all of the supported formats using {@link MACAddressStringParameters.Builder} to build a parameters instance of {@link MACAddressStringParameters}.
 * When not using the constructor that takes a {@link MACAddressStringParameters}, a default instance of {@link MACAddressStringParameters} is used that is generally permissive.
 * <p>
 * <h2>Supported formats</h2>
 * <p>
 * Ranges are supported:
 * <ul>
 * <li>wildcards '*' and ranges '-' (for example 1:*:1-3:1-4:5:6), useful for working with subnets</li>
 * <li>SQL wildcards '%" and "_", although '%' is considered an SQL wildcard only when it is not considered an IPv6 zone indicator</li>
 * </ul>
 * <p>
 * The different methods of representing MAC addresses are supported:
 * <ul>
 * <li>6 or 8 bytes in hex representation like aa:bb:cc:dd:ee:ff </li>
 * <li>The same but with a hyphen separator like aa-bb-cc-dd-ee-ff (the range separator in this case becomes '/')</li>
 * <li>The same but with space separator like aa bb cc dd ee ff</li>
 * <li>The dotted representation, 4 sets of 12 bits in hex representation like aaa.bbb.ccc.ddd</li>
 * <li>The 12 or 16 hex representation with no separators like aabbccddeeff</li>
 * </ul>
 * <p>
 * All of the above range variations also work for each of these ways of representing MAC addresses.
 * <p>
 * Some additional formats:
 * <ul>
 * <li>null or empty strings representing an unspecified address</li>
 * <li>the single wildcard address "*" which represents all MAC addresses</li>
 * </ul>
 * <p>
 * <h2>Usage</h2>
 * Once you have constructed a MACAddressString object, you can convert it to an MACAddress object with various methods.  
 * It is as simple as:<br>
 * <pre><code>
 * {@link MACAddress} address = new {@link MACAddressString}("1.2.3.4").{@link #getAddress()};
 * </code></pre>
 * <p>
 * If your application takes user input IP addresses, you can validate with:
 * <pre><code>
 * try {
 *  {@link MACAddress} address = new MACAddressString("1.2.3.4").{@link #toAddress()};
 * } catch({@link AddressStringException} e) {
 *	//e.getMessage() provides description of validation failure
 * }
 * </code></pre>
 * For empty addresses, both {@link #toAddress()} and {@link #getAddress()} returns null.  For invalid addresses, {@link #getAddress()} returns null.
 * <p>
 * This class is thread-safe.  In fact, MACAddressString objects are immutable.  
 * A MACAddressString object represents a single MAC address representation that cannot be changed after construction.
 * Some of the derived state is created upon demand and cached, such as the derived MACAddress instances.
 * <p>
 * 
 * @custom.core
 * @author sfoley
 *
 */
public class MACAddressString implements HostIdentifierString, Comparable<MACAddressString> {
	
	private static final long serialVersionUID = 4L;

	/* Generally permissive, settings are the default constants in MACAddressStringParameters.  */
	private static final MACAddressStringParameters DEFAULT_BASIC_VALIDATION_OPTIONS = new MACAddressStringParameters.Builder().toParams();
	
	public static final MACAddressString EMPTY_ADDRESS = new MACAddressString(""); //represents a blank address /* address string creation */
	public static final MACAddressString ALL_ADDRESSES = new MACAddressString(IPAddress.SEGMENT_WILDCARD_STR); //represents any MAC address /* address string creation */
	
	final MACAddressStringParameters validationOptions;
	
	/* the full original string address  */
	final String fullAddr;

	// fields for validation state

	/* exceptions and booleans for validation - for type INVALID it is non-null */
	private AddressStringException cachedException;
	
	// an object created by parsing that will provide the associated IPAddress(es)
	private MACAddressProvider parsedAddress;
	
	private Boolean isValid;
		
	/**
	 * Constructs an MACAddressString instance using the given String instance.
	 * 
	 * @param addr the address in string format, in some valid MAC address form.
	 * <p>
	 *		You can also alter the addresses to include ranges using the wildcards * and -, such as 1:*:1-2:3:4:5.
	 */
	public MACAddressString(String addr) {
		this(addr, DEFAULT_BASIC_VALIDATION_OPTIONS);
	}
	
	/**
	 * @param addr the address in string format
	 * 
	 * 	This constructor allows you to alter the default validation options.
	 */
	public MACAddressString(String addr, MACAddressStringParameters valOptions) {
		if(addr == null) {
			fullAddr = addr = "";
		} else {
			addr = addr.trim();
			fullAddr = addr;
		}
		this.validationOptions = valOptions;
	}
	
	public MACAddressString(MACAddress address) {
		validationOptions = null; // no validation required, already validated
		fullAddr = address.toNormalizedString();
		initByAddress(address);
	}

	void cacheAddress(MACAddress address) {
		initByAddress(address);
	}

	void initByAddress(MACAddress address) {
		this.parsedAddress = new ParsedMACAddressProvider(address);
		isValid = true;
	}

	public MACAddressStringParameters getValidationOptions() {
		return validationOptions;
	}

	/**
	 * @return whether this address represents the set of all addresses with the same prefix
	 */
	public boolean isPrefixed() {
		MACAddress addr = getAddress();
		return addr != null && addr.isPrefixed();
	}
	
	/**
	 * @return if this address is a valid prefixed address this returns that prefix length, otherwise returns null
	 */
	public Integer getPrefixLength() {
		MACAddress addr = getAddress();
		if(addr != null) {
			return addr.getPrefixLength();
		}
		return null;
	}
	
	/**
	 * @return whether the address represents the set all all valid MAC addresses 
	 */
	public boolean isAllAddresses() {
		MACAddress addr = getAddress();
		return addr != null && addr.isAllAddresses();
	}
	
	/**
	 * Returns true if the address is empty (zero-length).
	 * @return
	 */
	public boolean isEmpty() {
		return isValid() && getAddress() == null;
	}

	public boolean isZero() {
		MACAddress value = getAddress();
		return value != null && value.isZero();
	}
	
	/**
	 * @return whether the address represents one of the accepted address types, which are:
	 * a MAC address, the address representing all addresses of all types, or an empty string.
	 * If it does not, and you want more details, call validate() and examine the thrown exception.
	 */
	public boolean isValid() {
		if(isValid == null) {
			try {
				validate();
				return true;
			} catch(AddressStringException e) {
				return false;
			}
		}
		return isValid;
	}
	
	private boolean isValidated() throws AddressStringException {
		if(isValid != null) {
			if(cachedException != null) {
				throw cachedException;
			}
			return true;
		}
		return false;
	}

	/**
	 * Validates this string is a valid address, and if not, throws an exception with a descriptive message indicating why it is not.
	 * @throws AddressStringException
	 */
	@Override
	public void validate() throws AddressStringException {
		if(isValidated()) {
			return;
		}
		synchronized(this) {
			if(isValidated()) {
				return;
			}
			//we know nothing about this address.  See what it is.
			try {
				parsedAddress = getValidator().validateAddress(this);
				isValid = true;
			} catch(AddressStringException e) {
				cachedException = e;
				isValid = false;
				throw e;
			}
		}
	}

	protected HostIdentifierStringValidator getValidator() {
		return Validator.VALIDATOR;
	}

	@Override
	public int hashCode() {
		if(isValid() && !isEmpty()) {
			return getAddress().hashCode();
		}
		return toString().hashCode();
	}

	@Override
	public int compareTo(MACAddressString other) {
		if(this == other) {
			return 0;
		}
		if(isValid()) {
			if(other.isValid()) {
				if(isEmpty()) {
					if(other.isEmpty()) {
						return 0;
					}
					return -1;
				} else if(other.isEmpty()) {
					return 1;
				}
				return getAddress().compareTo(other.getAddress());
			}
			return 1;
		}
		if(other.isValid()) {
			return -1;
		}
		return toString().compareTo(other.toString());
	}
	
	/**
	 * Two MACAddressString objects are equal if they represent the same set of addresses.
	 * 
	 * If a MACAddressString is invalid, it is equal to another address only if the other address was constructed from the same string.
	 * 
	 */
	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof MACAddressString) {
			MACAddressString other = (MACAddressString) o;	
			//if they have the same string, they must be the same,
			//but the converse is not true, if they have different strings, they can still be the same

			// Also note that we do not call equals() on the validation options, this is intended as an optimization,
			// and probably better to avoid going through all the validation objects here
			boolean stringsMatch = toString().equals(other.toString());
			if(stringsMatch && validationOptions == other.validationOptions) {
				return true;
			}
			if(isEmpty()) {
				return other.isEmpty();
			}
			if(isValid()) {
				if(other.isValid()) {
					return getAddress().equals(other.getAddress());
				}
			} else if(!other.isValid()) {
				return stringsMatch; // Two invalid addresses are not equal unless strings match, regardless of validation options
			}
		}
		return false;
	}
	
	/**
	 * Produces the {@link MACAddress} corresponding to this MACAddressString.  
	 * 
	 * If this object does not represent a specific MACAddress or a ranged MACAddress, 
	 * or if the string used to construct this object is not a known format, null is returned.
	 * 
	 * It is equivalent to {@link #toAddress()} except for the fact that it does not throw AddressStringException for invalid address formats.
	 * 
	 */
	@Override
	public MACAddress getAddress() {
		if(isValid()) { //Avoid the exception the second time with this check
			return parsedAddress.getAddress();
		}
		return null;
	}

	/**
	 * Produces the {@link MACAddress} corresponding to this MACAddressString.  If this object does not represent a specific MACAddress or a ranged MACAddress, null is returned,
	 * which may be the case if this object represents the empty address string.
	 * 
	 * If the string used to construct this object is not a known format then this method throws AddressStringException, unlike the equivalent method {@link #getAddress()} which simply returns null in such cases.
	 * 
	 * As long as this object represents a valid address (but not necessarily a specific address), this method does not throw.
	 * 
	 * @throws AddressStringException if the address format is invalid
	 * @throws IncompatibleAddressException if a valid address string representing multiple addresses cannot be represented
	 * 
	 */
	@Override
	public MACAddress toAddress() throws AddressStringException, IncompatibleAddressException {
		validate(); //call validate so that we throw consistently, cover type == INVALID, and ensure the addressProvider exists
		return parsedAddress.getAddress();
	}

	@Override
	public String toNormalizedString() {
		MACAddress addr = getAddress();
		if(addr != null) {
			return addr.toNormalizedString();
		}
		return toString();
	}

	/**
	 * Gives us the original string provided to the constructor.  For variations, call {@link #getAddress()}/{@link #toAddress()} and then use string methods on the address object.
	 */
	@Override
	public String toString() {
		return fullAddr;
	}

	/**
	 * Given a string with comma delimiters to denote segment elements, this method will count the possible combinations.
	 * 
	 * For example, given "1,2:3:4,5:6:7:8", this method will return 4 for the possible combinations: "1:3:4:6:7:8", "1:3:5:6:7:8", "2:3:4:6:7:8" and "2:3:5:6:7:8"
	 * 
	 * @param str
	 * @return
	 */
	public static int countDelimitedAddresses(String str) {
		return IPAddressString.countDelimitedAddresses(str);
	}

	/**
	 * Given a string with comma delimiters to denote segment elements, this method will provide an iterator to iterate through the possible combinations.
	 * 
	 * 
	 * For example, given "1,2:3:4,5:6:7:8" this will iterate through "1:3:4:6:7:8", "1:3:5:6:7:8", "2:3:4:6:7:8" and "2:3:5:6:7:8"
	 * 
	 * Another example: "1-2,3:4:5:6:7:8" will iterate through "1-2:4:5:6:7:8" and "1-3:4:5:6:7:8"
	 * 
	 * This method will not validate strings.  Each string produced can be validated using an instance of MACAddressString.
	 * 
	 * @param str
	 * @return
	 */
	public static Iterator<String> parseDelimitedSegments(String str) { 
		return IPAddressString.parseDelimitedSegments(str);
	}
}
