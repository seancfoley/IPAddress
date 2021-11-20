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

package inet.ipaddr.format.validate;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameException;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.MACAddressString;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * Interface for validation and parsing of host identifier strings
 * 
 * @author sfoley
 *
 */
public interface HostIdentifierStringValidator {
	
	public static final int MAX_PREFIX = IPv6Address.BIT_COUNT;//the largest allowed value x for a /x prefix following an address or host name
	public static final int MAX_PREFIX_CHARS = Integer.toString(MAX_PREFIX).length();
	public static final String SMTP_IPV6_IDENTIFIER = "IPv6:";
	public static final char IPvFUTURE= 'v';
	
	ParsedHost validateHost(HostName fromHost) throws HostNameException;
	
	/**
	 * 
	 * @param fromString
	 * @return
	 * @throws AddressStringException
	 */
	IPAddressProvider validateAddress(IPAddressString fromString) throws AddressStringException;
	
	MACAddressProvider validateAddress(MACAddressString fromString) throws AddressStringException;
	
	int validatePrefix(CharSequence fullAddr, IPVersion version) throws AddressStringException;
}

///**
// * Interface for validation and parsing of host identifier strings
// * 
// * @author sfoley
// *
// */
//public interface HostIdentifierStringValidator {
//	
//	public static final int MAX_PREFIX = IPv6Address.BIT_COUNT;//the largest allowed value x for a /x prefix following an address or host name
//	public static final int MAX_PREFIX_CHARS = Integer.toString(MAX_PREFIX).length();
//	public static final String SMTP_IPV6_IDENTIFIER = "IPv6:";
//	public static final char IPvFUTURE= 'v';
//	
//	ParsedHost validateHostName(HostName fromHost) throws HostNameException;
//	
//	/**
//	 * 
//	 * @param fromString
//	 * @return
//	 * @throws AddressStringException
//	 */
//	IPAddressProvider validateIPAddressStr(IPAddressString fromString) throws AddressStringException;
//	
//	MACAddressProvider validateMACAddressStr(MACAddressString fromString) throws AddressStringException;
//	
//	int validatePrefixLenString(CharSequence fullAddr, IPVersion version) throws AddressStringException;
//
//	//TODO these methods are renamed...
//	// make backwards compatible, 
//	//I think you need to make the new methods default, calling the old methods
//	// and the old ones deprecated, calling the new ones, 
//	// but of course that's ugly because you can then implement nothung and end up with infinite recursion.
//	
//	//So, instead you need a new interface instead for the new stuff.  Old interface is deprecated.
//	// Our code uses the new stuff.
//	
//	// But then again, HostIdentifierStringValidator is only public for access internally from other packages
//	// It has no role in the API.
//	// So no need for any of that, really.  Stuff like this means you will perhaps need to do a major version perhaps.
//	// But then you will need some new functionality to justify.  Hmmm.
//	//
//	// In reality there will be a lot of methods renamed, because of name overloading
//	// so you may want to up the version, although you can perhaps keep all the old ones too.
//	
//	//TODO I am starting to lean away from renaming things public unless very good reason, matching go is not a good enough reason
//	// although these ones are semi-public, not really public, so maybe ok
//	
////	default ParsedHost validateHost(HostName fromHost) {
////		return validateHostName()
////	}
////
////	IPAddressProvider validateAddress(IPAddressString fromString) throws AddressStringException;
////	
////	MACAddressProvider validateAddress(MACAddressString fromString) throws AddressStringException;
////	
////	int validatePrefix(CharSequence fullAddr, IPVersion version) throws AddressStringException;
//
//}
