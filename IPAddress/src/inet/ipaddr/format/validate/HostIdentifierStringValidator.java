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
	 * @param stringChars optional, the characters to be parsed.  If null, fromString.toString() is used.
	 * @return
	 * @throws AddressStringException
	 */
	IPAddressProvider validateAddress(IPAddressString fromString) throws AddressStringException;
	
	MACAddressProvider validateAddress(MACAddressString fromString) throws AddressStringException;
	
	int validatePrefix(CharSequence fullAddr, IPVersion version) throws AddressStringException;
}
