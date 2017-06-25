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

package inet.ipaddr.format.validate;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameException;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringException;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * Interface for validation and parsing of host identifier strings
 * 
 * @author sfoley
 *
 */
public interface HostIdentifierStringValidator {
	
	public static final int MAX_PREFIX = IPv6Address.BIT_COUNT;
	public static final int MAX_PREFIX_CHARS = Integer.toString(MAX_PREFIX).length();
	public static final String SMTP_IPV6_IDENTIFIER = "IPv6:";
	
	ParsedHost validateHost(HostName fromHost) throws HostNameException;
	
	AddressProvider validateAddress(IPAddressString fromString) throws IPAddressStringException;
	
	int validatePrefix(CharSequence fullAddr, IPVersion version) throws IPAddressStringException;
}
