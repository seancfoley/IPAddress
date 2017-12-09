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

import java.io.Serializable;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IPAddress.IPVersion;

/**
 * The result of parsing a qualifier for a host name or address, the qualifier being either a mask, prefix length, or zone that follows the string.
 * 
 * @author sfoley
 *
 */
class ParsedHostIdentifierStringQualifier implements Serializable {

	private static final long serialVersionUID = 4L;

	/* if there is a prefix length for the address, this will be its numeric value */
	private final Integer networkPrefixLength; //non-null for a prefix-only address, sometimes non-null for IPv4, IPv6

	/* if there is a port for the host, this will be its numeric value */
	private final Integer port; //non-null for a host with port

	/* if instead of a prefix a mask was provided, this is the mask */
	private final ParsedIPAddress mask;

	/* this is the IPv6 scope id or network interface name */
	private final CharSequence zone;

	ParsedHostIdentifierStringQualifier() {
		this(null, null, null, null);
	}

	ParsedHostIdentifierStringQualifier(Integer networkPrefixLength, Integer port) {
		this(networkPrefixLength, null, null, port);
	}

	ParsedHostIdentifierStringQualifier(ParsedIPAddress mask) {
		this(null, mask, null, null);
	}

	ParsedHostIdentifierStringQualifier(CharSequence zone) {
		this(null, null, zone, null);
	}

	private ParsedHostIdentifierStringQualifier(Integer networkPrefixLength, ParsedIPAddress mask, CharSequence zone, Integer port) {
		this.networkPrefixLength = networkPrefixLength;
		this.mask = mask;
		this.zone = zone;
		this.port = port;
	}

	IPAddress getMask() {
		if(mask != null) {
			return mask.createAddresses().getAddress();
		}
		return null;
	}

	CharSequence getZone() {
		return zone;
	}

	Integer getNetworkPrefixLength() {
		return networkPrefixLength;
	}

	Integer getPort() {
		return port;
	}

	IPVersion inferVersion(IPAddressStringParameters validationOptions) {
		if(networkPrefixLength != null) {
			if(networkPrefixLength > IPAddress.getBitCount(IPVersion.IPV4) && 
					!validationOptions.getIPv4Parameters().allowPrefixesBeyondAddressSize) {
				return IPVersion.IPV6;
			}
		} else if(mask != null) {
			if(mask.isIPv6()) {
				return IPVersion.IPV6;
			} else if(mask.isIPv4()) {
				return IPVersion.IPV4;
			}
		} else if (zone != null) {
			return IPVersion.IPV6;
		}
		return null;
	}

	@Override
	public String toString() {
		return "network prefix length: " + networkPrefixLength +
				" mask: " + mask +
				" zone: " + zone + 
				" port: " + port;			
	}
}
