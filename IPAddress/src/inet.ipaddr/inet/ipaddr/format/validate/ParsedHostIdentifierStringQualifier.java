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
public class ParsedHostIdentifierStringQualifier implements Serializable {

	private static final long serialVersionUID = 4L;

	/* if there is a prefix length for the address, this will be its numeric value */
	private Integer networkPrefixLength; //non-null for a prefix-only address, sometimes non-null for IPv4, IPv6

	/* if there is a port for the host, this will be its numeric value */
	private final Integer port; //non-null for a host with port
	private final CharSequence service; //non-null for host with a service instead of a port

	/* if instead of a prefix a mask was provided, this is the mask */
	private ParsedIPAddress mask;

	/* this is the IPv6 scope id or network interface name */
	private final CharSequence zone;

	ParsedHostIdentifierStringQualifier() {
		this(null, null, null, null, null);
	}
	
	ParsedHostIdentifierStringQualifier(CharSequence zone) {
		this(null, null, zone, null, null);
	}
	
	ParsedHostIdentifierStringQualifier(CharSequence zone, Integer port) {
		this(null, null, zone, port, null);
	}
	
	ParsedHostIdentifierStringQualifier(Integer networkPrefixLength, CharSequence zone) {
		this(networkPrefixLength, null, zone, null, null);
	}
	
	ParsedHostIdentifierStringQualifier(ParsedIPAddress mask, CharSequence zone) {
		this(null, mask, zone, null, null);
	}

	ParsedHostIdentifierStringQualifier(CharSequence zone, CharSequence service) {
		this(null, null, zone, null, service);
		if(zone != null && service != null) {
			throw new IllegalArgumentException();
		}
	}

	private ParsedHostIdentifierStringQualifier(Integer networkPrefixLength, ParsedIPAddress mask, CharSequence zone, Integer port, CharSequence service) {
		this.networkPrefixLength = networkPrefixLength;
		this.mask = mask;
		this.zone = zone;
		this.port = port;
		this.service = service;
	}
	
	void mergePrefix(ParsedHostIdentifierStringQualifier other) {
		if(other.mask != null) {
			this.mask = other.mask;
		}
		if(other.networkPrefixLength != null) {
			this.networkPrefixLength = other.networkPrefixLength;
		}
	}

	IPAddress getMask() {
		if(mask != null) {
			return mask.createAddresses().getAddress();
		}
		return null;
	}
	
	Integer getEquivalentPrefixLength() {
		Integer pref = getNetworkPrefixLength();
		if(pref == null) {
			IPAddress mask = getMask();
			if(mask != null) {
				pref = mask.getBlockMaskPrefixLength(true);
			}
		}
		return pref;
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
	
	CharSequence getService() {
		return service;
	}
	
	IPVersion inferVersion(IPAddressStringParameters validationOptions) {
		if(networkPrefixLength != null) {
			if(networkPrefixLength > IPAddress.getBitCount(IPVersion.IPV4) && 
					!validationOptions.getIPv4Parameters().allowPrefixesBeyondAddressSize) {
				return IPVersion.IPV6;
			}
		} else if(mask != null) {
			if(mask.isProvidingIPv6()) {
				return IPVersion.IPV6;
			} else if(mask.isProvidingIPv4()) {
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
				" port: " + port + 
				" service: " + service;			
	}
}
