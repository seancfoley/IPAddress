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
class ParsedAddressQualifier implements Serializable {

	private static final long serialVersionUID = 1L;

	/* if there is a prefix length for the address, this will be its numeric value */
	private final Integer networkPrefixLength; //non-null for a prefix-only address, sometimes non-null for IPv4, IPv6
	
	/* if instead of a prefix a mask was provided, this is the mask */
	private final ParsedAddress mask;
	
	/* this is the IPv6 scope id or network interface name */
	private final String zone;
	
	ParsedAddressQualifier() {
		this(null, null, null);
	}
	
	ParsedAddressQualifier(Integer networkPrefixLength) {
		this(networkPrefixLength, null, null);
	}
	
	ParsedAddressQualifier(ParsedAddress mask) {
		this(null, mask, null);
	}
	
	ParsedAddressQualifier(String zone) {
		this(null, null, zone);
	}
	
	private ParsedAddressQualifier(Integer networkPrefixLength, ParsedAddress mask, String zone) {
		this.networkPrefixLength = networkPrefixLength;
		this.mask = mask;
		this.zone = zone;
	}
	
	IPAddress getMask() {
		if(mask != null) {
			return mask.createAddress();
		}
		return null;
	}
	
	String getZone() {
		return zone;
	}
	
	Integer getNetworkPrefixLength() {
		return networkPrefixLength;
	}
	
	IPVersion inferVersion(IPAddressStringParameters validationOptions) {
		if(networkPrefixLength != null) {
			if(networkPrefixLength > IPAddress.bitCount(IPVersion.IPV4) && 
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
}
