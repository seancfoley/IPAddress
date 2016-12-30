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
