package inet.ipaddr;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.IPAddressDivision;

/**
 * Represents situations when an object represents a valid type or format but that type does not match the required type or format for a given operation.
 * 
 * @author sfoley
 *
 */
public class IPAddressTypeException extends RuntimeException {
	
	private static final long serialVersionUID = 1L;
	
	private static String errorMessage = getMessage("ipaddress.address.error");
	
	static String getMessage(String key) {
		return IPAddressStringException.getMessage(key);
	}
	
	public IPAddressTypeException(IPAddress one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressSection one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(String one, String key) {
		super(one + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(long lower, long upper, String key) {
		super(lower + "-" + upper + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressSection one, int prefixLength, String key) {
		super(one + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressDivision one, int prefixLength, String key) {
		super(one + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressDivision one, String key) {
		super(one + " , " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(int prefixLength, IPVersion version, String key) {
		super(version + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(int prefixLength, String key) {
		super(prefixLength + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(CharSequence prefixLength, IPVersion version, String key, Throwable cause) {
		super(version + " /" + prefixLength + ", " + errorMessage + " " + getMessage(key), cause);
	}
	
	public IPAddressTypeException(IPAddressSegment one, int oneIndex, IPAddressSegment two, int twoIndex, String key) {
		super((oneIndex + 1) + ":" + one + ", " + (twoIndex + 1) + ":" + two + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressSegment one, IPAddressSegment two, String key) {
		super(one + ", " + two + ", " + errorMessage + " " + getMessage(key));
	}
	
	public IPAddressTypeException(IPAddressSection one, IPAddressSection two, String key) {
		super(one + ", " + two + ", " + errorMessage + " " + getMessage(key));
	}
}
