package inet.ipaddr;

/**
 * 
 * @author sfoley
 *
 */
public class IPAddressStringException extends HostIdentifierException {

	private static final long serialVersionUID = 1L;
	
	private static String errorMessage = getMessage("ipaddress.address.error");
	
	public IPAddressStringException(String str, String key, Throwable cause) {
		super(str, errorMessage, key, cause);
	}
	
	public IPAddressStringException(String str, String key) {
		super(str, errorMessage, key);
	}
	
	public IPAddressStringException(String str, int characterIndex, boolean combo) {
		super(str + ' ' + errorMessage + ' ' + 
				getMessage(combo ? "ipaddress.error.invalid.character.combination.at.index" : "ipaddress.error.invalid.character.at.index") + ' ' + characterIndex);
	}
	
	public IPAddressStringException(String key) {
		super(key, errorMessage);
	}
}
