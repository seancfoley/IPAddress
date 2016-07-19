package inet.ipaddr;

/**
 * 
 * @author sfoley
 *
 */
public class HostNameException extends HostIdentifierException {

	private static final long serialVersionUID = 1L;
	
	private static String errorMessage = getMessage("ipaddress.host.error");
	
	public HostNameException(String host, int index) {
		super(host + " " + errorMessage + " " + getMessage("ipaddress.host.error.invalid.character.at.index") + ' ' + index);
	}
	
	public HostNameException(String host, String key) {
		super(host, errorMessage, key);
	}
	
	public HostNameException(String host, IPAddressStringException e, String key) {
		super(host, errorMessage, key, e);
	}
}
