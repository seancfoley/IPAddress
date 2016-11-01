package inet.ipaddr;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * 
 * @author sfoley
 *
 */
public class HostIdentifierException extends Exception {

	private static final long serialVersionUID = 1L;

	static ResourceBundle bundle;
	
	static {
		String propertyFileName = "IPAddressResources";
		String name = HostIdentifierException.class.getPackage().getName() + '.' + propertyFileName;
		try {
			bundle = ResourceBundle.getBundle(name);
		} catch (MissingResourceException e) {
			System.err.println("bundle " + name + " is missing");
		}
	}
	
	public HostIdentifierException(String str, String errorMessage, String key, Throwable cause) {
		super(str + ' ' + errorMessage + ' ' + getMessage(key), cause);
	}
	
	public HostIdentifierException(String str, String errorMessage, String key) {
		super(str + ' ' + errorMessage + ' ' + getMessage(key));
	}
	
	public HostIdentifierException(String message) {
		super(message);
	}
	
	public HostIdentifierException(String errorMessage, String key) {
		super(errorMessage + ' ' + getMessage(key));
	}

	public static String getMessage(String key) {
		if(bundle != null) {
			try {
				return bundle.getString(key);
				
			} catch (MissingResourceException e1) {}
		}
		return key;
	}
}
