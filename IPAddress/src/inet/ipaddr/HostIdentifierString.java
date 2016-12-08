package inet.ipaddr;

/**
 * A string that is used to identify an internet host.
 * 
 * @author sfoley
 *
 */
interface HostIdentifierString {
	
	/**
	 * provides a unique normalized String representation for the host identified by this HostIdentifierString instance
	 *  
	 * @return the normalized string
	 */
	String toNormalizedString();
}
