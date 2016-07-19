package inet.ipaddr;

import java.util.Map;

/**
 * Choose a map of your choice to implement a cache of address strings and addresses.
 *
 * @author sfoley
 *
 */
public class IPAddressStringCache extends HostIdentifierStringCache<IPAddressString> implements HostIdentifierStringCache.HostIdentifierStringCreator<IPAddressString> {
	IPAddressStringParameters options;

	public IPAddressStringCache(Map<String, IPAddressString> backingMap, IPAddressStringParameters options) {
		this(backingMap);
		this.options = options;
	}
	
	public IPAddressStringCache(Map<String, IPAddressString> backingMap) {
		super(backingMap);
		creator = this;
	}

	@Override
	public IPAddressString create(String key) throws HostIdentifierException {
		return options == null ? new IPAddressString(key) : new IPAddressString(key, options);
	}
}
