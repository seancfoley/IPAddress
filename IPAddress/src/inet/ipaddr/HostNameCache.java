package inet.ipaddr;

import java.util.Map;

/**
 * Choose a map of your choice to implement a cache of host names and resolved addresses.
 *
 * @author sfoley
 *
 */
public class HostNameCache extends HostIdentifierStringCache<HostName> implements HostIdentifierStringCache.HostIdentifierStringCreator<HostName> {
	HostNameParameters options;

	public HostNameCache(Map<String, HostName> backingMap, HostNameParameters options) {
		this(backingMap);
		this.options = options;
	}
	
	public HostNameCache(Map<String, HostName> backingMap) {
		super(backingMap);
		creator = this;
	}

	@Override
	public HostName create(String key) throws HostIdentifierException {
		return options == null ? new HostName(key) : new HostName(key, options);
	}
}
