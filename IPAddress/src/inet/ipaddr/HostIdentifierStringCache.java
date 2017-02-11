package inet.ipaddr;

import java.util.Map;
import java.util.concurrent.ConcurrentMap;

/**
 * Choose a map of your choice to implement a cache of addresses and/or host names.
 * <p>
  * For long-running programs or servers that handle many addresses, the benefits of using a cache are that
 * <ul>
 * <li>the lookup can provide the same objects for different strings that identify the same host name or address</li>
 * <li>parsing and resolving repeated instances of the same address or host string is minimized.  Both IPAddressString and HostName cache their parsed and resolved addresses.</li>
 * <li>other functionality is optimized through caching, since Host Name, IPAddressString, and IPAddress also caches objects such as generated strings.  With cached objects, switching between host names, address strings and numeric addresses is instantaneous.</li>
 * </ul><p>
 * You choose the map of your choice to be the backing map for the cache.
 * For example, for thread-safe access to the cache, ConcurrentHashMap is a good choice.
 * For maps of bounded size, LinkedHashMap provides the removeEldestEntry method to override to implement LRU or other eviction mechanisms.
 * 
 * @author sfoley
 *
 * @param <T> the type to be cached, typically either IPAddressString or HostName
 */
public class HostIdentifierStringCache<T extends HostIdentifierString> {
	private Map<String, T> backingMap;
	protected HostIdentifierStringCreator<T> creator;
	
	public HostIdentifierStringCache(Map<String, T> backingMap, HostIdentifierStringCreator<T> creator) {
		this.backingMap = backingMap;
		this.creator = creator;
	}
	
	HostIdentifierStringCache(Map<String, T> backingMap) {
		this.backingMap = backingMap;
	}
	
	/*
	 * If you wish to maintain a count of added addresses, or a log, then override this method
	 */
	protected void added(T added) {}

	/**
	 * Returns whether the given instance is in the cache.
	 * @param value
	 * @return whether the given instance of T is in the cache
	 */
	public boolean contains(T value) {
		return backingMap.containsValue(value);
	}

	/**
	 * Gets the object for the given key.  If the object does not exist yet then it is created and added to the cache.
	 * @param key
	 * @return the object for the given key
	 * @throws HostIdentifierException if the key does not correspond to an instance of type T
	 */
	public T get(String key) throws HostIdentifierException {
		T result = backingMap.get(key);
		if(result == null) {
			result = creator.create(key);
			String normalizedKey = result.toNormalizedString();
			if(backingMap instanceof ConcurrentMap) {
				ConcurrentMap<String, T> concurrentMap = (ConcurrentMap<String, T>) backingMap;
				T existing = concurrentMap.putIfAbsent(normalizedKey, result);
				if(existing == null) {
					added(result);
				} else {
					result = existing;
				}
			} else {
		        T existing = backingMap.get(normalizedKey);
		        if (existing == null) {
		        	backingMap.put(normalizedKey, result);
		        } else {
		        	result = existing;
		        }
		        return result;
			}
			if(!normalizedKey.equals(key)) {
				backingMap.put(key, result);
			}
		}
		return result;
	}
	
	protected static interface HostIdentifierStringCreator<R extends HostIdentifierString> {
		R create(String key) throws HostIdentifierException;
	}
}
