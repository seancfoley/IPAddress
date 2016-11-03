package inet.ipaddr;

import java.util.Map;

import inet.ipaddr.IPAddress.IPVersion;


/**
 * A network of addresses of a single version (ie bit length).
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressNetwork {
	
	private final static IPAddressString subnetPrefixes[] = new IPAddressString[HostIdentifierStringValidator.MAX_PREFIX + 1];
		
	public IPAddress getNetworkMask(int networkPrefixLength) {
		return getNetworkMask(networkPrefixLength, true);
	}
	
	public abstract IPAddress getNetworkMask(int networkPrefixLength, boolean withPrefixLength);
	
	public abstract IPAddress getHostMask(int networkPrefixLength);
	
	public abstract int getSegmentNetworkMask(int segmentPrefixLength);
	
	public abstract int getSegmentHostMask(int segmentPrefixLength);
	
	public abstract long getSegmentNetworkMask(int segmentPrefixLength, int joinedSegments);
	
	public abstract long getSegmentHostMask(int segmentPrefixLength, int joinedSegments);
	
	public abstract IPAddress getLoopback();
	
	public abstract String[] getStandardLoopbackStrings();
	
	public boolean isIPv4() {
		return false;
	}

	public boolean isIPv6() {
		return false;
	}

	public abstract IPVersion getIPVersion();
	
	/**
	 * @param networkPrefixLength
	 * @return
	 * @throws IPAddressTypeException if the bits exceed the maximum prefix size
	 */
	public static IPAddressString getPrefix(int networkPrefixLength) throws IPAddressTypeException {
		return getPrefix(networkPrefixLength, subnetPrefixes);
	}
	
	private static IPAddressString getPrefix(int networkPrefixLength, IPAddressString cache[]) throws IPAddressTypeException {
		IPAddressString.validateNetworkPrefix(null, networkPrefixLength, false);
		int cacheIndex = networkPrefixLength;
		IPAddressString prefix = cache[cacheIndex];
		if(prefix == null) {
			synchronized(cache) {
				prefix = cache[cacheIndex];
				if(prefix == null) {//TODO get from creator
					cache[cacheIndex] = prefix = 
							new IPAddressString(new StringBuilder(HostIdentifierStringValidator.MAX_PREFIX_CHARS + 1).append(IPAddress.PREFIX_LEN_SEPARATOR).append(networkPrefixLength).toString());
				}
			}
		}
		return prefix;
	}
	
	/**
	 * Choose a map of your choice to implement a cache of addresses and/or host names.
	 * <p>
	  * For long-running programs or servers that handle many addresses, the benefits of using a cache are that
	 * <ul>
	 * <li>the lookup can provide the same objects for different strings that identify the same host name or address</li>
	 * <li>parsing and resolving repeated instances of the same address or host string is minimized.  Both IPAddressString and HostName cache their parsed and resolved addresses.</li>
	 * <li>other functionality is optimized through caching, since Host Name, IPAddressString, and IPAddress also caches objects such as generated strings.  With cached objects, switching between host names, address strings and numeric addresses is constant time.</li>
	 * </ul><p>
	 * You choose the map of your choice to be the backing map for the cache.
	 * For example, for thread-safe access to the cache, ConcurrentHashMap is a good choice.
	 * For maps of bounded size, LinkedHashMap provides the removeEldestEntry method to override to implement LRU or other eviction mechanisms.
	 * 
	 * @author sfoley
	 *
	 * @param <T> the type to be cached, typically either IPAddressString or HostName
	 */
	public static class HostIdentifierStringCache<T extends HostIdentifierString> {
		protected Map<String, T> backingMap;
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
		public T get(String key) {
			T result = backingMap.get(key);
			if(result == null) {
				result = creator.create(key);
				String normalizedKey = result.toNormalizedString();
				T existing = backingMap.putIfAbsent(normalizedKey, result);
				if(existing == null) {
					added(result);
				} else {
					result = existing;
				}
				if(!normalizedKey.equals(key)) {
					backingMap.put(key, result);
				}
			}
			return result;
		}
		
		protected static interface HostIdentifierStringCreator<R extends HostIdentifierString> {
			R create(String key);
		}
	}
	
	//TODO in doclet, make the nested classes appear with types even if core?  This is also causing a little clutter.  Maybe just add the core tag to them.
	//TODO we should perhaps provide the option to assign a cache to the network!  Then when creating addresses internally, the cache will be used.
	//When creating addresses externally, can add code to add to the cache in the constructor, but that still doesn't help avoid the creation... so maybe not.
	//the cache already uses the address creators, so need an interplay between them: when the cache is using the creator the creator cannot go back to that cache,
	//so maybe need a separate internal creator method for strings and hostnames that check the cache first and then call the main creator methods
	//while the cache itself calls the main creator methods, although be careful, the network cache is not always the same as the current cache, there can be many caches,
	//maybe the cache should check if it is the network cache to decide which creator method to call

	/**
	 * Choose a map of your choice to implement a cache of address strings and addresses.
	 * 
	 * The map will map string representations of the address to IPAddressString objects, which in turn cache any resulting IPAddress objects.
	 * 
	 * Those objects are all themselves thread-safe, but the cache will only be thread-safe if you choose a thread-safe map such as ConcurrentHashMap.
	 *
	 * @author sfoley
	 *
	 */
	public static class IPAddressStringCache extends HostIdentifierStringCache<IPAddressString> implements HostIdentifierStringCache.HostIdentifierStringCreator<IPAddressString> {
		IPAddressStringParameters options;

		public IPAddressStringCache(Map<String, IPAddressString> backingMap, IPAddressStringParameters options) {
			this(backingMap);
			this.options = options;
		}
		
		public IPAddressStringCache(Map<String, IPAddressString> backingMap) {
			super(backingMap);
			creator = this;
		}

		//TODO maybe I have just one type of cache taking both hosts and ip strings?
		@Override
		public IPAddressString create(String key) {
			IPAddressString str = options == null ? new IPAddressString(key) : new IPAddressString(key, options);
			return str;
		}
		
		//TODO if I want to cache in the network, then I need the caches to offer the same options as the constructors and the creators
		//but really, constructing from sections and segments is no concern, only from bytes and strings
		//so for one thing, TODO I need a method that takes bytes with the zone, and also with the prefix, and on the ipv4 side the prefix and also from an int
		//once these options exist, both here and in the creators, then 
		//I can put the hooks in the creators to the caches.
		//I can put the hooks in the few spots we create strings into the creators
		//external -> creator -> cache
		//internal -> creator -> cache
		//but there is two creators, the cache interface is simpler
		//
		//or?
		//external -> cache -> creator
		//clearly this second option not so simple since it is opposite from internal.
		//
		//really the purpose of the creator is for creation to go through one place, and we can assign our own
		//so if creator points to cache, then when we override, we bypass cache
		//so the second option is preferable
		//also, going that way eliminates the Ipv6 Ipv4 confusion.  You just have strings or bytes.
		//Still, with the bytes we need to offer the zone and the prefix on ipv6 and the prefix and the int on ipv4
		//
		//We need to be careful where we put hooks into the cache in the code, not anywhere in the string parsing
		
		//TODO this could be a host name too
		public IPAddressString get(byte bytes[]) {
			String key = IPAddress.toNormalizedString(bytes);
			IPAddressString result = backingMap.get(key);
			if(result == null) {
				IPAddress addr = IPAddress.from(bytes);
				result = addr.toAddressString();//TODO here is where I could instead construct a HostName xxx
				IPAddressString existing = backingMap.putIfAbsent(key, result);
				if(existing == null) {
					added(result);
					addr.cacheNormalizedString(key);
				} else {
					result = existing;
					result.cacheAddress(addr);
				}
			}
			return result;
		}
	}

	/**
	 * Choose a map of your choice to implement a cache of host names and resolved addresses.
	 * 
	 * The map will map string representations of the host to HostName objects.
	 * 
	 * Those HostName objects in turn cache any resulting IPAddressString objects if the string represents an address, 
	 * or any IPAddress objects obtained from resolving the HostName.
	 * 
	 * Those objects are all themselves thread-safe, but the cache will only be thread-safe if you choose a thread-safe map such as ConcurrentHashMap.
	 *
	 * @author sfoley
	 *
	 */
	public static class HostNameCache extends HostIdentifierStringCache<HostName> implements HostIdentifierStringCache.HostIdentifierStringCreator<HostName> {
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
		public HostName create(String key) {
			return options == null ? new HostName(key) : new HostName(key, options);
		}
	}
}
