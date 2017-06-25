/*
 * Copyright 2017 Sean C Foley
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *     or at
 *     https://github.com/seancfoley/IPAddress/blob/master/LICENSE
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package inet.ipaddr;

import java.io.Serializable;
import java.util.Map;

import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.validate.HostIdentifierStringValidator;
import inet.ipaddr.ipv4.IPv4Address;


/**
 * A network of addresses of a single IP version .
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressNetwork extends AddressNetwork {
	
	private final static IPAddressString subnetPrefixes[] = new IPAddressString[HostIdentifierStringValidator.MAX_PREFIX + 1];
		
	public IPAddress getNetworkMask(int networkPrefixLength) {
		return getNetworkMask(networkPrefixLength, true);
	}
	
	public abstract IPAddress getNetworkMask(int networkPrefixLength, boolean withPrefixLength);
	
	public abstract IPAddressSection getNetworkMaskSection(int networkPrefixLength);
	
	public abstract IPAddress getHostMask(int networkPrefixLength);
	
	public abstract IPAddressSection getHostMaskSection(int networkPrefixLength);
	
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
	 * @throws AddressTypeException if the bits exceed the maximum prefix size
	 */
	public static IPAddressString getPrefix(int networkPrefixLength) throws AddressTypeException {
		return getPrefix(networkPrefixLength, subnetPrefixes);
	}
	
	private static IPAddressString getPrefix(int networkPrefixLength, IPAddressString cache[]) throws AddressTypeException {
		IPAddressString.validateNetworkPrefix(null, networkPrefixLength, false);
		int cacheIndex = networkPrefixLength;
		IPAddressString prefix = cache[cacheIndex];
		if(prefix == null) {
			synchronized(cache) {
				prefix = cache[cacheIndex];
				if(prefix == null) {
					cache[cacheIndex] = prefix = /* address string creation */
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
	public static abstract class HostIdentifierStringCache<T extends HostIdentifierString> implements Serializable {
		private static final long serialVersionUID = 1L;
		
		protected Map<String, T> backingMap;
		
		public HostIdentifierStringCache(Map<String, T> backingMap) {
			this.backingMap = backingMap;
		}
		
		public Map<String, T> getBackingMap() {
			return backingMap;
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
				result = create(key);
				
				String normalizedKey = result.toNormalizedString();
				
				//we want to save the IPAddressString or HostName that was created from the normalized string for things like getHostAddress to have predictable behaviour
				result = create(normalizedKey);
				
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
		
		public static SegmentValueProvider getValueProvider(byte bytes[]) {
			return (segmentIndex, segmentByteCount) -> {	
				int value = 0;
				for(int start = segmentIndex * segmentByteCount, end = start + segmentByteCount; start < end; start++) {
					value = (value << 8) | (0xff & bytes[start]);
				}
				return value;
			};
		}
		
		public T get(byte bytes[]) {
			return get(bytes.length == IPv4Address.BYTE_COUNT ? IPVersion.IPV4 : IPVersion.IPV6, getValueProvider(bytes), null, null, null);
		}
		
		public T get(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength) {
			return get(version, lowerValueProvider, upperValueProvider, prefixLength, null);
		}
		
		public T get(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
			String key = IPAddress.toNormalizedString(version, lowerValueProvider, upperValueProvider, prefixLength, zone);
			T result = backingMap.get(key);
			if(result == null) {
				IPAddress addr = IPAddress.from(version, lowerValueProvider, upperValueProvider, prefixLength, zone);
				addr.cacheNormalizedString(key);
				
				//get the object that wraps the address, either HostName or IPAddressString or other
				result = create(addr);
				T existing = backingMap.putIfAbsent(key, result);
				if(existing == null) {
					added(result);
				} else {
					result = existing;
					//Since we have the address, we can make the existing host identifier string entry wrap the address
					cache(result, addr);
				}
			}
			return result;
		}
		
		protected abstract T create(String key);
			
		protected abstract T create(IPAddress addr);
		
		protected abstract void cache(T result, IPAddress addr);
	}

	/**
	 * Choose a map of your choice to implement a cache of address strings and their associated addresses.
	 * 
	 * The map will map string representations of the address to IPAddressString objects, which in turn cache any resulting IPAddress objects.
	 * 
	 * Those objects are all themselves thread-safe, but the cache will only be thread-safe if you choose a thread-safe map such as ConcurrentHashMap.
	 *
	 * @author sfoley
	 *
	 */
	public static class IPAddressStringCache extends HostIdentifierStringCache<IPAddressString> {

		private static final long serialVersionUID = 1L;
		
		IPAddressStringParameters options;

		public IPAddressStringCache(Map<String, IPAddressString> backingMap, IPAddressStringParameters options) {
			super(backingMap);
			this.options = options;
		}
		
		public IPAddressStringCache(Map<String, IPAddressString> backingMap) {
			super(backingMap);
		}

		@Override
		protected IPAddressString create(String addressString) {
			return options == null ? new IPAddressString(addressString) : new IPAddressString(addressString, options);
		}
		
		@Override
		protected IPAddressString create(IPAddress addr) {
			return addr.toAddressString();
		}
		
		@Override
		public IPAddressString get(String key) {//These methods that override and call super are superfluous but it seems this is only way to get them into javadoc
			return super.get(key);
		}
		
		@Override
		public IPAddressString get(byte bytes[]) {
			return super.get(bytes);
		}
		
		@Override
		public IPAddressString get(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength) {
			return super.get(version, lowerValueProvider, upperValueProvider, prefixLength);
		}
		
		@Override
		public IPAddressString get(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
			return super.get(version, lowerValueProvider, upperValueProvider, prefixLength, zone);
		}
		
		@Override
		protected void cache(IPAddressString result, IPAddress addr) {
			result.cacheAddress(addr);
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
	public static class HostNameCache extends HostIdentifierStringCache<HostName> {

		private static final long serialVersionUID = 1L;
		
		HostNameParameters options;

		public HostNameCache(Map<String, HostName> backingMap, HostNameParameters options) {
			super(backingMap);
			this.options = options;
		}
		
		public HostNameCache(Map<String, HostName> backingMap) {
			super(backingMap);
		}

		@Override
		protected HostName create(String key) {
			return options == null ? new HostName(key) : new HostName(key, options);
		}
		
		@Override
		protected HostName create(IPAddress addr) {
			return new HostName(addr);
		}
		
		@Override
		public HostName get(String key) {
			return super.get(key);
		}
		
		@Override
		public HostName get(byte bytes[]) {
			return super.get(bytes);
		}
		
		@Override
		public HostName get(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength) {
			return super.get(version, lowerValueProvider, upperValueProvider, prefixLength);
		}
		
		@Override
		public HostName get(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
			return super.get(version, lowerValueProvider, upperValueProvider, prefixLength, zone);
		}
		
		@Override
		protected void cache(HostName result, IPAddress addr) {
			result.cacheAddress(addr);
		}
	}
}
