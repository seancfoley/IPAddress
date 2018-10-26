/*
 * Copyright 2016-2018 Sean C Foley
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

import inet.ipaddr.Address.AddressValueProvider;
import inet.ipaddr.format.standard.AddressCreator;

/**
 * An object representing a collection of addresses.
 * <p>
 * It also encapsulates settings for handling all addresses in the network like the prefix configuration that determines certain properties of the addresses in the network.
 * <p>
 * If your use of the IPAddress library has non-default configuration settings in this AddressNetwork class, and within the same JVM the IPAddress library 
 * is being used elsewhere with different configuration settings, then you have two options available to you:
 * <p>
 * 1. Use classloaders to load the two uses of IPAddress in different classloaders, a common Java architecture that is part of the language itself to address just this issue
 * <p>
 * 2. Use your own network classes, and within them overide the configuration methods to return the values you desire.  
 * <p>
 * All access to the network classes is through public virtual accessor methods getNetwork or getXNetwork in the classes XAddress, XAddressSection, XAddressSegment
 * where X is one of MAC, IPv6, or IPv4.  So you need to subclass those classes, and then override those getNetwork and getXNetwork methods to return your own network instances.
 * There are a couple of other places to consider to ensure only your own network instances are used.  
 * XAddressString objects obtain their network object from the validation parameters supplied to the constructor, so you would customize those validation parameters as well.
 * The same is true for the HostName class, which uses an embedded address validation instance inside the host name parameters instance.  
 * Finally, the address generator/cache classes (that are nested classes that in the network) use validation parameters as well that would be customized to your own network instances.
 * <p>
 * Generally you would use the same network object for any given address type (ie one for IPv6, one for IPv4, one for MAC), although this is not necessary.  
 * However, it is necessary that the configuration is the same for any given address type.
 * <p>
 * Now suppose you wish to ensure any and all methods in this library create instances of your own subclasses of the XAddress, XAddressSection, XAddressSegment classes.
 * 
 * All internally created address components are created by the address creator instance owned by the network object.
 * So you override the getAddressCreator() in your new network classes to provide your own address creator object.
 * 
 * 
 * @author sfoley
 *
 */
public abstract class AddressNetwork<S extends AddressSegment> implements Serializable {

	private static final long serialVersionUID = 4L;

	public interface AddressSegmentCreator<S extends AddressSegment> {
		
		S[] createSegmentArray(int length);
		
		S createSegment(int value);
		
		S createSegment(int value, Integer segmentPrefixLength);
		
		S createSegment(int lower, int upper, Integer segmentPrefixLength);
	}

	public abstract AddressCreator<?, ?, ?, S> getAddressCreator();
	
	public void clearCaches() {
		getAddressCreator().clearCaches();
	}
	
	//// Configuration
	
	/*
	 * a few sources about the network address - 
	 * https://superuser.com/questions/379451/why-can-a-network-address-not-be-a-valid-host-address
	 * https://serverfault.com/questions/451238/why-cant-all-zeros-in-the-host-portion-of-ip-address-be-used-for-a-host
	 * //// Configuration
	 * Maybe use a bit from https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing, see the phrase "In common usage"
	 * https://github.com/ipaddress-gem/ipaddress
	 */

	/**
	 * Prefix Handling Configuration
	 * 
	 * The library is designed to treat prefixes three different ways:
	 * <p>1. All prefixes are subnets.  This was the legacy behaviour for version earlier than version 4.
	 * All prefixed addresses are converted to the block of addresses that share the same prefix.
	 * For addresses in which prefixes are derived from the address ranges, such as MAC, prefix lengths are implicitly calculated from the range,
	 * so 1:2:3:*:*:* implicitly has the prefix length of 24.  This is also the case for any address derived from the original.
	 * <p>
	 * 2. Addresses with zero-values hosts are treated as subnets.  More precisely, addresses whose hosts are entirely zero, 
	 * or addresses whose hosts start with zeros and end with the full range of values are treated as subnets.  
	 * So, for example, 1.2.0.0/16 is converted to 1.2.*.* which is the block of addresses with with prefix 1.2.
	 * Also, 1.2.0.* /16 or 1.2.*.* /16 are also equivalent to the block of 65535 addresses 1.2.*.* associated with prefix length 16.
	 * Addresses with non-zero hosts, such as 1.2.0.1/16 are treated differently. 1.2.0.1/16 is equivalent to the single address 1.2.0.1 and is not a treated as a subnet block of multiple addresses.
	 * The new behaviour is akin to the typical convention used by network administrators in which the address with a host of zero is known as the network address.
	 * The all-zero address 0.0.0.0 is conventionally known as INADDR_ANY (any address on the local machine), and when paired with prefix zero it is known as the default route (the route for all addresses).
	 * <p>
	 * The same is true on the IPv6 side, where 1:2:3:4::/64 is treated as the subnet of all addresses with prefix 1:2:3:4.  
	 * With IPv6 it is a common convention to depict a prefixed network as a:b:c:d::/64, with the host shown as all zeros.
	 * This is also known as the subnet router anycast address in IPv6.  The all-zero address '::' is the value of IN6ADDR_ANY_INIT, the analog to the IPv4 INADDR_ANY.
	 * <p>
	 * In summary:<br>
	 * <ul><li>A prefixed address whose host bits are all 0 is not a single host address, instead it represents a subnet, the block of all addresses with that prefix.
	 * </li><li>A prefixed address whose host is non-zero is treated as a single address with the given prefix length.
	 * </li></ul>
	 * <p>
	 * So for example, 1.2.0.0/16 will give you the subnet block 1.2.*.* /16, and once you have it, if you want just the single address 1.2.0.0/16, you can get it using {@link IPAddress#getLower()}.
	 * <p>
	 * This option has less meaning for other address types in which ranges are explicit, such as MAC addresses.  However, this option does allow you, using the appropriate constructor, to assign a prefix length to any address.
	 * So there is no automatic fixed mapping between the range of the address values and the associated prefix length.
	 * <p>
	 * Additionally, when starting with an address whose prefix was calculated from its range, you can derive additionally addresses from the original, and those addresses will have the same prefix.
	 * For instance, 1:2:3:*:*:* implicitly has the prefix length of 24 regardless of the prefix configuration.  But with this prefix configuration, 
	 * you can then construct a derived address with the same prefix, for example with new MACAddressString("1:2:3:*:*:*").getAddress().replace(MACAddressString("1:2:3:4:5:6").getSection(2));
	 * <p>
	 * 3. The third option is the setting for which prefixes are never automatically converted to subnets.  Any subnet must be explicitly defined,
	 * such as 1.2.*.* /16
	 * <p>
	 * For addresses in which ranges are explicit, such as MAC addresses, this option is no different than the second option.
	 * 
	 * <p>
	 * In summary:<ul>
	 * <li>When PrefixConfiguration == ALL_PREFIXES_ARE_SUBNETS all prefixed addresses have hosts that span all possible host values.</li>
	 * <li>When PrefixConfiguration == PREFIXED_ZERO_HOSTS_ARE_SUBNETS addresses constructed with zero host will have hosts that span all possible values, such as 1.2.0.0/16 which is equivalent to 1.2.*.* /16</li>
	 * <li>When PrefixConfiguration == EXPLICIT_SUBNETS hosts that span all values are explicit, such as 1.2.*.* /16, while 1.2.0.0/16 is just a single address with a single host value of zero.</li>
	 * </ul>
	 * <p>
	 * Note that when setting a non-default prefix configuration, indeterminate behaviour can result from the same addresses using different prefix configuration settings at different times, so this method must be used carefully.
	 * <p>
	 * Should you wish to use two different prefix configurations in the same app, it can be done safely using classloaders,
	 * and it can also be done using different network instances.  To used different networks, you can override the virtual methods
	 * for getting network instances in your address component classes.
	 */
	public enum PrefixConfiguration {
		ALL_PREFIXED_ADDRESSES_ARE_SUBNETS,//legacy behaviour
		PREFIXED_ZERO_HOSTS_ARE_SUBNETS,//default
		EXPLICIT_SUBNETS;
		
		/**
		 * @return whether this is ALL_PREFIXED_ADDRESSES_ARE_SUBNETS
		 */
		public boolean allPrefixedAddressesAreSubnets() {
			return this == ALL_PREFIXED_ADDRESSES_ARE_SUBNETS;
		}

		/**
		 * @return whether this is PREFIXED_ZERO_HOSTS_ARE_SUBNETS
		 */
		public boolean zeroHostsAreSubnets() {
			return this == PREFIXED_ZERO_HOSTS_ARE_SUBNETS;
		}
		
		/**
		 * @return whether this is EXPLICIT_SUBNETS
		 */
		public boolean prefixedSubnetsAreExplicit() {
			return this == EXPLICIT_SUBNETS;
		}
	}

	private static PrefixConfiguration defaultPrefixConfiguration = PrefixConfiguration.PREFIXED_ZERO_HOSTS_ARE_SUBNETS;
	//public static PrefixConfiguration prefixConfiguration = PrefixConfiguration.ALL_PREFIXES_ARE_SUBNETS; //old behaviour (version 3 and under)
	
	/**
	 * This method determines the prefix configuration in use by this network.
	 * <p>
	 * The prefix configuration determines whether a prefixed address like 1.2.0.0/16 results in a subnet block (ie 1.2.*.*) or just a single address (1.2.0.0) with a prefix length.
	 * <p>
	 * If you wish to change the default behaviour, you can either call {@link inet.ipaddr.ipv4.IPv4AddressNetwork#setDefaultPrefixConfiguration(PrefixConfiguration)},
	 * or {@link inet.ipaddr.ipv6.IPv6AddressNetwork#setDefaultPrefixConfiguration(PrefixConfiguration)} or you can override this method in your own network and use your own network for your addresses.
	 * 
	 * @see PrefixConfiguration
	 */
	public abstract PrefixConfiguration getPrefixConfiguration();
	
	public static PrefixConfiguration getDefaultPrefixConfiguration() {
		return defaultPrefixConfiguration;
	}
	
	/**
	 * Generates and caches HostIdentifierString instances.  Choose a map of your choice to implement a cache of address string identifiers.
	 * <p>
	 * You choose the map of your choice to be the backing map for the cache.
	 * For example, for thread-safe access to the cache, ConcurrentHashMap is a good choice.
	 * For maps of bounded size, LinkedHashMap provides the removeEldestEntry method to override to implement LRU or other eviction mechanisms.
	 * <p>
	 * @author sfoley
	 *
	 * @param <T> the type to be cached, typically either IPAddressString or HostName
	 */
	public static abstract class HostIdentifierStringGenerator<T extends HostIdentifierString> implements Serializable {
		private static final long serialVersionUID = 4L;
		
		protected final Map<String, T> backingMap;
		
		public HostIdentifierStringGenerator() {
			this(null);
		}
		
		public HostIdentifierStringGenerator(Map<String, T> backingMap) {
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
		 */
		public T get(String key) {
			if(backingMap == null) {
				return create(key);
			}
			T result = backingMap.get(key);
			if(result == null) {
				result = create(key);
				
				String normalizedKey = result.toNormalizedString();
				
				//we want to use only the IPAddressString or HostName that was created from the normalized string.
				//This helps things like getHostAddress to have predictable behaviour
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
		
		public abstract T get(byte bytes[]);
		
		public abstract T get(AddressValueProvider addressProvider);
		
		protected abstract T create(String key);
	}
}
