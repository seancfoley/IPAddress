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
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;

import inet.ipaddr.Address.AddressValueProvider;
import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.IPAddress.IPAddressValueProvider;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.standard.AddressCreator;
import inet.ipaddr.format.standard.IPAddressDivisionGrouping.RangeList;
import inet.ipaddr.format.validate.HostIdentifierStringValidator;
import inet.ipaddr.ipv4.IPv4Address;
import inet.ipaddr.ipv4.IPv4AddressNetwork;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;


/**
 * Represents a network of addresses of a single IP version providing a collection of standard addresses components for that version, such as masks and loopbacks.
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressNetwork<T extends IPAddress, R extends IPAddressSection, E extends IPAddressSection, S extends IPAddressSegment, J extends InetAddress> 
	extends AddressNetwork<S> {
	
	private static final long serialVersionUID = 4L;

	private final T subnets[];
	private final T subnetMasks[];
	private final T hostMasks[];
	private final int networkSegmentMasks[];
	private final int hostSegmentMasks[];
	private transient T loopback;
	private transient String loopbackStrings[];

	public static abstract class IPAddressCreator<T extends IPAddress, R extends IPAddressSection, E extends IPAddressSection, S extends IPAddressSegment, J extends InetAddress> extends AddressCreator<T, R, E, S> {

		private static final long serialVersionUID = 4L;
		
		private IPAddressNetwork<T, R, E, S, J> owner;

		protected IPAddressCreator(IPAddressNetwork<T, R, E, S, J> owner) {
			this.owner = owner;
		}

		@Override
		public IPAddressNetwork<T, R, E, S, J> getNetwork() {
			return owner;
		}
		
		@Override
		protected S createSegmentInternal(int value, Integer segmentPrefixLength, CharSequence addressStr, int originalVal, boolean isStandardString, int lowerStringStartIndex, int lowerStringEndIndex) {
			S segment = createSegment(value, segmentPrefixLength);
			segment.setStandardString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal);
			segment.setWildcardString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal);
			return segment;
		}
		
		@Override
		protected S createSegmentInternal(int lower, int upper, Integer segmentPrefixLength, CharSequence addressStr, int originalLower, int originalUpper, boolean isStandardString, boolean isStandardRangeString, int lowerStringStartIndex, int lowerStringEndIndex, int upperStringEndIndex) {
			S segment = createSegment(lower, upper, segmentPrefixLength);
			segment.setStandardString(addressStr, isStandardString,  isStandardRangeString, lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex, originalLower, originalUpper);
			segment.setWildcardString(addressStr, isStandardRangeString, lowerStringStartIndex, upperStringEndIndex, originalLower, originalUpper);
			return segment;
		}
		
		protected abstract R[] createSectionArray(int length);
		
		@Override
		protected abstract R createSectionInternal(S segments[]);
		
		protected abstract R createEmbeddedSectionInternal(IPAddressSection encompassingSection, S segments[]);
		
		@Override
		protected R createPrefixedSectionInternal(S segments[], Integer prefix) {
			return createPrefixedSectionInternal(segments, prefix, false);
		}
		
		@Override
		protected abstract R createPrefixedSectionInternal(S segments[], Integer prefix, boolean singleOnly);
		
		public abstract R createFullSectionInternal(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefix);
		
		public abstract R createSection(byte bytes[], int byteStartIndex, int byteEndIndex, Integer prefix);
		
		public abstract R createSection(byte bytes[], Integer prefix);
		
		public abstract R createSection(S segments[], Integer networkPrefixLength);
		
		public abstract R createSection(S segments[]);
		
		protected abstract T[] createAddressArray(int length);
		
		public T createAddress(S segments[]) {
			return createAddress(createSection(segments));
		}
		
		public T createAddress(S segments[], Integer prefix) {
			return createAddress(createSection(segments, prefix));
		}
		
		@Override
		protected T createAddressInternal(S segments[]) {
			return createAddress(createSectionInternal(segments));
		}
		
		@Override
		protected T createAddressInternal(S segments[], Integer prefix, boolean singleOnly) {
			return createAddress(createPrefixedSectionInternal(segments, prefix, singleOnly));
		}
		
		@Override
		protected T createAddressInternal(S segments[], Integer prefix) {
			return createAddress(createPrefixedSectionInternal(segments, prefix));
		}
		
		protected T createAddressInternal(S segments[], CharSequence zone) {
			return createAddressInternal(createSectionInternal(segments), zone);
		}
		
		public T createAddress(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefix) {
			return createAddress(createFullSectionInternal(lowerValueProvider, upperValueProvider, prefix));
		}
		
		public T createAddress(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefix, CharSequence zone) {
			return createAddressInternal(createFullSectionInternal(lowerValueProvider, upperValueProvider, prefix), zone);
		}
		
		protected R createSectionInternal(byte bytes[], Integer prefix) {
			return createSectionInternal(bytes, bytes.length, prefix, false);
		}
		
		protected T createAddressInternal(byte bytes[], Integer prefix) {
			return createAddress(createSectionInternal(bytes, prefix));
		}
		
		protected T createAddressInternal(byte bytes[], Integer prefix, CharSequence zone) {
			return createAddressInternal(createSectionInternal(bytes, prefix), zone);
		}
		
		@Override
		protected T createAddressInternal(byte bytes[], CharSequence zone) {
			return createAddressInternal(createSectionInternal(bytes, null), zone);
		}
		
		protected T createAddressInternal(byte bytes[], Integer prefix, CharSequence zone, HostName fromHost) {
			return createAddressInternal(createSectionInternal(bytes, prefix), zone, fromHost);
		}
		
		protected T createAddressInternal(byte bytes[], Integer prefix, HostName fromHost) {
			return createAddressInternal(createSectionInternal(bytes, prefix), fromHost);
		}
		
		public T createAddress(byte bytes[], Integer prefix) {
			return createAddress(createSection(bytes, prefix));
		}
		
		public T createAddress(byte bytes[]) {
			return createAddress(createSection(bytes, null));
		}
		
		@Override
		protected T createAddressInternal(R section, CharSequence zone, HostIdentifierString from) {
			T result = createAddressInternal(section, zone);
			result.cache(from);
			return result;
		}
		
		@Override
		protected T createAddressInternal(R section, HostIdentifierString from) {
			T result = createAddress(section);
			result.cache(from);
			return result;
		}
		
		protected abstract T createAddress(J inetAddress);
		
		/* this method exists and is protected because zone makes no sense for IPv4 so we do not expose it as public (internally it is always null) */
		protected abstract T createAddressInternal(R section, CharSequence zone);
		
		@Override
		public abstract T createAddress(R section);
	}

	private IPAddressCreator<T, R, E, S, J> creator;

	@SuppressWarnings("unchecked")
	protected IPAddressNetwork(Class<T> addressType) {
		IPVersion version = getIPVersion();
		int bitSize = IPAddress.getBitCount(version);
		this.subnets = (T[]) Array.newInstance(addressType, bitSize + 1);
		this.subnetMasks = this.subnets.clone();
		this.hostMasks = this.subnets.clone();
		this.creator = createAddressCreator();
		int segmentBitSize = IPAddressSegment.getBitCount(version);
		int fullMask = ~(~0 << segmentBitSize); //allBitSize must be 6 digits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
		networkSegmentMasks = new int[segmentBitSize + 1];
		hostSegmentMasks = networkSegmentMasks.clone();
		for(int i = 0; i <= segmentBitSize; i++) {
			int networkMask = this.networkSegmentMasks[i] = fullMask & (fullMask << (segmentBitSize - i));
			this.hostSegmentMasks[i] = ~networkMask & fullMask;
		}
	}
	
	@Override
	public void clearCaches() {
		Arrays.fill(subnets, null);//this cache has prefixed addresses
		Arrays.fill(subnetMasks, null);
		Arrays.fill(hostMasks, null);
		loopback = null;
		loopbackStrings = null;
		super.clearCaches();
	}

	public boolean isIPv4() {
		return false;
	}

	public boolean isIPv6() {
		return false;
	}

	public abstract IPVersion getIPVersion();
	
	protected abstract BiFunction<T, Integer, S> getSegmentProducer();
	
	protected abstract Function<T, R> getSectionProducer();
	
	protected abstract IPAddressCreator<T, R, E, S, J> createAddressCreator();

	@Override
	public IPAddressCreator<T, R, E, S, J> getAddressCreator() {
		return creator;
	}

	public T getLoopback() {
		if(loopback == null) {
			synchronized(this) {
				if(loopback == null) {
					loopback = createLoopback();
				}
			}
		}
		return loopback;
	}
	
	protected abstract T createLoopback();
	
	public String[] getStandardLoopbackStrings() {
		if(loopbackStrings == null) {
			synchronized(this) {
				if(loopbackStrings == null) {
					loopbackStrings = getLoopback().toStandardStrings();
				}
			}
		}
		return loopbackStrings;
	}
	
	public int getSegmentNetworkMask(int segmentPrefixLength) {
		//the 0th array are masks of just 1 segment and 1 segment is always less than 32 bits, so we can cast to an int
		return (int) networkSegmentMasks[segmentPrefixLength];
	}
	
	public int getSegmentHostMask(int segmentPrefixLength) {
		//the 0th array are masks of just 1 segment and 1 segment is always less than 32 bits, so we can cast to an int
		return (int) hostSegmentMasks[segmentPrefixLength];
	}
	
	public T getNetworkMask(int networkPrefixLength) {
		return getNetworkMask(networkPrefixLength, true);
	}
	
	public T getNetworkMask(int networkPrefixLength, boolean withPrefixLength) {
		return getMask(networkPrefixLength, withPrefixLength ? subnets : subnetMasks, true, withPrefixLength);
	}
	
	public R getNetworkMaskSection(int networkPrefixLength) {
		return getSectionProducer().apply(getNetworkMask(networkPrefixLength, true));
	}
	
	public T getHostMask(int networkPrefixLength) {
		return getMask(networkPrefixLength, hostMasks, false, false);
	}
	
	public R getHostMaskSection(int networkPrefixLength) {
		return getSectionProducer().apply(getHostMask(networkPrefixLength));
	}
	
	private T getMask(int networkPrefixLength, T cache[], boolean network, boolean withPrefixLength) {
		int bits = networkPrefixLength;
		IPVersion version = getIPVersion();
		int addressBitLength = IPAddress.getBitCount(version);
		if(bits < 0 || bits > addressBitLength) {
			throw new PrefixLenException(bits, version);
		}
		int cacheIndex = bits;
		T subnet = cache[cacheIndex];
		if(subnet == null) {
			int onesSubnetIndex, zerosSubnetIndex;
			if(network) {
				onesSubnetIndex = addressBitLength;
				zerosSubnetIndex = 0;
			} else {
				onesSubnetIndex = 0;
				zerosSubnetIndex = addressBitLength;
			}
			T onesSubnet = cache[onesSubnetIndex];
			T zerosSubnet = cache[zerosSubnetIndex];
			if(onesSubnet == null || zerosSubnet == null) {
				synchronized(cache) {
					int segmentCount = IPAddress.getSegmentCount(version);
					int bitsPerSegment = IPAddress.getBitsPerSegment(version);
					int bytesPerSegment = IPAddress.getBytesPerSegment(version);
					onesSubnet = cache[onesSubnetIndex];
					if(onesSubnet == null) {
						IPAddressCreator<T, ?, ?, S, ?> creator = getAddressCreator();
						S newSegments[] = creator.createSegmentArray(segmentCount);
						int maxSegmentValue = IPAddress.getMaxSegmentValue(version);
						if(network && withPrefixLength) {
							S segment = creator.createSegment(maxSegmentValue, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, addressBitLength) /* null */ );
							Arrays.fill(newSegments, 0, newSegments.length - 1, segment);
							S lastSegment = creator.createSegment(maxSegmentValue, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, bitsPerSegment) /* bitsPerSegment */ );
							newSegments[newSegments.length - 1] = lastSegment;
							onesSubnet = creator.createAddressInternal(newSegments, cacheBits(addressBitLength)); /* address creation */
						} else {
							S segment = creator.createSegment(maxSegmentValue);
							Arrays.fill(newSegments, segment);
							onesSubnet = creator.createAddressInternal(newSegments); /* address creation */
						}
						initMaskCachedValues(onesSubnet.getSection(), network, withPrefixLength, addressBitLength, onesSubnetIndex, segmentCount, bitsPerSegment, bytesPerSegment);
						cache[onesSubnetIndex] = onesSubnet;
					}
					zerosSubnet = cache[zerosSubnetIndex];
					if(zerosSubnet == null) {
						IPAddressCreator<T, ?, ?, S, ?> creator = getAddressCreator();
						S newSegments[] = creator.createSegmentArray(segmentCount);
						S seg;
						if(network && withPrefixLength) {
							seg = creator.createSegment(0, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, 0) /* 0 */);
							Arrays.fill(newSegments, seg);
							zerosSubnet = creator.createAddressInternal(newSegments, cacheBits(0)); /* address creation */
						} else {
							seg = creator.createSegment(0);
							Arrays.fill(newSegments, seg);
							zerosSubnet = creator.createAddressInternal(newSegments); /* address creation */
						}
						initMaskCachedValues(zerosSubnet.getSection(), network, withPrefixLength, addressBitLength, zerosSubnetIndex, segmentCount, bitsPerSegment, bytesPerSegment);
						cache[zerosSubnetIndex] = zerosSubnet;
					}
				}
			}
			
			synchronized(cache) {
				subnet = cache[cacheIndex];
				if(subnet == null) {			
					BiFunction<T, Integer, S> segProducer = getSegmentProducer();				
					int segmentCount = IPAddress.getSegmentCount(version);
					int bitsPerSegment = IPAddress.getBitsPerSegment(version);
					int bytesPerSegment = IPAddress.getBytesPerSegment(version);
					int prefix = bits;
					S onesSegment = segProducer.apply(onesSubnet, 1);
					S zerosSegment = segProducer.apply(zerosSubnet, 1);
					IPAddressCreator<T, ?, ?, S, ?> creator = getAddressCreator();
					
					ArrayList<S> segmentList = new ArrayList<S>(segmentCount);
					int i = 0;
					for(; bits > 0; i++, bits -= bitsPerSegment) {
						if(bits <= bitsPerSegment) {
							S segment = null;
							
							//first do a check whether we have already created a segment like the one we need
							int offset = ((bits - 1) % bitsPerSegment) + 1;
							for(int j = 0, entry = offset; j < segmentCount; j++, entry += bitsPerSegment) {
								if(entry != cacheIndex) { //we already know that the entry at cacheIndex is null
									T prev = cache[entry];
									if(prev != null) {
										segment = segProducer.apply(prev, j);
										break;
									}
								}
							}
							
							//if none of the other addresses with a similar segment are created yet, we need a new segment.
							if(segment == null) {
								int mask = getSegmentNetworkMask(bits);
								if(network) {
									if(withPrefixLength) {
										segment = creator.createSegment(mask, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, bits));
									} else {
										segment = creator.createSegment(mask);
									}
								} else {
									segment = creator.createSegment(getSegmentHostMask(bits));
								}
							}
							segmentList.add(segment);
						} else {
							segmentList.add(network ? onesSegment : zerosSegment);
						}
					}
					for(; i<segmentCount; i++) {
						segmentList.add(network ? zerosSegment : onesSegment);
					}
					S newSegments[] = creator.createSegmentArray(segmentList.size());
					segmentList.toArray(newSegments);
					if(network && withPrefixLength) {
						subnet = creator.createAddressInternal(newSegments, cacheBits(prefix)); /* address creation */
					} else {
						subnet = creator.createAddressInternal(newSegments); /* address creation */
					}
					//initialize the cache fields since we know what they are now - they do not have to be calculated later
					initMaskCachedValues(subnet.getSection(), network, withPrefixLength, addressBitLength, prefix, segmentCount, bitsPerSegment, bytesPerSegment);
					cache[cacheIndex] = subnet; //last thing is to put into the cache - don't put it there before we are done with it
				} // end subnet from cache is null
			} //end synchronized
		} // end subnet from cache is null
		return subnet;
	}

	private void initMaskCachedValues(
			IPAddressSection section, 
			boolean network,
			boolean withPrefixLength, 
			int addressBitLength, 
			int networkPrefixLength,
			int segmentCount, 
			int bitsPerSegment,
			int bytesPerSegment) {
		Integer cachedNetworkPrefix, cachedMinPrefix, cachedEquivalentPrefix;
		BigInteger cachedCount;
		RangeList zeroSegments, zeroRanges;
		boolean hasZeroRanges = network ? addressBitLength - networkPrefixLength >= bitsPerSegment : networkPrefixLength >= bitsPerSegment;
		RangeList noZeros = IPAddressSection.getNoZerosRange();
		if(hasZeroRanges) {
			int rangeIndex, rangeLen;
			if(network) {
				int segmentIndex = IPAddressSection.getNetworkSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment) + 1;
				rangeIndex = segmentIndex;
				rangeLen = segmentCount - segmentIndex;
			} else {
				rangeIndex = 0;
				rangeLen = IPAddressSection.getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
			}
			zeroRanges = IPAddressSection.getSingleRange(rangeIndex, rangeLen);
			zeroSegments = (network && withPrefixLength && !getPrefixConfiguration().prefixedSubnetsAreExplicit()) ? noZeros : zeroRanges;
		} else {
			zeroSegments = zeroRanges = noZeros;
		}
		Integer npl = cacheBits(networkPrefixLength);
		if(network && withPrefixLength) {
			if(getPrefixConfiguration().prefixedSubnetsAreExplicit()) {
				cachedEquivalentPrefix = cachedMinPrefix = cacheBits(addressBitLength);
				cachedNetworkPrefix = npl;
				cachedCount = BigInteger.ONE;
			} else {
				cachedEquivalentPrefix = cachedMinPrefix = cachedNetworkPrefix = npl;
				cachedCount = BigInteger.valueOf(2).pow(addressBitLength - networkPrefixLength);
			}
		} else {
			cachedEquivalentPrefix = cachedMinPrefix = cacheBits(addressBitLength);
			cachedNetworkPrefix = null;
			cachedCount = BigInteger.ONE;
		}
		section.initCachedValues(npl, network, cachedNetworkPrefix, cachedMinPrefix, cachedEquivalentPrefix, cachedCount, zeroSegments, zeroRanges);
	}
	
	protected static Integer cacheBits(int i) {
		return IPAddressSection.cacheBits(i);
	}

	public static String getPrefixString(int networkPrefixLength) {
		return new StringBuilder(HostIdentifierStringValidator.MAX_PREFIX_CHARS + 1).append(IPAddress.PREFIX_LEN_SEPARATOR).append(networkPrefixLength).toString();
	}

	/**
	 * <p>
	 * A factory of address strings or host names, which can be particularly useful if you are using your own network, 
	 * or if you are using your own validation options.
	 * <p>
	 *  
	 * @author sfoley
	 *
	 */
	public static class IPAddressGenerator implements Serializable {
		private static final long serialVersionUID = 4L;
		
		protected final IPAddressStringParameters options;
		
		public IPAddressGenerator() {
			this(null);
		}
		
		/**
		 * Copies the default string options but inserts the given networks.
		 * Either argument can be null to use the default networks.
		 * 
		 * @param ipv4Network
		 * @param ipv6Network
		 */
		public IPAddressGenerator(IPv4AddressNetwork ipv4Network, IPv6AddressNetwork ipv6Network) {
			this(new IPAddressStringParameters.Builder().
						getIPv4AddressParametersBuilder().setNetwork(ipv4Network).
						getParentBuilder().
						getIPv6AddressParametersBuilder().setNetwork(ipv6Network).
							getEmbeddedIPv4AddressParametersBuilder().setNetwork(ipv4Network).
							getEmbeddedIPv4AddressParentBuilder().
						getParentBuilder().
					toParams());
		}
		
		public IPAddressGenerator(IPAddressStringParameters options) {
			if(options == null) {
				options = IPAddressString.DEFAULT_VALIDATION_OPTIONS;
			}
			this.options = options;
		}

		protected String toNormalizedString(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
			if(version == IPVersion.IPV4) {
				IPv4AddressNetwork network = options.getIPv4Parameters().getNetwork();
				return IPv4Address.toNormalizedString(network, lowerValueProvider, upperValueProvider, prefixLength);
			}
			if(version == IPVersion.IPV6) {
				IPv6AddressNetwork network = options.getIPv6Parameters().getNetwork();
				return IPv6Address.toNormalizedString(network, lowerValueProvider, upperValueProvider, prefixLength, zone);
			}
			throw new IllegalArgumentException();
		}
		
		public IPAddress from(InetAddress inetAddress) {
			if(inetAddress instanceof Inet4Address) {
				return getIPv4Creator().createAddress((Inet4Address) inetAddress);
			} else if(inetAddress instanceof Inet6Address) {
				return getIPv6Creator().createAddress((Inet6Address) inetAddress);
			}
			return null;
		}
		
		public IPAddress from(byte bytes[]) {
			return from(bytes, null, null);
		}
		
		public IPAddress from(byte bytes[], Integer prefixLength) {
			return from(bytes, prefixLength, null);
		}
		
		public IPAddress from(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength) {
			return from(version, lowerValueProvider, upperValueProvider, prefixLength, null);
		}
		
		private IPv4AddressCreator getIPv4Creator() {
			IPv4AddressNetwork network = options.getIPv4Parameters().getNetwork();
			IPv4AddressCreator addressCreator = network.getAddressCreator();
			return addressCreator;
		}
		
		private IPv6AddressCreator getIPv6Creator() {
			IPv6AddressNetwork network = options.getIPv6Parameters().getNetwork();
			IPv6AddressCreator addressCreator = network.getAddressCreator();
			return addressCreator;
		}

		private IPAddress from(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
			if(version == IPVersion.IPV4) {
				return getIPv4Creator().createAddress(lowerValueProvider, upperValueProvider, prefixLength);
			}
			if(version == IPVersion.IPV6) {
				return getIPv6Creator().createAddress(lowerValueProvider, upperValueProvider, prefixLength, zone);
			}
			throw new IllegalArgumentException();
		}
		
		private IPAddress from(byte bytes[], Integer prefixLength, CharSequence zone) {
			if(bytes.length < IPv6Address.BYTE_COUNT) {
				return getIPv4Creator().createAddressInternal(bytes, prefixLength);
			}
			return getIPv6Creator().createAddressInternal(bytes, prefixLength, zone);
		}
	}
	
	/**
	 * Choose a map of your choice to implement a cache of addresses and/or host names.
	 * <p>
	 * You can also use this class without a cache to serve as a factory of addresses or host names, 
	 * which can be particularly useful if you are using your own network, or if you are using your own validation options.
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
	public static abstract class HostIDStringAddressGenerator<T extends HostIdentifierString> implements Serializable {
		private static final long serialVersionUID = 4L;
		
		private final IPAddressGenerator addressGenerator;
		protected final Map<String, T> backingMap;
		
		public HostIDStringAddressGenerator() {
			this(null, null);
		}
		
		public HostIDStringAddressGenerator(IPAddressStringParameters options) {
			this(null, options);
		}
		
		public HostIDStringAddressGenerator(Map<String, T> backingMap) {
			this(backingMap, null);
		}
		
		public HostIDStringAddressGenerator(Map<String, T> backingMap, IPAddressStringParameters options) {
			this.backingMap = backingMap;
			this.addressGenerator = new IPAddressGenerator(options);
		}
		
		public Map<String, T> getBackingMap() {
			return backingMap;
		}
		
		public static SegmentValueProvider getValueProvider(byte bytes[]) {
			int segmentByteCount = (bytes.length == IPv4Address.BYTE_COUNT) ? IPv4Address.BYTES_PER_SEGMENT : IPv6Address.BYTES_PER_SEGMENT;
			return getValueProvider(bytes, segmentByteCount);
		}
		
		public static SegmentValueProvider getValueProvider(byte bytes[], int segmentByteCount) {
			return (segmentIndex) -> {	
				int value = 0;
				for(int start = segmentIndex * segmentByteCount, end = start + segmentByteCount; start < end; start++) {
					value = (value << 8) | (0xff & bytes[start]);
				}
				return value;
			};
		}
		
		public T get(byte bytes[]) {
			IPVersion version = bytes.length == IPv4Address.BYTE_COUNT ? IPVersion.IPV4 : IPVersion.IPV6;
			int segmentByteCount = version.isIPv4() ? IPv4Address.BYTES_PER_SEGMENT : IPv6Address.BYTES_PER_SEGMENT;
			return get(version, getValueProvider(bytes, segmentByteCount), null, null, null);
		}

		public T get(AddressValueProvider addressProvider) {
			if(addressProvider instanceof IPAddressValueProvider) {
				return get((IPAddressValueProvider) addressProvider);
			}
			return get(addressProvider.getSegmentCount() == IPv4Address.SEGMENT_COUNT ? IPVersion.IPV4 : IPVersion.IPV6, 
					addressProvider.getValues(), addressProvider.getUpperValues(), null, null);	
		}

		public T get(IPAddressValueProvider addressProvider) {
			return get(addressProvider.getIPVersion(), addressProvider.getValues(), addressProvider.getUpperValues(), addressProvider.getPrefixLength(), addressProvider.getZone());
		}

		public T get(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength) {
			return get(version, lowerValueProvider, upperValueProvider, prefixLength, null);
		}

		public T get(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
			return get(IPVersion.IPV6, lowerValueProvider, upperValueProvider, prefixLength, zone);
		}

		private T get(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
			if(backingMap == null) {
				IPAddress addr = addressGenerator.from(version, lowerValueProvider, upperValueProvider, prefixLength, zone);
				return create(addr);
			}
			String key = toNormalizedString(version, lowerValueProvider, upperValueProvider, prefixLength, zone);
			T result = backingMap.get(key);
			if(result == null) {
				IPAddress addr = addressGenerator.from(version, lowerValueProvider, upperValueProvider, prefixLength, zone);
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
		
		protected String toNormalizedString(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
			return addressGenerator.toNormalizedString(version, lowerValueProvider, upperValueProvider, prefixLength, zone);
		}
		
		protected abstract T create(IPAddress addr);

		protected abstract void cache(T result, IPAddress addr);
		
		protected abstract void added(T added);
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
	public static class IPAddressStringGenerator extends HostIdentifierStringGenerator<IPAddressString> {

		private static final long serialVersionUID = 4L;
		
		private final HostIDStringAddressGenerator<IPAddressString> addressGenerator;

		@SuppressWarnings("serial")
		public IPAddressStringGenerator(Map<String, IPAddressString> backingMap, IPAddressStringParameters options) {
			super(backingMap);
			addressGenerator = new HostIDStringAddressGenerator<IPAddressString>(backingMap, options) {
				
				@Override
				protected IPAddressString create(IPAddress addr) {
					return addr.toAddressString();
				}
				
				@Override
				protected void cache(IPAddressString result, IPAddress addr) {
					result.cacheAddress(addr);
				}

				@Override
				protected void added(IPAddressString added) {
					IPAddressStringGenerator.this.added(added);
				}
			};
		}
		
		public IPAddressStringGenerator(Map<String, IPAddressString> backingMap) {
			this(backingMap, null);
		}
		
		public IPAddressStringGenerator(IPAddressStringParameters options) {
			this(null, options);
		}
		
		public IPAddressStringGenerator() {
			this(null, null);
		}

		@Override
		protected IPAddressString create(String addressString) {
			IPAddressStringParameters options = addressGenerator.addressGenerator.options;
			return options == null ? new IPAddressString(addressString) : new IPAddressString(addressString, options);
		}
		
		public static SegmentValueProvider getValueProvider(byte bytes[]) {
			return HostIDStringAddressGenerator.getValueProvider(bytes);
		}
		
		@Override
		public IPAddressString get(byte bytes[]) {
			return addressGenerator.get(bytes);
		}
		
		public IPAddressString get(IPAddressValueProvider addressProvider) {
			return addressGenerator.get(addressProvider);
		}
		
		@Override
		public IPAddressString get(AddressValueProvider addressProvider) {
			return addressGenerator.get(addressProvider);
		}
		
		public IPAddressString get(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength) {
			return addressGenerator.get(version, lowerValueProvider, upperValueProvider, prefixLength);
		}
		
		public IPAddressString get(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
			return addressGenerator.get(lowerValueProvider, upperValueProvider, prefixLength, zone);
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
	public static class HostNameGenerator extends HostIdentifierStringGenerator<HostName> {

		private static final long serialVersionUID = 4L;
		
		private final HostIDStringAddressGenerator<HostName> addressGenerator;
		private final HostNameParameters options;
		
		@SuppressWarnings("serial")
		public HostNameGenerator(Map<String, HostName> backingMap, HostNameParameters options, boolean reverseLookup) {
			super(backingMap);
			addressGenerator = new HostIDStringAddressGenerator<HostName>(backingMap, options.addressOptions) {
				@Override
				protected HostName create(IPAddress addr) {
					if(reverseLookup) {
						return new HostName(addr.toInetAddress().getHostName());
					}
					return new HostName(addr);
				}
				
				@Override
				protected void cache(HostName result, IPAddress addr) {
					result.cacheAddress(addr);
				}

				@Override
				protected void added(HostName added) {
					HostNameGenerator.this.added(added);
				}
			};
			this.options = options;
		}
		
		public HostNameGenerator(Map<String, HostName> backingMap) {
			this(backingMap, HostName.DEFAULT_VALIDATION_OPTIONS, false);
		}
		
		public HostNameGenerator(HostNameParameters options) {
			this(null, options, false);
		}
		
		public HostNameGenerator() {
			this(null, null, false);
		}

		@Override
		protected HostName create(String key) {
			return options == null ? new HostName(key) : new HostName(key, options);
		}
		
		public static SegmentValueProvider getValueProvider(byte bytes[]) {
			return HostIDStringAddressGenerator.getValueProvider(bytes);
		}
		
		@Override
		public HostName get(byte bytes[]) {
			return addressGenerator.get(bytes);
		}
		
		@Override
		public HostName get(AddressValueProvider addressProvider) {
			return addressGenerator.get(addressProvider);
		}
		
		public HostName get(IPVersion version, SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength) {
			return addressGenerator.get(version, lowerValueProvider, upperValueProvider, prefixLength);
		}
		
		public HostName get(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefixLength, CharSequence zone) {
			return addressGenerator.get(lowerValueProvider, upperValueProvider, prefixLength, zone);
		}
	}
}
