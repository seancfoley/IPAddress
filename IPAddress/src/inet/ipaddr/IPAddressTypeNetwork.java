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

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.BiFunction;
import java.util.function.Function;

import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.AddressCreator;
import inet.ipaddr.format.IPAddressDivisionGrouping.RangeList;

/**
 * A network of addresses of a single version (ie bit length) providing a collection of standard addresses and segments for that version, such as masks and loopbacks.
 * 
 * @author sfoley
 *
 * @param <T> the address class
 */
public abstract class IPAddressTypeNetwork<T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> extends IPAddressNetwork {
	private final T subnets[];
	private final T subnetMasks[];
	private final T hostMasks[];
	private final long networkSegmentMasks[][];
	private final long hostSegmentMasks[][];
	private T loopback;
	private String loopbackStrings[];

	protected static abstract class IPAddressCreator<T extends IPAddress, R extends IPAddressSection, E extends IPAddressSection, S extends IPAddressSegment> 
			extends AddressCreator<T, R, E, S> {
		
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
		
		protected abstract R createSection(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefix);
		
		protected abstract R createSectionInternal(byte bytes[], Integer prefix);
		
		@Override
		protected T createAddressInternal(S segments[]) {
			return createAddress(createSectionInternal(segments), null);
		}
		
		protected T createAddressInternal(S segments[], CharSequence zone) {
			return createAddress(createSectionInternal(segments), zone);
		}
		
		protected T createAddressInternal(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefix) {
			return createAddress(createSection(lowerValueProvider, upperValueProvider, prefix));
		}
		
		protected T createAddressInternal(SegmentValueProvider lowerValueProvider, SegmentValueProvider upperValueProvider, Integer prefix, CharSequence zone) {
			return createAddress(createSection(lowerValueProvider, upperValueProvider, prefix), zone);
		}

		protected T createAddressInternal(byte bytes[], Integer prefix) {
			return createAddress(createSectionInternal(bytes, prefix));
		}
		
		protected T createAddressInternal(byte bytes[], Integer prefix, CharSequence zone) {
			return createAddress(createSectionInternal(bytes, prefix), zone);
		}
		
		protected T createAddressInternal(byte bytes[], Integer prefix, CharSequence zone, HostName fromHost) {
			return createAddressInternal(createSectionInternal(bytes, prefix), zone, fromHost);
		}
		
		protected T createAddressInternal(byte bytes[], Integer prefix, HostName fromHost) {
			return createAddressInternal(createSectionInternal(bytes, prefix), fromHost);
		}

		@Override
		protected T createAddressInternal(R section, CharSequence zone, HostIdentifierString from) {
			T result = createAddress(section, zone);
			result.cache(from);
			return result;
		}

		@Override
		protected T createAddressInternal(R section, HostIdentifierString from) {
			T result = createAddress(section);
			result.cache(from);
			return result;
		}

		/* this method exists and is protected because zone makes no sense for IPv4 so we do not expose it (internally it is always null) */
		protected abstract T createAddress(R section, CharSequence zone);

		@Override
		public abstract T createAddress(R section);
	}
	
	private IPAddressCreator<T, R, ?, S> creator;
	
	@SuppressWarnings("unchecked")
	protected IPAddressTypeNetwork(Class<T> addressType) {
		IPVersion version = getIPVersion();
		int bitSize = IPAddress.bitCount(version);
		this.subnets = (T[]) Array.newInstance(addressType, bitSize + 1);
		this.subnetMasks = this.subnets.clone();
		this.hostMasks = this.subnets.clone();
		this.creator = createAddressCreator();
		int segmentBitSize = IPAddressSegment.getBitCount(version);
		int segmentCount = IPAddress.segmentCount(version);
		this.networkSegmentMasks = new long[segmentCount][];
		this.hostSegmentMasks = this.networkSegmentMasks.clone();
		for(int h = 0, allBitSize = segmentBitSize; h < segmentCount && allBitSize < Long.SIZE; h++, allBitSize += segmentBitSize) {
			long fullMask = ~(~0L << allBitSize); //allBitSize must be 6 digits at most for this shift to work per the java spec (so it must be less than 2^6 = 64)
			networkSegmentMasks[h] = new long[allBitSize + 1];
			hostSegmentMasks[h] = networkSegmentMasks[h].clone();
			for(int i = 0; i <= allBitSize; i++) {
				long networkMask = this.networkSegmentMasks[h][i] = fullMask & (fullMask << (allBitSize - i));
				this.hostSegmentMasks[h][i] = ~networkMask & fullMask;
			}
		}
	}
	
	protected abstract BiFunction<T, Integer, S> getSegmentProducer();
	
	protected abstract Function<T, R> getSectionProducer();
	
	protected abstract IPAddressCreator<T, R, ?, S> createAddressCreator();

	protected IPAddressCreator<T, R, ?, S> getAddressCreator() {
		return creator;
	}

	@Override
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
	
	@Override
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
	
	@Override
	public int getSegmentNetworkMask(int segmentPrefixLength) {
		//the 0th array are masks of just 1 segment and 1 segment is always less than 32 bits, so we can cast to an int
		return (int) networkSegmentMasks[0][segmentPrefixLength];
	}
	
	@Override
	public int getSegmentHostMask(int segmentPrefixLength) {
		//the 0th array are masks of just 1 segment and 1 segment is always less than 32 bits, so we can cast to an int
		return (int) hostSegmentMasks[0][segmentPrefixLength];
	}

	@Override
	public long getSegmentNetworkMask(int segmentPrefixLength, int joinedSegments) {
		return networkSegmentMasks[joinedSegments][segmentPrefixLength];
	}
	
	@Override
	public long getSegmentHostMask(int segmentPrefixLength, int joinedSegments) {
		return hostSegmentMasks[joinedSegments][segmentPrefixLength];
	}
	
	@Override
	public T getNetworkMask(int networkPrefixLength) {
		return getNetworkMask(networkPrefixLength, true);
	}
	
	@Override
	public T getNetworkMask(int networkPrefixLength, boolean withPrefixLength) {
		return getMask(networkPrefixLength, withPrefixLength ? subnets : subnetMasks, true, withPrefixLength);
	}
	
	@Override
	public R getNetworkMaskSection(int networkPrefixLength) {
		return getSectionProducer().apply(getNetworkMask(networkPrefixLength, true));
	}
	
	@Override
	public T getHostMask(int networkPrefixLength) {
		return getMask(networkPrefixLength, hostMasks, false, false);
	}
	
	@Override
	public R getHostMaskSection(int networkPrefixLength) {
		return getSectionProducer().apply(getHostMask(networkPrefixLength));
	}
	
	private T getMask(int networkPrefixLength, T cache[], boolean network, boolean withPrefixLength) {
		int bits = networkPrefixLength;
		IPVersion version = getIPVersion();
		int addressBitLength = IPAddress.bitCount(version);
		if(bits < 0 || bits > addressBitLength) {
			throw new AddressTypeException(bits, version, "ipaddress.error.prefixSize");
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
					int segmentCount = IPAddress.segmentCount(version);
					int bitsPerSegment = IPAddress.bitsPerSegment(version);
					onesSubnet = cache[onesSubnetIndex];
					if(onesSubnet == null) {
						IPAddressCreator<T, ?, ?, S> creator = getAddressCreator();
						S newSegments[] = creator.createSegmentArray(segmentCount);
						int maxSegmentValue = IPAddress.maxSegmentValue(version);
						if(network && withPrefixLength) {
							S segment = creator.createSegment(maxSegmentValue, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, addressBitLength) /* null */ );
							Arrays.fill(newSegments, 0, newSegments.length - 1, segment);
							S lastSegment = creator.createSegment(maxSegmentValue, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, bitsPerSegment) /* bitsPerSegment */ );
							newSegments[newSegments.length - 1] = lastSegment;
						} else {
							S segment = creator.createSegment(maxSegmentValue);
							Arrays.fill(newSegments, segment);
						}
						onesSubnet = creator.createAddressInternal(newSegments); /* address creation */
						initMaskCachedValues(onesSubnet.getSection(), network, withPrefixLength, addressBitLength, onesSubnetIndex, segmentCount, bitsPerSegment);
						cache[onesSubnetIndex] = onesSubnet;
					}
					zerosSubnet = cache[zerosSubnetIndex];
					if(zerosSubnet == null) {
						IPAddressCreator<T, ?, ?, S> creator = getAddressCreator();
						S newSegments[] = creator.createSegmentArray(segmentCount);
						S seg;
						if(network && withPrefixLength) {
							seg = creator.createSegment(0, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, 0) /* 0 */);
						} else {
							seg = creator.createSegment(0);
						}
						Arrays.fill(newSegments, seg);
						zerosSubnet = creator.createAddressInternal(newSegments); /* address creation */
						initMaskCachedValues(zerosSubnet.getSection(), network, withPrefixLength, addressBitLength, zerosSubnetIndex, segmentCount, bitsPerSegment);
						cache[zerosSubnetIndex] = zerosSubnet;
					}
				}
			}
			
			synchronized(cache) {
				subnet = cache[cacheIndex];
				if(subnet == null) {			
					BiFunction<T, Integer, S> segProducer = getSegmentProducer();				
					int segmentCount = IPAddress.segmentCount(version);
					int bitsPerSegment = IPAddress.bitsPerSegment(version);
					int prefix = bits;
					S onesSegment = segProducer.apply(onesSubnet, 1);
					S zerosSegment = segProducer.apply(zerosSubnet, 1);
					IPAddressCreator<T, ?, ?, S> creator = getAddressCreator();
					
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
					subnet = creator.createAddressInternal(newSegments); /* address creation */
					
					//initialize the cache fields since we know what they are now - they do not have to be calculated later
					initMaskCachedValues(subnet.getSection(), network, withPrefixLength, addressBitLength, prefix, segmentCount, bitsPerSegment);
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
			int bitsPerSegment) {
		Integer cachedNetworkPrefix, cachedMinPrefix, cachedEquivalentPrefix;
		BigInteger cachedCount;
		RangeList zeroSegments, zeroRanges;
		boolean hasZeroRanges = network ? addressBitLength - networkPrefixLength >= bitsPerSegment : networkPrefixLength >= bitsPerSegment;
		RangeList noZeros = IPAddressSection.getNoZerosRange();
		if(hasZeroRanges) {
			int rangeIndex, rangeLen;
			if(network) {
				int segmentIndex = (networkPrefixLength + bitsPerSegment - 1) / bitsPerSegment;//for network we round up
				rangeIndex = segmentIndex;
				rangeLen = segmentCount - segmentIndex;
			} else {
				rangeIndex = 0;
				rangeLen = networkPrefixLength / bitsPerSegment;//for host we round down
			}
			zeroRanges = IPAddressSection.getSingleRange(rangeIndex, rangeLen);
			zeroSegments = (network && withPrefixLength) ? noZeros : zeroRanges;
		} else {
			zeroSegments = zeroRanges = noZeros;
		}
		if(network && withPrefixLength) {
			cachedEquivalentPrefix = cachedMinPrefix = cachedNetworkPrefix = networkPrefixLength;
			cachedCount = BigInteger.valueOf(2).pow(addressBitLength - networkPrefixLength);
		} else {
			cachedEquivalentPrefix = cachedMinPrefix = addressBitLength;
			cachedNetworkPrefix = -1;
			cachedCount = BigInteger.ONE;
		}
		section.initCachedValues(networkPrefixLength, network, cachedNetworkPrefix, cachedMinPrefix, cachedEquivalentPrefix, cachedCount, zeroSegments, zeroRanges);
	}
}
