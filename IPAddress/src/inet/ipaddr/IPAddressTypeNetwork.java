package inet.ipaddr;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.IPAddressSegmentGrouping.RangeList;
import inet.ipaddr.format.validate.ParsedAddressCreator;

/**
 * A network of addresses of a single version (ie bit length) providing a collection of standard addresses and segments for that version, such as masks and loopbacks.
 * 
 * @author sfoley
 *
 * @param <T> the address class
 */
public abstract class IPAddressTypeNetwork<T extends IPAddress> extends IPAddressNetwork {
	private final T subnets[];
	private final T subnetMasks[];
	private final T hostMasks[];
	private final long networkSegmentMasks[][];
	private final long hostSegmentMasks[][];
	private T loopback;
	private String loopbackStrings[];
	
	static interface IPAddressSegmentCreator<S extends IPAddressSegment> {
		
		S[] createAddressSegmentArray(int length);
		
		S createAddressSegment(int value);
		
		S createAddressSegment(int value, Integer segmentPrefixLength);
		
		S createAddressSegment(int lower, int upper, Integer segmentPrefixLength);
	}

	protected static abstract class IPAddressCreator<T extends IPAddress, R extends IPAddressSection, S extends IPAddressSegment> 
			extends ParsedAddressCreator<T,R,S> implements IPAddressSegmentCreator<S> {
		
		protected abstract R[] createAddressSectionArray(int length);
		
		protected T createAddressInternal(S segments[]) {
			return createAddress(createSectionInternal(segments));
		}
		
		protected T createAddressInternal(S segments[], String zone) {
			return createAddressInternal(createSectionInternal(segments), zone);
		}
		
		protected abstract T createAddress(R section);
		
		protected abstract T createAddressInternal(R section, String zone);
		
		@Override
		protected S createAddressSegmentInternal(int value, Integer segmentPrefixLength, String addressStr, int originalVal, boolean isStandardString, int lowerStringStartIndex, int lowerStringEndIndex) {
			S segment = createAddressSegment(value, segmentPrefixLength);
			segment.setStandardString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal);
			segment.setWildcardString(addressStr, isStandardString, lowerStringStartIndex, lowerStringEndIndex, originalVal);
			return segment;
		}
		
		@Override
		protected S createAddressSegmentInternal(int lower, int upper, Integer segmentPrefixLength, String addressStr, int originalLower, int originalUpper, boolean isStandardString, boolean isStandardRangeString, int lowerStringStartIndex, int lowerStringEndIndex, int upperStringEndIndex) {
			S segment = createAddressSegment(lower, upper, segmentPrefixLength);
			segment.setStandardString(addressStr, isStandardString,  isStandardRangeString, lowerStringStartIndex, lowerStringEndIndex, upperStringEndIndex, originalLower, originalUpper);
			segment.setWildcardString(addressStr, isStandardRangeString, lowerStringStartIndex, upperStringEndIndex, originalLower, originalUpper);
			return segment;
		}

		@Override
		protected abstract R createSectionInternal(S segments[]);
		
		@Override
		protected abstract R createSectionInternal(byte bytes[]);
		
		@Override
		protected T createAddressInternal(R section, String zone, IPAddressString fromString) {
			T result = createAddressInternal(section, zone);
			result.fromString = fromString;
			return result;
		}
		
		@Override
		protected T createAddressInternal(R section, String zone, HostName fromHost) {
			T result = createAddressInternal(section, zone);
			result.fromHost = fromHost;
			return result;
		}

		@Override
		protected T createAddressInternal(R section, IPAddressString fromString) {
			T result = createAddress(section);
			result.fromString = fromString;
			return result;
		}
		
		@Override
		protected T createAddressInternal(R section, HostName fromHost) {
			T result = createAddress(section);
			result.fromHost = fromHost;
			return result;
		}
	}
	
	private IPAddressCreator<T, ?, ?> creator;
	
	protected IPAddressTypeNetwork(Class<T> addressType) {
		IPVersion version = getIPVersion();
		int bitSize = IPAddress.bitCount(version);
		this.subnets = IPAddressSection.cast(Array.newInstance(addressType, bitSize + 1));
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
	
	protected abstract <R extends IPAddressSection, S extends IPAddressSegment> IPAddressCreator<T, R, S> createAddressCreator();

	protected IPAddressCreator<T, ?, ?> getAddressCreator() {
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
		return getMask(networkPrefixLength, withPrefixLength ? subnets : subnetMasks, true, creator, withPrefixLength);
	}
	
	@Override
	public T getHostMask(int networkPrefixLength) {
		return getMask(networkPrefixLength, hostMasks, false, creator, false);
	}
	
	private <R extends IPAddressSection, S extends IPAddressSegment> T getMask(int networkPrefixLength, T cache[], boolean network, IPAddressCreator<T, R, S> creator, boolean withPrefixLength) {
		int bits = networkPrefixLength;
		IPVersion version = getIPVersion();
		int addressBitLength = IPAddress.bitCount(version);
		if(bits < 0 || bits > addressBitLength) {
			throw new IPAddressTypeException(bits, version, "ipaddress.error.prefixSize");
		}
		int prefix = bits;
		int cacheIndex = bits;
		int segmentCount = IPAddress.segmentCount(version);
		int bitsPerSegment = IPAddress.bitsPerSegment(version);
		int onesSubnetIndex = network ? addressBitLength : 0;
		int zerosSubnetIndex = network ? 0 : addressBitLength;
		
		S onesSegment, zerosSegment;
		T onesSubnet = cache[onesSubnetIndex];
		T zerosSubnet = cache[zerosSubnetIndex];
		if(onesSubnet == null || zerosSubnet == null) {
			synchronized(cache) {
				onesSubnet = cache[onesSubnetIndex];
				if(onesSubnet == null) {
					S newSegments[] = creator.createAddressSegmentArray(segmentCount);
					int maxSegmentValue = IPAddress.maxSegmentValue(version);
					if(network && withPrefixLength) {
						S segment = creator.createAddressSegment(maxSegmentValue, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, addressBitLength) /* null */ );
						Arrays.fill(newSegments, 0, newSegments.length - 1, segment);
						S lastSegment = creator.createAddressSegment(maxSegmentValue, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, bitsPerSegment) /* bitsPerSegment */ );
						newSegments[newSegments.length - 1] = lastSegment;
					} else {
						S segment = creator.createAddressSegment(maxSegmentValue);
						Arrays.fill(newSegments, segment);
					}
					onesSubnet = creator.createAddressInternal(newSegments);
					initMaskCachedValues(onesSubnet.addressSection, network, withPrefixLength, addressBitLength, onesSubnetIndex, segmentCount, bitsPerSegment);
					cache[onesSubnetIndex] = onesSubnet;
				}
				zerosSubnet = cache[zerosSubnetIndex];
				if(zerosSubnet == null) {
					S newSegments[] = creator.createAddressSegmentArray(segmentCount);
					S seg;
					if(network && withPrefixLength) {
						seg = creator.createAddressSegment(0, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, 0) /* 0 */);
					} else {
						seg = creator.createAddressSegment(0);
					}
					Arrays.fill(newSegments, seg);
					zerosSubnet = creator.createAddressInternal(newSegments);
					initMaskCachedValues(zerosSubnet.addressSection, network, withPrefixLength, addressBitLength, zerosSubnetIndex, segmentCount, bitsPerSegment);
					cache[zerosSubnetIndex] = zerosSubnet;
				}
			}
		}
		onesSegment = IPAddressSection.cast(onesSubnet.getSegment(1));
		zerosSegment = IPAddressSection.cast(zerosSubnet.getSegment(1));
		T subnet = cache[cacheIndex];
		if(subnet == null) {
			synchronized(cache) {
				subnet = cache[cacheIndex];
				if(subnet == null) {
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
										segment = IPAddressSection.cast(prev.getSegment(j));
										break;
									}
								}
							}
							
							//if none of the other addresses with a similar segment are created yet, we need a new segment.
							if(segment == null) {
								int mask = getSegmentNetworkMask(bits);
								if(network) {
									if(withPrefixLength) {
										segment = creator.createAddressSegment(mask, IPAddressSection.getSegmentPrefixLength(bitsPerSegment, bits));
									} else {
										segment = creator.createAddressSegment(mask);
									}
								} else {
									segment = creator.createAddressSegment(getSegmentHostMask(bits));
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
					S newSegments[] = creator.createAddressSegmentArray(segmentList.size());
					segmentList.toArray(newSegments);
					subnet = creator.createAddressInternal(newSegments);
					
					//initialize the cache fields since we know what they are now - they do not have to be calculated later
					initMaskCachedValues(subnet.addressSection, network, withPrefixLength, addressBitLength, prefix, segmentCount, bitsPerSegment);
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
