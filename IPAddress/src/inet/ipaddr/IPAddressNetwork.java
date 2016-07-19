package inet.ipaddr;

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
	 * 
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
				if(prefix == null) {
					cache[cacheIndex] = prefix = 
							new IPAddressString(new StringBuilder(HostIdentifierStringValidator.MAX_PREFIX_CHARS + 1).append(IPAddress.PREFIX_LEN_SEPARATOR).append(networkPrefixLength).toString());
				}
			}
		}
		return prefix;
	}
}
