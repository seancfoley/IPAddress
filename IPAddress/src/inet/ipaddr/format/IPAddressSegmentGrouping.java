package inet.ipaddr.format;

import java.math.BigInteger;
import java.util.Arrays;

import inet.ipaddr.IPAddress;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * IPAddressSegmentGrouping objects consist of a series of IPAddressDivision objects, each division containing one or more segments.
 * <p>
 * With the IPAddressSection subclass, each division is one segment (eg either groupings of 4 like 1.2.3.4 or groupings of 8 like 1:2:3:4:5:6:7:8). 
 * 
 * For IPv6, a compressed segment still counts as one of the groupings, it is simply not printed as part of the text representation.
 * 
 * Alternative groupings include ipv4 groupings define by inet_aton (eg groupings of 1, 2, or 3 divisions like 1, 1.2, and 1.2.3) and the mixed ipv6/ipv4 representation of ipv6 addresses (eg a grouping of 10 divisions like a:b:c:d:e:f:1.2.3.4)
 * 
 * IPAddressSegmentGrouping objects are immutable.  Some of the derived state is created upon demand and cached.
 * 
 * This also makes them thread-safe.
 * 
 *  @author sfoley
 */
public class IPAddressSegmentGrouping implements IPAddressPart, Comparable<IPAddressSegmentGrouping> {

	private static final long serialVersionUID = 1L;
	protected static final RangeCache ZEROS_CACHE = new RangeCache();
	static {
		if(RangeCache.PRELOAD_CACHE) {
			ZEROS_CACHE.preloadCache(-1);
		}
	}
	
	protected final IPAddressDivision divisions[];
	protected String string;
	private transient BigInteger cachedCount;
	private transient Integer cachedNetworkPrefix; //null indicates this field not initialized, -1 indicates the prefix len is null
	
	protected int hashCode;
	
	public IPAddressSegmentGrouping(IPAddressDivision divisions[]) {
		this.divisions = divisions;
	}
	
	protected void initCachedValues(
			Integer cachedNetworkPrefix,
			BigInteger cachedCount) {
		this.cachedNetworkPrefix = cachedNetworkPrefix;
		this.cachedCount = cachedCount;
	}
	
	@Override
	public IPAddressDivision getDivision(int index) {
		return divisions[index];
	}

	@Override
	public int getDivisionCount() {
		return divisions.length;
	}
	
	@Override
	public int getByteCount() {
		int bytes = 0;
		for(IPAddressDivision combo: divisions) {
			bytes += combo.getByteCount();
		}
		return bytes;
	}
	
	public int getBitCount() {
		int bits = 0;
		for(IPAddressDivision combo: divisions) {
			bits += combo.getBitCount();
		}
		return bits;
	}
	
	/**
	 * @return whether this address represents a network prefix or the set of all addresses with the same network prefix
	 */
	public boolean isPrefixed() {
		//across the address prefixes are (none)::(1 to 16)::(0), see getSegmentPrefixLength
		//so it is enough to check just the last one
		return divisions.length > 0 && divisions[divisions.length - 1].isPrefixed();
	}
	
	@Override
	public Integer getNetworkPrefixLength() {
		Integer ret = cachedNetworkPrefix;
		if(ret == null) {
			if(isPrefixed()) {
				int result = 0;
				for(int i=0; i < divisions.length; i++) { 
					IPAddressDivision div = divisions[i];
					Integer prefix = div.getDivisionPrefixLength();
					if(prefix != null) {
						result += prefix;
						break; //the rest will be 0
					} else {
						result += div.getBitCount();
					}
				}
				return cachedNetworkPrefix = result;
			} else {
				cachedNetworkPrefix = -1;
				return null;
			}
		}
		if(ret < 0) {
			return null;
		}
		return ret;
	}
	
	/**
	 * gets the count of addresses that this address may represent
	 * 
	 * If this address is not a CIDR and it has no range, then there is only one such address.
	 * 
	 * @return
	 */
	public BigInteger getCount() {
		if(cachedCount != null) {
			return cachedCount;
		}
		BigInteger result = BigInteger.ONE;
		if(isMultiple()) {
			for(int i = 0; i < divisions.length; i++) {
				long segCount = divisions[i].getCount();
				result = result.multiply(BigInteger.valueOf(segCount));
			}
		}
		return cachedCount = result;
	}
	
	/**
	 * @return whether this address represents more than one address.
	 * Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
	 */
	public boolean isMultiple() {
		for(int i = divisions.length - 1; i >= 0; i--) {//go in reverse order, with prefixes multiple more likely to show up in last segment
			IPAddressDivision seg = divisions[i];
			if(seg.isMultiple()) {
				return true;
			}
		}
		return false;
	}
	
	public boolean isMultipleByNetworkPrefix() {
		if(!isPrefixed()) {
			return false;
		}
		IPAddressDivision div = divisions[divisions.length - 1];
		return div.getDivisionPrefixLength() < div.getBitCount(); 
	}

	/**
	 * @return whether this address represents more than one address determined entirely by the network prefix length.
	 */
	public boolean isRangeEquivalentToPrefix() {
		if(!isMultipleByNetworkPrefix()) {
			return !isMultiple();
		}
		for(int i = 0; i < divisions.length; i++) {
			IPAddressDivision div = divisions[i];
			if(div.isPrefixed() && div.getDivisionPrefixLength() == 0) {
				//all subsequent prefixes will also be 0 and the range will be full on all of them
				break;
			}
			if(!div.isRangeEquivalentToPrefix()) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	public int hashCode() {
		int res = hashCode;
		if(res == 0) {
			int fullResult = 1;
			for(int i = 0; i < getDivisionCount(); i++) {
				IPAddressDivision combo = getDivision(i);
				long value = combo.getLowerValue();
				long shifted = value >>> 32;
				int adjusted = (int) ((shifted == 0) ? value : (value ^ shifted));
				fullResult = 31 * fullResult + adjusted;
				long upperValue = combo.getUpperValue();
				if(upperValue != value) {
					shifted = upperValue >>> 32;
					adjusted = (int) ((shifted == 0) ? upperValue : (upperValue ^ shifted));
					fullResult = 31 * fullResult + adjusted;
				}
			}
			hashCode = res = fullResult;
		}
		return res;
	}
	
	protected boolean isSameGrouping(IPAddressSegmentGrouping other) {
		IPAddressDivision oneSegs[] = divisions;
		IPAddressDivision twoSegs[] = other.divisions;
		if(oneSegs.length != twoSegs.length) {
			return false;
		}
		for(int i = 0; i < oneSegs.length; i++) {
			IPAddressDivision one = oneSegs[i];
			IPAddressDivision two = twoSegs[i];
			if(!one.isSameValues(two)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof IPAddressSegmentGrouping) {
			IPAddressSegmentGrouping other = (IPAddressSegmentGrouping) o;
			return other.isSameGrouping(this); //we call isSameGrouping on the other object to defer to subclasses
		}
		return false;
	}

	@Override
	public int compareTo(IPAddressSegmentGrouping other) {
		return IPAddress.addressComparator.compare(this, other);
	}

	@Override
	public String toString() {
		if(string == null) {
			string = Arrays.asList(divisions).toString();
		}
		return string;
	}
	
	public boolean isZero() {
		for(int i = 0; i < getDivisionCount(); i++) {
			if(!getDivision(i).isZero()) {
				return false;
			}
		}
		return true;
	}
	
	/**
	 * @return the segments which are zero
	 */
	public RangeList getZeroSegments() {
		return getZeroSegments(false);
	}

	/**
	 * @return the segments which are zero or whose prefix-based range includes 0
	 */
	public RangeList getZeroRangeSegments() {
		if(isPrefixed()) {
			return getZeroSegments(true);
		}
		return getZeroSegments();
	}
	
	protected static RangeList getNoZerosRange() {
		return RangeCache.NO_ZEROS;
	}
	
	protected static RangeList getSingleRange(int index, int len) {
		RangeCache cache = ZEROS_CACHE.addRange(index, -1, len);
		return cache.get();
	}
	
	protected RangeList getZeroSegments(boolean includeRanges) {
		RangeCache cache = ZEROS_CACHE;
		int divisionCount = getDivisionCount();
		int currentIndex = -1, lastIndex = -1, currentCount = 0;
		for(int i = 0; i < divisionCount; i++) {
			IPAddressDivision division = getDivision(i);
			boolean isCompressible = division.isZero() || (includeRanges && division.isSamePrefixedRange(0));
			if(isCompressible) {
				if(++currentCount == 1) {
					currentIndex = i;
				}
				if(i == divisionCount - 1) {
					cache = cache.addRange(currentIndex, lastIndex, currentCount);
					lastIndex = currentIndex + currentCount;
				}
			} else if(currentCount > 0) {
				cache = cache.addRange(currentIndex, lastIndex, currentCount);
				lastIndex = currentIndex + currentCount;
				currentCount = 0;
			}
		}
		return cache.get();
	}

	public static class Range {
		public final int index;
		public final int length;
		
		Range(int index, int length) {
			this.index = index;
			this.length = length;
		}
		
		@Override
		public String toString() {
			return "[" + index + ',' + (index + length) + ']';
		}
	}
	
	public static class RangeList {
		final Range ranges[];
		
		RangeList(Range ranges[]) {
			this.ranges = ranges;
		}

		public int size() {
			return ranges.length;
		}
		
		public Range getRange(int index) {
			return ranges[index];
		}
	}

	/**
	 * A cache of ZeroRange objects in a tree structure.
	 * 
	 * Starting from the root of the tree, as you traverse an address grouping from left to right,
	 * if you have another range located at offset x from the last one, and it has length y,
	 * then you follow nextRange[x][y] in the tree.
	 * 
	 * When you have no more ranges (and this no more tree nodes to follow), then you can use the field for the cached ZeroRanges object
	 * which is associated with the path you've followed (which corresponds to the zero-ranges in the address).
	 * 
	 * @author sfoley
	 *
	 */
	private static class RangeCache {
		static boolean PRELOAD_CACHE;
		static final int MAX_DIVISION_COUNT = IPv6Address.SEGMENT_COUNT;
		static final RangeList NO_ZEROS = new RangeList(new Range[0]);
		
		RangeCache nextRange[][];//nextRange[x - 1][y - 1] indicates tree entry for cases where the next range is at offset x from the current one and has length y
		RangeCache parent;//the parent of this entry in the tree
		RangeList zeroRanges;
		Range range;
		
		RangeCache() {
			this(null, MAX_DIVISION_COUNT, null);
			zeroRanges = NO_ZEROS;
		}
		
		private RangeCache(RangeCache parent, int potentialZeroOffsets, Range range) {
			if(potentialZeroOffsets > 0) {
				nextRange = new RangeCache[potentialZeroOffsets][];
				for(int i = 0; i < potentialZeroOffsets; i++) {
					nextRange[i] = new RangeCache[potentialZeroOffsets - i];
				}
			}
			this.parent = parent;
			this.range = range;
		}
		
		private void get(Range ranges[], int rangesIndex) {
			ranges[--rangesIndex] = range;
			if(rangesIndex > 0) {
				parent.get(ranges, rangesIndex);
			}
		}
		
		public RangeList get() {
			RangeList result = zeroRanges;
			if(result == null) {
				int depth = 0;
				RangeCache up = parent;
				while(up != null) {
					depth++;
					up = up.parent;
				}
				Range ranges[] = new Range[depth];
				if(depth > 0) {
					ranges[--depth] = range;
					if(depth > 0) {
						parent.get(ranges, depth);
					}
				}
				zeroRanges = result = new RangeList(ranges);
			}
			return result;
		}

		void preloadCache(int lastIndex) {
			if(nextRange != null) {
				for(int i = 0; i < nextRange.length; i++) {
					RangeCache next[] = nextRange[i];
					for(int j = 0; j < next.length; j++) {
						Range newRange;
						if(lastIndex == -1) {//we are the root ZEROS_CACHE
							newRange = new Range(i + lastIndex + 1, j + 1);
						} else {
							newRange = ZEROS_CACHE.nextRange[i + lastIndex + 1][j].range;
						}
						int nextPotentialZeroIndex = i + lastIndex + j + 3;
						int remainingPotentialZeroOffsets = RangeCache.MAX_DIVISION_COUNT - nextPotentialZeroIndex;
						RangeCache newRangeCache = new RangeCache(this, remainingPotentialZeroOffsets, newRange);
						newRangeCache.get();
						next[j] = newRangeCache;
					}
				}
				for(int i = 0; i < nextRange.length; i++) {
					RangeCache next[] = nextRange[i];
					for(int j = 0; j < next.length; j++) {
						RangeCache nextCache = next[j];
						Range nextRange = nextCache.range;
						nextCache.preloadCache(nextRange.index + nextRange.length);
					}
				}
			}
		}
		
		public RangeCache addRange(int currentIndex, int lastIndex, int currentCount) {
			int offset = currentIndex - lastIndex;//the offset from the end of the last zero-range, which must be at least 1
			int cacheOffset = offset - 1;//since offset must be at least 1 we adjust by 1
			int cacheCount = currentCount - 1;//since currentCount must be at least 1, we adjust by 1
			RangeCache next = nextRange[cacheOffset][cacheCount];
			if(next == null) {
				//we will never reach here when the cache is preloaded.
				synchronized(this) {
					next = nextRange[cacheOffset][cacheCount];
					if(next == null) {
						int nextPotentialZeroIndex = lastIndex + 1;//we adjust by 1 the next potential index since at offset 0 we do not have a 0
						int remainingPotentialZeroOffsets = RangeCache.MAX_DIVISION_COUNT - nextPotentialZeroIndex;
						Range newRange;
						if(this == ZEROS_CACHE) {
							newRange = new Range(currentIndex, currentCount);
						} else {
							RangeCache rootNext = ZEROS_CACHE.nextRange[currentIndex][currentCount - 1];
							if(rootNext == null) {
								ZEROS_CACHE.nextRange[currentIndex][currentCount - 1] = new RangeCache(ZEROS_CACHE, RangeCache.MAX_DIVISION_COUNT, newRange = new Range(currentIndex, currentCount));
							} else {
								newRange = rootNext.range;
							}
						}
						nextRange[cacheOffset][cacheCount] = next = new RangeCache(this, remainingPotentialZeroOffsets, newRange);
					}
				}
			}
			return next;
		}
	}
}
