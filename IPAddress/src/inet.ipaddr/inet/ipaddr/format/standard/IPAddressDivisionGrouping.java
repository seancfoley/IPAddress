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

package inet.ipaddr.format.standard;

import java.util.Arrays;

import inet.ipaddr.AddressNetwork;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.AddressValueException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressNetwork;
import inet.ipaddr.IPAddressSection.WildcardOptions.WildcardOption;
import inet.ipaddr.IPAddressSegment;
import inet.ipaddr.InconsistentPrefixException;
import inet.ipaddr.format.AddressDivisionGroupingBase;
import inet.ipaddr.format.AddressDivisionSeries;
import inet.ipaddr.format.IPAddressDivisionSeries;
import inet.ipaddr.format.string.IPAddressStringDivision;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.IPAddressStringWriter;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * IPAddressDivisionGrouping objects consist of a series of IPAddressDivision objects, each division containing one or more segments.
 * <p>
 * With the IPAddressSection subclass, each division is one segment (eg either groupings of 4 like 1.2.3.4 or groupings of 8 like 1:2:3:4:5:6:7:8). 
 * <p>
 * For IPv6, a compressed segment still counts as one of the groupings, it is simply not printed as part of the text representation.
 * <p>
 * Alternative groupings include ipv4 groupings define by inet_aton (eg groupings of 1, 2, or 3 divisions like 1, 1.2, and 1.2.3) and the mixed ipv6/ipv4 representation of ipv6 addresses (eg a grouping of 10 divisions like a:b:c:d:e:f:1.2.3.4)
 * <p>
 * IPAddressDivisionGrouping objects are immutable.  Some of the derived state is created upon demand and cached.  This also makes them thread-safe.
 * <p>
 * IPAddressDivisionGrouping objects may be associated with a prefix length, in which case that number of bits in the upper-most
 * portion of the object represent a prefix, while the remaining bits assume all possible values.
 * <p>
 * IPAddressDivision objects use long to represent their values, so this places a cap on the size of the divisions in IPAddressDivisionGrouping.
 * <p>
 *  @author sfoley
 */
public class IPAddressDivisionGrouping extends AddressDivisionGrouping implements IPAddressDivisionSeries {

	private static final long serialVersionUID = 4L;
	
	private final IPAddressNetwork<?, ?, ?, ?, ?> network;
	protected static final RangeCache ZEROS_CACHE = new RangeCache();
	
	static {
		if(RangeCache.PRELOAD_CACHE) {
			ZEROS_CACHE.preloadCache(-1);
		}
	}

	/**
	 * If the grouping is prefixed, then note that we allow both null:null:x:0:0 where is x is the division bit count and null:null:0:0:0 which essentially have the same overall prefix grouping prefix.
	 * For further discussion of this, see {@link AddressDivisionGrouping#normalizePrefixBoundary(int, IPAddressSegment[], int, int, java.util.function.BiFunction)}
	 * 
	 * @param divisions
	 * @param network
	 * @throws NullPointerException if network is null or a division is null
	 */
	public IPAddressDivisionGrouping(IPAddressDivision divisions[], IPAddressNetwork<?, ?, ?, ?, ?> network) throws AddressValueException {
		super(divisions);
		if(network == null) {
			throw new NullPointerException(getMessage("ipaddress.error.nullNetwork"));
		}
		this.network = network;
		int totalPrefixBits = 0;
		for(int i = 0; i < divisions.length; i++) {
			IPAddressDivision division = divisions[i];
			/**
			 * Across an address prefixes are:
			 * (null):...:(null):(1 to x):(0):...:(0)
			 */
			Integer divPrefix = division.getDivisionPrefixLength();
			if(divPrefix != null) {
				cachedPrefixLength = cacheBits(totalPrefixBits + divPrefix);
				for(++i; i < divisions.length; i++) {
					division = divisions[i];
					divPrefix = division.getDivisionPrefixLength();
					if(divPrefix == null || divPrefix != 0) {
						throw new InconsistentPrefixException(divisions[i - 1], division, divPrefix);
					}
				}
				return;
			}
			totalPrefixBits += division.getBitCount();
		}
		cachedPrefixLength = NO_PREFIX_LENGTH;
	}
	
	/**
	 * @throws NullPointerException if getNetwork() returns null or a division is null
	 * @param divisions
	 * @param checkSegs
	 */
	protected IPAddressDivisionGrouping(IPAddressDivision divisions[], boolean checkSegs) {
		super(divisions, checkSegs);
		network = getNetwork();//getNetwork() must be overridden in subclasses
		if(network == null) {
			throw new NullPointerException(getMessage("ipaddress.error.nullNetwork"));
		}
	}
	
	@Override
	public IPAddressNetwork<?, ?, ?, ?, ?> getNetwork() {
		return network;
	}
	
	@Override
	public IPAddressDivision getDivision(int index) {
		return (IPAddressDivision) super.getDivision(index);
	}
	
	@Override
	public int isMore(AddressDivisionSeries other) {
		if(!isMultiple()) {
			return other.isMultiple() ? -1 : 0;
		}
		if(!other.isMultiple()) {
			return 1;
		}
		if(isSinglePrefixBlock() && other.isSinglePrefixBlock()) {
			int bits = getBitCount() - getPrefixLength();
			int otherBits = other.getBitCount() - other.getPrefixLength();
			return bits - otherBits;
		}
		return getCount().compareTo(other.getCount());
	}
	
	@Override
	public Integer getPrefixLength() {
		return getNetworkPrefixLength();
	}

	@Override
	public Integer getNetworkPrefixLength() {
		Integer ret = cachedPrefixLength;
		if(ret == null) {
			Integer result = calculatePrefix(this);
			if(result != null) {
				return cachedPrefixLength = result;
			}
			cachedPrefixLength = NO_PREFIX_LENGTH;
			return null;
		}
		if(ret.intValue() == NO_PREFIX_LENGTH.intValue()) {
			return null;
		}
		return ret;
	}

	/**
	 * Returns whether this address section represents a subnet block of addresses associated its prefix length.
	 * 
	 * Returns false if it has no prefix length, if it is a single address with a prefix length (ie not a subnet), or if it is a range of addresses that does not include
	 * the entire subnet block for its prefix length.
	 * 
	 * If {@link AddressNetwork#getPrefixConfiguration} is set to consider all prefixes as subnets, this returns true for any grouping with prefix length.
	 * 
	 * @return
	 */
	@Override
	public boolean isPrefixBlock() {
		Integer networkPrefixLength = getNetworkPrefixLength();
		if(networkPrefixLength == null) {
			return false;
		}
		if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			return true;
		}
		return containsPrefixBlock(networkPrefixLength);
	}
	
	@Override
	public boolean containsPrefixBlock(int prefixLength) {
		return containsPrefixBlock(this, prefixLength);
	}

	@Override
	public boolean containsSinglePrefixBlock(int prefixLength) {
		return containsSinglePrefixBlock(this, prefixLength);
	}

	/**
	 * Returns whether the division grouping range matches the block of values for its prefix length.
	 * In other words, returns true if and only if it has a prefix length and it has just a single prefix.
	 */
	@Override
	public boolean isSinglePrefixBlock() {
		Integer networkPrefixLength = getNetworkPrefixLength();
		if(networkPrefixLength == null) {
			return false;
		}
		return containsSinglePrefixBlock(networkPrefixLength);
	}
	
	@Override
	public Integer getPrefixLengthForSingleBlock() {
		return getPrefixLengthForSingleBlock(this);
	}

	public boolean includesZeroHost() {
		Integer networkPrefixLength = getNetworkPrefixLength();
		if(networkPrefixLength == null || networkPrefixLength >= getBitCount()) {
			return false;
		}
		if(getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets()) {
			return true;
		}
		int divCount = getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			IPAddressDivision div = getDivision(i);
			Integer segmentPrefixLength = div.getDivisionPrefixLength();
			if(segmentPrefixLength != null) {
				long mask = ~(~0 << (div.getBitCount() - segmentPrefixLength));
				if((mask & div.getDivisionValue()) != 0) {
					return false;
				}
				for(++i; i < divCount; i++) {
					div = getDivision(i);
					if(!div.includesZero()) {
						return false;
					}
				}
			}
		}
		return true;
	}

	@Override
	protected boolean isSameGrouping(AddressDivisionGroupingBase other) {
		return other instanceof IPAddressDivisionGrouping && super.isSameGrouping(other);
	}
	
	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof IPAddressDivisionGrouping) {
			IPAddressDivisionGrouping other = (IPAddressDivisionGrouping) o;
			// we call isSameGrouping on the other object to defer to subclasses IPv4 and IPv6 which check for type IPv4AddressSection and IPv6AddressSection
			return other.isSameGrouping(this); 
		}
		return false;
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
		boolean isFullRangeHost = !getNetwork().getPrefixConfiguration().prefixedSubnetsAreExplicit() && isPrefixBlock();
		includeRanges &= isFullRangeHost;
		int currentIndex = -1, lastIndex = -1, currentCount = 0;
		for(int i = 0; i < divisionCount; i++) {
			IPAddressDivision division = getDivision(i);
			boolean isCompressible = division.isZero() || 
					(includeRanges && division.isPrefixed() && division.isSinglePrefixBlock(0, division.getDivisionPrefixLength()));
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
			if(ranges == null) {
				throw new NullPointerException();
			}
			this.ranges = ranges;
		}

		public int size() {
			return ranges.length;
		}
		
		public Range getRange(int index) {
			return ranges[index];
		}
		
		@Override
		public String toString() {
			return Arrays.asList(ranges).toString();
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
	
	/**
	 * Each StringParams has settings to write exactly one type of IP address part string.
	 * 
	 * @author sfoley
	 */
	protected static class IPAddressStringParams<T extends IPAddressStringDivisionSeries> extends AddressStringParams<T> implements IPAddressStringWriter<T> {
		
		public static final WildcardOption DEFAULT_WILDCARD_OPTION = WildcardOption.NETWORK_ONLY;
		
		protected static final int EXTRA_SPACE = 16;
		 
		private WildcardOption wildcardOption = DEFAULT_WILDCARD_OPTION;
		private int expandSegment[]; //the same as expandSegments but for each segment
		private String addressSuffix = "";
		
		public IPAddressStringParams(int radix, Character separator, boolean uppercase) {
			this(radix, separator, uppercase, (char) 0);
		}
		
		public IPAddressStringParams(int radix, Character separator, boolean uppercase, char zoneSeparator) {
			super(radix, separator, uppercase, zoneSeparator);
		}
		
		public String getAddressSuffix() {
			return addressSuffix;
		}
		
		public void setAddressSuffix(String suffix) {
			this.addressSuffix = suffix;
		}
		
		@Override
		public boolean preferWildcards() {
			return wildcardOption == WildcardOption.ALL;
		}
		
		public void setWildcardOption(WildcardOption option) {
			wildcardOption = option;
		}
		
		public int getExpandedSegmentLength(int segmentIndex) {
			if(expandSegment == null || expandSegment.length <= segmentIndex) {
				return 0;
			}
			return expandSegment[segmentIndex];
		}
		
		public void expandSegment(int index, int expansionLength, int segmentCount) {
			if(expandSegment == null) {
				expandSegment = new int[segmentCount];
			}
			expandSegment[index] = expansionLength;
		}

		@Override
		public char getTrailingSegmentSeparator() {
			return separator;
		}
		
		public StringBuilder appendSuffix(StringBuilder builder) {
			String suffix = getAddressSuffix();
			if(suffix != null) {
				builder.append(suffix);
			}
			return builder;
		}
		
		public int getAddressSuffixLength() {
			String suffix = getAddressSuffix();
			if(suffix != null) {
				return suffix.length();
			}
			return 0;
		}
		
		//returns -1 for MAX, or 0, 1, 2, 3 to indicate the string prefix length
		@Override
		public int getLeadingZeros(int segmentIndex) {
			if(expandSegments) {
				return -1;
			} else if(expandSegment != null && expandSegment.length > segmentIndex) {
				return expandSegment[segmentIndex];
			}
			return 0;
		}
		
		@Override
		public IPAddressStringParams<T> clone() {
			IPAddressStringParams<T> parms = (IPAddressStringParams<T>) super.clone();
			if(expandSegment != null) {
				parms.expandSegment = expandSegment.clone();
			}
			return parms;
			
		}

		@Override
		public int getTrailingSeparatorCount(T addr) {
			int count = addr.getDivisionCount();
			if(count > 0) {
				return count - 1;
			}
			return 0;
		}
		
		public static int getPrefixIndicatorStringLength(IPAddressStringDivisionSeries addr) {
			if(addr.isPrefixed()) {
				return AddressDivision.toUnsignedStringLengthFast(addr.getPrefixLength(), 10) + 1;
			}
			return 0;
		}
		
		@Override
		public int getStringLength(T addr) {
			int count = getSegmentsStringLength(addr);
			if(!isReverse() && !preferWildcards()) {
				count += getPrefixIndicatorStringLength(addr);
			}
			return count + getAddressSuffixLength() + getAddressLabelLength();
		}
		
		public void appendPrefixIndicator(StringBuilder builder, IPAddressStringDivisionSeries addr) {
			if(addr.isPrefixed()) {
				builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(addr.getPrefixLength());
			}
		}
		
		@Override
		public StringBuilder append(StringBuilder builder, T addr, CharSequence zone) {
			/* 
			 * Our order is label, then segments, then zone, then suffix, then prefix length.  
			 * This is documented in more detail in IPv6AddressSection for the IPv6-only case.
			 */
			appendSuffix(appendZone(appendSegments(appendLabel(builder), addr), zone));
			if(!isReverse() && !preferWildcards()) {
				appendPrefixIndicator(builder, addr);
			}
			return builder;
		}
		
		@Override
		protected int appendSegment(int segmentIndex, StringBuilder builder, T part) {
			IPAddressStringDivision seg = part.getDivision(segmentIndex);
			PrefixConfiguration config = part.getNetwork().getPrefixConfiguration();
			//consider all the cases in which we need not account for prefix length
			Integer prefix; 
			if(config.prefixedSubnetsAreExplicit() || preferWildcards() 
					|| (prefix = seg.getDivisionPrefixLength()) == null  || prefix >= seg.getBitCount()
					|| (config.zeroHostsAreSubnets() && !part.isPrefixBlock())
					|| isSplitDigits()) {
				return seg.getStandardString(segmentIndex, this, builder);
			}
			//prefix length will have an impact on the string - either we need not print the range at all
			//because it is equivalent to the prefix length, or we need to adjust the upper value of the 
			//range so that the host is zero when printing the string
			if(seg.isSinglePrefixBlock()) {
				return seg.getLowerStandardString(segmentIndex, this, builder);
			}
			return seg.getPrefixAdjustedRangeString(segmentIndex, this, builder);
		}
	}
}
