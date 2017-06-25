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

package inet.ipaddr.format;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSection.WildcardOptions.WildcardOption;
import inet.ipaddr.format.util.IPAddressStringWriter;
import inet.ipaddr.ipv6.IPv6Address;

/**
 * IPAddressDivisionGrouping objects consist of a series of IPAddressDivision objects, each division containing one or more segments.
 * <p>
 * With the IPAddressSection subclass, each division is one segment (eg either groupings of 4 like 1.2.3.4 or groupings of 8 like 1:2:3:4:5:6:7:8). 
 * 
 * For IPv6, a compressed segment still counts as one of the groupings, it is simply not printed as part of the text representation.
 * 
 * Alternative groupings include ipv4 groupings define by inet_aton (eg groupings of 1, 2, or 3 divisions like 1, 1.2, and 1.2.3) and the mixed ipv6/ipv4 representation of ipv6 addresses (eg a grouping of 10 divisions like a:b:c:d:e:f:1.2.3.4)
 * 
 * IPAddressDivisionGrouping objects are immutable.  Some of the derived state is created upon demand and cached.
 * 
 * This also makes them thread-safe.
 * 
 * May be associated with a prefix length, in which case that number of bits in the upper-most
 * portion of the object represent a prefix, while the remaining bits can assume all possible values.
 * 
 *  @author sfoley
 */
public class IPAddressDivisionGrouping extends AddressDivisionGrouping implements IPAddressStringDivisionSeries {

	private static final long serialVersionUID = 3L;
	
	protected static final RangeCache ZEROS_CACHE = new RangeCache();
	static {
		if(RangeCache.PRELOAD_CACHE) {
			ZEROS_CACHE.preloadCache(-1);
		}
	}
	
	public IPAddressDivisionGrouping(IPAddressDivision divisions[]) {
		super(divisions);
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
		if(isRangeEquivalentToPrefix() && other.isRangeEquivalentToPrefix()) {
			int bits = getBitCount() - getPrefixLength();
			int otherBits = other.getBitCount() - other.getPrefixLength();
			return bits - otherBits;
		}
		return getCount().compareTo(other.getCount());
	}
	
	/**
	 * @return whether this address represents a network prefix or the set of all addresses with the same network prefix
	 */
	@Override
	public boolean isPrefixed() {
		//across the address prefixes are (none)::(1 to 16)::(0), see getSegmentPrefixLength
		//so it is enough to check just the last one
		int count = getDivisionCount();
		return count > 0 && getDivision(count - 1).isPrefixed();
	}
	
	@Override
	public Integer getPrefixLength() {
		return getNetworkPrefixLength();
	}
	
	public Integer getNetworkPrefixLength() {
		Integer ret = cachedPrefix;
		if(ret == null) {
			if(isPrefixed()) {
				int result = 0;
				for(int i=0; i < divisions.length; i++) { 
					IPAddressDivision div = getDivision(i);
					Integer prefix = div.getDivisionPrefixLength();
					if(prefix != null) {
						result += prefix;
						break; //the rest will be 0
					} else {
						result += div.getBitCount();
					}
				}
				return cachedPrefix = result;
			} else {
				cachedPrefix = -1;
				return null;
			}
		}
		if(ret < 0) {
			return null;
		}
		return ret;
	}

	public boolean isMultipleByNetworkPrefix() {
		if(!isPrefixed()) {
			return false;
		}
		IPAddressDivision div = getDivision(getDivisionCount() - 1);
		return div.getDivisionPrefixLength() < div.getBitCount(); 
	}

	@Override
	public boolean isMultipleByPrefix() {
		return isMultipleByNetworkPrefix();
	}
	
	/**
	 * @return whether this address represents more than one address determined entirely by the network prefix length.
	 */
	@Override
	public boolean isRangeEquivalentToPrefix() {
		if(!isMultipleByNetworkPrefix()) {
			return !isMultiple();
		}
		int count = getDivisionCount();
		for(int i = 0; i < count; i++) {
			IPAddressDivision div = getDivision(i);
			Integer divPrefix = div.getDivisionPrefixLength();
			if(divPrefix != null && divPrefix == 0) {
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
	public Integer getEquivalentPrefix() {
		int totalPrefix = 0;
		int divCount = getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			IPAddressDivision div = getDivision(i);
			int segPrefix = div.getMinPrefix();
			if(!div.isRangeEquivalent(segPrefix)) {
				return null;
			}
			if(div.isPrefixed()) {
				return totalPrefix + segPrefix;
			}
			if(segPrefix < div.getBitCount()) {
				//remaining segments must be full range or we return null
				for(i++; i < divCount; i++) {
					IPAddressDivision laterDiv = getDivision(i);
					if(!laterDiv.isFullRange()) {
						return null;
					}
				}
				return totalPrefix + segPrefix;
			}
			totalPrefix += segPrefix;
		}
		return totalPrefix;
	}

	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof IPAddressDivisionGrouping) {
			IPAddressDivisionGrouping other = (IPAddressDivisionGrouping) o;
			return other.isSameGrouping(this); //we call isSameGrouping on the other object to defer to subclasses
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
			if(addr.getDivisionCount() > 0) {
				return addr.getDivisionCount() - 1;
			}
			return 0;
		}
		
		public static int getPrefixStringLength(IPAddressStringDivisionSeries addr) {
			if(addr.isPrefixed()) {
				return AddressDivision.toUnsignedStringLengthFast(addr.getPrefixLength(), 10) + 1;
			}
			return 0;
		}
		
		@Override
		public int getStringLength(T addr) {
			int count = getSegmentsStringLength(addr);
			if(!isReverse() && !preferWildcards()) {
				count += getPrefixStringLength(addr);
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
			 * Our order is zone, then suffix, then prefix length.  This is documented in more detail for the IPv6-only case.
			 */
			appendSegments(appendLabel(builder), addr);
			if(zone != null) {
				appendZone(builder, zone);
			}
			appendSuffix(builder);
			if(!isReverse() && !preferWildcards()) {
				appendPrefixIndicator(builder, addr);
			}
			return builder;
		}
	}
}
