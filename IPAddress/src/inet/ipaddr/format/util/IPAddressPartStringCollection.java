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

package inet.ipaddr.format.util;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import inet.ipaddr.IPAddressSection.IPStringBuilderOptions;
import inet.ipaddr.IPAddressSection.WildcardOptions;
import inet.ipaddr.format.IPAddressDivision;
import inet.ipaddr.format.IPAddressPart;

/**
 * 
 * @author sfoley
 *
 */
public class IPAddressPartStringCollection extends AddressPartStringCollection<IPAddressPart, IPAddressPartStringParams<?>, IPAddressPartConfiguredString<?, ?>> {
	
	private final List<IPAddressPartStringSubCollection<?, ?, ? extends IPAddressPartConfiguredString<?, ?>>> collections = 
			new ArrayList<IPAddressPartStringSubCollection<?, ?, ? extends IPAddressPartConfiguredString<?, ?>>>();
	
	protected IPAddressPartStringCollection(){}
	
	protected void add(IPAddressPartStringSubCollection<?, ?, ? extends IPAddressPartConfiguredString<?, ?>> collection) {
		this.collections.add(collection);
	}
	
	protected void addAll(IPAddressPartStringCollection collections) {
		this.collections.addAll(collections.collections);
	}
	
	public int getPartCount() {
		return collections.size();
	}
	
	public IPAddressPart getPart(int index) {
		return this.getSubCollection(index).part;
	}
	
	public IPAddressPart[] getParts(IPAddressPart[] array) {
		int size = getPartCount();
		IPAddressPart result[];
		if (array.length < size) {
			result = (IPAddressPart[]) Array.newInstance(array.getClass().getComponentType(), size);
		} else {
			result = array;
		}
		int i = 0;
		for(IPAddressPartStringSubCollection<?, ?, ?> coll : collections) {
			result[i++] = coll.part;
		}
		return result;
	}
	
	public IPAddressPartStringSubCollection<?,?,?> getSubCollection(IPAddressPart part) {
		for(IPAddressPartStringSubCollection<?,?,?> sub : collections) {
			if(sub.params.equals(part)) {
				return sub;
			}
		}
		return null;
	}
	
	public IPAddressPartStringSubCollection<?,?,?> getSubCollection(int index) {
		return collections.get(index);
	}
	
	@Override
	public int size() {
		int size = 0;
		for(IPAddressPartStringSubCollection<?, ?, ?> collection : collections) {
			size += collection.size();
		}
		return size;
	}

	@Override
	public Iterator<IPAddressPartConfiguredString<?, ?>> iterator() {
		return new Iterator<IPAddressPartConfiguredString<?, ?>>() {
			private int i;
			private Iterator<? extends IPAddressPartConfiguredString<?, ?>> currentIterator;
			
			@Override
			public boolean hasNext() {
				while(true) {
					if(currentIterator == null) {
						if(i < collections.size()) {
							currentIterator = collections.get(i++).iterator();
						} else {
							return false;
						}
					}
					if(currentIterator.hasNext()) {
						return true;
					}
					currentIterator = null;
				}
			}

			@Override
			public IPAddressPartConfiguredString<?, ?> next() {
				if(hasNext()) {
					return currentIterator.next();
				}
				throw new NoSuchElementException();
			}

			@Override
			public void remove() {
				if(currentIterator == null) {
					throw new IllegalStateException();
				}
				currentIterator.remove();
			}
		};
	}
	
	/**
	 * 
	 * @author sfoley
	 *
	 * @param <T> the type of the address part from which this builder was derived
	 * @param <P> the type of the params used to generate each string
	 * @param <S> the type of the configurable strings, each of which pairs an IPAddressPart and a IPAddressPartStringParams to produce a string.
	 * @param <C> the type of the collection produced by this builder
	 * @param <O> the type of the options used by this builder to control which strings are produced
	 */
	protected static abstract class AddressPartStringBuilder< 
			T extends IPAddressPart,
			P extends IPAddressPartStringParams<T>,
			S extends IPAddressPartConfiguredString<T, P>,
			C extends IPAddressPartStringSubCollection<T, P, S>,
			O extends IPStringBuilderOptions> {
		
		//for each base, indicates the number of leading zeros that can be added for each segment
		//so leadingZeros[16][1] indicates the leading zeros that can be added to the segment at index 1 when using base 16
		protected static int MAX_BASE = 16;
		private int leadingZeros[][];
		protected final T addressSection;
		protected final O options;
		protected final C collection;
		private boolean done;
		
		protected AddressPartStringBuilder(T addressSection, O options, C collection) {
			this.addressSection = addressSection;
			this.options = options;
			this.collection = collection;
		}
		
		public C getVariations() {
			if(!done) {
				synchronized(this) {
					if(!done) {
						done = true;
						addAllVariations();
					}
				}
			}
			return collection;
		}
		
		protected abstract void addAllVariations();
		
		protected void addStringParam(P stringParams) {
			collection.add(stringParams);
		}
		
		protected boolean isExpandable(int radix) {
			return isExpandable(radix, addressSection);
		}
		
		protected boolean isExpandableOutsideRange(int radix, int segmentIndex, int count) {
			return isExpandableOutsideRange(radix, addressSection, segmentIndex, count);
		}

		private static boolean isExpandable(int radix, IPAddressPart part) {
			return isExpandableOutsideRange(radix, part, -1, 0);
		}
		
		private static boolean isExpandableOutsideRange(int radix, IPAddressPart part, int segmentIndex, int count) {
			int nextSegmentIndex = segmentIndex + count;
			for(int i = 0; i < part.getDivisionCount(); i++) {
				if(i >= segmentIndex && i < nextSegmentIndex) {
					continue;
				}
				IPAddressDivision seg = part.getDivision(i);
				if(seg.getMaxLeadingZeros(radix) > 0) {
					return true;
				}
			}
			return false;
		}
		
		protected int[] getExpandableSegments(int radix) {
			int result[];
			if(leadingZeros == null) {
				leadingZeros = new int[MAX_BASE + 1][];
				leadingZeros[radix] = result = getExpandableSegments(radix, addressSection);
			} else {
				if((result = leadingZeros[radix]) == null) {
					leadingZeros[radix] = result = getExpandableSegments(radix, addressSection);
				}
			}
			return result;
		}
		
		protected static int[] getExpandableSegments(int radix, IPAddressPart part) {
			int count = part.getDivisionCount();
			int expandables[] = new int[count];
			for(int i = 0; i < count; i++) {
				expandables[i] = part.getDivision(i).getMaxLeadingZeros(radix);
			}
			return expandables;
		}
	}
	
	/**
	 * Each StringParams has settings to write exactly one IP address part string.
	 * 
	 * @author sfoley
	 */
	//TODO make protected again, but not sure how, this is accessed in IPaddressSection package and no collection class for enclosing it 
	public static class StringParams<T extends IPAddressPart> extends IPAddressPartStringParams<T> {
		
		public static final WildcardOptions DEFAULT_WILDCARD_OPTIONS = new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY);
		protected static final int EXTRA_SPACE = 16;
		 
		private WildcardOptions wildcardOptions = DEFAULT_WILDCARD_OPTIONS;
		private boolean expandSegments; //whether to expand 1 to 001 for IPv4 or 0001 for IPv6
		private int expandSegment[]; //the same as expandSegments but for each segment
		private String segmentStrPrefix; //eg for inet_aton style there is 0x for hex, 0 for octal
		private int radix;
		
		//the segment separator and in the case of split digits, the digit separator
		private Character separator;
		
		private String addressLabel = "";
		private String addressSuffix = "";
		
		//print the segments in reverse, and in the case of splitDigits, print the digits in reverse as well
		private boolean reverse;
		
		//in each segment, split the digits with the separator, so that 123.456.1.1 becomes 1.2.3.4.5.6.1.1
		private boolean splitDigits;
		
		private boolean uppercase; //whether to print A or a
		
		public StringParams(int radix, Character separator, boolean uppercase) {
			this.radix = radix;
			this.separator = separator;
			this.uppercase = uppercase;
		}
		
		public void setUppercase(boolean uppercase) {
			this.uppercase = uppercase;
		}
		
		public boolean isUppercase() {
			return uppercase;
		}
		
		public void setSplitDigits(boolean split) {
			this.splitDigits = split;
		}
		
		public boolean isSplitDigits() {
			return splitDigits;
		}
		
		public void setReverse(boolean rev) {
			this.reverse = rev;
		}
		
		public boolean isReverse() {
			return reverse;
		}
		
		public String getAddressSuffix() {
			return addressSuffix;
		}
		
		public void setAddressSuffix(String suffix) {
			this.addressSuffix = suffix;
		}
		
		public String getAddressLabel() {
			return addressLabel;
		}
		
		public void setAddressLabel(String str) {
			this.addressLabel = str;
		}
		
		public Character getSeparator() {
			return separator;
		}
		
		public void setSeparator(Character separator) {
			this.separator = separator;
		}
		
		public int getRadix() {
			return radix;
		}
		
		public void setRadix(int radix) {
			this.radix = radix;
		}
		
		public String getSegmentStrPrefix() {
			return segmentStrPrefix;
		}
		
		public void setSegmentStrPrefix(String segmentStrPrefix) {
			this.segmentStrPrefix = segmentStrPrefix;
		}
		
		public void setWildcardOption(WildcardOptions options) {
			wildcardOptions = options;
		}
		
		public WildcardOptions getWildcardOption() {
			return wildcardOptions;
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
		
		public void expandSegments(boolean expand) {
			expandSegments = expand;
		}
		
		@Override
		public char getTrailingSegmentSeparator() {
			return separator;
		}
		
		public void appendSuffix(StringBuilder builder) {
			String suffix = getAddressSuffix();
			if(suffix != null) {
				builder.append(suffix);
			}
		}
		
		public int getAddressSuffixLength() {
			String suffix = getAddressSuffix();
			if(suffix != null) {
				return suffix.length();
			}
			return 0;
		}
		
		public void appendLabel(StringBuilder builder) {
			String str = getAddressLabel();
			if(str != null) {
				builder.append(str);
			}
		}
		
		public int getAddressLabelLength() {
			String str = getAddressLabel();
			if(str != null) {
				return str.length();
			}
			return 0;
		}
		
		//returns -1 for MAX, or 0, 1, 2, 3 to indicate the string prefix length
		protected int getLeadingZeros(int segmentIndex) {
			if(expandSegments) {
				return -1;
			} else if(expandSegment != null && expandSegment.length > segmentIndex) {
				return expandSegment[segmentIndex];
			}
			return 0;
		}
		
		@Override
		public IPAddressPartStringCollection.StringParams<T> clone() {
			IPAddressPartStringParams<T> params = super.clone();
			IPAddressPartStringCollection.StringParams<T> parms = (IPAddressPartStringCollection.StringParams<T>) params;
			if(expandSegment != null) {
				parms.expandSegment = expandSegment.clone();
			}
			return parms;
		}
		
		@Override
		public String toString(T addr) {	
			int length = getStringLength(addr);
			StringBuilder builder = new StringBuilder(length);
			append(builder, addr);
			checkLengths(length, builder);
			return builder.toString();
		}
		
		@Override
		public int getTrailingSeparatorCount(T addr) {
			if(addr.getDivisionCount() > 0) {
				return addr.getDivisionCount() - 1;
			}
			return 0;
		}
		
		@Override
		public int getStringLength(T addr) {
			int count = getSegmentsStringLength(addr);
			if(!isReverse() && getWildcardOption().wildcardOption != WildcardOptions.WildcardOption.ALL) {
				count += addr.getPrefixStringLength();
			}
			count += getAddressSuffixLength();
			count += getAddressLabelLength();
			return count;
		}
		
		@Override
		public StringBuilder append(StringBuilder builder, T addr) {
			appendLabel(builder);
			appendSegments(builder, addr);
			/*
			 * Our order is suffix, then prefix length.
			 * This is documented in more detail on the IPv6 side.
			 */
			appendSuffix(builder);
			if(!isReverse() && getWildcardOption().wildcardOption != WildcardOptions.WildcardOption.ALL) {
				appendPrefixIndicator(builder, addr);
			}
			return builder;
		}

		public int getSegmentsStringLength(T part) {
			int count = 0;
			if(part.getDivisionCount() != 0) {
				WildcardOptions wildcardOptions = getWildcardOption();
				WildcardOptions.WildcardOption wildcardOption = wildcardOptions.wildcardOption;
				boolean isAll = wildcardOption == WildcardOptions.WildcardOption.ALL;
				int divCount = part.getDivisionCount();
				Character separator = getSeparator();
				for(int i = 0; i < divCount; i++) {
					IPAddressDivision seg = part.getDivision(i);
					int leadingZeroCount = getLeadingZeros(i);
					if(isAll || isSplitDigits()) {
						count += seg.getWildcardString(wildcardOptions.wildcards, leadingZeroCount, getSegmentStrPrefix(), getRadix(), isUppercase(), isSplitDigits(), separator, false, null);
					} else { //wildcardOption == WildcardOptions.WildcardOption.NETWORK_ONLY
						count += seg.getPrefixAdjustedWildcardString(wildcardOptions.wildcards, leadingZeroCount, getSegmentStrPrefix(), getRadix(), isUppercase(), null);
					}
				}
				if(separator != null) {
					count += divCount - 1;
				}
			}
			return count;
		}

		public StringBuilder appendSegments(StringBuilder builder, T part) {
			if(part.getDivisionCount() != 0) {
				WildcardOptions wildcardOptions = getWildcardOption();
				WildcardOptions.WildcardOption wildcardOption = wildcardOptions.wildcardOption;
				boolean isAll = wildcardOption == WildcardOptions.WildcardOption.ALL;
				int count = part.getDivisionCount();
				boolean reverse = isReverse();
				int i = 0;
				Character separator = getSeparator();
				while(true) {
					int segIndex;
					if(reverse) {
						segIndex = count - i - 1;
					} else {
						segIndex = i;
					}
					IPAddressDivision seg = part.getDivision(segIndex);
					int leadingZeroCount = getLeadingZeros(segIndex);
					if(isAll || isSplitDigits()) {
						seg.getWildcardString(wildcardOptions.wildcards, leadingZeroCount, getSegmentStrPrefix(), getRadix(), isUppercase(), isSplitDigits(), separator, isReverse(), builder);
					} else { //wildcardOption == WildcardOptions.WildcardOption.NETWORK_ONLY
						seg.getPrefixAdjustedWildcardString(wildcardOptions.wildcards, leadingZeroCount, getSegmentStrPrefix(), getRadix(), isUppercase(), builder);
					}
					if(++i == count) {
						break;
					}
					if(separator != null) {
						builder.append(separator);
					}
				}
			}
			return builder;
		}
	}
}
