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
	protected static abstract class StringParams<T extends IPAddressPart> extends IPAddressPartStringParams<T> {
		
		public static final WildcardOptions DEFAULT_WILDCARD_OPTIONS = new WildcardOptions(WildcardOptions.WildcardOption.NETWORK_ONLY);
		protected static final int EXTRA_SPACE = 16;
		 
		private WildcardOptions wildcardOptions = DEFAULT_WILDCARD_OPTIONS;
		private boolean expandSegments; //whether to expand 1 to 001 for IPv4 or 0001 for IPv6
		private int expandSegment[]; //the same as expandSegments but for each segment
		private String segmentStrPrefix; //eg for inet_aton style there is 0x for hex, 0 for octal
		private int radix;
		private char separator;
		private String addressSuffix = "";
		
		protected StringParams(int radix, char separator) {
			this.radix = radix;
			this.separator = separator;
		}
		
		public String getAddressSuffix() {
			return addressSuffix;
		}
		
		public void setAddressSuffix(String suffix) {
			this.addressSuffix = suffix;
		}
		
		public char getSeparator() {
			return separator;
		}
		
		public void setSeparator(char separator) {
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

		@Override
		public abstract StringBuilder append(StringBuilder builder, T addr);
		
		public abstract StringBuilder appendSegments(StringBuilder builder, T part);
		
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
	}
}
