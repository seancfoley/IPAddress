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

package inet.ipaddr.format;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.ToLongFunction;

import inet.ipaddr.AddressComponent;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.HostIdentifierException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSection.IPStringOptions;
import inet.ipaddr.IPAddressSection.WildcardOptions.WildcardOption;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.standard.AddressDivisionGrouping.StringOptions;
import inet.ipaddr.format.standard.AddressDivisionGrouping.StringOptions.Wildcards;
import inet.ipaddr.format.string.AddressStringDivision;
import inet.ipaddr.format.string.AddressStringDivisionSeries;
import inet.ipaddr.format.string.IPAddressStringDivision;
import inet.ipaddr.format.string.IPAddressStringDivisionSeries;
import inet.ipaddr.format.util.AddressComponentSpliterator;
import inet.ipaddr.format.util.AddressDivisionWriter;
import inet.ipaddr.format.util.AddressComponentRangeSpliterator;
import inet.ipaddr.format.util.AddressSegmentParams;
import inet.ipaddr.format.util.IPAddressStringWriter;
import inet.ipaddr.format.validate.ParsedAddressGrouping;

/**
 * AddressDivisionGrouping objects consist of a series of AddressDivision objects, each division containing one or more segments.
 * <p>
 * AddressDivisionGrouping objects are immutable.  This also makes them thread-safe.
 * <p>
 * AddressDivision objects use long to represent their values, so this places a cap on the size of the divisions in AddressDivisionGrouping.
 * <p>
 *  @author sfoley
 */
public abstract class AddressDivisionGroupingBase implements AddressDivisionSeries {

	private static final long serialVersionUID = 1L;
	
	protected static final Integer NO_PREFIX_LENGTH = -1;
	static final BigInteger ALL_ONES = BigInteger.ZERO.not();
	
	protected static BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);
	
	static ResourceBundle bundle;
	
	static {
		//reuse the same properties file
		String propertyFileName = "IPAddressResources";
		String name = HostIdentifierException.class.getPackage().getName() + '.' + propertyFileName;
		try {
			bundle = ResourceBundle.getBundle(name);
		} catch (MissingResourceException e) {
			System.err.println("bundle " + name + " is missing");
		}
	}
	
	protected static class ValueCache {
		/* the address grouping bytes */
		public byte[] lowerBytes, upperBytes;
		public BigInteger value, upperValue;
		
		/* only used when address section is full section owned by an address */
		public InetAddress inetAddress;
	}
	
	protected transient ValueCache valueCache;
	
	private final AddressDivisionBase divisions[];
	protected Integer cachedPrefixLength; // null indicates this field not initialized, NO_PREFIX indicates the prefix len is null
	
	/* for addresses not multiple, we must check each segment, so we cache */
	private transient Boolean isMultiple;
	private transient BigInteger cachedCount;
	private transient BigInteger cachedPrefixCount;

	protected transient int hashCode;

	public AddressDivisionGroupingBase(AddressDivisionBase divisions[]) {
		this(divisions, true);
	}

	public AddressDivisionGroupingBase(AddressDivisionBase divisions[], boolean checkDivisions) {
		this.divisions = divisions;
		if(checkDivisions) {
			for(int i = 0; i < divisions.length; i++) {
				if(divisions[i] == null) {
					throw new NullPointerException(getMessage("ipaddress.error.null.segment"));
				}
			}
		}
	}

	protected static String getMessage(String key) {
		if(bundle != null) {
			try {
				return bundle.getString(key);
				
			} catch (MissingResourceException e1) {}
		}
		return key;
	}
	
	@Override
	public AddressDivisionBase getDivision(int index) {
		return getDivisionsInternal()[index];
	}

	protected void initCachedValues(Integer cachedNetworkPrefixLength, BigInteger cachedCount) {
		this.cachedPrefixLength = cachedNetworkPrefixLength == null ? NO_PREFIX_LENGTH : cachedNetworkPrefixLength;
		this.cachedCount = cachedCount;
	}

	@Override
	public int getDivisionCount() {
		return getDivisionsInternal().length;
	}
	
	/**
	 * Gets the bytes for the lowest address in the range represented by this address.
	 * <p>
	 * Since bytes are signed values while addresses are unsigned, values greater than 127 are
	 * represented as the (negative) two's complement value of the actual value.
	 * You can get the unsigned integer value i from byte b using i = 0xff &amp; b.
	 * 
	 * @return
	 */
	@Override
	public byte[] getBytes() {
		return getBytesInternal().clone();
	}
	
	//gets the bytes, sharing the cached array and does not clone it
	protected byte[] getBytesInternal() {
		byte cached[];
		if(hasNoValueCache() || (cached = valueCache.lowerBytes) == null) {
			valueCache.lowerBytes = cached = getBytesImpl(true);
		}
		return cached;
	}
	
	/**
	 * Gets the value for the lowest address in the range represented by this address division.
	 * <p>
	 * If the value fits in the specified array, the same array is returned with the value.  
	 * Otherwise, a new array is allocated and returned with the value.
	 * <p>
	 * You can use {@link #getBitCount()} to determine the required array length for the bytes.
	 * <p>
	 * Since bytes are signed values while addresses are unsigned, values greater than 127 are
	 * represented as the (negative) two's complement value of the actual value.
	 * You can get the unsigned integer value i from byte b using i = 0xff &amp; b.
	 * 
	 * @return
	 */
	@Override
	public byte[] getBytes(byte bytes[], int index) {
		return getBytesCopy(bytes, index, getBytesInternal(), getBitCount());
	}
	
	/**
	 * Equivalent to {@link #getBytes(byte[], int)} with index of 0.
	 */
	@Override
	public byte[] getBytes(byte bytes[]) {
		return getBytes(bytes, 0);
	}

	private static byte[] getBytesCopy(byte[] bytes, int startIndex, byte[] cached, int bitCount) {
		int byteCount = (bitCount + 7) >> 3;
		if(bytes == null || bytes.length < byteCount + startIndex) {
			if(startIndex > 0) {
				byte bytes2[] = new byte[byteCount + startIndex];
				if(bytes != null) {
					System.arraycopy(bytes, 0, bytes2, 0, Math.min(startIndex, bytes.length));
				}
				System.arraycopy(cached, 0, bytes2, startIndex, cached.length);
				return bytes2;
			}
			return cached.clone();
		}
		System.arraycopy(cached, 0, bytes, startIndex, byteCount);
		return bytes;
	}
	
	/**
	 * Gets the bytes for the highest address in the range represented by this address.
	 * 
	 * @return
	 */
	@Override
	public byte[] getUpperBytes() {
		return getUpperBytesInternal().clone();
	}
	
	/**
	 * Gets the bytes for the highest address in the range represented by this address.
	 * 
	 * @return
	 */
	protected byte[] getUpperBytesInternal() {
		byte cached[];
		if(hasNoValueCache()) {
			ValueCache cache = valueCache;
			cache.upperBytes = cached = getBytesImpl(false);
			if(!isMultiple()) {
				cache.lowerBytes = cached;
			}
		} else {
			ValueCache cache = valueCache;
			if((cached = cache.upperBytes) == null) {
				if(!isMultiple()) {
					if((cached = cache.lowerBytes) != null) {
						cache.upperBytes = cached;
					} else {
						cache.lowerBytes = cache.upperBytes = cached = getBytesImpl(false);
					}
				} else {
					cache.upperBytes = cached = getBytesImpl(false);
				}
			}
		}
		return cached;
	}

	/**
	 * Similar to {@link #getBytes(byte[], int)}, but for obtaining the upper value of the range.
	 * If this division represents a single value, equivalent to {@link #getBytes(byte[], int)}
	 */
	@Override
	public byte[] getUpperBytes(byte bytes[], int index) {
		return getBytesCopy(bytes, index, getUpperBytesInternal(), getBitCount());
	}
	
	/**
	 * Equivalent to {@link #getBytes(byte[], int)} with index of 0.
	 */
	@Override
	public byte[] getUpperBytes(byte bytes[]) {
		return getBytes(bytes, 0);
	}
	
	protected abstract byte[] getBytesImpl(boolean low);
	
	//only called in constructors
	protected void setBytes(byte bytes[]) {
		if(valueCache == null) {
			valueCache = new ValueCache();
		}
		valueCache.lowerBytes = bytes;
	}
	
	//only called in constructors
	protected void setUpperBytes(byte bytes[]) {
		if(valueCache == null) {
			valueCache = new ValueCache();
		}
		valueCache.upperBytes = bytes;
	}
	
	@Override
	public BigInteger getValue() {
		BigInteger cached;
		if(hasNoValueCache() || (cached = valueCache.value) == null) {
			valueCache.value = cached = new BigInteger(1, getBytesInternal());
		}
		return cached;
	}
	
	@Override
	public BigInteger getUpperValue() {
		BigInteger cached;
		if(hasNoValueCache()) {
			ValueCache cache = valueCache;
			cache.upperValue = cached = new BigInteger(1, getUpperBytesInternal());
			if(!isMultiple()) {
				cache.value = cached;
			}
		} else {
			ValueCache cache = valueCache;
			if((cached = cache.upperValue) == null) {
				if(!isMultiple()) {
					if((cached = cache.value) != null) {
						cache.upperValue = cached;
					} else {
						cache.value = cache.upperValue = cached = new BigInteger(1, getUpperBytesInternal());
					}
				} else {
					cache.upperValue = cached = new BigInteger(1, getUpperBytesInternal());
				}
			}
		}
		return cached;
	}
	
	protected boolean hasNoValueCache() {
		if(valueCache == null) {
			synchronized(this) {
				if(valueCache == null) {
					valueCache = new ValueCache();
					return true;
				}
			}
		}
		return false;
	}
	
	// only called from constructors, no locking is necessary
	protected void setInetAddress(InetAddress addr) {
		if(valueCache == null) {
			valueCache = new ValueCache();
		}
		valueCache.inetAddress = addr;
	}
	

	@Override
	public boolean isPrefixed() {
		return getPrefixLength() != null;
	}

	@Override
	public Integer getPrefixLength() {
		return cachedPrefixLength;
	}
	
	protected static Integer calculatePrefix(IPAddressDivisionSeries series) {
		int count = series.getDivisionCount();
		if(count > 0) {
			if(series.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets() && !series.getDivision(count - 1).isPrefixed()) {
				return null;
			}
			int result = 0;
			for(int i = 0; i < count; i++) { 
				IPAddressGenericDivision div = series.getDivision(i);
				Integer prefix = div.getDivisionPrefixLength();
				if(prefix != null) {
					result += prefix;
					return ParsedAddressGrouping.cache(result);
				} else {
					result += div.getBitCount();
				}
			}
			
		}
		return null;
	}
	
	/**
	 * Returns the smallest prefix length possible such that this address division grouping includes the block of addresses for that prefix.
	 *
	 * @return the prefix length
	 */
	@Override
	public int getMinPrefixLengthForBlock() {
		int count = getDivisionCount();
		int totalPrefix = getBitCount();
		for(int i = count - 1; i >= 0 ; i--) {
			AddressDivisionBase div = getDivision(i);
			int segBitCount = div.getBitCount();
			int segPrefix = div.getMinPrefixLengthForBlock();
			if(segPrefix == segBitCount) {
				break;
			} else {
				totalPrefix -= segBitCount;
				if(segPrefix != 0) {
					totalPrefix += segPrefix;
					break;
				}
			}
		}
		return totalPrefix;
	}
	
	/**
	 * Returns a prefix length for which the range of this segment grouping matches the block of addresses for that prefix.
	 * 
	 * If no such prefix exists, returns null
	 * 
	 * If this segment grouping represents a single value, returns the bit length
	 * 
	 * @return the prefix length or null
	 */
	@Override
	public Integer getPrefixLengthForSingleBlock() {
		int count = getDivisionCount();
		int totalPrefix = 0;
		for(int i = 0; i < count; i++) {
			AddressDivisionBase div = getDivision(i);
			Integer divPrefix = div.getPrefixLengthForSingleBlock();
			if(divPrefix == null) {
				return null;
			}
			totalPrefix += divPrefix;
			if(divPrefix < div.getBitCount()) {
				//remaining segments must be full range or we return null
				for(i++; i < count; i++) {
					AddressDivisionBase laterDiv = getDivision(i);
					if(!laterDiv.isFullRange()) {
						return null;
					}
				}
			}
		}
		return cacheBits(totalPrefix);
	}
	
	protected static Integer getPrefixLengthForSingleBlock(IPAddressDivisionSeries series) {
		int count = series.getDivisionCount();
		int totalPrefix = 0;
		boolean isAutoSubnets = series.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		for(int i = 0; i < count; i++) {
			IPAddressGenericDivision div = series.getDivision(i);
			Integer divPrefix = div.getPrefixLengthForSingleBlock();
			if(divPrefix == null) {
				return null;
			}
			totalPrefix += divPrefix;
			if(isAutoSubnets && div.isPrefixed()) {
				return cacheBits(totalPrefix);
			}
			if(divPrefix < div.getBitCount()) {
				//remaining divisions must be full range or we return null
				for(i++; i < count; i++) {
					IPAddressGenericDivision laterDiv = series.getDivision(i);
					if(!laterDiv.isFullRange()) {
						return null;
					}
					if(isAutoSubnets && laterDiv.isPrefixed()) {
						return cacheBits(totalPrefix);
					}
				}
			}
		}
		return cacheBits(totalPrefix);
	}

	protected static Integer cacheBits(int i) {
		return ParsedAddressGrouping.cache(i);
	}

	/**
	 * gets the count of addresses that this address division grouping may represent
	 * 
	 * If this address division grouping is not a subnet block of multiple addresses or has no range of values, then there is only one such address.
	 * 
	 * @return
	 */
	@Override
	public BigInteger getCount() {
		BigInteger cached = cachedCount;
		if(cached == null) {
			cachedCount = cached = getCountImpl();
		}
		return cached;
	}
	
	protected BigInteger getCountImpl() {
		return AddressDivisionSeries.super.getCount();
	}
	
	@Override
	public BigInteger getPrefixCount() {
		BigInteger cached = cachedPrefixCount;
		if(cached == null) {
			Integer prefixLength = getPrefixLength();
			if(prefixLength == null || prefixLength >= getBitCount()) {
				cachedPrefixCount = cached = getCount();
			} else {
				cachedPrefixCount = cached = getPrefixCountImpl();
			}
		}
		return cached;
	}
	
	protected BigInteger getPrefixCountImpl() {
		return AddressDivisionSeries.super.getPrefixCount();
	}

	/**
	 * @return whether this address represents more than one address.
	 * Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
	 */
	@Override
	public boolean isMultiple() {
		Boolean result = isMultiple;
		if(result == null) {
			for(int i = getDivisionCount() - 1; i >= 0; i--) {//go in reverse order, with prefixes multiple more likely to show up in last segment
				AddressDivisionBase seg = getDivision(i);
				if(seg.isMultiple()) {
					return isMultiple = Boolean.TRUE;
				}
			}
			return isMultiple = Boolean.FALSE;
		}
		return result;
	}

	protected static int adjustHashCode(int currentHash, long lowerValue, long upperValue) {
		return AddressDivisionBase.adjustHashCode(currentHash, lowerValue, upperValue);
	}
	
	@Override
	public int hashCode() {//designed so that this hashcode matches the same in AddressDivision if values are long-sized
		int res = hashCode;
		if(res == 0) {
			res = 1;
			int count = getDivisionCount();
			for(int i = 0; i < count; i++) {
				AddressDivisionBase combo = getDivision(i);
				BigInteger lower = combo.getValue(), upper = combo.getUpperValue();
				int longBits = Long.SIZE;
				do {
					long low = lower.longValue();
					long up = upper.longValue();
					lower = lower.shiftRight(longBits);
					upper = upper.shiftRight(longBits);
					res = adjustHashCode(res, low, up);
				} while(!upper.equals(BigInteger.ZERO));
			}
			hashCode = res;
		}
		return res;
	}

	protected boolean isSameGrouping(AddressDivisionGroupingBase other) {
		int count = getDivisionCount();
		if(count != other.getDivisionCount()) {
			return false;
		} else for(int i = 0; i < count; i++) {
			AddressDivisionBase one = getDivision(i);
			AddressDivisionBase two = other.getDivision(i);
			if(!one.equals(two)) {//this checks the division types and also the bit counts
				return false;
			}
		}
		return true;
	}

	/**
	 * Two groupings are equal if:
	 * - they match type/version (ipv4, ipv6, mac, or a specific grouping class)
	 * - they match division counts
	 * - each division matches bit counts
	 * - each division matches their specific grouping class
	 * - each division matches values
	 * 
	 * Prefix lengths, for those groupings and/or divisionsS that have them, are ignored.
	 */
	@Override
	public boolean equals(Object o) {
		if(o == this) {
			return true;
		}
		if(o instanceof AddressDivisionGroupingBase) {
			AddressDivisionGroupingBase other = (AddressDivisionGroupingBase) o;
			// we call isSameGrouping on the other object to defer to subclasses
			// in particlar, if the other is IPv4/6/MAC/AddressSection, then we call the overridden isSameGrouping
			// in those classes which check for IPv4/6/MAC
			// Equality and containment consider address versions and types.
			// However, the other grouping classes, the division grouping classes:
			// -do not support containment
			// -support equality across types, similar to java.util.Collections equality with lists, sets, and maps
			return other.isSameGrouping(this);
		}
		return false;
	}

	protected AddressDivisionBase[] getDivisionsInternal() {
		return divisions;
	}
	
	@Override
	public String toString() {
		return Arrays.asList(getDivisionsInternal()).toString();
	}
	
	@Override
	public String[] getDivisionStrings() {
		String result[] = new String[getDivisionCount()];
		Arrays.setAll(result, i -> getDivision(i).getWildcardString());
		return result;
	}
	
	@Override
	public boolean isZero() {
		int divCount = getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			if(!getDivision(i).isZero()) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	public boolean includesZero() {
		int divCount = getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			if(!getDivision(i).includesZero()) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	public boolean isMax() {
		int divCount = getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			if(!getDivision(i).isMax()) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	public boolean includesMax() {
		int divCount = getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			if(!getDivision(i).includesMax()) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	public boolean isFullRange() {
		int divCount = getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			AddressDivisionBase div = getDivision(i);
			if(!div.isFullRange()) {
				return false;
			}
		}
		return true;
	}

	protected static void checkSubnet(AddressDivisionSeries series, int prefixLength) throws PrefixLenException {
		if(prefixLength < 0 || prefixLength > series.getBitCount()) {
			throw new PrefixLenException(series, prefixLength);
		}
	}
	
	@Override
	public boolean isSinglePrefixBlock() {//Note for any given prefix length you can compare with getPrefixLengthForSingleBlock
		return isPrefixed() && containsSinglePrefixBlock(getPrefixLength());
	}

	@Override
	public boolean isPrefixBlock() { //Note for any given prefix length you can compare with getMinPrefixLengthForBlock
		return isPrefixed() && containsPrefixBlock(getPrefixLength());
	}
	
	protected static boolean containsPrefixBlock(IPAddressDivisionSeries series, int prefixLength) {
		checkSubnet(series, prefixLength);
		boolean isAllSubnets = series.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		if(isAllSubnets && series.isPrefixed() && series.getNetworkPrefixLength() <= prefixLength) {
			return true;
		}
		int prevBitCount = 0;
		int divCount = series.getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			IPAddressGenericDivision div = series.getDivision(i);
			int bitCount = div.getBitCount();
			int totalBitCount = bitCount + prevBitCount;
			if(prefixLength < totalBitCount) {
				int divPrefixLen = Math.max(0, prefixLength - prevBitCount);
				if(!div.containsPrefixBlock(divPrefixLen)) {
					return false;
				}
				if(isAllSubnets && div.isPrefixed()) {
					return true;
				}
				for(++i; i < divCount; i++) {
					div = series.getDivision(i);
					if(!div.isFullRange()) {
						return false;
					}
					if(isAllSubnets && div.isPrefixed()) {
						return true;
					}
				}
				return true;
			}
			prevBitCount = totalBitCount;
		}
		return true;
	}

	protected static boolean containsSinglePrefixBlock(IPAddressDivisionSeries series, int prefixLength) {
		checkSubnet(series, prefixLength);
		boolean isAllSubnets = series.getNetwork().getPrefixConfiguration().allPrefixedAddressesAreSubnets();
		if(isAllSubnets && series.isPrefixed() && series.getNetworkPrefixLength() < prefixLength) {
			return false;
		}
		int prevBitCount = 0;
		int divCount = series.getDivisionCount();
		for(int i = 0; i < divCount; i++) {
			IPAddressGenericDivision div = series.getDivision(i);
			int bitCount = div.getBitCount();
			int totalBitCount = bitCount + prevBitCount;
			if(prefixLength >= totalBitCount) {
				if(div.isMultiple()) {
					return false;
				}
			} else  {
				int divPrefixLen = Math.max(0, prefixLength - prevBitCount);
				if(!div.containsSinglePrefixBlock(divPrefixLen)) {
					return false;
				}
				if(isAllSubnets && div.isPrefixed()) {
					return true;
				}
				for(++i; i < divCount; i++) {
					div = series.getDivision(i);
					if(!div.isFullRange()) {
						return false;
					}
					if(isAllSubnets && div.isPrefixed()) {
						return true;
					}
				}
				return true;
			}
			prevBitCount = totalBitCount;
		}
		return true;
	}

	@FunctionalInterface
	protected static interface IteratorProvider<S, T> {
		Iterator<T> apply(boolean isLowestRange, boolean isHighestRange, S iteratedAddressItem);
	}

	protected static class AddressItemRangeSpliterator<S extends AddressComponentRange, T>
		extends AddressItemSpliteratorBase<S, T> implements SplitterSink<S, T> {

		private S forIteration;
		private Iterator<T> iterator;

		private S split1, split2; // To be assigned by splitter when splitting

		protected final IteratorProvider<S, T> iteratorProvider;
		private boolean isLowest;
		private final boolean isHighest;

		private Function<S, BigInteger> sizer; // Can be null: when null, we use longSizer
		private Predicate<S> downSizer;
		private final ToLongFunction<S> longSizer; // To be used only when sizer is null.
		private long longSize;
		private BigInteger bigSize;
		
		final Predicate<SplitterSink<S, T>> splitter;
		
		protected AddressItemRangeSpliterator(
				S forIteration,
				Predicate<SplitterSink<S, T>> splitter,
				IteratorProvider<S, T> iteratorProvider,
				Function<S, BigInteger> sizer /* can be null */,
				Predicate<S> downSizer,
				ToLongFunction<S> longSizer /* not to be used if sizer not null */) {
			this(forIteration, splitter, iteratorProvider, true, true, sizer, downSizer, longSizer);
			updateSizers();
		}
		
		protected AddressItemRangeSpliterator(
				S forIteration,
				Predicate<SplitterSink<S, T>> splitter,
				IteratorProvider<S, T> iteratorProvider,
				boolean isLowest,
				boolean isHighest,
				Function<S, BigInteger> sizer /* can be null */,
				Predicate<S> downSizer,
				ToLongFunction<S> longSizer /* not to be used if sizer not null */) {
			this.forIteration = forIteration;
			this.iteratorProvider = iteratorProvider;
			this.isLowest = isLowest;
			this.isHighest = isHighest;
			this.longSizer = longSizer;
			this.sizer = sizer;
			this.downSizer = downSizer;
			this.splitter = splitter;
			updateSizers();
		}

		void updateSizers() {
			if(sizer != null) { 
				isBig = downSizer == null || !downSizer.test(forIteration);
				if(!isBig) {
					sizer = null;
					downSizer = null;
				}
			} else {
				isBig = false;
			}
			longSize = -1;
			bigSize = null;
		}
		
		private long originalLongSize() {
			long size = longSize;
			if(size < 0) {
				longSize = size = longSizer.applyAsLong(forIteration);
			}
			return size;
		}
		
		private long currentLongSize() {
			return originalLongSize() - iteratedCountL;
		}
		
		@Override
		public long estimateSize() {
			if(isBig) {
				// if we have iterated a lot, bring us below LONG_MAX, we can give a better estimate
				if(currentBigSize().compareTo(LONG_MAX) <= 0) {
					return currentBigSize().longValue();
				}
				return Long.MAX_VALUE;
			}
			return currentLongSize();
		}

		private BigInteger originalBigSize() {
			BigInteger size = bigSize;
			if(bigSize == null) {
				bigSize = size = sizer.apply(forIteration);
			}
			return size;
		}
		
		private BigInteger currentBigSize() {
			return originalBigSize().subtract(iteratedCountB);
		}

		@Override
		public BigInteger getSize() {
			if(isBig) {
				return currentBigSize().subtract(BigInteger.valueOf(iteratedCountI));
			}
			return BigInteger.valueOf(currentLongSize());
		}

		@Override
		public S getAddressItem() {
			return forIteration;
		}

		@Override
		public int characteristics() {
			if(isBig) {
				return CONCURRENT | NONNULL | SORTED | ORDERED | DISTINCT;
			}
			return super.characteristics();
		}

		private Iterator<T> provideIterator() {
			if(iterator == null) {
				iterator = iteratorProvider.apply(isLowest, isHighest, forIteration);
			}
			return iterator;
		}

		@Override
		public boolean tryAdvance(Consumer<? super T> action) {
			if(inForEach) {
				return false;
			}
			if(isBig ? iteratedCountB.signum() <= 0 || iteratedCountB.compareTo(originalBigSize()) < 0 : iteratedCountL < originalLongSize()) {
				return tryAdvance(provideIterator(), action);
			}
			return false;
		}
		
		@Override
		public void forEachRemaining(Consumer<? super T> action) {
			if(inForEach) {
				return;
			}
			inForEach = true;
			try {
				if(isBig) {
					forEachRemaining(provideIterator(), action, originalBigSize());
				} else {
					forEachRemaining(provideIterator(), action, originalLongSize());
				}
				return;
			} finally {
				inForEach = false;
			}
		}
		
		protected boolean canSplit() {
			// we can split if no forEachRemaining or tryAdvance in progress, and we are big enough to split into two
			if(inForEach) {
				return false;
			}
			// we can split if we are big enough to split into two
			return isBig ? iteratedCountB.compareTo(originalBigSize().shiftRight(1)) < 0 :
					iteratedCountL < (originalLongSize() >> 1);
		}
		
		protected boolean split() {
			return splitter.test(this);
		}

		protected AddressItemRangeSpliterator<S, T> createSpliterator(
				S split, 
				boolean isLowest,
				Function<S, BigInteger> sizer,
				Predicate<S> downSizer,
				ToLongFunction<S> longSizer) {
			return new AddressItemRangeSpliterator<S, T>(split, splitter, iteratorProvider, isLowest, false, sizer, downSizer, longSizer);
		}

		@Override
		public AddressItemRangeSpliterator<S, T> trySplit() {
			if(!canSplit() || !split()) {
				return null;
			}
			boolean hasIterated = isBig ? iteratedCountB.signum() > 0 : iteratedCountL > 0;
			BigInteger splitSizeBig = null;
			long splitSize = -1;
			// check that we haven't iterated too far for the split
			if(hasIterated) {
				if(isBig) {
					splitSizeBig = sizer.apply(split1);
					if(iteratedCountB.compareTo(splitSizeBig) >= 0) {
						return null;
					}
				} else {
					splitSize = longSizer.applyAsLong(split1);
					if(iteratedCountL >= splitSize) {
						return null;
					}
				}
			}
			AddressItemRangeSpliterator<S, T> splitOff = createSpliterator(split1, isLowest, sizer, downSizer, longSizer);
			if(hasIterated) {
				if(isBig) {
					if(splitOff.isBig) {
						splitOff.iteratedCountB = iteratedCountB;
					} else {
						splitOff.iteratedCountL = iteratedCountB.longValue();
					}
					iteratedCountB = BigInteger.ZERO;
				} else {
					splitOff.iteratedCountL = iteratedCountL;
					iteratedCountL = 0;
				}
				splitOff.iterator = iterator;
				iterator = null;
				splitOff.bigSize = splitSizeBig;
				splitOff.longSize = splitSize;
			}
			forIteration = split2;
			isLowest = false;
			updateSizers();
			return splitOff;
		}

		@Override
		public void setSplitValues(S left, S right) {
			split1 = left;
			split2 = right;
		}
	}

	protected static interface SplitterSink<S, T> {
		void setSplitValues(S left, S right);
		
		S getAddressItem();
	};
	
	protected static <S extends AddressComponentRange,T> AddressComponentRangeSpliterator<S, T> createItemSpliterator(
			S forIteration,
			Predicate<SplitterSink<S, T>> splitter,
			IteratorProvider<S, T> iteratorProvider,
			Function<S, BigInteger> sizer /* can be null */,
			Predicate<S> downSizer,
			ToLongFunction<S> longSizer /* not to be used if sizer not null */) {
		return new AddressItemRangeSpliterator<S, T>(forIteration, splitter, iteratorProvider, sizer, downSizer, longSizer);
	}

	protected static <T extends AddressComponent> AddressComponentSpliterator<T> createSeriesSpliterator(
			T forIteration,
			Predicate<SplitterSink<T,T>> splitter,
			IteratorProvider<T, T> iteratorProvider,
			Function<T, BigInteger> sizer /* can be null */,
			Predicate<T> downSizer,
			ToLongFunction<T> longSizer /* not to be used if sizer not null */) {
		return new AddressSeriesSpliterator<T>(forIteration, splitter, iteratorProvider, sizer, downSizer, longSizer);
	}

	protected static class AddressStringParams<T extends AddressStringDivisionSeries> implements AddressDivisionWriter, AddressSegmentParams, Cloneable {
		public static final Wildcards DEFAULT_WILDCARDS = new Wildcards();
		
		private Wildcards wildcards = DEFAULT_WILDCARDS;
		
		protected boolean expandSegments; //whether to expand 1 to 001 for IPv4 or 0001 for IPv6
		
		private String segmentStrPrefix = ""; //eg for inet_aton style there is 0x for hex, 0 for octal

		private int radix;
		
		//the segment separator and in the case of split digits, the digit separator
		protected Character separator;
				
		private boolean uppercase; //whether to print A or a
		
		//print the segments in reverse, and in the case of splitDigits, print the digits in reverse as well
		private boolean reverse;
				
		//in each segment, split the digits with the separator, so that 123.456.1.1 becomes 1.2.3.4.5.6.1.1
		private boolean splitDigits;
		
		private String addressLabel = "";
		
		private char zoneSeparator;
		
		public AddressStringParams(int radix, Character separator, boolean uppercase) {
			this(radix, separator, uppercase, (char) 0);
		}
		
		public AddressStringParams(int radix, Character separator, boolean uppercase, char zoneSeparator) {
			this.radix = radix;
			this.separator = separator;
			this.uppercase = uppercase;
			this.zoneSeparator  = zoneSeparator;
		}

		public void setZoneSeparator(char zoneSeparator) {
			this.zoneSeparator = zoneSeparator;
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
		
		@Override
		public Wildcards getWildcards() {
			return wildcards;
		}
		
		public void setWildcards(Wildcards wc) {
			wildcards = wc;
		}
		
		@Override
		public boolean preferWildcards() {
			return true;
		}
		
		//returns -1 to expand
		@Override
		public int getLeadingZeros(int segmentIndex) {
			if(expandSegments) {
				return -1;
			}
			return 0;
		}
		
		@Override
		public String getSegmentStrPrefix() {
			return segmentStrPrefix;
		}
		
		public void setSegmentStrPrefix(String segmentStrPrefix) {
			if(segmentStrPrefix == null) {
				throw new NullPointerException();
			}
			this.segmentStrPrefix = segmentStrPrefix;
		}
		
		@Override
		public int getRadix() {
			return radix;
		}
		
		public void setRadix(int radix) {
			this.radix = radix;
		}
		
		public void setUppercase(boolean uppercase) {
			this.uppercase = uppercase;
		}
		
		@Override
		public boolean isUppercase() {
			return uppercase;
		}
		
		public void setSplitDigits(boolean split) {
			this.splitDigits = split;
		}
		
		@Override
		public boolean isSplitDigits() {
			return splitDigits;
		}
		
		@Override
		public Character getSplitDigitSeparator() {
			return separator;
		}
		
		@Override
		public boolean isReverseSplitDigits() {
			return reverse;
		}
		
		public void setReverse(boolean rev) {
			this.reverse = rev;
		}
		
		public boolean isReverse() {
			return reverse;
		}
		
		public void expandSegments(boolean expand) {
			expandSegments = expand;
		}
		
		public StringBuilder appendLabel(StringBuilder builder) {
			String str = getAddressLabel();
			if(str != null && str.length() > 0) {
				builder.append(str);
			}
			return builder;
		}
		
		public int getAddressLabelLength() {
			String str = getAddressLabel();
			if(str != null) {
				return str.length();
			}
			return 0;
		}
		
		public int getSegmentsStringLength(T part) {
			int count = 0;
			if(part.getDivisionCount() != 0) {
				int divCount = part.getDivisionCount();
				for(int i = 0; i < divCount; i++) {
					count += appendSegment(i, null, part);
				}
				Character separator = getSeparator();
				if(separator != null) {
					count += divCount - 1;
				}
			}
			return count;
		}

		public StringBuilder appendSegments(StringBuilder builder, T part) {
			int count = part.getDivisionCount();
			if(count != 0) {
				boolean reverse = isReverse();
				int i = 0;
				Character separator = getSeparator();
				while(true) {
					int segIndex = reverse ? (count - i - 1) : i;
					appendSegment(segIndex, builder, part);
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
		
		public int appendSingleDivision(AddressStringDivision seg, StringBuilder builder) {
			if(builder == null) {
				return getAddressLabelLength() + seg.getStandardString(0, this, null);
			}
			appendLabel(builder);
			seg.getStandardString(0, this, builder);
			return 0;
		}
		
		protected int appendSegment(int segmentIndex, StringBuilder builder, T part) {
			AddressStringDivision seg = part.getDivision(segmentIndex);
			return seg.getStandardString(segmentIndex, this, builder);
		}
		
		public int getZoneLength(CharSequence zone) {
			if(zone != null && zone.length() > 0) {
				return zone.length() + 1; /* zone separator is one char */
			}
			return 0;
		}
		
		public int getStringLength(T addr, CharSequence zone) {
			int result = getStringLength(addr);
			if(zone != null) {
				result += getZoneLength(zone);
			}
			return result;
		}
		
		public int getStringLength(T addr) {
			return getAddressLabelLength() + getSegmentsStringLength(addr);
		}
		
		public StringBuilder appendZone(StringBuilder builder, CharSequence zone) {
			if(zone != null && zone.length() > 0) {
				builder.append(zoneSeparator).append(zone);
			}
			return builder;
		}

		public StringBuilder append(StringBuilder builder, T addr, CharSequence zone) {
			return appendZone(appendSegments(appendLabel(builder), addr), zone);
		}
		
		public StringBuilder append(StringBuilder builder, T addr) {
			return append(builder, addr, null);
		}
		
		@Override
		public int getDivisionStringLength(AddressStringDivision seg) {
			return appendSingleDivision(seg, null);
		}
		
		@Override
		public StringBuilder appendDivision(StringBuilder builder, AddressStringDivision seg) {
			appendSingleDivision(seg, builder);
			return builder;
		}

		public String toString(T addr, CharSequence zone) {	
			int length = getStringLength(addr, zone);
			StringBuilder builder = new StringBuilder(length);
			append(builder, addr, zone);
			checkLengths(length, builder);
			return builder.toString();
		}
		
		public String toString(T addr) {	
			return toString(addr, null);
		}
		
		public static void checkLengths(int length, StringBuilder builder) {
			//Note: re-enable this when doing development
//				boolean calcMatch = length == builder.length();
//				boolean capMatch = length == builder.capacity();
//				if(!calcMatch || !capMatch) {
//					throw new IllegalStateException("length is " + builder.length() + ", capacity is " + builder.capacity() + ", expected length is " + length);
//				}
		}

		public static AddressStringParams<AddressStringDivisionSeries> toParams(StringOptions opts) {
			//since the params here are not dependent on the section, we could cache the params in the options 
			//this is not true on the IPv6 side where compression settings change based on the section
			@SuppressWarnings("unchecked")
			AddressStringParams<AddressStringDivisionSeries> result = (AddressStringParams<AddressStringDivisionSeries>) getCachedParams(opts);
			if(result == null) {
				result = new AddressStringParams<AddressStringDivisionSeries>(opts.base, opts.separator, opts.uppercase);
				result.expandSegments(opts.expandSegments);
				result.setWildcards(opts.wildcards);
				result.setSegmentStrPrefix(opts.segmentStrPrefix);
				result.setAddressLabel(opts.addrLabel);
				result.setReverse(opts.reverse);
				result.setSplitDigits(opts.splitDigits);
				setCachedParams(opts, result);
			}
			return result;
		}
		
		@Override
		public AddressStringParams<T> clone() {
			try {
				@SuppressWarnings("unchecked")
				AddressStringParams<T> parms = (AddressStringParams<T>) super.clone();
				return parms;
			} catch(CloneNotSupportedException e) {
				 return null;
			}
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
				return AddressDivisionBase.toUnsignedStringLengthFast(addr.getPrefixLength(), 10) + 1;
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
	
	protected static class StringOptionsBase {
		//use this field if the options to params conversion is not dependent on the address part so it can be reused
		AddressDivisionWriter cachedParams; 	
	}
	
	protected static AddressDivisionWriter getCachedParams(StringOptionsBase opts) {
		return opts.cachedParams;
	}
	
	protected static void setCachedParams(StringOptionsBase opts, AddressDivisionWriter cachedParams) {
		opts.cachedParams = cachedParams;
	}
	
	protected static AddressStringParams<IPAddressStringDivisionSeries> toIPParams(IPStringOptions opts) {
		return AddressDivisionBase.toParams(opts);
	}
}
