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
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import inet.ipaddr.HostIdentifierException;
import inet.ipaddr.PrefixLenException;
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
		public InetAddress inetAddress, upperInetAddress;
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
	 * Returns a prefix length for which the range of this segment grouping matches the the block of addresses for that prefix.
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
					return isMultiple = true;
				}
			}
			return isMultiple = false;
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
}
