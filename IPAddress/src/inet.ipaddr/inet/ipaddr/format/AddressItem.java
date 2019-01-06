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

import java.io.Serializable;
import java.math.BigInteger;

import inet.ipaddr.Address;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.standard.AddressDivisionGrouping;
import inet.ipaddr.format.string.AddressStringDivisionSeries;

/**
 * Represents any part of an address, whether divided into the standard arrangement of AddressComponent objects, or whether an alternative arrangement using AddressDivision objects.
 * <p>
 * The basic difference between the AddressComponent hierarchy and the AddressDivision hierarchy is that <br>
 * AddressComponent hierarchy uses<br>
 * <ul><li>standardized/typical arrangement (ie for ipv4, 4 equal segments of 1 byte each, for ipv6, 8 equal segments of 2 bytes each, for mac, 6 or 8 equal segments of 1 byte each)</li>
 * <li>equal size segments</li>
 * <li>segments divided along byte boundaries</li></ul>
 * <p>
 * AddressDivision allows alternative arrangements, such as inet_aton style of presenting ipv4 in fewer divisions, 
 * or base 85 for ipv6 which does not even use a base that is a power of 2 (and hence so subdivisions possibly using bit boundaries), 
 * or the aaa-bbb-ccc-ddd mac format with which segments are not divided along byte boundaries
 * <p>
 * Parsing creates objects in the AddressComponent hierarchy, which can then be used to create alternative arrangements using {@link AddressDivisionGrouping} or {@link AddressStringDivisionSeries}
 * <p>
 * @author sfoley
 *
 */
public interface AddressItem extends Comparable<AddressItem>, Serializable {

	/**
	 * Uses {@link Address#DEFAULT_ADDRESS_COMPARATOR}, an instance of {@link inet.ipaddr.AddressComparator.CountComparator}, to compare any two address items.
	 */
	@Override
	default int compareTo(AddressItem other) {
		return Address.DEFAULT_ADDRESS_COMPARATOR.compare(this, other);
	}

	/**
	 * The count of possible distinct values for this AddressComponent.  If not multiple, this is 1.
	 * 
	 * For instance, if this is the ip address series subnet 0::/64, then the count is 2 to the power of 64.
	 * 
	 * If this is a the segment 3-7, then the count is 5.
	 * 
	 * @return
	 */
	default BigInteger getCount() {
		return getUpperValue().subtract(getValue()).add(BigInteger.ONE);
	}

	/**
	 * The count of the number of distinct values within the prefix part of the address item, the bits that appear within the prefix length.
	 * 
	 * @param prefixLength
	 * @return
	 */
	default BigInteger getPrefixCount(int prefixLength) {
		if(prefixLength < 0) {
			throw new PrefixLenException(this, prefixLength);
		}
		int bitCount = getBitCount();
		if(bitCount <= prefixLength) {
			return getCount();
		}
		int shiftAdjustment = bitCount - prefixLength;
		BigInteger lower = getValue(), upper = getUpperValue();
		return upper.shiftRight(shiftAdjustment).subtract(lower.shiftRight(shiftAdjustment)).add(BigInteger.ONE);
	}
	
	/**
	 * Provides the number of bits comprising this address item
	 * 
	 * @return the number of bits
	 */
	int getBitCount();
	
	/**
	 * Provides the number of bytes required for this address item, rounding up if the bit count is not a multiple of 8
	 * 
	 * @return the number of bytes
	 */
	default int getByteCount() {
		return (getBitCount() + (Byte.SIZE - 1)) >>> 3;
	}
	
	/**
	 * Whether this represents multiple potential values (eg a prefixed address or a segment representing a range of values)
	 */
	default boolean isMultiple() {
		return !getCount().equals(BigInteger.ONE);
	}
	
	/**
	 * 
	 * @return the bytes of the smallest address item represented by this address item
	 */
	byte[] getBytes();
	
	/**
	 * Copies the bytes of the smallest address item represented by this address item into the supplied array,
	 * and returns that array.
	 * 
	 * If the supplied array is null or of insufficient size, a new array is created and returned.
	 * 
	 * @return the bytes of the smallest address represented by this address item.
	 */
	byte[] getBytes(byte bytes[]);
	
	/**
	 * Copies the bytes of the smallest address item represented by this address item into the supplied array starting at the given index,
	 * and returns that array.
	 * 
	 * If the supplied array is null or of insufficient size, a new array is created and returned, with the rest of the array contents the same as the original.
	 * 
	 * @return the bytes of the smallest address represented by this address item.
	 */
	byte[] getBytes(byte bytes[], int index);
	
	/**
	 * 
	 * @return the bytes of the largest address item represented by this address item
	 */
	byte[] getUpperBytes();
	
	/**
	 * Copies the bytes of the largest address item represented by this address item into the supplied array,
	 * and returns that array.
	 * 
	 * If the supplied array is null or of insufficient size, a new array is created and returned, with the rest of the array contents the same as the original.
	 * 
	 * @return the bytes of the largest address represented by this address item.
	 */
	byte[] getUpperBytes(byte bytes[]);
	
	/**
	 * Copies the bytes of the largest address item represented by this address item into the supplied array at the given index,
	 * and returns that array.
	 * 
	 * If the supplied array is null or of insufficient size, a new array is created and returned.
	 * 
	 * @return the bytes of the largest address represented by this address item.
	 */
	byte[] getUpperBytes(byte bytes[], int index);
	
	/**
	 * Returns the lowest value represented by this address item, the lowest value included in the range of values
	 * 
	 * @return the lowest value represented by this address item
	 */
	BigInteger getValue();
	
	/**
	 * Returns the highest value represented by this address item, the highest value included in the range of values
	 * 
	 * @return the highest value represented by this address item
	 */
	BigInteger getUpperValue();
		
	/**
	 * Returns whether this item matches the value of zero
	 * 
	 * @return whether this item matches the value of zero
	 */
	boolean isZero();
	
	/**
	 * Returns whether this item includes the value of zero within its range
	 * 
	 * @return whether this item includes the value of zero within its range
	 */
	boolean includesZero();
	
	/**
	 * Returns whether this item matches the maximum possible value for the address type or version
	 * 
	 * @return whether this item matches the maximum possible value
	 */
	boolean isMax();
	
	/**
	 * Returns whether this item includes the maximum possible value for the address type or version within its range
	 * 
	 * @return whether this item includes the maximum possible value within its range
	 */
	boolean includesMax();
	
	/**
	 * @return whether this address item represents all possible values attainable by an address item of this type,
	 * or in other words, both includesZero() and includesMax() return true
	 */
	default boolean isFullRange() {
		return includesZero() && includesMax();
	}
	
	static boolean testRange(BigInteger lowerValue, BigInteger upperValue, BigInteger finalUpperValue, BigInteger networkMask, BigInteger hostMask) {
		return lowerValue.equals(lowerValue.and(networkMask)) && finalUpperValue.equals(upperValue.or(hostMask));
	}
	
	static boolean testRange(BigInteger lowerValue, BigInteger upperValue, BigInteger finalUpperValue, int bitCount, int divisionPrefixLen) {
		BigInteger networkMask = AddressDivisionGroupingBase.ALL_ONES.shiftLeft(bitCount - divisionPrefixLen);
		BigInteger hostMask = networkMask.not();
		return testRange(lowerValue, upperValue, finalUpperValue, networkMask, hostMask);
	}

	/**
	 * Returns whether the values of this series contains the prefix block for the given prefix length.
	 * <p>
	 * Use {@link #getMinPrefixLengthForBlock()} to determine the smallest prefix length for which this method returns true.
	 * 
	 * @param divisionPrefixLen
	 * @throws PrefixLenException if prefixLength exceeds the bit count or is negative
	 * @return
	 */
	default boolean containsPrefixBlock(int divisionPrefixLen) {
		if(divisionPrefixLen == 0) {
			return isFullRange();
		}
		BigInteger upper = getUpperValue();
		return testRange(getValue(), upper, upper, getBitCount(), divisionPrefixLen);
	}
	
	/**
	 * Returns whether the values of this series contains a single prefix block for the given prefix length.
	 * <p>
	 * Use {@link #getPrefixLengthForSingleBlock()} to determine whether there is a prefix length for which this method returns true.
	 * 
	 * @param divisionPrefixLen
	 * @throws PrefixLenException if prefixLength exceeds the bit count or is negative
	 * @return
	 */
	default boolean containsSinglePrefixBlock(int divisionPrefixLen) {
		if(divisionPrefixLen == 0) {
			return isFullRange();
		}
		BigInteger lower = getValue(), upper = getUpperValue();
		return testRange(lower, lower, upper, getBitCount(), divisionPrefixLen);
	}
	
	/**
	 * Returns the smallest prefix length possible such that this item includes the block of all values for that prefix length.
	 * <p>
	 * If the entire range can be dictated this way, then this method returns the same value as {@link #getPrefixLengthForSingleBlock()}.  
	 * Otherwise, this method will return the minimal possible prefix that can be paired with this address, while {@link #getPrefixLengthForSingleBlock()} will return null.
	 * <p>
	 * In cases where the final bit is constant so there is no such block, this returns the bit count.
	 *
	 * @return the prefix length
	 */
	default int getMinPrefixLengthForBlock() {
		int result = getBitCount();
		BigInteger lower = getValue(), upper = getUpperValue();
		int longBits = Long.SIZE;
		do {
			long low = lower.longValue();
			int lowerZeros = Long.numberOfTrailingZeros(low);
			if(lowerZeros == 0) {
				break;
			}
			long up = upper.longValue();
			int upperOnes = Long.numberOfTrailingZeros(~up);
			if(upperOnes == 0) {
				break;
			}
			int prefixedBitCount = Math.min(lowerZeros, upperOnes);
			result -= prefixedBitCount;
			if(prefixedBitCount < longBits) {
				break;
			}
			lower = lower.shiftRight(longBits);
			upper = upper.shiftRight(longBits);
		} while(!upper.equals(BigInteger.ZERO));
		return result;
	}
	
	/**
	 * Returns a prefix length for which the range of this item matches the block of all values for that prefix length.
	 * <p>
	 * If the range can be dictated this way, then this method returns the same value as {@link #getMinPrefixLengthForBlock()}.
	 * <p>
	 * If no such prefix length exists, returns null.
	 * <p>
	 * If this item represents a single value, this returns the bit count.
	 * 
	 * @return the prefix length or null
	 */
	default Integer getPrefixLengthForSingleBlock() {
		int divPrefix = getMinPrefixLengthForBlock();
		BigInteger lower = getValue(), upper = getUpperValue();
		int bitCount = getBitCount();
		if(divPrefix == bitCount) {
			if(lower.equals(upper)) {
				return AddressDivisionGroupingBase.cacheBits(divPrefix);
			}
		} else {
			int shift = bitCount - divPrefix;
			if(lower.shiftRight(shift).equals(upper.shiftRight(shift))) {
				return AddressDivisionGroupingBase.cacheBits(divPrefix);
			}
		}
		return null;
	}
}
