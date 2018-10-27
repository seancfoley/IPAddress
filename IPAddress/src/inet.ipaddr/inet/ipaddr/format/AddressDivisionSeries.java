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

import inet.ipaddr.AddressNetwork;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.string.AddressStringDivisionSeries;

/**
 * Represents a series of groups of address divisions or segments.  Each group may have a different bit size.
 * 
 * This interface is the super interface of all interfaces and classes representing a series of divisions or segments.
 * 
 * @author sfoley
 *
 */
public interface AddressDivisionSeries extends AddressItem, AddressStringDivisionSeries {
	
	/**
	 * Use this method to compare the counts of two address series.
	 * 
	 * Rather than calculating counts with getCount(), there can be more efficient ways of comparing whether one series represents more individual address series than another.
	 * 
	 * @return a positive integer if this AddressDivisionSeries has a larger count than the provided, 0 if they are the same, a negative integer if the other has a larger count.
	 */
	default int isMore(AddressDivisionSeries other) {
		if(!isMultiple()) {
			return other.isMultiple() ? -1 : 0;
		}
		if(!other.isMultiple()) {
			return 1;
		}
		return getCount().compareTo(other.getCount());
	}
	
	/**
	 * @return the given division in this series.  The first is at index 0.
	 */
	@Override
	AddressGenericDivision getDivision(int index);
	
	/**
	 * Get standard-format strings for each of the divisions in the series.
	 * 
	 * @return
	 */
	String[] getDivisionStrings();

	/**
	 * The bit-length of the portion of the address that is not specific to an individual address but common amongst a group of addresses.
	 * <p>
	 * Typically this is the largest number of bits in the upper-most portion of the section for which the remaining bits assume all possible values.
	 * <p>
	 * For IP addresses, this must be explicitly defined when the address is created. For example, 1.2.0.0/16 has a prefix length of 16, while 1.2.*.* has no prefix length,
	 * even though they both represent the same set of addresses and are considered equal.  Prefixes can be considered variable for any given IP addresses and can
	 * depend on the routing table.
	 * <p>
	 * The methods {@link AddressDivisionSeries#getMinPrefixLengthForBlock()} and {@link AddressDivisionSeries#getPrefixLengthForSingleBlock()} can help you to obtain or define a prefix length if one does not exist already.  
	 * 1.2.0.0/16 and 1.2.*.* both the same equivalent and minimum prefix length of 16.
	 * <p>
	 * For MAC addresses, the prefix is initially defined by the range, so 1:2:3:*:*:* has a prefix length of 24 by definition.  Addresses derived from the original may retain the original prefix length regardless of their range.
	 * <p>
	 */
	Integer getPrefixLength();

	/**
	 * Whether there exists a prefix length associated with this series.
	 */
	boolean isPrefixed();

	/**
	 * Returns whether this address segment series represents a block of addresses associated with its prefix length.
	 * <p>
	 * This returns false if it has no prefix length or if it is a range of addresses that does not include
	 * the entire subnet block for the prefix length.
	 * <p>
	 * If {@link AddressNetwork#getPrefixConfiguration} is set to consider all prefixes as subnets, this returns true for any series with a prefix length.
	 * <p>
	 * An important distinction of {@link #containsPrefixBlock(int)} with this method is that this method returns
	 * false if the series does not have a prefix length assigned to it, 
	 * even if there exists one or more prefix lengths for which {@link #containsPrefixBlock(int)} returns true.
	 * @return
	 */
	boolean isPrefixBlock();
	
	/**
	 * Returns whether the range of values matches a single subnet block for the prefix length
	 * <p>
	 * An important distinction of this method with {@link #containsSinglePrefixBlock(int)} is that this method returns
	 * false if the series does not have a prefix length assigned to it, 
	 * even if there exists a prefix length for which {@link #containsSinglePrefixBlock(int)}
	 * returns true.
	 * 
	 * 
	 * @return
	 */
	boolean isSinglePrefixBlock();

	/**
	 * If this has a prefix length, the count of the range of values in the prefix.
	 * <p>
	 * If this has no prefix length, returns the same value as {@link #getCount()}
	 * 
	 * @return
	 */
	default BigInteger getPrefixCount() {
		Integer prefixLength = getPrefixLength();
		if(prefixLength == null || prefixLength >= getBitCount()) {
			return getCount();
		}
		return getPrefixCount(prefixLength);
	}
	
	@Override
	default BigInteger getPrefixCount(int prefixLength) {
		if(prefixLength < 0 || prefixLength > getBitCount()) {
			throw new PrefixLenException(this, prefixLength);
		}
		BigInteger result = BigInteger.ONE;
		if(isMultiple()) {
			int divisionCount = getDivisionCount();
			int divPrefixLength = prefixLength;
			for(int i = 0; i < divisionCount; i++) {
				AddressGenericDivision division = getDivision(i);
				int divBitCount = division.getBitCount();
				if(division.isMultiple()) {
					BigInteger divCount = (divPrefixLength < divBitCount) ? division.getPrefixCount(divPrefixLength) : division.getCount();
					result = result.multiply(divCount);
				}
				if(divPrefixLength <= divBitCount) {
					break;
				}
				divPrefixLength -= divBitCount;
			}
		}
		return result;
	}
	
	@Override
	default BigInteger getCount() {
		BigInteger result = BigInteger.ONE;
		int count = getDivisionCount();
		if(count > 0) {
			for(int i = 0; i < count; i++) {
				AddressGenericDivision div = getDivision(i);
				if(div.isMultiple()) {
					BigInteger divCount = getDivision(i).getCount();
					result = result.multiply(divCount);
				}
			}
		}
		return result;
	}

	/**
	 * Returns the count of values in the initial (higher) count of segments.
	 * 
	 * @return
	 */
	default BigInteger getBlockCount(int segmentCount) {
		if(segmentCount < 0) {
			throw new IllegalArgumentException();
		}
		BigInteger result = BigInteger.ONE;
		int divisionCount = getDivisionCount();
		if(segmentCount < divisionCount) {
			divisionCount = segmentCount;
		}
		for(int i = 0; i < divisionCount; i++) {
			AddressGenericDivision division = getDivision(i);
			if(division.isMultiple()) {
				result = result.multiply(division.getCount());
			}
		}
		return result;
	}
	
	@Override
	default int getBitCount() {
		int count = getDivisionCount();
		int bitCount = 0;
		for(int i = 0; i < count; i++) {
			bitCount += getDivision(i).getBitCount();
		}
		return bitCount;
	}
	
	/**
	 * If the series represents a range of values that are sequential.
	 * 
	 * Generally, this means that any division covering a range of values must be followed by divisions that are full range, covering all values.
	 * 
	 * @return
	 */
	default boolean isSequential() {
		int count = getDivisionCount();
		if(count > 1) {
			for(int i = 0; i < count; i++) {
				if(getDivision(i).isMultiple()) {
					for(++i; i < count; i++) {
						if(!getDivision(i).isFullRange()) {
							return false;
						}
					}
				}
			}
		}
		return true;
	}
}
