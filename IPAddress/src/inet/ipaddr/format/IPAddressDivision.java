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
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.util.AddressSegmentParams;

/**
 * A division of an IP address.
 * 
 * May be associated with a prefix length, in which case that number of bits in the upper-most
 * portion of the object represent a prefix, while the remaining bits can assume all possible values.
 * 
 * @author sfoley
 *
 */
public abstract class IPAddressDivision extends AddressDivision implements IPAddressStringDivision {

	private static final long serialVersionUID = 4L;

	private final Integer divisionNetworkPrefix;//the prefix length for this division, or null if there is none
	
	protected transient String cachedWildcardString;
	private transient Boolean isSinglePrefixBlock;
	
	protected IPAddressDivision() {
		this(null);
	}
	
	protected IPAddressDivision(Integer networkPrefixLength) {
		if(networkPrefixLength != null && networkPrefixLength < 0) {
			throw new PrefixLenException(networkPrefixLength);
		}
		this.divisionNetworkPrefix = networkPrefixLength;
	}

	public boolean isPrefixed() {
		return divisionNetworkPrefix != null;
	}
	
	/**
	 * Returns the network prefix for the division.
	 * 
	 * The network prefix is 16 for an address like 1.2.0.0/16.
	 * 
	 * When it comes to each address division or segment, the prefix for the division is the
	 * prefix obtained when applying the address or section prefix.
	 * 
	 * For instance, with the address 1.2.0.0/20, 
	 * segment 1 has no prefix because the address prefix 20 extends beyond the 8 bits in the first segment, it does not even apply to the segment, 
	 * segment 2 has no prefix because the address prefix extends beyond bits 9 to 16 which lie in the second segment, it does not apply to that segment either,
	 * segment 3 has the prefix 4 because the address prefix 20 corresponds to the first 4 bits in the 3rd segment,
	 * which means that the first 4 bits are part of the network section of the address or segment,
	 * and segment 4 has the prefix 0 because not a single bit is in the network section of the address or segment
	 * 
	 * The prefix applied across the address is null ... null ... (1 to segment bit length) ... 0 ... 0
	 * 
	 * If the segment has no prefix then null is returned.
	 * 
	 * @return
	 */
	@Override
	public Integer getDivisionPrefixLength() {
		return divisionNetworkPrefix;
	}

	public boolean matchesWithPrefixMask(long value, Integer divisionPrefixLen) {
		if(divisionPrefixLen == null) {
			return matches(value);
		}
		long mask = getDivisionNetworkMask(divisionPrefixLen);
		long matchingValue = value & mask;
		return matchingValue == (getLowerValue() & mask) && matchingValue == (getUpperValue() & mask);
	}
	
	protected abstract long getDivisionNetworkMask(int bits);
	
	protected abstract long getDivisionHostMask(int bits);
	
	/**
	 * If this is equivalent to the mask for a CIDR prefix length block or subnet class, it returns the prefix length.
	 * Otherwise, it returns null.
	 * A CIDR network mask is an address with all 1s in the network section (the upper bits) and then all 0s in the host section.
	 * A CIDR host mask is an address with all 0s in the network section (the lower bits) and then all 1s in the host section.
	 * The prefix length is the length of the network section.
	 * 
	 * Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length used to construct this object.
	 * The prefix length used to construct indicates the network and host portion of this address.  
	 * The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host of an address with that prefix length.
	 * Therefore the two values can be different values, or one can be null while the other is not.
	 * 
	 * This method applies only to the lower value of the range if this segment represents multiple values.
	 * 
	 * @see IPAddressSection#getPrefixLengthForSingleBlock()
	 * 
	 * @param network whether to check for a network mask or a host mask
	 * @return the prefix length corresponding to this mask, or null if there is no such prefix length
	 */
	public Integer getBlockMaskPrefixLength(boolean network) {
		long val, invertedVal;
		if(network) {
			val = getLowerValue();
			invertedVal = ~val & getMaxValue();
		} else {
			invertedVal = getLowerValue();
			val = ~invertedVal & getMaxValue();
		}
		int bitCount = getBitCount();
		int hostLength  = Math.min(Long.numberOfTrailingZeros(val), bitCount);
		long shifted = invertedVal >>> hostLength;
		return shifted == 0 ? bitCount - hostLength : null;
	}

	@Override
	boolean isPrefixBlock(long segmentValue, long upperValue, int divisionPrefixLen) {
		if(divisionPrefixLen == 0) {
			return isFullRange();
		}
		return testRange(segmentValue,
				upperValue,
				upperValue,
				getDivisionNetworkMask(divisionPrefixLen),
				getDivisionHostMask(divisionPrefixLen));
	}

	@Override
	boolean isSinglePrefixBlock(long segmentValue, long upperValue, int divisionPrefixLen) {
		return testRange(segmentValue,
				segmentValue,
				upperValue,
				getDivisionNetworkMask(divisionPrefixLen),
				getDivisionHostMask(divisionPrefixLen));
	}
	
	/**
	 * Whether the range of this division matches the range for a single prefix with the given value and the given prefix length.
	 * 
	 * @param divisionPrefixLen
	 * @return whether the range of this segment matches the block of address divisions for that prefix.
	 */
	boolean isSinglePrefixBlock(long segmentValue, int divisionPrefixLen) {
		return isSinglePrefixBlock(segmentValue, getUpperValue(), divisionPrefixLen);
	}
	
	/**
	 * @return whether the division range includes the block of values for the given prefix length
	 */
	public boolean isPrefixBlock(int divisionPrefixLen) {
		return isPrefixBlock(getLowerValue(), getUpperValue(), divisionPrefixLen);
	}

	/**
	 * @return whether the division range includes the block of values for the division prefix length,
	 *  or false if the division has no prefix length
	 */
	@Override
	public boolean isPrefixBlock() {
		return isPrefixed() && isPrefixBlock(getDivisionPrefixLength());
	}

	/**
	 * Returns whether the division range matches exactly the block of values for the given prefix length.
	 * If the given prefix length is null, return false.
	 * 
	 * @return whether the range of this division matches the range for a single prefix with a single value and the given prefix length.
	 * 
	 * @param divisionPrefixLen
	 * @return whether the range of this segment matches the block of address divisions for that prefix.
	 * 	If the prefix is null or equal to the bit length, then this returns true for non-multiple addresses.
	 */
	public boolean isSinglePrefixBlock(int divisionPrefixLen) {
		return isSinglePrefixBlock(getLowerValue(), getUpperValue(), divisionPrefixLen);
	}

	/**
	 * @return whether the division range matches exactly the block of values for its prefix length.
	 */
	@Override
	public boolean isSinglePrefixBlock() {//since this one is commonly used for string production, it is cached
		if(isSinglePrefixBlock == null) {
			isSinglePrefixBlock = isPrefixed() && isSinglePrefixBlock(getDivisionPrefixLength());
		}
		return isSinglePrefixBlock;
	}
	
	protected boolean isBitwiseOrCompatibleWithRange(long maskValue, Integer divisionPrefixLen, boolean isAutoSubnets) {
		long value = getLowerValue();
		long upperValue = getUpperValue();
		long maxValue = getMaxValue();
		if(divisionPrefixLen != null) {
			int divPrefLen = divisionPrefixLen;
			int bitCount = getBitCount();
			if(divPrefLen < 0 || divPrefLen > bitCount) {
				throw new PrefixLenException(this, divisionPrefixLen);
			}
			if(isAutoSubnets) {
				int shift = bitCount - divPrefLen;
				maskValue >>>= shift;
				value >>>= shift;
				upperValue >>>= shift;
				maxValue >>>= shift;
			}
		}
		return isBitwiseOrCompatibleWithRange(value, upperValue, maskValue, maxValue);
	}

	protected boolean isMaskCompatibleWithRange(long maskValue, Integer divisionPrefixLen, boolean isAutoSubnets) {
		long value = getLowerValue();
		long upperValue = getUpperValue();
		long maxValue = getMaxValue();
		if(divisionPrefixLen != null) {
			int divPrefLen = divisionPrefixLen;
			int bitCount = getBitCount();
			if(divPrefLen < 0 || divPrefLen > bitCount) {
				throw new PrefixLenException(this, divisionPrefixLen);
			}
			if(isAutoSubnets) {
				int shift = bitCount - divPrefLen;
				maskValue >>>= shift;
				value >>>= shift;
				upperValue >>>= shift;
				maxValue >>>= shift;
			}
		}
		return isMaskCompatibleWithRange(value, upperValue, maskValue, maxValue);
	}

	/**
	 * Produces a normalized string to represent the segment.
	 * If the segment CIDR prefix length covers the range, then it is assumed to be a CIDR, and the string has only the lower value of the CIDR range.
	 * Otherwise, the explicit range will be printed.
	 * @return
	 */
	@Override
	public String getString() {
		String result = cachedString;
		if(result == null) {
			synchronized(this) {
				result = cachedString;
				if(result == null) {
					if(isSinglePrefixBlock() || !isMultiple()) { //covers the case of !isMultiple, ie single addresses, when there is no prefix or the prefix is the bit count
						result = getDefaultString();
					} else if(isFullRange()) {
						result = IPAddress.SEGMENT_WILDCARD_STR;
					} else {
						long upperValue = getUpperValue();
						if(isPrefixBlock()) {
							upperValue &= getDivisionNetworkMask(getDivisionPrefixLength());
						}
						result = getDefaultRangeString(getLowerValue(), upperValue, getDefaultTextualRadix());
					}
					cachedString = result;
				}
			}
		}
		return result;
	}

	/**
	 * Produces a string to represent the segment, favouring wildcards and range characters over the network prefix to represent subnets.
	 * If it exists, the segment CIDR prefix is ignored and the explicit range is printed.
	 * @return
	 */
	@Override
	public String getWildcardString() {
		String result = cachedWildcardString;
		if(result == null) {
			synchronized(this) {
				result = cachedWildcardString;
				if(result == null) {
					if(!isPrefixed() || !isMultiple()) {
						result = getString();
					} else if(isFullRange()) {
						result = IPAddress.SEGMENT_WILDCARD_STR;
					} else {
						result = getDefaultRangeString();
					}
					cachedWildcardString = result;
				}
			}
		}
		return result;
	}
	
	@Override
	protected void setDefaultAsFullRangeWildcardString() {
		if(cachedWildcardString == null) {
			synchronized(this) {
				cachedWildcardString = IPAddress.SEGMENT_WILDCARD_STR;
			}
		}
	}

	@Override
	protected void getUpperStringMasked(int radix, boolean uppercase, StringBuilder appendable) {
		long upperValue = getUpperValue();
		long mask = getDivisionNetworkMask(getDivisionPrefixLength());
		upperValue &= mask;
		toUnsignedString(upperValue, radix, 0, uppercase, uppercase ? UPPERCASE_DIGITS : DIGITS, appendable);
	}
	
	@Override
	public int getPrefixAdjustedRangeString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable) {
		return super.getPrefixAdjustedRangeString(segmentIndex, params, appendable);
	}
}
