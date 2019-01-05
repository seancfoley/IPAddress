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

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.PrefixLenException;
import inet.ipaddr.format.IPAddressGenericDivision;
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
public abstract class IPAddressDivision extends AddressDivision implements IPAddressGenericDivision {

	private static final long serialVersionUID = 4L;

	private final Integer divisionNetworkPrefix;//the prefix length for this division, or null if there is none
	
	protected transient String cachedString;
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

	@Override
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
		return matchingValue == (getDivisionValue() & mask) && matchingValue == (getUpperDivisionValue() & mask);
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
			val = getDivisionValue();
			invertedVal = ~val & getMaxValue();
		} else {
			invertedVal = getDivisionValue();
			val = ~invertedVal & getMaxValue();
		}
		int bitCount = getBitCount();
		int hostLength  = Math.min(Long.numberOfTrailingZeros(val), bitCount);
		long shifted = invertedVal >>> hostLength;
		return shifted == 0 ? bitCount - hostLength : null;
	}

	@Override
	protected boolean isPrefixBlock(long segmentValue, long upperValue, int divisionPrefixLen) {
		if(divisionPrefixLen == 0) {
			//is full range?
			return segmentValue == 0 && upperValue == getMaxValue();
		}
		return testRange(segmentValue,
				upperValue,
				upperValue,
				getDivisionNetworkMask(divisionPrefixLen),
				getDivisionHostMask(divisionPrefixLen));
	}

	@Override
	protected boolean isSinglePrefixBlock(long segmentValue, long upperValue, int divisionPrefixLen) {
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
		return isSinglePrefixBlock(segmentValue, getUpperDivisionValue(), divisionPrefixLen);
	}
	
	/**
	 * @return whether the division range includes the block of values for the given prefix length
	 */
	@Override
	public boolean containsPrefixBlock(int divisionPrefixLen) {
		return isPrefixBlock(getDivisionValue(), getUpperDivisionValue(), divisionPrefixLen);
	}

	/**
	 * @return whether the division range includes the block of values for the division prefix length,
	 *  or false if the division has no prefix length
	 */
	@Override
	public boolean isPrefixBlock() {
		return isPrefixed() && containsPrefixBlock(getDivisionPrefixLength());
	}

	/**
	 * Returns whether the division range matches exactly the block of values for the given prefix length.
	 * 
	 * @return whether the range of this division matches the range for a single prefix with a single value and the given prefix length.
	 * 
	 * @param divisionPrefixLen
	 * @return whether the range of this segment matches the block of address divisions for that prefix.
	 */
	@Override
	public boolean containsSinglePrefixBlock(int divisionPrefixLen) {
		return isSinglePrefixBlock(getDivisionValue(), getUpperDivisionValue(), divisionPrefixLen);
	}

	/**
	 * @return whether the division range matches exactly the block of values for its prefix length.
	 */
	@Override
	public boolean isSinglePrefixBlock() {//since this one is commonly used for string production, it is cached
		if(isSinglePrefixBlock == null) {
			isSinglePrefixBlock = isPrefixed() && containsSinglePrefixBlock(getDivisionPrefixLength());
		}
		return isSinglePrefixBlock;
	}
	
	protected boolean isBitwiseOrCompatibleWithRange(long maskValue, Integer divisionPrefixLen, boolean isAutoSubnets) {
		long value = getDivisionValue();
		long upperValue = getUpperDivisionValue();
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
		long value = getDivisionValue();
		long upperValue = getUpperDivisionValue();
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
						result = getDefaultLowerString();
					} else if(isFullRange()) {
						result = IPAddress.SEGMENT_WILDCARD_STR;
					} else {
						long upperValue = getUpperDivisionValue();
						if(isPrefixBlock()) {
							upperValue &= getDivisionNetworkMask(getDivisionPrefixLength());
						}
						result = getDefaultRangeString(getDivisionValue(), upperValue, getDefaultTextualRadix());
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
	protected String getCachedDefaultLowerString() {
		String result = cachedString;
		if(result == null) {
			synchronized(this) {
				result = cachedString;
				if(result == null) {
					cachedString = result = getDefaultLowerString();
				}
			}
		}
		return result;
	}

	@Override
	protected void getUpperStringMasked(int radix, boolean uppercase, StringBuilder appendable) {
		long upperValue = getUpperDivisionValue();
		long mask = getDivisionNetworkMask(getDivisionPrefixLength());
		upperValue &= mask;
		toUnsignedString(upperValue, radix, 0, uppercase, uppercase ? UPPERCASE_DIGITS : DIGITS, appendable);
	}
	
	@Override
	public int getPrefixAdjustedRangeString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable) {
		return super.getPrefixAdjustedRangeString(segmentIndex, params, appendable);
	}
}
