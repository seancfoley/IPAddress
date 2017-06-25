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

import inet.ipaddr.AddressTypeException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSection;
import inet.ipaddr.format.AddressDivisionGrouping.StringOptions.Wildcards;
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
public abstract class IPAddressDivision extends AddressDivision {

	private static final long serialVersionUID = 3L;

	//when printing a string, whether the prefix affects the printed range, for instance, whether to print 100-127/5 or 100-124/5
	public static final boolean ADJUST_RANGES_BY_PREFIX = true;

	private final Integer divisionNetworkPrefix;//the prefix length for this division, or null if there is none
	
	protected transient String cachedWildcardString;
	private transient Boolean isRangeEquivalentToPrefix;
	
	protected IPAddressDivision() {
		this(null);
	}
	
	protected IPAddressDivision(Integer networkPrefixLength) {
		if(networkPrefixLength != null && networkPrefixLength < 0) {
			throw new IllegalArgumentException();
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
	public Integer getDivisionPrefixLength() {
		return divisionNetworkPrefix;
	}

	public boolean matchesWithPrefix(long value, Integer divisionPrefixLen) {
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
	 * If this is equivalent to the mask for a CIDR prefix, it returns that prefix length.
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
	 * @see IPAddressSection#getEquivalentPrefix()
	 * 
	 * @param network whether to check for a network mask or a host mask
	 * @return the prefix length corresponding to this mask, or null if this address is not a CIDR prefix mask
	 */
	public Integer getMaskPrefixLength(boolean network) {
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

	/** 
	 * @param lowerValue
	 * @return whether the range of this segment matches the range of a segment with the given value and the CIDR prefix length of this segment
	 */
	public boolean isSamePrefixedRange(long lowerValue) {
		return isPrefixed() ? isSamePrefixedRange(lowerValue, getDivisionPrefixLength()) : (lowerValue == getLowerValue() && !isMultiple());
	}
	
	/**
	 * @param lowerValue
	 * @param divisionPrefixLen
	 * @return whether the range of this segment matches the range of a segment with the given value and CIDR prefix length
	 */
	private boolean isSamePrefixedRange(long lowerValue, int divisionPrefixLen) {
		long mask = getDivisionNetworkMask(divisionPrefixLen);
		long expectedValue = lowerValue & mask;
		return getLowerValue() == expectedValue
			&&  getUpperValue() == (lowerValue | getDivisionHostMask(divisionPrefixLen));
	}
	
	private static boolean testRange(long lowerValue, long upperValue, long finalUpperValue, long networkMask, long hostMask) {
		return lowerValue == (lowerValue & networkMask)
				&& finalUpperValue == (upperValue | hostMask);
	}
	
	/**
	 * 
	 * @param segmentValue
	 * @param divisionPrefixLen
	 * @return whether the given range remains the same with the given prefix applied 
	 */
	private boolean isRangeUnchanged(long segmentValue, long upperValue, int divisionPrefixLen) {
		return testRange(segmentValue,
				upperValue,
				upperValue,
				getDivisionNetworkMask(divisionPrefixLen),
				getDivisionHostMask(divisionPrefixLen));
	}
	
	/**
	 * 
	 * @param segmentValue
	 * @param divisionPrefixLen
	 * @return whether the given range of segmentValue to upperValue is equivalent to the range of segmentValue with the prefix of divisionPrefixLen 
	 */
	protected boolean isRangeEquivalent(long segmentValue, long upperValue, int divisionPrefixLen) {
		return testRange(segmentValue,
				segmentValue,
				upperValue,
				getDivisionNetworkMask(divisionPrefixLen),
				getDivisionHostMask(divisionPrefixLen));
	}
	
	/**
	 * @param divisionPrefixLen
	 * @return whether the range of this segment can be specified only using the segment's lower value and the given prefix length
	 * 	If the prefix is null or equal to the bit length, then this returns true for non-multiple addresses.
	 */
	public boolean isRangeEquivalent(Integer divisionPrefixLen) {
		if(divisionPrefixLen == null) {
			return !isMultiple();
		}
		return divisionPrefixLen == 0 || isRangeEquivalent(getLowerValue(), getUpperValue(), divisionPrefixLen);
	}
	
	/**
	 * 
	 * @param divisionPrefixLen
	 * @return whether the given range remains the same with the given prefix applied 
	 */
	public boolean isRangeUnchanged(Integer divisionPrefixLen) {
		if(divisionPrefixLen == null) {
			return true;
		}
		if(divisionPrefixLen == 0) {
			return isFullRange();
		}
		return isRangeUnchanged(getLowerValue(), getUpperValue(), divisionPrefixLen);
	}
	
	/**
	 * @return whether the range of this segment can be specified only using the segment's lower value and the segment's prefix length
	 */
	@Override
	public boolean isRangeEquivalentToPrefix() {
		if(isRangeEquivalentToPrefix == null) {
			isRangeEquivalentToPrefix = isRangeEquivalent(getDivisionPrefixLength());
		}
		return isRangeEquivalentToPrefix;
	}
	
	@Override
	protected boolean isRangeAdjustedToPrefix() {
		return !isPrefixed() || divisionNetworkPrefix == getBitCount() || !ADJUST_RANGES_BY_PREFIX;
	}

	public boolean isBitwiseOrCompatibleWithRange(long maskValue, Integer divisionPrefixLen) {
		boolean hasBits = (divisionPrefixLen != null);
		int divPrefLen;
		if(hasBits) {
			divPrefLen = divisionPrefixLen;
			if(divPrefLen < 0 || divPrefLen > getBitCount()) {
				throw new AddressTypeException(this, divisionPrefixLen, "ipaddress.error.prefixSize");
			}
		} else {
			divPrefLen = getBitCount();
		}
		if(!isMultiple() || maskValue == getMaxValue() || maskValue == 0) {
			return true;
		}
		long networkMask = getDivisionNetworkMask(divPrefLen); //but only the bits we care about, the applied divisionPrefixLen eliminates our concern about certain bits
		if(hasBits && (networkMask & maskValue) == networkMask) {//any problematic bits will be eliminated by the prefix
			return true;
		}
		
		long value = getLowerValue();
		long upperValue = getUpperValue();
		
		//algorithm:
		//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
		//then we find the highest bit in the mask that is 0 that is the same or below highestDifferingBitInRange (if such a bit exists)
		
		//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
		//if this latter bit exists, then any bit below it in the mask must be 0 to include the entire range.
		
		long differing = (value ^ upperValue) & networkMask;
		boolean foundDiffering = (differing != 0);
		boolean differingIsLowestBit = (differing == 1);
		if(foundDiffering && !differingIsLowestBit) {
			int highestDifferingBitInRange = Long.numberOfLeadingZeros(differing);
			long maskMask = ~0L >>> highestDifferingBitInRange;
			long differingMasked = maskValue & maskMask;
			foundDiffering = (differingMasked != maskMask);
			differingIsLowestBit = ((differingMasked | 1) == maskMask);
			if(foundDiffering && !differingIsLowestBit) {
				//anything below highestDifferingBitMasked in the mask must be zeros 
				int highestDifferingBitMasked = Long.numberOfLeadingZeros(~differingMasked & maskMask);
				long hostMask = ~0L >>> (highestDifferingBitMasked + 1);
				maskValue &= getDivisionNetworkMask(divPrefLen);//but only the bits we care about, the applied divisionPrefixLen eliminates our concern about non-prefix bits
				if((maskValue & hostMask) != 0) { //check if all zeros below
					return false;
				}
			}
		}
		return true;
	}
	
	
	public boolean isMaskCompatibleWithRange(long maskValue, Integer divisionPrefixLen) {
		boolean hasBits = (divisionPrefixLen != null);
		int divPrefLen;
		if(hasBits) {
			divPrefLen = divisionPrefixLen;
			if(divPrefLen < 0 || divPrefLen > getBitCount()) {
				throw new AddressTypeException(this, divisionPrefixLen, "ipaddress.error.prefixSize");
			}
		} else {
			divPrefLen = getBitCount();
		}
		if(!isMultiple() || maskValue == getMaxValue() || maskValue == 0) {
			return true;
		}
		long networkMask = getDivisionNetworkMask(divPrefLen); //but only the bits we care about, the applied divisionPrefixLen eliminates our concern about certain bits
		if(hasBits && (networkMask & maskValue) == 0) {//any problematic bits will be eliminated by the prefix
			return true;
		}
		
		long value = getLowerValue();
		long upperValue = getUpperValue();
		
		//algorithm:
		//here we find the highest bit that is part of the range, highestDifferingBitInRange (ie changes from lower to upper)
		//then we find the highest bit in the mask that is 1 that is the same or below highestDifferingBitInRange (if such a bit exists)
		
		//this gives us the highest bit that is part of the masked range (ie changes from lower to upper after applying the mask)
		//if this latter bit exists, then any bit below it in the mask must be 1 to include the entire range.
		
		long differing = (value ^ upperValue) & networkMask;
		boolean foundDiffering = (differing != 0);
		boolean differingIsLowestBit = (differing == 1);
		if(foundDiffering && !differingIsLowestBit) {
			int highestDifferingBitInRange = Long.numberOfLeadingZeros(differing);
			long maskMask = ~0L >>> highestDifferingBitInRange;
			long differingMasked = maskValue & maskMask;
			foundDiffering = (differingMasked != 0);
			differingIsLowestBit = (differingMasked == 1);
			if(foundDiffering && !differingIsLowestBit) {
				//anything below highestDifferingBitMasked in the mask must be ones 
				int highestDifferingBitMasked = Long.numberOfLeadingZeros(differingMasked);
				long hostMask = ~0L >>> (highestDifferingBitMasked + 1);
				maskValue |= getDivisionHostMask(divPrefLen); //but only the bits we care about, the applied divisionPrefixLen eliminates our concern about non-prefix bits
				if((maskValue & hostMask) != hostMask) { //check if all ones below
					return false;
				}
			}
		}
		return true;
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
					if(isRangeEquivalentToPrefix()) { //covers the case of !isMultiple, ie single addresses
						result = getDefaultString();
					} else if(isFullRange()) {
						result = IPAddress.SEGMENT_WILDCARD_STR;
					} else {
						long upperValue = getUpperValue();
						boolean maskUpper = ADJUST_RANGES_BY_PREFIX && isPrefixed();
						if(maskUpper) {
							upperValue &= getDivisionNetworkMask(getDivisionPrefixLength());
						}
						result = getDefaultRangeString(getLowerValue(), upperValue, getDefaultTextualRadix(), maskUpper);
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
	protected void setFullRangeWildcardString() {
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
		toUnsignedString(upperValue, radix, 0, uppercase, uppercase ? UPPED_DIGITS : DIGITS, appendable);
	}
	
	/**
	 * Produces a string to represent the segment.
	 * <p>
	 * Use this instead of {@link #getString(Wildcards, int, String, int, boolean, boolean, char, boolean, StringBuilder)}
	 * if you wish to avoid printing wildcards in the host section of the address.
	 * Instead, this method will rely on the prefix length instead.
	 * <p>
	 * Use this instead of getString() if you have a customized wildcard or range separator or you have a non-zero leadingZeroCount,
	 * or you have a string prefix, or you have a non-default radix (for IPv4 default radix is 10, for IPv6 it is 16)
	 * 
	 * @return if the supplied appendable is null, returns the length of the string that would have been appended, otherwise returns 0
	 */
	@Override
	public int getConfiguredString(int segmentIndex, AddressSegmentParams params, StringBuilder appendable) {
		if(params.preferWildcards() || params.isSplitDigits()) {
			return getStandardString(segmentIndex, params, appendable);
		}
		return getPrefixAdjustedString(segmentIndex, params, appendable);
	}
}
