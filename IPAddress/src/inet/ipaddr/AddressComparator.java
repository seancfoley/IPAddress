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

package inet.ipaddr;

import java.util.Comparator;
import java.util.Objects;

import inet.ipaddr.format.AddressDivision;
import inet.ipaddr.format.AddressDivisionGrouping;
import inet.ipaddr.format.AddressDivisionSeries;
import inet.ipaddr.format.IPAddressDivisionGrouping;
import inet.ipaddr.format.IPAddressJoinedSegments;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv4.IPv4JoinedSegments;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6v4MixedAddressSection;
import inet.ipaddr.ipv6.IPv6AddressSegment;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSegment;

/**
 * 
 * @author sfoley
 *
 */
public interface AddressComparator extends Comparator<Address> {

	int compare(AddressDivisionSeries one, AddressDivisionSeries two);
	
	int compare(AddressDivision one, AddressDivision two);

	/**
	 * This is similar to the default comparator CountComparator in the way they treat addresses representing a single address.
	 * 
	 * For individual addresses, it simply compares segment to segment from high to low, so 1.2.3.4 &lt; 1.2.3.5 and 2.2.3.4 &gt; 1.2.3.5.
	 * 
	 * The difference is how they treat addresses representing multiple addresses (ie subnets) like 1::/8 or 1.*.*.*
	 * 
	 * The count comparator considers addresses which represent more individual addresses to be larger.
	 * 
	 * The value comparator goes by either the highest value or the lowest value in the range of represented addresses.
	 * <p>
	 * So, for instance, consider 1.2.3.4 and 1.0.0.*
	 * 
	 * With count comparator, 1.2.3.4 &lt; 1.2.3.* since the second represents more addresses (ie 1 &lt; 255)
	 * 
	 * With value comparator using the high value, 1.2.3.4 &lt; 1.2.3.* since 1.2.3.4 &lt; 1.2.3.255
	 * 
	 * With value comparator using the low value, 1.2.3.4 &gt; 1.2.3.* since 1.2.3.4 &gt; 1.2.3.0
	 * 
	 * @author sfoley
	 *
	 */
	public static class ValueComparator extends BaseComparator {
		private final boolean compareHighValue;
		
		public ValueComparator(boolean compareHighValue) {
			this.compareHighValue = compareHighValue;
		}

		protected int compareSegmentLowValues(AddressSegmentSeries one, AddressSegmentSeries two) {
			int segCount = one.getSegmentCount();
			for(int i = 0; i < segCount; i++) {
				AddressSegment segOne = one.getSegment(i);
				AddressSegment segTwo = two.getSegment(i);
				int oneValue = segOne.getLowerSegmentValue();
				int twoValue = segTwo.getLowerSegmentValue();
				int result = oneValue - twoValue;
				if(result != 0) {
					return result;
				}
			}
			return 0;
		}
		
		@Override
		protected int compareParts(AddressSection one, AddressSection two) {
			int sizeResult = one.getByteCount() - two.getByteCount();
			if(sizeResult != 0) {
				return sizeResult;
			}
			boolean compareHigh = compareHighValue;
			do {
				if(!compareHigh) {
					int result = compareSegmentLowValues(one, two);
					if(result != 0) {
						return result;
					}
				} else {
					int segCount = one.getSegmentCount();
					for(int i = 0; i < segCount; i++) {
						AddressSegment segOne = one.getSegment(i);
						AddressSegment segTwo = two.getSegment(i);
						int oneValue = segOne.getUpperSegmentValue();
						int twoValue = segTwo.getUpperSegmentValue();
						int result = oneValue - twoValue;
						if(result != 0) {
							return result;
						}
					}
				}
				compareHigh = !compareHigh;
			} while(compareHigh != compareHighValue);
			return 0;
		}
		
		@Override
		protected int compareParts(AddressDivisionSeries one, AddressDivisionSeries two) {
			int sizeResult = one.getBitCount() - two.getBitCount();
			if(sizeResult != 0) {
				return sizeResult;
			}
			boolean compareHigh = compareHighValue;
			do {
				int oneBitCount, twoBitCount, oneIndex, twoIndex;
				long oneValue, twoValue;
				AddressDivision oneCombo, twoCombo;
				oneValue = twoValue = oneBitCount = twoBitCount = oneIndex = twoIndex = 0;
				while(oneIndex < one.getDivisionCount() || twoIndex < two.getDivisionCount()) {
					if(oneBitCount == 0) {
						oneCombo = one.getDivision(oneIndex++);
						oneBitCount = oneCombo.getBitCount();
						oneValue = compareHigh ? oneCombo.getUpperValue() : oneCombo.getLowerValue();
					}
					if(twoBitCount == 0) {
						twoCombo = two.getDivision(twoIndex++);
						twoBitCount = twoCombo.getBitCount();
						twoValue = compareHigh ? twoCombo.getUpperValue() : twoCombo.getLowerValue();
					}
					long result;
					long oneResultValue = oneValue, twoResultValue = twoValue;
					if(twoBitCount == oneBitCount) {
						//no adjustment required, compare the values straight up
						oneBitCount = twoBitCount = 0;
					} else {
						int diffBits = twoBitCount - oneBitCount;
						if(diffBits > 0) {
							twoResultValue >>= diffBits;
							twoValue &= ~(~0L << diffBits);//difference in bytes must be less than 8 for this this shift to work per the java spec
							twoBitCount = diffBits;
							oneBitCount = 0;
						} else {
							diffBits = -diffBits;
							oneResultValue >>= diffBits;
							oneValue &= ~(~0L << diffBits); 
							oneBitCount = diffBits;
							twoBitCount = 0;
						}
					}
					result = oneResultValue - twoResultValue;
					if(result != 0) {
						return convertResult(result);
					}
				}
				compareHigh = !compareHigh;
			} while(compareHigh != compareHighValue);
			return 0;
		}
		
		@Override
		protected long compareValues(long oneUpper, long oneLower, long twoUpper, long twoLower) {
			long result;
			if(compareHighValue) {
				result = oneUpper - twoUpper;
				if(result == 0) {
					result = oneLower - twoLower;
				}
			} else {
				result = oneLower - twoLower;
				if(result == 0) {
					result = oneUpper - twoUpper;
				}
			}
			return result;
		}
		
		@Override
		protected int compareValues(int oneUpper, int oneLower, int twoUpper, int twoLower) {
			int result;
			if(compareHighValue) {
				result = oneUpper - twoUpper;
				if(result == 0) {
					result = oneLower - twoLower;
				}
			} else {
				result = oneLower - twoLower;
				if(result == 0) {
					result = oneUpper - twoUpper;
				}
			}
			return result;
		}
	}

	public static class CountComparator extends BaseComparator {
		
		private static int compareCount(AddressDivisionSeries one, AddressDivisionSeries two) {
			return one.isMore(two);
		}
		
		@Override
		protected int compareParts(AddressSection one, AddressSection two) {
			int result = one.getBitCount() - two.getBitCount();
			if(result == 0) {
				result = compareCount(one, two);
				if(result == 0) {
					result = compareEqualSizedSections(one, two);
				}
			}
			return result;
		}
		
		@Override
		protected int compareParts(AddressDivisionSeries one, AddressDivisionSeries two) {
			int result = one.getBitCount() - two.getBitCount();
			if(result == 0) {
				result = compareCount(one, two);
				if(result == 0) {
					result = compareSegmentGroupings(one, two);
				}
			}
			return result;
		}
		
		private int compareSegmentGroupings(AddressDivisionSeries one, AddressDivisionSeries two) {
			int oneBitCount, twoBitCount, oneIndex, twoIndex;
			long oneUpper, oneLower, twoUpper, twoLower;
			AddressDivision oneCombo, twoCombo;
			oneUpper = oneLower = twoUpper = twoLower = oneBitCount = twoBitCount = oneIndex = twoIndex = 0;
			while(oneIndex < one.getDivisionCount() || twoIndex < two.getDivisionCount()) {
				if(oneBitCount == 0) {
					oneCombo = one.getDivision(oneIndex++);
					oneBitCount = oneCombo.getBitCount();
					oneUpper = oneCombo.getUpperValue();
					oneLower = oneCombo.getLowerValue();
				}
				if(twoBitCount == 0) {
					twoCombo = two.getDivision(twoIndex++);
					twoBitCount = twoCombo.getBitCount();
					twoUpper = twoCombo.getUpperValue();
					twoLower = twoCombo.getLowerValue();
				}
				long oneResultUpper = oneUpper, oneResultLower = oneLower, twoResultUpper = twoUpper, twoResultLower = twoLower;
				if(twoBitCount == oneBitCount) {
					//no adjustment required, compare the values straight up
					oneBitCount = twoBitCount = 0;
				} else {
					int diffBits = twoBitCount - oneBitCount;
					if(diffBits > 0) {
						twoResultUpper >>= diffBits;
						twoResultLower >>= diffBits;
						long mask = ~(~0L << diffBits);
						twoUpper &= mask;
						twoLower &= mask;
						twoBitCount = diffBits;
						oneBitCount = 0;
					} else {
						diffBits = -diffBits;
						oneResultUpper >>= diffBits;
						oneResultLower >>= diffBits;
						long mask = ~(~0L << diffBits);
						oneUpper &= mask;
						oneLower &= mask;
						oneBitCount = diffBits;
						twoBitCount = 0;
					}
				}
				long result = compareValues(oneResultUpper, oneResultLower, twoResultUpper, twoResultLower);
				if(result != 0) {
					return convertResult(result);
				}
			}
			return 0;
		}
		
		protected int compareEqualSizedSections(AddressSection one, AddressSection two) {
			int segCount = one.getSegmentCount();
			for(int i = 0; i < segCount; i++) {
				AddressSegment segOne = one.getSegment(i);
				AddressSegment segTwo = two.getSegment(i);
				int oneUpper = segOne.getUpperSegmentValue();
				int twoUpper = segTwo.getUpperSegmentValue();
				int oneLower = segOne.getLowerSegmentValue();
				int twoLower = segTwo.getLowerSegmentValue();
				int result = compareValues(oneUpper, oneLower, twoUpper, twoLower);
				if(result != 0) {
					return result;
				}
			}
			return 0;
		}
		
		@Override
		protected int compareValues(int oneUpper, int oneLower, int twoUpper, int twoLower) {
			int result = (oneUpper - oneLower) - (twoUpper - twoLower);
			if(result == 0) {
				//the size of the range is the same, so just compare either upper or lower values
				result = oneLower - twoLower;
			}
			return result;
		}

		@Override
		protected long compareValues(long oneUpper, long oneLower, long twoUpper, long twoLower) {
			long result = (oneUpper - oneLower) - (twoUpper - twoLower);
			if(result == 0) {
				//the size of the range is the same, so just compare either upper or lower values
				result = oneLower - twoLower;
				
			} //else the size of the range is the same, so just compare either upper or lower values
			return result;
		}
	}
}

abstract class BaseComparator implements AddressComparator {
	@Override
	public int compare(Address one, Address two) {
		if(one == two) {
			return 0;
		}
		int result = compare(one.getSection(), two.getSection());
		if(result == 0 && one instanceof IPv6Address) {
			IPv6Address oneIPv6 = (IPv6Address) one;
			IPv6Address twoIPv6 = (IPv6Address) two;
			result = Objects.compare(oneIPv6.getZone(), twoIPv6.getZone(), Comparator.nullsFirst(String::compareTo));
		}
		return result;
	}
	
	private static int mapGroupingClass(Class<?> clazz) {
		if(IPv6AddressSection.class.isAssignableFrom(clazz)) {
			return 6;
		}
		if(IPv6v4MixedAddressSection.class.isAssignableFrom(clazz)) {
			return 5;
		}
		if(IPv4AddressSection.class.isAssignableFrom(clazz)) {
			return 4;
		}
		//other IP address groupings
		if(IPAddressDivisionGrouping.class.isAssignableFrom(clazz)) {
			return 3;
		}
		if(MACAddressSection.class.isAssignableFrom(clazz)) {
			return 3;
		}
		//other address groupings
		if(AddressDivisionGrouping.class.isAssignableFrom(clazz)) {
			return 1;
		}
		return 0;
	}
	
	private static int mapDivisionClass(Class<?> clazz) {
		if(clazz.equals(MACAddressSegment.class)) {
			return 1;
		}
		if(clazz.equals(IPv4JoinedSegments.class)) {
			return 2;
		}
		if(clazz.equals(IPv4AddressSegment.class)) {
			return 3;
		}
		if(clazz.equals(IPv6AddressSegment.class)) {
			return 4;
		}
		return 0;
	}
	
	public int compare(AddressSection one, AddressSection two) {
		if(one == two) {
			return 0;
		}
		Class<? extends AddressSection> oneClass = one.getClass();
		Class<? extends AddressSection> twoClass = two.getClass();
		if(!oneClass.equals(twoClass)) {
			int result = mapGroupingClass(oneClass) - mapGroupingClass(twoClass);
			if(result != 0) {
				return result;
			}
		}
		if(one instanceof IPv6AddressSection) {
			IPv6AddressSection o1 = (IPv6AddressSection) one;
			IPv6AddressSection o2 = (IPv6AddressSection) two;
			int result = o2.addressSegmentIndex - o1.addressSegmentIndex;
			if(result != 0) {
				return result;
			}
		} else if(one instanceof MACAddressSection) {
			MACAddressSection o1 = (MACAddressSection) one;
			MACAddressSection o2 = (MACAddressSection) two;
			int result = o2.addressSegmentIndex - o1.addressSegmentIndex;
			if(result != 0) {
				return result;
			}
		}
		return compareParts(one, two);
	}
	
	@Override
	public int compare(AddressDivisionSeries one, AddressDivisionSeries two) {
		if(one instanceof AddressSection && two instanceof AddressSection) {
			return compare((AddressSection) one, (AddressSection) two);
		}
		if(one instanceof Address && two instanceof Address) {
			return compare((Address) one, (Address) two);
		}
		if(one == two) {
			return 0;
		}
		Class<? extends AddressDivisionSeries> oneClass = one.getClass();
		Class<? extends AddressDivisionSeries> twoClass = two.getClass();
		if(!oneClass.equals(twoClass)) {
			return mapGroupingClass(oneClass) - mapGroupingClass(twoClass);
		}
		return compareParts(one, two);
	}
	
	public int compare(AddressSegment one, AddressSegment two) {
		if(one == two) {
			return 0;
		}
		Class<? extends AddressSegment> oneClass = one.getClass();
		Class<? extends AddressSegment> twoClass = two.getClass();
		if(!oneClass.equals(twoClass)) {
			return mapDivisionClass(oneClass) - mapDivisionClass(twoClass);
		}
		return compareValues(one.getUpperSegmentValue(), one.getLowerSegmentValue(), two.getUpperSegmentValue(), two.getLowerSegmentValue());
	}
	
	@Override
	public int compare(AddressDivision one, AddressDivision two) {
		if(one instanceof AddressSegment && two instanceof AddressSegment) {
			return compare((AddressSegment) one, (AddressSegment) two);
		}
		if(one == two) {
			return 0;
		}
		Class<? extends AddressDivision> oneClass = one.getClass();
		Class<? extends AddressDivision> twoClass = two.getClass();
		if(!oneClass.equals(twoClass)) {
			return mapDivisionClass(oneClass) - mapDivisionClass(twoClass);
		}
		if(one instanceof IPAddressJoinedSegments) {
			IPAddressJoinedSegments o1 = (IPAddressJoinedSegments) one;
			IPAddressJoinedSegments o2 = (IPAddressJoinedSegments) two;
			int result = o1.getJoinedCount() - o2.getJoinedCount();
			if(result != 0) {
				return result;
			}
		}
		return convertResult(compareValues(one.getUpperValue(), one.getLowerValue(), two.getUpperValue(), two.getLowerValue()));
	}
			
	protected abstract int compareParts(AddressDivisionSeries one, AddressDivisionSeries two);
	
	protected abstract int compareParts(AddressSection one, AddressSection two);
	
	protected abstract long compareValues(long oneUpper, long oneLower, long twoUpper, long twoLower);
	
	protected abstract int compareValues(int oneUpper, int oneLower, int twoUpper, int twoLower);
	
	static int convertResult(long v) {
		return v == 0 ? 0 : (v > 0 ? 1 : -1);
		//return (v >> 32) | (v & 0x7fffffff);
	}
}
