package inet.ipaddr;

import java.math.BigInteger;
import java.util.Comparator;

import inet.ipaddr.format.IPAddressDivision;
import inet.ipaddr.format.IPAddressJoinedSegments;
import inet.ipaddr.format.IPAddressSegmentGrouping;
import inet.ipaddr.format.validate.HostIdentifierStringValidator;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv4.IPv4JoinedSegments;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSegment;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6v4MixedAddressSection;

/**
 * 
 * @author sfoley
 *
 */
public interface IPAddressComparator extends Comparator<IPAddress> {

	int compare(IPAddressSegmentGrouping one, IPAddressSegmentGrouping two);
	
	int compare(IPAddressDivision one, IPAddressDivision two);
	
	
	
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

		@Override
		protected int compareParts(IPAddressSegmentGrouping one, IPAddressSegmentGrouping two) {
			int sizeResult = one.getByteCount() - two.getByteCount();
			if(sizeResult != 0) {
				return sizeResult;
			}
			boolean compareHigh = compareHighValue;
			do {
				int oneByteCount, twoByteCount, oneIndex, twoIndex;
				long oneValue, twoValue;
				IPAddressDivision oneCombo, twoCombo;
				oneValue = twoValue = oneByteCount = twoByteCount = oneIndex = twoIndex = 0;
				while(oneIndex < one.getDivisionCount() || twoIndex < two.getDivisionCount()) {
					if(oneByteCount == 0) {
						oneCombo = one.getDivision(oneIndex++);
						oneByteCount = oneCombo.getByteCount();
						oneValue = compareHigh ? oneCombo.getUpperValue() : oneCombo.getLowerValue();
					}
					if(twoByteCount == 0) {
						twoCombo = two.getDivision(twoIndex++);
						twoByteCount = twoCombo.getByteCount();
						twoValue = compareHigh ? twoCombo.getUpperValue() : twoCombo.getLowerValue();
					}
					long result;
					long oneResultValue = oneValue, twoResultValue = twoValue;
					if(twoByteCount == oneByteCount) {
						//no adjustment required, compare the values straight up
						oneByteCount = twoByteCount = 0;
					} else {
						int diffBytes = twoByteCount - oneByteCount;
						if(diffBytes > 0) {
							int diffBits = diffBytes << 3;
							twoResultValue >>= diffBits;
							twoValue &= ~(~0L << diffBits);//diffBytes must be less than 8 for this this shift to work per the java spec
							twoByteCount = diffBytes;
							oneByteCount = 0;
						} else {
							diffBytes = -diffBytes;
							int diffBits = diffBytes << 3;
							oneResultValue >>= diffBits;
							oneValue &= ~(~0L << diffBits); 
							oneByteCount = diffBytes;
							twoByteCount = 0;
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
	}
	
	
	public static class CountComparator extends BaseComparator {
		
		@Override
		protected int compareParts(IPAddressSegmentGrouping one, IPAddressSegmentGrouping two) {
			int result = one.getByteCount() - two.getByteCount();
			if(result == 0) {
				//check which one represents more addresses
				if(one.isMultiple()) {
					if(two.isMultiple()) {
						if(one.isRangeEquivalentToPrefix() && two.isRangeEquivalentToPrefix()) {
							result = compareCountByPrefix(one.getNetworkPrefixLength(), two.getNetworkPrefixLength());
						} else {
							BigInteger oneCount = one.getCount();
							BigInteger otherCount = two.getCount();
							result = oneCount.subtract(otherCount).signum();
						}
						if(result == 0) {
							//both represent the same address space and the same number of addresses, so we compare by value
							result = compareSegmentGroupings(one, two);
						}
					} else {
						result = 1;
					}
				} else if(two.isMultiple()) {
					result = -1;
				} else {
					result = compareSegmentGroupings(one, two);
				}
			}
			return result;
		}
		
		private static int compareCountByPrefix(Integer thisBits, Integer otherBits) {
			if(thisBits == null) {
				thisBits = HostIdentifierStringValidator.MAX_PREFIX;
			}
			if(otherBits == null) {
				otherBits = HostIdentifierStringValidator.MAX_PREFIX;
			}
			return otherBits - thisBits;//matches compareByCount
		}
		
		private int compareSegmentGroupings(IPAddressSegmentGrouping one, IPAddressSegmentGrouping two) {
			int oneByteCount, twoByteCount, oneIndex, twoIndex;
			long oneUpper, oneLower, twoUpper, twoLower;
			IPAddressDivision oneCombo, twoCombo;
			oneUpper = oneLower = twoUpper = twoLower = oneByteCount = twoByteCount = oneIndex = twoIndex = 0;
			while(oneIndex < one.getDivisionCount() || twoIndex < two.getDivisionCount()) {
				if(oneByteCount == 0) {
					oneCombo = one.getDivision(oneIndex++);
					oneByteCount = oneCombo.getByteCount();
					oneUpper = oneCombo.getUpperValue();
					oneLower = oneCombo.getLowerValue();
				}
				if(twoByteCount == 0) {
					twoCombo = two.getDivision(twoIndex++);
					twoByteCount = twoCombo.getByteCount();
					twoUpper = twoCombo.getUpperValue();
					twoLower = twoCombo.getLowerValue();
				}
				long oneResultUpper = oneUpper, oneResultLower = oneLower, twoResultUpper = twoUpper, twoResultLower = twoLower;
				if(twoByteCount == oneByteCount) {
					//no adjustment required, compare the values straight up
					oneByteCount = twoByteCount = 0;
				} else {
					int diffBytes = twoByteCount - oneByteCount;
					if(diffBytes > 0) {
						int diffBits = diffBytes << 3;
						twoResultUpper >>= diffBits;
						twoResultLower >>= diffBits;
						long mask = ~(~0L << diffBits);
						twoUpper &= mask;
						twoLower &= mask;
						twoByteCount = diffBytes;
						oneByteCount = 0;
					} else {
						diffBytes = -diffBytes;
						int diffBits = diffBytes << 3;
						oneResultUpper >>= diffBits;
						oneResultLower >>= diffBits;
						long mask = ~(~0L << diffBits);
						oneUpper &= mask;
						oneLower &= mask;
						oneByteCount = diffBytes;
						twoByteCount = 0;
					}
				}
				long result = compareValues(oneResultUpper, oneResultLower, twoResultUpper, twoResultLower);
				if(result != 0) {
					return convertResult(result);
				}
			}
			return 0;
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

abstract class BaseComparator implements IPAddressComparator {
	@Override
	public int compare(IPAddress one, IPAddress two) {
		if(one == two) {
			return 0;
		}
		if(!one.getIPVersion().equals(two.getIPVersion())) {
			return one.getIPVersion().ordinal() - two.getIPVersion().ordinal();
		}
		int result = compare(one.getSection(), two.getSection());
		if(result == 0) {
			if(one.isIPv6()) {
				IPv6Address oneIPv6 = (IPv6Address) one;
				IPv6Address twoIPv6 = (IPv6Address) two;
				result = oneIPv6.getZone().compareTo(twoIPv6.getZone());
			}
		}
		return result;
	}
	
	private static int mapGroupingClass(Class<? extends IPAddressSegmentGrouping> clazz) {
		if(clazz.equals(IPAddressSegmentGrouping.class)) {
			return 1;
		}
		if(clazz.equals(IPv4AddressSection.class)) {
			return 2;
		}
		if(clazz.equals(IPv6v4MixedAddressSection.class)) {
			return 3;
		}
		if(clazz.equals(IPv6AddressSection.class)) {
			return 4;
		}
		return 0;
	}
	
	private static int mapDivisionClass(Class<? extends IPAddressDivision> clazz) {
		if(clazz.equals(IPv4JoinedSegments.class)) {
			return 1;
		}
		if(clazz.equals(IPv4AddressSegment.class)) {
			return 2;
		}
		if(clazz.equals(IPv6AddressSegment.class)) {
			return 3;
		}
		return 0;
	}
	
	@Override
	public int compare(IPAddressSegmentGrouping one, IPAddressSegmentGrouping two) {
		if(one == two) {
			return 0;
		}
		Class<? extends IPAddressSegmentGrouping> oneClass = one.getClass();
		Class<? extends IPAddressSegmentGrouping> twoClass = two.getClass();
		if(!oneClass.equals(twoClass)) {
			return mapGroupingClass(oneClass) - mapGroupingClass(twoClass);
		}
		if(one instanceof IPv6AddressSection) {
			IPv6AddressSection o1 = (IPv6AddressSection) one;
			IPv6AddressSection o2 = (IPv6AddressSection) two;
			int result = o2.startIndex - o1.startIndex;
			if(result != 0) {
				return result;
			}
		}
		return compareParts(one, two);
	}
	
	@Override
	public int compare(IPAddressDivision one, IPAddressDivision two) {
		if(one == two) {
			return 0;
		}
		Class<? extends IPAddressDivision> oneClass = one.getClass();
		Class<? extends IPAddressDivision> twoClass = two.getClass();
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
			
	protected abstract int compareParts(IPAddressSegmentGrouping one, IPAddressSegmentGrouping two);
	
	protected abstract long compareValues(long oneUpper, long oneLower, long twoUpper, long twoLower);
	
	static int convertResult(long v) {
		return v == 0 ? 0 : (v > 0 ? 1 : -1);
		//return (v >> 32) | (v & 0x7fffffff);
	}
}
