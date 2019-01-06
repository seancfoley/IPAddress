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

package inet.ipaddr;

import java.math.BigInteger;
import java.util.Comparator;
import java.util.Objects;

import inet.ipaddr.format.AddressDivisionSeries;
import inet.ipaddr.format.AddressGenericDivision;
import inet.ipaddr.format.AddressItem;
import inet.ipaddr.format.large.IPAddressLargeDivision;
import inet.ipaddr.format.large.IPAddressLargeDivisionGrouping;
import inet.ipaddr.format.standard.AddressBitsDivision;
import inet.ipaddr.format.standard.AddressDivision;
import inet.ipaddr.format.standard.AddressDivisionGrouping;
import inet.ipaddr.format.standard.IPAddressBitsDivision;
import inet.ipaddr.format.standard.IPAddressDivisionGrouping;
import inet.ipaddr.ipv4.IPv4AddressSection;
import inet.ipaddr.ipv4.IPv4AddressSegment;
import inet.ipaddr.ipv4.IPv4JoinedSegments;
import inet.ipaddr.ipv4.IPv4AddressSeqRange;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressSection;
import inet.ipaddr.ipv6.IPv6AddressSection.IPv6v4MixedAddressSection;
import inet.ipaddr.ipv6.IPv6AddressSegment;
import inet.ipaddr.ipv6.IPv6AddressSeqRange;
import inet.ipaddr.mac.MACAddressSection;
import inet.ipaddr.mac.MACAddressSegment;

/**
 * 
 * @author sfoley
 *
 */
public abstract class AddressComparator implements Comparator<AddressItem> {
	
	protected final boolean equalsConsistent;
	
	/**
	 * @param equalsConsistent when true, those with different types, versions, bit counts, and other identifying characteristics, those cannot have comparison of zero, consistent with equals in the various classes (ranges, divisions, groupings, addresses)
	 * 	Otherwise, objects with similar structure and values can have comparison of zero
	 */
	AddressComparator(boolean equalsConsistent) {
		this.equalsConsistent = equalsConsistent;
	}
	
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
	
	private static int mapGrouping(AddressDivisionSeries series) {
		if(series instanceof IPv6AddressSection) {
			return 6;
		} else if(series instanceof IPv6v4MixedAddressSection) {
			return 5;
		} else if(series instanceof IPv4AddressSection) {
			return 4;
		} else if(series instanceof MACAddressSection) {
			return 3;
		} else if(series instanceof IPAddressDivisionGrouping) {
			return -1;
		} else if(series instanceof IPAddressLargeDivisionGrouping) {
			return -2;
		} else if(series instanceof AddressDivisionGrouping) {
			return -3;
		}
		return 0;
	}
	
	private static int mapDivision(AddressGenericDivision div) {
		if(div instanceof MACAddressSegment) {
			return 1;
		} else if(div instanceof IPv4JoinedSegments) {
			return 2;
		} else if(div instanceof IPv4AddressSegment) {
			return 3;
		} else if(div instanceof IPv6AddressSegment) {
			return 4;
		} else if(div instanceof IPAddressLargeDivision) {
			return -1;
		} else if(div instanceof IPAddressBitsDivision) {
			return -2;
		} else if(div instanceof AddressBitsDivision) {
			return -3;
		}
		return 0;
	}
	
	private static int mapRange(IPAddressSeqRange range) {
		if(range instanceof IPv4AddressSeqRange) {
			return 1;
		} else if(range instanceof IPv6AddressSeqRange) {
			return 2;
		} 
		return 0;
	}
	
	public int compare(AddressSection one, AddressSection two) {
		if(one == two) {
			return 0;
		}
		if(!one.getClass().equals(two.getClass())) {
			int result = mapGrouping(one) - mapGrouping(two);
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
	public int compare(AddressItem one, AddressItem two) {
		if(one instanceof AddressDivisionSeries) {
			if(two instanceof AddressDivisionSeries) {
				return compare((AddressDivisionSeries) one, (AddressDivisionSeries) two);
			} else if (equalsConsistent) {
				return 1;
			} else if(one.isMultiple()) {
				AddressDivisionSeries oneSeries = (AddressDivisionSeries) one;
				if(oneSeries.getDivisionCount() > 0) {
					return 1;
				}
				one = oneSeries.getDivision(0);
			}
		}
		if(one instanceof AddressGenericDivision) {
			if(two instanceof AddressGenericDivision) {
				return compare((AddressGenericDivision) one, (AddressGenericDivision) two);
			} else if (equalsConsistent) {
				return -1;
			}
		} else if(one instanceof IPAddressSeqRange) {
			if(two instanceof IPAddressSeqRange) {
				return compare((IPAddressSeqRange) one, (IPAddressSeqRange) two);
			} else if (equalsConsistent) {
				if(two instanceof AddressDivisionSeries) {
					return -1;
				} 
				return 1;
			}
		}
		if(one == two) {
			return 0;
		}
		if(equalsConsistent) {
			int bitDiff = one.getBitCount() - two.getBitCount();
			if(bitDiff != 0) {
				return bitDiff;
			}
		}
		if(two instanceof AddressDivisionSeries) {
			//if a series of multiple values over multiple divisions, ranges are not comparable
			AddressDivisionSeries twoSeries = (AddressDivisionSeries) two;
			if(two.isMultiple()) {
				if(twoSeries.getDivisionCount() > 0) {
					return 1;
				}
			}
			if(one instanceof AddressGenericDivision) {
				return compare((AddressGenericDivision) one, twoSeries.getDivision(0));
			}
			two = twoSeries.getDivision(0);
		}
		return compareValues(one.getUpperValue(), one.getValue(), two.getUpperValue(), two.getValue());
	}
	
	public int compare(AddressDivisionSeries one, AddressDivisionSeries two) {
		if(one instanceof Address) {
			if(two instanceof Address) {
				return compare((Address) one, (Address) two);
			} else {
				if(equalsConsistent) {
					return -1;
				}
				one = ((Address) one).getSection();
			}
		} else if(two instanceof Address) {
			if(equalsConsistent) {
				return 1;
			}
			two = ((Address) two).getSection();
		}
		if(one instanceof AddressSection && two instanceof AddressSection) {
			return compare((AddressSection) one, (AddressSection) two);
		}
		if(one == two) {
			return 0;
		}
		if(!one.getClass().equals(two.getClass())) {
			int result = mapGrouping(one) - mapGrouping(two);
			if(result != 0) {
				return result;
			}
		}
		return compareParts(one, two);
	}
	
	protected static int compareDivBitCounts(AddressDivisionSeries oneSeries, AddressDivisionSeries twoSeries) {
		//when this is called we knwo the two series have the same bit-size, we want to check that the divisions
		//also have the same bit size (which of course also implies that there are the same number of divisions)
		int count = oneSeries.getDivisionCount();
		int result = count - twoSeries.getDivisionCount();
		if(result == 0) {
			for(int i = 0; i < count; i++) {
				result = oneSeries.getDivision(i).getBitCount() - twoSeries.getDivision(i).getBitCount();
				if(result != 0) {
					break;
				}
			}
		}
		return result;
	}
	
	public int compare(AddressSegment one, AddressSegment two) {
		if(one == two) {
			return 0;
		}
		if(!one.getClass().equals(two.getClass())) {
			int result = mapDivision(one) - mapDivision(two);
			if(result != 0) {
				return result;
			}
		}
		return compareValues(one.getUpperSegmentValue(), one.getSegmentValue(), two.getUpperSegmentValue(), two.getSegmentValue());
	}
	
	public int compare(IPAddressSeqRange one, IPAddressSeqRange two) {
		if(one == two) {
			return 0;
		}
		if(!one.getClass().equals(two.getClass())) {
			int result = mapRange(one) - mapRange(two);
			if(result != 0) {
				return result;
			}
		}
		if(one instanceof IPv4AddressSeqRange && two instanceof IPv4AddressSeqRange) {
			IPv4AddressSeqRange gOne = (IPv4AddressSeqRange) one;
			IPv4AddressSeqRange gTwo = (IPv4AddressSeqRange) two;
			return compareValues(gOne.getUpper().longValue(), gOne.getLower().longValue(), gTwo.getUpper().longValue(), gTwo.getLower().longValue());
		}
		return compareValues(one.getUpperValue(), one.getValue(), two.getUpperValue(), two.getValue());
	}
	
	public int compare(AddressGenericDivision one, AddressGenericDivision two) {
		if(one instanceof AddressSegment && two instanceof AddressSegment) {
			return compare((AddressSegment) one, (AddressSegment) two);
		}
		if(one == two) {
			return 0;
		}
		if(!one.getClass().equals(two.getClass())) {
			int result = mapDivision(one) - mapDivision(two);
			if(result != 0) {
				return result;
			}
		}
		if(equalsConsistent) {
			int bitDiff = one.getBitCount() - two.getBitCount();
			if(bitDiff != 0) {
				return bitDiff;
			}
		}
		if(one instanceof AddressDivision && two instanceof AddressDivision) {
			AddressDivision gOne = (AddressDivision) one;
			AddressDivision gTwo = (AddressDivision) two;
			return compareValues(gOne.getUpperDivisionValue(), gOne.getDivisionValue(), gTwo.getUpperDivisionValue(), gTwo.getDivisionValue());
		}
		return compareValues(one.getUpperValue(), one.getValue(), two.getUpperValue(), two.getValue());
	}
			
	protected abstract int compareParts(AddressDivisionSeries one, AddressDivisionSeries two);
	
	protected abstract int compareParts(AddressSection one, AddressSection two);
	
	protected abstract int compareValues(BigInteger oneUpper, BigInteger oneLower, BigInteger twoUpper, BigInteger twoLower);
	
	protected abstract int compareValues(long oneUpper, long oneLower, long twoUpper, long twoLower);
	
	protected abstract int compareValues(int oneUpper, int oneLower, int twoUpper, int twoLower);
	
	static int convertResult(long v) {
		return v == 0 ? 0 : (v > 0 ? 1 : -1);
		//return (v >> 32) | (v & 0x7fffffff);
	}
	
	/**
	 * ValueComparator is similar to the default comparator CountComparator in the way they treat addresses representing a single address.
	 * <p>
	 * For individual addresses, it simply compares segment to segment from high to low, so 1.2.3.4 &lt; 1.2.3.5 and 2.2.3.4 &gt; 1.2.3.5.
	 * <p>
	 * The difference is how they treat addresses representing multiple addresses (ie subnets) like 1::/64 or 1.*.*.*
	 * <p>
	 * The count comparator considers addresses which represent more individual addresses to be larger.
	 * <p>
	 * The value comparator goes by either the highest value or the lowest value in the range of represented addresses.
	 * <p>
	 * So, for instance, consider 1.2.3.4 and 1.0.0.*
	 * <br>
	 * With count comparator, 1.2.3.4 &lt; 1.2.3.* since the second represents more addresses (ie 1 &lt; 255)
	 * <br>
	 * With value comparator using the high value, 1.2.3.4 &lt; 1.2.3.* since 1.2.3.4 &lt; 1.2.3.255
	 * <br>
	 * With value comparator using the low value, 1.2.3.4 &gt; 1.2.3.* since 1.2.3.4 &gt; 1.2.3.0
	 * 
	 * Also see {@link CountComparator}
	 * 
	 * @author sfoley
	 *
	 */
	public static class ValueComparator extends AddressComparator {
		private final boolean compareHighValue;
		
		public ValueComparator(boolean compareHighValue) {
			this(true, compareHighValue);
		}
		
		public ValueComparator(boolean equalsConsistent, boolean compareHighValue) {
			super(equalsConsistent);
			this.compareHighValue = compareHighValue;
		}
		
		@Override
		protected int compareParts(AddressSection one, AddressSection two) {
			int sizeResult = one.getByteCount() - two.getByteCount();
			if(sizeResult != 0) {
				return sizeResult;
			}
			boolean compareHigh = compareHighValue;
			do {
				int segCount = one.getSegmentCount();
				for(int i = 0; i < segCount; i++) {
					AddressSegment segOne = one.getSegment(i);
					AddressSegment segTwo = two.getSegment(i);
					int result = compareHigh ? 
							(segOne.getUpperSegmentValue() - segTwo.getUpperSegmentValue()) : 
								(segOne.getSegmentValue() - segTwo.getSegmentValue());
					if(result != 0) {
						return result;
					}
				}
				compareHigh = !compareHigh;
			} while(compareHigh != compareHighValue);
			return 0;
		}
		
		@Override
		protected int compareParts(AddressDivisionSeries oneSeries, AddressDivisionSeries twoSeries) {
			int sizeResult = oneSeries.getBitCount() - twoSeries.getBitCount();
			if(sizeResult != 0) {
				return sizeResult;
			}
			if(equalsConsistent || oneSeries.isMultiple() || twoSeries.isMultiple()) {
				int result = compareDivBitCounts(oneSeries, twoSeries);
				if(result != 0) {
					return result;
				}
			}
			boolean compareHigh = compareHighValue;
			AddressDivisionGrouping one, two;
			if(oneSeries instanceof AddressDivisionGrouping && twoSeries instanceof AddressDivisionGrouping) {
				one = (AddressDivisionGrouping) oneSeries;
				 two = (AddressDivisionGrouping) twoSeries;
			} else {
				one = two = null;
			}
			do {
				int oneSeriesByteCount = oneSeries.getByteCount(), twoSeriesByteCount = twoSeries.getByteCount();
				byte oneBytes[] = new byte[oneSeriesByteCount], twoBytes[] = new byte[twoSeriesByteCount];
				int oneTotalBitCount, twoTotalBitCount, oneByteCount, twoByteCount, oneByteIndex, twoByteIndex;
				oneByteIndex = twoByteIndex = oneByteCount = twoByteCount = oneTotalBitCount = twoTotalBitCount = 0;
				
				int oneBitCount, twoBitCount, oneIndex, twoIndex;
				oneBitCount = twoBitCount = oneIndex = twoIndex = 0;
				long oneValue, twoValue;
				oneValue = twoValue = 0;
				while(oneIndex < oneSeries.getDivisionCount() || twoIndex < twoSeries.getDivisionCount()) {
					if(one != null) {
						if(oneBitCount == 0) {
							AddressDivision oneCombo = one.getDivision(oneIndex++);
							oneBitCount = oneCombo.getBitCount();
							oneValue = compareHigh ? oneCombo.getUpperDivisionValue() : oneCombo.getDivisionValue();
						}
						if(twoBitCount == 0) {
							AddressDivision twoCombo = two.getDivision(twoIndex++);
							twoBitCount = twoCombo.getBitCount();
							twoValue = compareHigh ? twoCombo.getUpperDivisionValue() : twoCombo.getDivisionValue();
						}
					} else {
						if(oneBitCount == 0) {
							if(oneByteCount == 0) {
								AddressGenericDivision oneCombo = oneSeries.getDivision(oneIndex++);
								oneBytes = compareHigh ? oneCombo.getUpperBytes(oneBytes) : oneCombo.getBytes(oneBytes);
								oneTotalBitCount = oneCombo.getBitCount();
								oneByteCount = oneCombo.getByteCount();
								oneByteIndex = 0;
							}
							//put some or all of the bytes into a long
							int count = Long.BYTES - 1;
							oneValue = 0;
							if(count < oneByteCount) {
								oneBitCount = count << 3;
								oneTotalBitCount -= oneBitCount;
								oneByteCount -= count;
								while(count-- > 0) {
									oneValue = (oneValue << Byte.SIZE) | oneBytes[++oneByteIndex];
								}
							} else {
								int shortCount = oneByteCount - 1;
								int lastBitsCount = oneTotalBitCount - (shortCount << 3);
								while(shortCount-- > 0) {
									oneValue = (oneValue << Byte.SIZE) | oneBytes[++oneByteIndex];
								}
								oneValue = (oneValue << lastBitsCount) | (oneBytes[++oneByteIndex] >>> (Byte.SIZE - lastBitsCount));
								oneBitCount = oneTotalBitCount;
								oneTotalBitCount = oneByteCount = 0;
							}
						}
						if(twoBitCount == 0) {
							if(twoByteCount == 0) {
								AddressGenericDivision twoCombo = twoSeries.getDivision(twoIndex++);
								twoBytes = compareHigh ? twoCombo.getUpperBytes(twoBytes) : twoCombo.getBytes(twoBytes);
								twoTotalBitCount = twoCombo.getBitCount();
								twoByteCount = twoCombo.getByteCount();
								twoByteIndex = 0;
							}
							//put some or all of the bytes into a long
							int count = Long.BYTES - 1;
							twoValue = 0;
							if(count < twoByteCount) {
								twoBitCount = count << 3;
								twoTotalBitCount -= twoBitCount;
								twoByteCount -= count;
								while(count-- > 0) {
									twoValue = (twoValue << Byte.SIZE) | oneBytes[++twoByteIndex];
								}
							} else {
								int shortCount = twoByteCount - 1;
								int lastBitsCount = twoTotalBitCount - (shortCount << 3);
								while(shortCount-- > 0) {
									twoValue = (twoValue << Byte.SIZE) | oneBytes[++twoByteIndex];
								}
								twoValue = (twoValue << lastBitsCount) | (oneBytes[++twoByteIndex] >>> (Byte.SIZE - lastBitsCount));
								twoBitCount = twoTotalBitCount;
								twoTotalBitCount = twoByteCount = 0;
							}
						}
					}
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
					long result = oneResultValue - twoResultValue;
					if(result != 0) {
						return convertResult(result);
					}
				}
				compareHigh = !compareHigh;
			} while(compareHigh != compareHighValue);
			return 0;
		}
		
		@Override
		protected int compareValues(BigInteger oneUpper, BigInteger oneLower, BigInteger twoUpper, BigInteger twoLower) {
			int result;
			if(compareHighValue) {
				result = oneUpper.compareTo(twoUpper);
				if(result == 0) {
					result = oneLower.compareTo(twoLower);
				}
			} else {
				result = oneLower.compareTo(twoLower);
				if(result == 0) {
					result = oneUpper.compareTo(twoUpper);
				}
			}
			return convertResult(result);
		}
		
		@Override
		protected int compareValues(long oneUpper, long oneLower, long twoUpper, long twoLower) {
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
			return convertResult(result);
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

	/**
	 * CountComparator first compares two address items by count, first by bit count for dissimilar items, {@link AddressItem#getBitCount()}, then by count of values for similar items, ({@link AddressItem#getCount()}) and if both match,
	 * defers to the address item values for comparison.
	 * 
	 * Also see {@link ValueComparator}
	 * 
	 * @author sfoley
	 *
	 */
	public static class CountComparator extends AddressComparator {
		
		public CountComparator() {
			this(true);
		}
		
		public CountComparator(boolean equalsConsistent) {
			super(equalsConsistent);
		}
		
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
		
		private int compareSegmentGroupings(AddressDivisionSeries oneSeries, AddressDivisionSeries twoSeries) {
			AddressDivisionGrouping one, two;
			if(oneSeries instanceof AddressDivisionGrouping && twoSeries instanceof AddressDivisionGrouping) {
				one = (AddressDivisionGrouping) oneSeries;
				two = (AddressDivisionGrouping) twoSeries;
			} else {
				one = two = null;
			}
			if(equalsConsistent || oneSeries.isMultiple() || twoSeries.isMultiple()) {
				int result = compareDivBitCounts(oneSeries, twoSeries);
				if(result != 0) {
					return result;
				}
			}
			int oneSeriesByteCount = oneSeries.getByteCount(), twoSeriesByteCount = twoSeries.getByteCount();
			byte oneUpperBytes[] = new byte[oneSeriesByteCount], oneLowerBytes[] = new byte[oneSeriesByteCount], 
					twoUpperBytes[] = new byte[twoSeriesByteCount], twoLowerBytes[] = new byte[twoSeriesByteCount];
			int oneTotalBitCount, twoTotalBitCount, oneByteCount, twoByteCount, oneByteIndex, twoByteIndex;
			oneByteIndex = twoByteIndex = oneByteCount = twoByteCount = oneTotalBitCount = twoTotalBitCount = 0;
			
			int oneBitCount, twoBitCount, oneIndex, twoIndex;
			oneBitCount = twoBitCount = oneIndex = twoIndex = 0;
			long oneUpper, oneLower, twoUpper, twoLower;
			oneUpper = oneLower = twoUpper = twoLower = 0;
			while(oneIndex < oneSeries.getDivisionCount() || twoIndex < twoSeries.getDivisionCount()) {
				if(one != null) {
					if(oneBitCount == 0) {
						AddressDivision oneCombo = one.getDivision(oneIndex++);
						oneBitCount = oneCombo.getBitCount();
						oneUpper = oneCombo.getUpperDivisionValue();
						oneLower = oneCombo.getDivisionValue();
					}
					if(twoBitCount == 0) {
						AddressDivision twoCombo = two.getDivision(twoIndex++);
						twoBitCount = twoCombo.getBitCount();
						twoUpper = twoCombo.getUpperDivisionValue();
						twoLower = twoCombo.getDivisionValue();
					}
				} else {
					if(oneBitCount == 0) {
						if(oneByteCount == 0) {
							AddressGenericDivision oneCombo = oneSeries.getDivision(oneIndex++);
							oneUpperBytes = oneCombo.getUpperBytes(oneUpperBytes);
							oneLowerBytes = oneCombo.getBytes(oneLowerBytes);
							oneTotalBitCount = oneCombo.getBitCount();
							oneByteCount = oneCombo.getByteCount();
							oneByteIndex = 0;
						}
						
						//put some or all of the bytes into a long
						int count = Long.BYTES - 1;
						oneUpper = oneLower = 0;
						if(count < oneByteCount) {
							oneBitCount = count << 3;
							oneTotalBitCount -= oneBitCount;
							oneByteCount -= count;
							while(count-- > 0) {
								byte upperByte = oneUpperBytes[++oneByteIndex];
								byte lowerByte = oneLowerBytes[oneByteIndex];
								oneUpper = (oneUpper << Byte.SIZE) | upperByte;
								oneLower = (oneLower << Byte.SIZE) | lowerByte;
							}
						} else {
							int shortCount = oneByteCount - 1;
							int lastBitsCount = oneTotalBitCount - (shortCount << 3);
							while(shortCount-- > 0) {
								byte upperByte = oneUpperBytes[++oneByteIndex];
								byte lowerByte = oneLowerBytes[oneByteIndex];
								oneUpper = (oneUpper << Byte.SIZE) | upperByte;
								oneLower = (oneLower << Byte.SIZE) | lowerByte;
							}
							byte upperByte = oneUpperBytes[++oneByteIndex];
							byte lowerByte = oneLowerBytes[oneByteIndex];
							oneUpper = (oneUpper << lastBitsCount) | (upperByte>>> (Byte.SIZE - lastBitsCount));
							oneLower = (oneLower << lastBitsCount) | (lowerByte >>> (Byte.SIZE - lastBitsCount));
							oneBitCount = oneTotalBitCount;
							oneTotalBitCount = oneByteCount = 0;
						}
					}
					if(twoBitCount == 0) {
						if(twoByteCount == 0) {
							AddressGenericDivision twoCombo = twoSeries.getDivision(twoIndex++);
							twoUpperBytes = twoCombo.getUpperBytes(twoUpperBytes);
							twoLowerBytes = twoCombo.getBytes(twoLowerBytes);
							twoTotalBitCount = twoCombo.getBitCount();
							twoByteCount = twoCombo.getByteCount();
							twoByteIndex = 0;
						}
						
						//put some or all of the bytes into a long
						int count = Long.BYTES - 1;
						twoUpper = twoLower = 0;
						if(count < twoByteCount) {
							twoBitCount = count << 3;
							twoTotalBitCount -= twoBitCount;
							twoByteCount -= count;
							while(count-- > 0) {
								byte upperByte = twoUpperBytes[++twoByteIndex];
								byte lowerByte = twoLowerBytes[twoByteIndex];
								twoUpper = (twoUpper << Byte.SIZE) | upperByte;
								twoLower = (twoLower << Byte.SIZE) | lowerByte;
							}
						} else {
							int shortCount = twoByteCount - 1;
							int lastBitsCount = twoTotalBitCount - (shortCount << 3);
							while(shortCount-- > 0) {
								byte upperByte = twoUpperBytes[++twoByteIndex];
								byte lowerByte = twoLowerBytes[twoByteIndex];
								twoUpper = (twoUpper << Byte.SIZE) | upperByte;
								twoLower = (twoLower << Byte.SIZE) | lowerByte;
							}
							byte upperByte = twoUpperBytes[++twoByteIndex];
							byte lowerByte = twoLowerBytes[twoByteIndex];
							twoUpper = (twoUpper << lastBitsCount) | (upperByte>>> (Byte.SIZE - lastBitsCount));
							twoLower = (twoLower << lastBitsCount) | (lowerByte >>> (Byte.SIZE - lastBitsCount));
							twoBitCount = twoTotalBitCount;
							twoTotalBitCount = twoByteCount = 0;
						}
					}
				}
				
				long oneResultUpper = oneUpper, oneResultLower = oneLower, twoResultUpper = twoUpper, twoResultLower = twoLower;
				if(twoBitCount == oneBitCount) {
					//no adjustment required, compare the values straight up
					oneBitCount = twoBitCount = 0;
				} else {
					int diffBits = twoBitCount - oneBitCount;
					if(diffBits > 0) {
						twoResultUpper >>>= diffBits;//look at the high bits only (we are comparing left to right, high to low)
						twoResultLower >>>= diffBits;
						long mask = ~(~0L << diffBits);
						twoUpper &= mask;
						twoLower &= mask;
						twoBitCount = diffBits;
						oneBitCount = 0;
					} else {
						diffBits = -diffBits;
						oneResultUpper >>>= diffBits;
						oneResultLower >>>= diffBits;
						long mask = ~(~0L << diffBits);
						oneUpper &= mask;
						oneLower &= mask;
						oneBitCount = diffBits;
						twoBitCount = 0;
					}
				}
				int result = compareValues(oneResultUpper, oneResultLower, twoResultUpper, twoResultLower);
				if(result != 0) {
					return result;
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
				int oneLower = segOne.getSegmentValue();
				int twoLower = segTwo.getSegmentValue();
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
		protected int compareValues(long oneUpper, long oneLower, long twoUpper, long twoLower) {
			long result = (oneUpper - oneLower) - (twoUpper - twoLower);
			if(result == 0) {
				//the size of the range is the same, so just compare either upper or lower values
				result = oneLower - twoLower;
				
			} //else the size of the range is the same, so just compare either upper or lower values
			return convertResult(result);
		}
		
		@Override
		protected int compareValues(BigInteger oneUpper, BigInteger oneLower, BigInteger twoUpper, BigInteger twoLower) {
			BigInteger oneCount = oneUpper.subtract(oneLower);
			BigInteger twoCount = twoUpper.subtract(twoLower);
			int result = oneCount.compareTo(twoCount);
			if(result == 0) {
				result = oneLower.compareTo(twoLower);
			}
			return result;
		}
	}
}
