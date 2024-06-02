/*
 * Copyright 2018-2024 Sean C Foley
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
package inet.ipaddr.format.validate;

import inet.ipaddr.Address.SegmentValueProvider;
import inet.ipaddr.AddressNetwork.PrefixConfiguration;
import inet.ipaddr.format.standard.AddressDivisionGrouping.DivisionLengthProvider;
import inet.ipaddr.format.standard.AddressDivisionGrouping.DivisionValueProvider;
import inet.ipaddr.ipv6.IPv6Address;

public class ParsedAddressGrouping {
	
	/**
	 * Returns the index of the segment containing the last byte within the network prefix
	 * When networkPrefixLength is zero (so there are no segments containing bytes within the network prefix), returns -1
	 * 
	 * @param networkPrefixLength
	 * @param byteLength
	 * @return
	 */
	public static int getNetworkSegmentIndex(int networkPrefixLength, int bytesPerSegment, int bitsPerSegment) {
		if(bytesPerSegment > 1) {
			if(bytesPerSegment == 2) {
				return (networkPrefixLength - 1) >> 4;//note this is intentionally a signed shift and not >>> so that networkPrefixLength of 0 returns -1
			}
			return (networkPrefixLength - 1) / bitsPerSegment;
		}
		return (networkPrefixLength - 1) >> 3;
	}
	
	/**
	 * Returns the index of the segment containing the first byte outside the network prefix.
	 * When networkPrefixLength is null, or it matches or exceeds the bit length, returns the segment count.
	 * 
	 * @param networkPrefixLength
	 * @param byteLength
	 * @return
	 */
	public static int getHostSegmentIndex(int networkPrefixLength, int bytesPerSegment, int bitsPerSegment) {
		if(bytesPerSegment > 1) {
			if(bytesPerSegment == 2) {
				return networkPrefixLength >> 4;
			}
			return networkPrefixLength / bitsPerSegment;
		}
		return networkPrefixLength >> 3;
	}

	/**
	 * Returns the total number of bits for the given segment count, with each segment having the given number of bits.
	 * The number of bytes must correspond to the number of bits.
	 * 
	 * @param segmentCount
	 * @param bytesPerSegment
	 * @param bitsPerSegment
	 * @return
	 */
	public static int getTotalBits(int segmentCount, int bytesPerSegment, int bitsPerSegment) {
		if(bytesPerSegment != 1) {
			if(bytesPerSegment == 2) {
				return segmentCount << 4;
			}
			return segmentCount * bitsPerSegment;
		}
		return segmentCount << 3;
	}
	
	/**
	 * Across an address prefixes are:
	 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
	 * or IPv4: ...(null).(1 to 8).(0)...
	 */
	public static Integer getSegmentPrefixLength(int bitsPerSegment, Integer prefixLength, int segmentIndex) {
		if(prefixLength != null) {
			return getPrefixedSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
		}
		return null;
	}

	public static Integer getPrefixedSegmentPrefixLength(int bitsPerSegment, int prefixLength, int segmentIndex) {
		int decrement = (bitsPerSegment == 8) ? segmentIndex << 3 : ((bitsPerSegment == 16) ? segmentIndex << 4 :  segmentIndex * bitsPerSegment);
		return getDivisionPrefixLength(bitsPerSegment, prefixLength - decrement);
	}
	
	/**
	 * Across an address prefixes are:
	 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
	 * or IPv4: ...(null).(1 to 8).(0)...
	 */
	public static Integer getDivisionPrefixLength(int divisionBits, int divisionPrefixedBits) {
		if(divisionPrefixedBits <= 0) {
			return cache(0); //none of the bits in this segment matter
		} else if(divisionPrefixedBits <= divisionBits) {
			return cache(divisionPrefixedBits);//some of the bits in this segment matter
		}
		return null; //all the bits in this segment matter
	}
	
	/**
	 * Translates a non-null segment prefix length into an address prefix length.  
	 * When calling this for the first segment with a non-null prefix length, this gives the overall prefix length.
	 * <p>
	 * Across an address prefixes are:
	 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
	 * or IPv4: ...(null).(1 to 8).(0)...
	 */
	public static Integer getNetworkPrefixLength(int bitsPerSegment, int segmentPrefixLength, int segmentIndex) {
		int increment = (bitsPerSegment == 8) ? segmentIndex << 3 : ((bitsPerSegment == 16) ? segmentIndex << 4 :  segmentIndex * bitsPerSegment);
		return cache(increment + segmentPrefixLength);
	}
	
	public static boolean isPrefixSubnet(
			DivisionValueProvider lowerValueProvider,
			DivisionValueProvider lowerExtendedValueProvider,
			DivisionValueProvider upperValueProvider,
			DivisionValueProvider upperExtendedValueProvider,
			DivisionLengthProvider bitLengthProvider,
			int divisionCount,
			Integer networkPrefixLength,
			PrefixConfiguration prefixConfiguration,
			boolean fullRangeOnly) {
		if(networkPrefixLength == null || prefixConfiguration.prefixedSubnetsAreExplicit()) {
			return false;
		}
		if(networkPrefixLength < 0) {
			networkPrefixLength = 0;
		}
		int totalBitLength = 0;
		topLoop:
		for(int i = 0; i < divisionCount; i++) {
			int divBitLength = bitLengthProvider.getLength(i);
			Integer divisionPrefLength = ParsedAddressGrouping.getDivisionPrefixLength(divBitLength, networkPrefixLength - totalBitLength);
			if(divBitLength == 0) {
				continue;
			}
			if(divisionPrefLength == null) {
				totalBitLength += divBitLength;
				continue;
			}
			int divisionPrefixLength = divisionPrefLength;
			int extendedPrefixLength, extendedDivBitLength;
			boolean isExtended, hasExtendedPrefixLength;
			boolean hasPrefLen = divisionPrefixLength != divBitLength;
			if(hasPrefLen) {
				// for values larger than 64 bits, the "extended" values are the upper (aka most significant, leftmost) bits
				if(isExtended = (divBitLength > Long.SIZE)) {
					extendedDivBitLength = divBitLength - Long.SIZE;
					divBitLength = Long.SIZE;
					if(hasExtendedPrefixLength = (divisionPrefixLength < extendedDivBitLength)) {
						extendedPrefixLength = divisionPrefixLength;
						divisionPrefixLength = 0;
					} else {
						isExtended = false;
						extendedPrefixLength = extendedDivBitLength;
						divisionPrefixLength -= extendedDivBitLength;
					}
				} else {
					extendedPrefixLength = extendedDivBitLength = 0;
					hasExtendedPrefixLength = false;
				}
			} else {
				extendedPrefixLength = extendedDivBitLength = 0;
				hasExtendedPrefixLength = isExtended = false;// we may be extended, but we set to false because we do nothing when no prefix
			}
			while(true) {
				if(isExtended) {
					long extendedLower = lowerExtendedValueProvider.getValue(i);
					if(extendedPrefixLength == 0) {
						if(extendedLower != 0) {
							return false;
						}
						long extendedUpper = upperExtendedValueProvider.getValue(i);
						if(fullRangeOnly) {
							long maxVal = ~0L >>> (Long.SIZE - extendedDivBitLength);
							if(extendedUpper != maxVal) {
								return false;
							}
						} else {
							int upperOnes = Long.numberOfTrailingZeros(~extendedUpper);
							if(upperOnes > 0) {
								if(upperOnes < Long.SIZE && (extendedUpper >>> upperOnes) != 0) {
									return false;
								}
								fullRangeOnly = true;
							} else if(extendedUpper != 0) {
								return false;
							}
						}
					} else if(hasExtendedPrefixLength) {
						int divHostBits = extendedDivBitLength - extendedPrefixLength; // < 64, when 64 handled by block above
						if(fullRangeOnly) {
							long hostMask = ~(~0L << divHostBits);
							if((hostMask & extendedLower) != 0) {
								return false;
							}
							long extendedUpper = upperExtendedValueProvider.getValue(i);
							if((hostMask & extendedUpper) != hostMask) {
								return false;
							}
						} else {
							int lowerZeros = Long.numberOfTrailingZeros(extendedLower);
							if(lowerZeros < divHostBits) {
								return false;
							}
							long extendedUpper = upperExtendedValueProvider.getValue(i);
							int upperOnes = Long.numberOfTrailingZeros(~extendedUpper);
							if(upperOnes < divHostBits) {
								int upperZeros = Long.numberOfTrailingZeros(extendedUpper >>> upperOnes);
								if(upperOnes + upperZeros < divHostBits) {
									return false;
								}
								fullRangeOnly = upperOnes > 0;
							} else {
								fullRangeOnly = true;
							}
						}
					}
				}
				if(divisionPrefixLength == 0) {
					long lower = lowerValueProvider.getValue(i);
					if(lower != 0) {
						return false;
					}
					long upper = upperValueProvider.getValue(i);
					if(fullRangeOnly) {	
						long maxVal = ~0L >>> (Long.SIZE - divBitLength);
						if(upper != maxVal) {
							return false;
						}
					} else {
						int upperOnes = Long.numberOfTrailingZeros(~upper);
						if(upperOnes > 0) {
							if(upperOnes < Long.SIZE && (upper >>> upperOnes) != 0) {
								return false;
							}
							fullRangeOnly = true;
						} else if(upper != 0) {
							return false;
						}
					}
				} else if(hasPrefLen){
					long lower = lowerValueProvider.getValue(i);
					int divHostBits = divBitLength - divisionPrefixLength; // < 64, when 64 handled by block above
					if(fullRangeOnly) {
						long hostMask = ~(~0L << divHostBits);
						if((hostMask & lower) != 0) {
							return false;
						}
						long upper = upperValueProvider.getValue(i);
						if((hostMask & upper) != hostMask) {
							return false;
						}
					} else {
						int lowerZeros = Long.numberOfTrailingZeros(lower);
						if(lowerZeros < divHostBits) {
							return false;
						}
						long upper = upperValueProvider.getValue(i);
						int upperOnes = Long.numberOfTrailingZeros(~upper);
						if(upperOnes < divHostBits) {
							int upperZeros = Long.numberOfTrailingZeros(upper >>> upperOnes);
							if(upperOnes + upperZeros < divHostBits) {
								return false;
							}
							fullRangeOnly = upperOnes > 0;
						} else {
							fullRangeOnly = true;
						}
					}
				}
				if(++i == divisionCount) {
					break topLoop;
				}
				divBitLength = bitLengthProvider.getLength(i);
				if(hasExtendedPrefixLength = isExtended = (divBitLength > Long.SIZE)) {
					extendedDivBitLength = divBitLength - Long.SIZE;
					divBitLength = Long.SIZE;
				} else {
					extendedDivBitLength = 0;
				}
				extendedPrefixLength = divisionPrefixLength = 0;
			} // end while
		}
		return true;
	}
	
	// For explicit prefix config this always returns false.  
	// For all prefix subnets config this always returns true if the prefix length does not extend beyond the address end.
	public static boolean isPrefixSubnet(
			SegmentValueProvider lowerValueProvider,
			SegmentValueProvider upperValueProvider,
			int segmentCount,
			int bytesPerSegment,
			int bitsPerSegment,
			int segmentMaxValue,
			Integer networkPrefixLength,
			PrefixConfiguration prefixConfiguration,
			boolean fullRangeOnly) {
		if(networkPrefixLength == null || prefixConfiguration.prefixedSubnetsAreExplicit()) {
			return false;
		}
		if(networkPrefixLength < 0) {
			networkPrefixLength = 0;
		} else {
			int totalBitCount = (bitsPerSegment == 8) ? segmentCount << 3 : ((bitsPerSegment == 16) ? segmentCount << 4 : segmentCount * bitsPerSegment);
			if(networkPrefixLength >= totalBitCount) {
				return false;
			}
		}
		if(prefixConfiguration.allPrefixedAddressesAreSubnets()) {
			return true;
		}
		int prefixedSegment = getHostSegmentIndex(networkPrefixLength, bytesPerSegment, bitsPerSegment);
		int i = prefixedSegment;
		if(i < segmentCount) {
			int segmentPrefixLength = getPrefixedSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
			do {
				//we want to see if there is a sequence of zeros followed by a sequence of full-range bits from the prefix onwards
				//once we start seeing full range bits, the remained of the section must be full range
				//for instance x marks the start of zeros and y marks the start of full range:
				//segment 1 segment 2 ...
				//upper: 10101010  10100111 11111111 11111111
				//lower: 00111010  00100000 00000000 00000000
				//                    x y
				//upper: 10101010  10100000 00000000 00111111
				//lower: 00111010  00100000 10000000 00000000
				//                           x         y
				//
				//the bit marked x in each set of 4 segment of 8 bits is a sequence of zeros, followed by full range bits starting at bit y
				int lower = lowerValueProvider.getValue(i);
				if(segmentPrefixLength == 0) {
					if(lower != 0) {
						return false;
					}
					int upper = upperValueProvider.getValue(i);
					if(fullRangeOnly) {
						if(upper != segmentMaxValue) {
							return false;
						}
					} else {
						int upperOnes = Integer.numberOfTrailingZeros(~upper);
						if(upperOnes > 0) {
							if((upper >>> upperOnes) != 0) {
								return false;
							}
							fullRangeOnly = true;
						} else if(upper != 0) {
							return false;
						}
					}
				} else if(segmentPrefixLength < bitsPerSegment) {
					int segHostBits = bitsPerSegment - segmentPrefixLength;
					if(fullRangeOnly) {
						int hostMask = ~(~0 << segHostBits);
						if((hostMask & lower) != 0) {
							return false;
						}
						int upper = upperValueProvider.getValue(i);
						if((hostMask & upper) != hostMask) {
							return false;
						}
					} else {
						int lowerZeros = Integer.numberOfTrailingZeros(lower);
						if(lowerZeros < segHostBits) {
							return false;
						}
						int upper = upperValueProvider.getValue(i);
						int upperOnes = Integer.numberOfTrailingZeros(~upper);
						if(upperOnes < segHostBits) {
							int upperZeros = Integer.numberOfTrailingZeros((upper | (~0 << bitsPerSegment)) >>> upperOnes);
							if(upperOnes + upperZeros < segHostBits) {
								return false;
							}
							fullRangeOnly = upperOnes > 0;
						} else {
							fullRangeOnly = true;
						}
					}
				}
				segmentPrefixLength = 0;
			} while(++i < segmentCount);
		}
		return true;
	}
	
	// this is used to cache:
	// - ports
	// - prefix lengths and bit lengths
	// - segment mask values
	// so it needs to be large enough to accommodate all of those, but we only populate the bit lengths to start
	private static final Integer cache[] = new Integer[Short.MAX_VALUE]; static {
		for(int i = 0; i <= IPv6Address.BIT_COUNT; i++) {
			cache[i] = i;
		}
	}
     
	public static Integer cache(int i) {
		if(i >= 0 && i < cache.length) {
			Integer result = cache[i];
			if(result == null) {
				result = cache[i] = i;
			}
			return result;
		}
		return i;
	}
}
