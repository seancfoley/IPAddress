/*
 * Copyright 2018 Sean C Foley
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
import inet.ipaddr.ipv4.IPv4Address;

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
		return getSegmentPrefixLength(bitsPerSegment, prefixLength - decrement);
	}
	
	/**
	 * Across an address prefixes are:
	 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
	 * or IPv4: ...(null).(1 to 8).(0)...
	 */
	public static Integer getSegmentPrefixLength(int segmentBits, int segmentPrefixedBits) {
		if(segmentPrefixedBits <= 0) {
			return 0; //none of the bits in this segment matter
		} else if(segmentPrefixedBits <= segmentBits) {
			return segmentPrefixedBits;//some of the bits in this segment matter
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
		return increment + segmentPrefixLength;
	}

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
			int segmentPrefixLength = getSegmentPrefixLength(bitsPerSegment, networkPrefixLength, i);
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
				} else {
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
						int upperZeros = Integer.numberOfTrailingZeros((upper | (~0 << bitsPerSegment)) >>> upperOnes);
						if(upperOnes + upperZeros < segHostBits) {
							return false;
						}
						if(upperOnes > 0) {
							fullRangeOnly = true;
						}
					}
				}
				segmentPrefixLength = 0;
			} while(++i < segmentCount);
		}
		return true;
	}
	
	private static final Integer cache[] = new Integer[IPv4Address.MAX_VALUE_PER_SEGMENT + 1]; static {
		for(int i = 0; i < cache.length; i++) {
			cache[i] = i;
		}
	}
     
	public static Integer cache(int i) {
		if(i >= 0 && i < cache.length) {
			return cache[i];
		}
		return i;
	}
}
