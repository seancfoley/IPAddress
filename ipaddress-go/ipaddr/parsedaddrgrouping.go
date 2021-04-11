package ipaddr

import "math/bits"

// getNetworkSegmentIndex returns the index of the segment containing the last byte within the network prefix
// When networkPrefixLength is zero (so there are no segments containing bytes within the network prefix), returns -1
func getNetworkSegmentIndex(networkPrefixLength BitCount, bytesPerSegment int, bitsPerSegment BitCount) int {
	if bytesPerSegment > 1 {
		if bytesPerSegment == 2 {
			return int((networkPrefixLength - 1) >> 4) //note this is intentionally a signed shift and not >>> so that networkPrefixLength of 0 returns -1
		}
		return int((networkPrefixLength - 1) / bitsPerSegment)
	}
	return int((networkPrefixLength - 1) >> 3)
}

/**
 * Returns the index of the segment containing the first byte outside the network prefix.
 * When networkPrefixLength is null, or it matches or exceeds the bit length, returns the segment count.
 *
 * @param networkPrefixLength
 * @param byteLength
 * @return
 */
func getHostSegmentIndex(networkPrefixLength BitCount, bytesPerSegment int, bitsPerSegment BitCount) int {
	if bytesPerSegment > 1 {
		if bytesPerSegment == 2 {
			return int(networkPrefixLength >> 4)
		}
		return int(networkPrefixLength / bitsPerSegment)
	}
	return int(networkPrefixLength >> 3)
}

/**
 * Across an address prefixes are:
 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
 * or IPv4: ...(null).(1 to 8).(0)...
 */
func getSegmentPrefixLength(bitsPerSegment BitCount, prefixLength PrefixLen, segmentIndex int) PrefixLen {
	if prefixLength != nil {
		return getPrefixedSegmentPrefixLength(bitsPerSegment, *prefixLength, segmentIndex)
	}
	return nil
}

func getPrefixedSegmentPrefixLength(bitsPerSegment BitCount, prefixLength BitCount, segmentIndex int) PrefixLen {
	var decrement int
	if bitsPerSegment == 8 {
		decrement = segmentIndex << 3
	} else if bitsPerSegment == 16 {
		decrement = segmentIndex << 4
	} else {
		decrement = segmentIndex * int(bitsPerSegment)
	}
	return getDivisionPrefixLength(bitsPerSegment, prefixLength-BitCount(decrement))
}

/**
 * Across an address prefixes are:
 * IPv6: (null):...:(null):(1 to 16):(0):...:(0)
 * or IPv4: ...(null).(1 to 8).(0)...
 */
func getDivisionPrefixLength(divisionBits, divisionPrefixedBits BitCount) PrefixLen {
	if divisionPrefixedBits <= 0 {
		return cache(0) //none of the bits in this segment matter
	} else if divisionPrefixedBits <= divisionBits {
		return cache(divisionPrefixedBits) //some of the bits in this segment matter
	}
	return nil //all the bits in this segment matter
}

// Translates a non-null segment prefix length into an address prefix length.
// When calling this for the first segment with a non-null prefix length, this gives the overall prefix length.
//
// Across an address prefixes are:
// IPv6: (null):...:(null):(1 to 16):(0):...:(0)
// or IPv4: ...(null).(1 to 8).(0)...
func getNetworkPrefixLength(bitsPerSegment, segmentPrefixLength BitCount, segmentIndex int) PrefixLen {
	var increment BitCount
	if bitsPerSegment == 8 {
		increment = BitCount(segmentIndex) << 3
	} else if bitsPerSegment == 16 {
		increment = BitCount(segmentIndex) << 4
	} else {
		increment = BitCount(segmentIndex) * bitsPerSegment
	}
	return cache(increment + segmentPrefixLength)
}

func getSegmentsBitCount(bitsPerSegment BitCount, segmentCount int) BitCount {
	if bitsPerSegment == 8 {
		return BitCount(segmentCount) << 3
	} else if bitsPerSegment == 16 {
		return BitCount(segmentCount) << 4
	}
	return BitCount(segmentCount) * bitsPerSegment
}

var cachedPrefixLens = initPrefLens()

func initPrefLens() []PrefixLen {
	cachedPrefLens := make([]PrefixLen, IPv6BitCount+1)
	for i := 0; i <= IPv6BitCount; i++ {
		bc := BitCount(i)
		cachedPrefLens[i] = &bc
	}
	return cachedPrefLens
}

func cache(i BitCount) PrefixLen {
	if i >= 0 && i < BitCount(len(cachedPrefixLens)) {
		result := cachedPrefixLens[i]
		return result
	}
	bc := BitCount(i)
	return &bc
}

// TODO This extended prefix subnet
//
//public static boolean isPrefixSubnet(
//		DivisionValueProvider lowerValueProvider,
//		DivisionValueProvider lowerExtendedValueProvider,
//		DivisionValueProvider upperValueProvider,
//		DivisionValueProvider upperExtendedValueProvider,
//		DivisionLengthProvider bitLengthProvider,
//		int divisionCount,
//		Integer networkPrefixLength,
//		PrefixConfiguration prefixConfiguration,
//		boolean fullRangeOnly) {
//	if(networkPrefixLength == null || prefixConfiguration.prefixedSubnetsAreExplicit()) {
//		return false;
//	}
//	if(networkPrefixLength < 0) {
//		networkPrefixLength = 0;
//	}
//	int totalBitLength = 0;
//	topLoop:
//	for(int i = 0; i < divisionCount; i++) {
//		int divBitLength = bitLengthProvider.getLength(i);
//		Integer divisionPrefLength = ParsedAddressGrouping.getDivisionPrefixLength(divBitLength, networkPrefixLength - totalBitLength);
//		if(divBitLength == 0) {
//			continue;
//		}
//		if(divisionPrefLength == null) {
//			totalBitLength += divBitLength;
//			continue;
//		}
//		int divisionPrefixLength = divisionPrefLength;
//		int extendedPrefixLength, extendedDivBitLength;
//		boolean isExtended, hasExtendedPrefixLength;
//		boolean hasPrefLen = divisionPrefixLength != divBitLength;
//		if(hasPrefLen) {
//			// for values larger than 64 bits, the "extended" values are the upper (aka most significant, leftmost) bits
//			if(isExtended = (divBitLength > Long.SIZE)) {
//				extendedDivBitLength = divBitLength - Long.SIZE;
//				divBitLength = Long.SIZE;
//				if(hasExtendedPrefixLength = (divisionPrefixLength < extendedDivBitLength)) {
//					extendedPrefixLength = divisionPrefixLength;
//					divisionPrefixLength = 0;
//				} else {
//					isExtended = false;
//					extendedPrefixLength = extendedDivBitLength;
//					divisionPrefixLength -= extendedDivBitLength;
//				}
//			} else {
//				extendedPrefixLength = extendedDivBitLength = 0;
//				hasExtendedPrefixLength = false;
//			}
//		} else {
//			extendedPrefixLength = extendedDivBitLength = 0;
//			hasExtendedPrefixLength = isExtended = false;// we may be extended, but we set to false because we do nothing when no prefix
//		}
//		while(true) {
//			if(isExtended) {
//				long extendedLower = lowerExtendedValueProvider.getValue(i);
//				if(extendedPrefixLength == 0) {
//					if(extendedLower != 0) {
//						return false;
//					}
//					long extendedUpper = upperExtendedValueProvider.getValue(i);
//					if(fullRangeOnly) {
//						long maxVal = ~0L >>> (Long.SIZE - extendedDivBitLength);
//						if(extendedUpper != maxVal) {
//							return false;
//						}
//					} else {
//						int upperOnes = Long.numberOfTrailingZeros(~extendedUpper);
//						if(upperOnes > 0) {
//							if(upperOnes < Long.SIZE && (extendedUpper >>> upperOnes) != 0) {
//								return false;
//							}
//							fullRangeOnly = true;
//						} else if(extendedUpper != 0) {
//							return false;
//						}
//					}
//				} else if(hasExtendedPrefixLength) {
//					int divHostBits = extendedDivBitLength - extendedPrefixLength; // < 64, when 64 handled by block above
//					if(fullRangeOnly) {
//						long hostMask = ~(~0L << divHostBits);
//						if((hostMask & extendedLower) != 0) {
//							return false;
//						}
//						long extendedUpper = upperExtendedValueProvider.getValue(i);
//						if((hostMask & extendedUpper) != hostMask) {
//							return false;
//						}
//					} else {
//						int lowerZeros = Long.numberOfTrailingZeros(extendedLower);
//						if(lowerZeros < divHostBits) {
//							return false;
//						}
//						long extendedUpper = upperExtendedValueProvider.getValue(i);
//						int upperOnes = Long.numberOfTrailingZeros(~extendedUpper);
//						if(upperOnes < divHostBits) {
//							int upperZeros = Long.numberOfTrailingZeros(extendedUpper >>> upperOnes);
//							if(upperOnes + upperZeros < divHostBits) {
//								return false;
//							}
//							fullRangeOnly = upperOnes > 0;
//						} else {
//							fullRangeOnly = true;
//						}
//					}
//				}
//			}
//			if(divisionPrefixLength == 0) {
//				long lower = lowerValueProvider.getValue(i);
//				if(lower != 0) {
//					return false;
//				}
//				long upper = upperValueProvider.getValue(i);
//				if(fullRangeOnly) {
//					long maxVal = ~0L >>> (Long.SIZE - divBitLength);
//					if(upper != maxVal) {
//						return false;
//					}
//				} else {
//					int upperOnes = Long.numberOfTrailingZeros(~upper);
//					if(upperOnes > 0) {
//						if(upperOnes < Long.SIZE && (upper >>> upperOnes) != 0) {
//							return false;
//						}
//						fullRangeOnly = true;
//					} else if(upper != 0) {
//						return false;
//					}
//				}
//			} else if(hasPrefLen){
//				long lower = lowerValueProvider.getValue(i);
//				int divHostBits = divBitLength - divisionPrefixLength; // < 64, when 64 handled by block above
//				if(fullRangeOnly) {
//					long hostMask = ~(~0L << divHostBits);
//					if((hostMask & lower) != 0) {
//						return false;
//					}
//					long upper = upperValueProvider.getValue(i);
//					if((hostMask & upper) != hostMask) {
//						return false;
//					}
//				} else {
//					int lowerZeros = Long.numberOfTrailingZeros(lower);
//					if(lowerZeros < divHostBits) {
//						return false;
//					}
//					long upper = upperValueProvider.getValue(i);
//					int upperOnes = Long.numberOfTrailingZeros(~upper);
//					if(upperOnes < divHostBits) {
//						int upperZeros = Long.numberOfTrailingZeros(upper >>> upperOnes);
//						if(upperOnes + upperZeros < divHostBits) {
//							return false;
//						}
//						fullRangeOnly = upperOnes > 0;
//					} else {
//						fullRangeOnly = true;
//					}
//				}
//			}
//			if(++i == divisionCount) {
//				break topLoop;
//			}
//			divBitLength = bitLengthProvider.getLength(i);
//			if(hasExtendedPrefixLength = isExtended = (divBitLength > Long.SIZE)) {
//				extendedDivBitLength = divBitLength - Long.SIZE;
//				divBitLength = Long.SIZE;
//			} else {
//				extendedDivBitLength = 0;
//			}
//			extendedPrefixLength = divisionPrefixLength = 0;
//		} // end while
//	}
//	return true;
//}
//
// For explicit prefix config this always returns false.
// For all prefix subnets config this always returns true if the prefix length does not extend beyond the address end.
func isPrefixSubnet(
	lowerValueProvider,
	upperValueProvider SegmentValueProvider,
	segmentCount,
	bytesPerSegment int,
	bitsPerSegment BitCount,
	segmentMaxValue SegInt,
	prefLen BitCount,
	//networkPrefixLength BitCount,
	fullRangeOnly bool) bool {
	//if networkPrefixLength == nil {
	//	return false
	//}
	//prefLen := *networkPrefixLength
	zero := BitCount(0)
	if prefLen < 0 {
		prefLen = 0
		//networkPrefixLength = &zero
	} else {
		var totalBitCount BitCount
		if bitsPerSegment == 8 {
			totalBitCount = BitCount(segmentCount) << 3
		} else if bitsPerSegment == 16 {
			totalBitCount = BitCount(segmentCount) << 4
		} else {
			totalBitCount = BitCount(segmentCount) * bitsPerSegment
		}
		if prefLen >= totalBitCount {
			return false
		}
	}
	prefixedSegment := getHostSegmentIndex(prefLen, bytesPerSegment, bitsPerSegment)
	i := prefixedSegment
	if i < segmentCount {
		segmentPrefixLength := getPrefixedSegmentPrefixLength(bitsPerSegment, prefLen, i)
		for {
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
			lower := lowerValueProvider(i)
			prefLen := *segmentPrefixLength
			if prefLen == 0 {
				if lower != 0 {
					return false
				}
				upper := upperValueProvider(i)
				if fullRangeOnly {
					if upper != segmentMaxValue {
						return false
					}
				} else {
					upperOnes := bits.TrailingZeros64(^uint64(upper))
					if upperOnes > 0 {
						if (upper >> upperOnes) != 0 {
							return false
						}
						fullRangeOnly = true
					} else if upper != 0 {
						return false
					}
				}
			} else if prefLen < bitsPerSegment {
				segHostBits := bitsPerSegment - prefLen
				if fullRangeOnly {
					hostMask := ^(^SegInt(0) << segHostBits)
					if (hostMask & lower) != 0 {
						return false
					}
					upper := upperValueProvider(i)
					if (hostMask & upper) != hostMask {
						return false
					}
				} else {
					lowerZeros := BitCount(bits.TrailingZeros64(uint64(lower)))
					if lowerZeros < segHostBits {
						return false
					}
					upper := upperValueProvider(i)
					upperOnes := BitCount(bits.TrailingZeros64(^uint64(upper)))
					if upperOnes < segHostBits {
						upperZeros := BitCount(bits.TrailingZeros64(uint64(upper|(^SegInt(0)<<bitsPerSegment)) >> upperOnes))
						if upperOnes+upperZeros < segHostBits {
							return false
						}
						fullRangeOnly = upperOnes > 0
					} else {
						fullRangeOnly = true
					}
				}
			}
			segmentPrefixLength = &zero
			i++
			if i >= segmentCount {
				break
			}
		}
	}
	return true
}

/*
In Go, << is left shift, >> is sign-extending right shift.
Conversion just grabs the low bits.

For conversion, the spec says:
When converting between integer types, if the value is a signed integer,
it is sign extended to implicit infinite precision;
otherwise it is zero extended. It is then truncated to fit in the result type's size.
For example, if v := uint16(0x10F0), then uint32(int8(v)) == 0xFFFFFFF0.
The conversion always yields a valid value; there is no indication of overflow.

var i  int32 = -1
var i2  uint32 = 0xffffffff
var i3  int32 = 0x7fffffff
var i4  int32 = -1

func main() {
	fmt.Printf("%d %d, %d %d\n",i, i >> 1, i2, i2 >> 1) // -1 -1, 4294967295 2147483647

	fmt.Printf("%d %d\n", uint32(i), uint32(i) >> 1) // 4294967295 2147483647

	fmt.Printf("%d %d\n", i3, i3 << 1) // 2147483647 -2 or 0x7fffffff << 1 becomes 0xfffffff0

	fmt.Printf("%d %d\n", uint16(i2), int16(i3)) // 65535 -1 or both become 0xffff

	fmt.Printf("%d %d\n", uint16(i4), int16(uint32(i4))) // 65535 -1 or both become 0xffff
}
*/

// the methods below not needed because of math.bits

//func numberOfTrailingZerosi64(i int64) BitCount {
//	return numberOfTrailingZeros64(uint64(i))
//}
//
//func numberOfTrailingZeros64(i uint64) BitCount {
//	half := uint32(i & 0xffffffff)
//	if half == 0 {
//		return 32 + numberOfLeadingZeros32(uint32(i>>32))
//	}
//	return numberOfLeadingZeros32(half)
//}
//
//func numberOfTrailingZerosi32(i int32) BitCount {
//	return numberOfTrailingZeros32(uint32(i))
//}
//
//func numberOfTrailingZeros32(i uint32) BitCount {
//	if i == 0 {
//		return 32
//	}
//	result := BitCount(31)
//	half := i << 16
//	if half != 0 {
//		result -= 16
//		i = half
//	}
//	half = i << 8
//	if half != 0 {
//		result -= 8
//		i = half
//	}
//	half = i << 4
//	if half != 0 {
//		result -= 4
//		i = half
//	}
//	half = i << 2
//	if half != 0 {
//		result -= 2
//		i = half
//	}
//	return result - BitCount((i<<1)>>31)
//}
//
//func numberOfLeadingZerosi64(i int64) BitCount {
//	return numberOfLeadingZeros64(uint64(i))
//}
//
//func numberOfLeadingZeros64(i uint64) BitCount {
//	half := uint32(i >> 32)
//	if half == 0 {
//		return 32 + numberOfLeadingZeros32(uint32(i))
//	}
//	return numberOfLeadingZeros32(half)
//}
//
//func numberOfLeadingZerosi32(i int32) BitCount {
//	return numberOfLeadingZeros32(uint32(i))
//}
//
//func numberOfLeadingZeros32(i uint32) BitCount {
//	half := uint16(i >> 16)
//	if half == 0 {
//		return 16 + numberOfLeadingZeros16(uint16(i))
//	}
//	return numberOfLeadingZeros16(half)
//}
//
//func numberOfLeadingZerosi16(i int16) BitCount {
//	return numberOfLeadingZeros16(uint16(i))
//}
//
//func numberOfLeadingZeros16(i uint16) BitCount {
//	half := uint8(i >> 8)
//	if half == 0 {
//		return 8 + numberOfLeadingZeros8(uint8(i))
//	}
//	return numberOfLeadingZeros8(half)
//}
//
//func numberOfLeadingZerosi8(i int8) BitCount {
//	return numberOfLeadingZeros8(uint8(i))
//}
//
//func numberOfLeadingZeros8(i uint8) BitCount {
//	if i == 0 {
//		return 8
//	}
//	result := BitCount(1)
//	half := i >> 4
//	if half == 0 {
//		result += 4
//		i <<= 4
//	}
//	half = i >> 6
//	if half == 0 {
//		result += 2
//		i <<= 2
//	}
//	result -= BitCount(i >> 7)
//	return result
//}
