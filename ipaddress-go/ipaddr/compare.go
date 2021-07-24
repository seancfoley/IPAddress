package ipaddr

import "math/big"

var (
	// Compares by count first, then by value
	CountComparator = AddressComparator{countComparator{}}

	// Compare by value first, whether low or high or both
	HighValueComparator        = AddressComparator{valueComparator{compareHighValue: true}}
	LowValueComparator         = AddressComparator{valueComparator{}}
	ReverseHighValueComparator = AddressComparator{valueComparator{compareHighValue: true, flipSecond: true}}
	ReverseLowValueComparator  = AddressComparator{valueComparator{flipSecond: true}}
)

type componentComparator interface {
	compareSectionParts(one, two *AddressSection) int

	compareParts(one, two AddressDivisionSeries) int

	compareSegValues(oneUpper, oneLower, twoUpper, twoLower SegInt) int

	compareValues(oneUpper, oneLower, twoUpper, twoLower uint64) int

	compareLargeValues(oneUpper, oneLower, twoUpper, twoLower *big.Int) int
}

type AddressComparator struct {
	componentComparator
}

const (
	ipv6sectype          = 7
	ipv6v4groupingtype   = 6
	ipv4sectype          = 5
	ipsectype            = 4
	macsectype           = 3
	sectype              = 1
	largegroupingtype    = -2
	standardgroupingtype = -3
)

const (
	ipv6segtype     = 6
	ipv4segtype     = 5
	ipsegtype       = 4
	macsegtype      = 3
	segtype         = 1
	largedivtype    = -2
	standarddivtype = 0
)

const (
	ipv6rangetype = 2
	ipv4rangetype = 1
	iprangetype   = 0
)

func mapDivision(genericDiv DivisionType) int {
	if div, ok := genericDiv.(StandardDivisionType); ok {
		addrDiv := div.ToAddressDivision()
		if addrDiv.IsIPv6AddressSegment() {
			return ipv6segtype
		} else if addrDiv.IsIPv4AddressSegment() {
			return ipv4segtype
		} else if addrDiv.IsMACAddressSegment() {
			return macsegtype
		} else if addrDiv.IsIPAddressSegment() {
			return ipsegtype
		} else if addrDiv.IsAddressSegment() {
			return segtype
		} //} else if(div instanceof IPv4JoinedSegments) {
		//	return 2;
		return standarddivtype
		//} else if(div instanceof IPAddressBitsDivision) {
		//	return -2;
		//} else if(div instanceof AddressBitsDivision) {
		//	return -3;
		//}
	}
	//else if(div instanceof IPAddressLargeDivision) {
	//	return -1;
	//}
	return standarddivtype
}

func mapGrouping(series AddressDivisionSeries) int {
	if grouping, ok := series.(StandardDivisionGroupingType); ok {
		group := grouping.ToAddressDivisionGrouping()
		if group.IsIPv6AddressSection() {
			return ipv6sectype
		} else if group.IsIPv6v4MixedAddressGrouping() {
			return ipv6v4groupingtype
		} else if group.IsIPv4AddressSection() {
			return ipv4sectype
		} else if group.IsMACAddressSection() {
			return macsectype
		} else if group.IsIPAddressSection() {
			return ipsectype
		} else if group.isAddressSection() {
			return sectype
		}
		return standardgroupingtype
	} //} else if(series instanceof IPAddressLargeDivisionGrouping) { TODO later
	//	return -2;
	//}
	return 0
}

func mapRange(rngType IPAddressSeqRangeType) int {
	rng := rngType.ToIPAddressSeqRange()
	if rng.IsIPv4SequentialRange() {
		return ipv4rangetype
	} else if rng.IsIPv6SequentialRange() {
		return ipv6rangetype
	}
	return iprangetype
}

func (comp AddressComparator) CompareAddresses(one, two AddressType) int {
	oneAddr := one.ToAddress()
	twoAddr := two.ToAddress()
	result := comp.CompareAddressSections(oneAddr.GetSection(), twoAddr.GetSection())
	if result == 0 {
		if oneIPv6 := oneAddr.ToIPv6Address(); oneIPv6 != nil {
			twoIPv6 := twoAddr.ToIPv6Address()
			oneZone := oneIPv6.zone
			twoZone := twoIPv6.zone
			if oneZone == twoZone {
				return 0
			} else if oneZone < twoZone {
				return -1
			}
			return 1
		}
	}
	return result
}

func (comp AddressComparator) CompareAddressSections(one, two AddressSectionType) int {
	result := mapGrouping(one) - mapGrouping(two)
	if result != 0 {
		return result
	}
	oneSec := one.ToAddressSection()
	twoSec := two.ToAddressSection()
	if oneIPv6 := oneSec.ToIPv6AddressSection(); oneIPv6 != nil {
		twoIPv6 := twoSec.ToIPv6AddressSection()
		result = int(oneIPv6.addressSegmentIndex - twoIPv6.addressSegmentIndex)
		if result != 0 {
			return result
		}
	}
	if oneMAC := oneSec.ToMACAddressSection(); oneMAC != nil {
		twoMAC := twoSec.ToMACAddressSection()
		result = int(oneMAC.addressSegmentIndex - twoMAC.addressSegmentIndex)
		if result != 0 {
			return result
		}
	}
	return comp.compareSectionParts(oneSec, twoSec)
}

func unwrapWrapper(item AddressDivisionSeries) AddressDivisionSeries {
	if wrapper, ok := item.(ExtendedIPSegmentSeries); ok {
		return wrapper.Unwrap()
	}
	return item
}

func (comp AddressComparator) CompareSeries(one, two AddressDivisionSeries) int {
	one = unwrapWrapper(one)
	two = unwrapWrapper(two)
	if addrSeries1, ok := one.(AddressType); ok {
		if addrSeries2, ok := two.(AddressType); ok {
			return comp.CompareAddresses(addrSeries1, addrSeries2)
		}
		return -1
	} else if _, ok := two.(AddressType); ok {
		return 1
	}
	if addrSection1, ok := one.(AddressSectionType); ok {
		if addrSection2, ok := two.(AddressSectionType); ok {
			return comp.CompareAddressSections(addrSection1, addrSection2)
		}
	}
	result := mapGrouping(one) - mapGrouping(two)
	if result != 0 {
		return result
	}
	return comp.compareParts(one, two)
}

func (comp AddressComparator) CompareSegments(one, two AddressSegmentType) int {
	result := mapDivision(one) - mapDivision(two)
	if result != 0 {
		return result
	}
	return comp.compareSegValues(one.GetUpperSegmentValue(), one.GetSegmentValue(), two.GetUpperSegmentValue(), two.GetSegmentValue())
}

func (comp AddressComparator) CompareDivisions(one, two DivisionType) int {
	if addrSeg1, ok := one.(AddressSegmentType); ok {
		if addrSeg2, ok := two.(AddressSegmentType); ok {
			return comp.CompareSegments(addrSeg1, addrSeg2)
		}
	}
	result := mapDivision(one) - mapDivision(two)
	if result != 0 {
		return result
	}
	result = int(one.GetBitCount()) - int(two.GetBitCount())
	if result != 0 {
		return result
	}
	if addrDiv1, ok := one.(StandardDivisionType); ok {
		if addrDiv2, ok := two.(StandardDivisionType); ok {
			div1 := addrDiv1.ToAddressDivision()
			div2 := addrDiv2.ToAddressDivision()
			return comp.compareValues(div1.GetUpperDivisionValue(), div1.GetDivisionValue(), div2.GetUpperDivisionValue(), div2.GetDivisionValue())
		}
	}
	return comp.compareLargeValues(one.GetUpperValue(), one.GetValue(), two.GetUpperValue(), two.GetValue())
}

func (comp AddressComparator) CompareRanges(one, two IPAddressSeqRangeType) int {
	r1Type := mapRange(one)
	result := r1Type - mapRange(two)
	if result != 0 {
		return result
	}
	if r1Type == ipv4rangetype {
		r1 := one.ToIPAddressSeqRange().ToIPv4SequentialRange()
		r2 := two.ToIPAddressSeqRange().ToIPv4SequentialRange()
		return comp.compareValues(uint64(r1.GetUpper().Uint32Value()), uint64(r1.GetLower().Uint32Value()), uint64(r2.GetUpper().Uint32Value()), uint64(r2.GetLower().Uint32Value()))
	}
	r1 := one.ToIPAddressSeqRange()
	r2 := two.ToIPAddressSeqRange()
	return comp.compareLargeValues(r1.GetUpperValue(), r1.GetValue(), r2.GetUpperValue(), r2.GetValue())
}

func (comp AddressComparator) Compare(one, two AddressItem) int {
	// Comparison works as follows:
	// 1. use type assertion with AddressDivisionSeries, covering all addresses and all groupings, including large
	// 		if true, we split off to AddressDivisionSeries
	//		1a check for addresses with AddressType type assertion
	//			then use a mapping to address types (map to type with type switch and ints, then if both same type, use generic compare(Address one, two))
	//		1b check for addresSections, using type assertion with AddressSectionType (DONE)
	//			the use mapping to compare address sections (map to type with type switch and ints, then if both same type, use generic compare(AddressSection one, two))
	//		1c compare division series types
	//		1d compare division series for general case when 1c types the same
	//				this checks for both StandardDivisionGroupingType (DONE), so we can use longs,
	//				if either not, then we use bytes and AddressDivisionSeries
	// 2. type assertion for DivisionType, covering all divisions, including large
	//		2a check for AddressSegmentType with type assertion
	//			then use a mapping to address types (map to type with type switch and ints, then if both same type, use genetic compare(AddressSegment one, two))
	//		2b compare division types (ie mapDivision)
	//		2c check bit diff
	//		2d check for AddressStandardDivisionwith type assertion
	//			// then use compareValue on all 4 u64 division values, one low/high, two low/high
	//		2e  use compareValue on all 4 bigint division values, one low/high, two low/high
	// 3. Go for IPAddressSeqRange
	// 4. compare bit counts
	//
	// So we need:
	// AddressDivisionSeries (split off all division groupings including large)
	// AddressType to convert to Address
	// AddressSectionType to convert to AddressSection
	// StandardDivisionGroupingType (all standard divisons) so we can grab longs when comparing divisions
	// DivisionType (all divisions including large)
	// AddressSegmentType to convert to AddressSegment
	// StandardDivisionType so we can convert to AddressDivision and grab longs when comparing division grouping or divisions
	// IPAddressSeqRangeType (split off all ranges)
	if divSeries1, ok := one.(AddressDivisionSeries); ok {
		if divSeries2, ok := two.(AddressDivisionSeries); ok {
			return comp.CompareSeries(divSeries1, divSeries2)
		} else {
			return 1
		}
	} else if div1, ok := one.(DivisionType); ok {
		if div2, ok := two.(DivisionType); ok {
			return comp.CompareDivisions(div1, div2)
		} else {
			return -1
		}
	} else if rng1, ok := one.(IPAddressSeqRangeType); ok {
		if rng2, ok := two.(IPAddressSeqRangeType); ok {
			return comp.CompareRanges(rng1, rng2)
		} else if _, ok := two.(AddressDivisionSeries); ok {
			return -1
		}
		return 1
	}
	// we've covered all known address items for one, so check two
	if _, ok := two.(AddressDivisionSeries); ok {
		return -1
	} else if _, ok := two.(DivisionType); ok {
		return 1
	} else if _, ok := two.(IPAddressSeqRangeType); ok {
		return -1
	}
	// neither are a known AddressItem type
	return int(one.GetBitCount() - two.GetBitCount())
}

type valueComparator struct {
	compareHighValue, flipSecond bool
}

func (comp valueComparator) compareSectionParts(one, two *AddressSection) int {
	sizeResult := one.GetByteCount() - two.GetByteCount()
	if sizeResult != 0 {
		return sizeResult
	}
	compareHigh := comp.compareHighValue
	for {
		segCount := one.GetSegmentCount()
		for i := 0; i < segCount; i++ {
			segOne := one.GetSegment(i)
			segTwo := two.GetSegment(i)
			var s1, s2 SegInt
			if compareHigh {
				s1 = segOne.GetUpperSegmentValue()
				s2 = segTwo.GetUpperSegmentValue()
			} else {
				s1 = segOne.GetSegmentValue()
				s2 = segTwo.GetSegmentValue()
			}
			if s1 != s2 {
				var result int
				if s1 > s2 {
					result = 1
				} else {
					result = -1
				}
				if comp.flipSecond && compareHigh != comp.compareHighValue {
					result = -result
				}
				return result
			}
		}
		compareHigh = !compareHigh
		if compareHigh == comp.compareHighValue {
			break
		}
	}
	return 0
}

func (comp valueComparator) compareParts(oneSeries, twoSeries AddressDivisionSeries) int {
	sizeResult := int(oneSeries.GetBitCount() - twoSeries.GetBitCount())
	if sizeResult != 0 {
		return sizeResult
	}
	result := compareDivBitCounts(oneSeries, twoSeries)
	if result != 0 {
		return result
	}
	compareHigh := comp.compareHighValue
	var one, two *AddressDivisionGrouping
	if o, ok := oneSeries.(StandardDivisionGroupingType); ok {
		if t, ok := twoSeries.(StandardDivisionGroupingType); ok {
			one = o.ToAddressDivisionGrouping()
			two = t.ToAddressDivisionGrouping()
		}
	}
	oneSeriesByteCount := oneSeries.GetByteCount()
	twoSeriesByteCount := twoSeries.GetByteCount()
	oneBytes := make([]byte, oneSeriesByteCount)
	twoBytes := make([]byte, twoSeriesByteCount)
	for {
		var oneByteCount, twoByteCount, oneByteIndex, twoByteIndex, oneIndex, twoIndex int
		var oneBitCount, twoBitCount, oneTotalBitCount, twoTotalBitCount BitCount
		var oneValue, twoValue uint64
		for oneIndex < oneSeries.GetDivisionCount() || twoIndex < twoSeries.GetDivisionCount() {
			if one != nil {
				if oneBitCount == 0 {
					oneCombo := one.GetDivision(oneIndex)
					oneIndex++
					oneBitCount = oneCombo.GetBitCount()
					if compareHigh {
						oneValue = oneCombo.GetUpperDivisionValue()
					} else {
						oneValue = oneCombo.GetDivisionValue()
					}
				}
				if twoBitCount == 0 {
					twoCombo := two.GetDivision(twoIndex)
					twoIndex++
					twoBitCount = twoCombo.GetBitCount()
					if compareHigh {
						twoValue = twoCombo.GetUpperDivisionValue()
					} else {
						twoValue = twoCombo.GetDivisionValue()
					}
				}
			} else {
				if oneBitCount == 0 {
					if oneByteCount == 0 {
						oneCombo := oneSeries.GetGenericDivision(oneIndex)
						oneIndex++
						if compareHigh {
							oneBytes = oneCombo.CopyUpperBytes(oneBytes)
						} else {
							oneBytes = oneCombo.CopyBytes(oneBytes)
						}
						oneTotalBitCount = oneCombo.GetBitCount()
						oneByteCount = oneCombo.GetByteCount()
						oneByteIndex = 0
					}
					//put some or all of the bytes into a long
					count := 8
					oneValue = 0
					if count < oneByteCount {
						oneBitCount = BitCount(count) << 3
						oneTotalBitCount -= oneBitCount
						oneByteCount -= count
						for count > 0 {
							count--

							oneValue = (oneValue << 8) | uint64(oneBytes[oneByteIndex])
							oneByteIndex++
						}
					} else {
						shortCount := oneByteCount - 1
						lastBitsCount := oneTotalBitCount - (BitCount(shortCount) << 3)
						for shortCount > 0 {
							shortCount--

							oneValue = (oneValue << 8) | uint64(oneBytes[oneByteIndex])
							oneByteIndex++
						}
						oneValue = (oneValue << uint64(lastBitsCount)) | uint64(oneBytes[oneByteIndex]>>uint64(8-lastBitsCount))
						oneByteIndex++
						oneBitCount = oneTotalBitCount
						oneTotalBitCount = 0
						oneByteCount = 0
					}
				}
				if twoBitCount == 0 {
					if twoByteCount == 0 {
						twoCombo := twoSeries.GetGenericDivision(twoIndex)
						twoIndex++
						if compareHigh {
							twoBytes = twoCombo.CopyUpperBytes(twoBytes)
						} else {
							twoBytes = twoCombo.CopyBytes(twoBytes)
						}
						twoTotalBitCount = twoCombo.GetBitCount()
						twoByteCount = twoCombo.GetByteCount()
						twoByteIndex = 0
					}
					//put some or all of the bytes into a long
					count := 8
					twoValue = 0
					if count < twoByteCount {
						twoBitCount = BitCount(count) << 3
						twoTotalBitCount -= twoBitCount
						twoByteCount -= count
						for count > 0 {
							count--

							twoValue = (twoValue << 8) | uint64(twoBytes[twoByteIndex])
							twoByteIndex++
						}
					} else {
						shortCount := twoByteCount - 1
						lastBitsCount := twoTotalBitCount - (BitCount(shortCount) << 3)
						for shortCount > 0 {
							shortCount--

							twoValue = (twoValue << 8) | uint64(twoBytes[twoByteIndex])
							twoByteIndex++
						}
						twoValue = (twoValue << uint(lastBitsCount)) | uint64(twoBytes[twoByteIndex]>>uint(8-lastBitsCount))
						twoByteIndex++
						twoBitCount = twoTotalBitCount
						twoTotalBitCount = 0
						twoByteCount = 0
					}
				}
			}
			oneResultValue := oneValue
			twoResultValue := twoValue
			if twoBitCount == oneBitCount {
				//no adjustment required, compare the values straight up
				oneBitCount = 0
				twoBitCount = 0
			} else {
				diffBits := twoBitCount - oneBitCount
				if diffBits > 0 {
					twoResultValue >>= uint(diffBits)
					twoValue &= ^(^uint64(0) << uint(diffBits))
					twoBitCount = diffBits
					oneBitCount = 0
				} else {
					diffBits = -diffBits
					oneResultValue >>= uint(diffBits)
					oneValue &= ^(^uint64(0) << uint(diffBits))
					oneBitCount = diffBits
					twoBitCount = 0
				}
			}
			if oneResultValue != twoResultValue {
				if comp.flipSecond && compareHigh != comp.compareHighValue {
					if oneResultValue > twoResultValue {
						return -1
					}
					return 1
				}
				if oneResultValue > twoResultValue {
					return 1
				}
				return -1
			}
		}
		compareHigh = !compareHigh
		if compareHigh == comp.compareHighValue {
			break
		}
	}
	return 0
}

func (comp valueComparator) compareSegValues(oneUpper, oneLower, twoUpper, twoLower SegInt) int {
	if comp.compareHighValue {
		if oneUpper == twoUpper {
			if oneLower == twoLower {
				return 0
			} else if oneLower > twoLower {
				if !comp.flipSecond {
					return 1
				}
			}
		} else if oneUpper > twoUpper {
			return 1
		}
	} else {
		if oneLower == twoLower {
			if oneUpper == twoUpper {
				return 0
			} else if oneUpper > twoUpper {
				if !comp.flipSecond {
					return 1
				}
			}
		} else if oneLower > twoLower {
			return 1
		}
	}
	return -1
}

func (comp valueComparator) compareValues(oneUpper, oneLower, twoUpper, twoLower uint64) int {
	if comp.compareHighValue {
		if oneUpper == twoUpper {
			if oneLower == twoLower {
				return 0
			} else if oneLower > twoLower {
				if !comp.flipSecond {
					return 1
				}
			}
		} else if oneUpper > twoUpper {
			return 1
		}
	} else {
		if oneLower == twoLower {
			if oneUpper == twoUpper {
				return 0
			} else if oneUpper > twoUpper {
				if !comp.flipSecond {
					return 1
				}
			}
		} else if oneLower > twoLower {
			return 1
		}
	}
	return -1
}

func (comp valueComparator) compareLargeValues(oneUpper, oneLower, twoUpper, twoLower *big.Int) int {
	var result int
	if comp.compareHighValue {
		result = oneUpper.CmpAbs(twoUpper)
		if result == 0 {
			result = oneLower.CmpAbs(twoLower)
			if comp.flipSecond {
				result = -result
			}
		}
	} else {
		result = oneLower.CmpAbs(twoLower)
		if result == 0 {
			result = oneUpper.CmpAbs(twoUpper)
			if comp.flipSecond {
				result = -result
			}
		}
	}
	return result
}

type countComparator struct{}

func (comp countComparator) compareSectionParts(one, two *AddressSection) int {
	result := int(one.GetBitCount() - two.GetBitCount())
	if result == 0 {
		result = compareCount(one, two)
		if result == 0 {
			result = comp.compareEqualSizedSections(one, two)
		}
	}
	return result
}

func (comp countComparator) compareEqualSizedSections(one, two *AddressSection) int {
	segCount := one.GetSegmentCount()
	for i := 0; i < segCount; i++ {
		segOne := one.GetSegment(i)
		segTwo := two.GetSegment(i)
		oneUpper := segOne.GetUpperSegmentValue()
		twoUpper := segTwo.GetUpperSegmentValue()
		oneLower := segOne.GetSegmentValue()
		twoLower := segTwo.GetSegmentValue()
		result := comp.compareSegValues(oneUpper, oneLower, twoUpper, twoLower)
		if result != 0 {
			return result
		}
	}
	return 0
}

func (comp countComparator) compareParts(one, two AddressDivisionSeries) int {
	result := int(one.GetBitCount() - two.GetBitCount())
	if result == 0 {
		result = compareCount(one, two)
		if result == 0 {
			result = comp.compareDivisionGroupings(one, two)
		}
	}
	return result
}

func (comp countComparator) compareDivisionGroupings(oneSeries, twoSeries AddressDivisionSeries) int {
	var one, two *AddressDivisionGrouping
	if o, ok := oneSeries.(StandardDivisionGroupingType); ok {
		if t, ok := twoSeries.(StandardDivisionGroupingType); ok {
			one = o.ToAddressDivisionGrouping()
			two = t.ToAddressDivisionGrouping()
		}
	}
	result := compareDivBitCounts(oneSeries, twoSeries)
	if result != 0 {
		return result
	}

	oneSeriesByteCount := oneSeries.GetByteCount()
	twoSeriesByteCount := twoSeries.GetByteCount()

	oneUpperBytes := make([]byte, oneSeriesByteCount)
	oneLowerBytes := make([]byte, oneSeriesByteCount)
	twoUpperBytes := make([]byte, twoSeriesByteCount)
	twoLowerBytes := make([]byte, twoSeriesByteCount)

	var oneByteCount, twoByteCount, oneByteIndex, twoByteIndex, oneIndex, twoIndex int
	var oneBitCount, twoBitCount, oneTotalBitCount, twoTotalBitCount BitCount
	var oneUpper, oneLower, twoUpper, twoLower uint64
	for oneIndex < oneSeries.GetDivisionCount() || twoIndex < twoSeries.GetDivisionCount() {
		if one != nil {
			if oneBitCount == 0 {
				oneCombo := one.getDivision(oneIndex)
				oneIndex++
				oneBitCount = oneCombo.GetBitCount()
				oneUpper = oneCombo.GetUpperDivisionValue()
				oneLower = oneCombo.GetDivisionValue()
			}
			if twoBitCount == 0 {
				twoCombo := two.getDivision(twoIndex)
				twoIndex++
				twoBitCount = twoCombo.GetBitCount()
				twoUpper = twoCombo.GetUpperDivisionValue()
				twoLower = twoCombo.GetDivisionValue()
			}
		} else {
			if oneBitCount == 0 {
				if oneByteCount == 0 {
					oneCombo := oneSeries.GetGenericDivision(oneIndex)
					oneIndex++
					oneUpperBytes = oneCombo.CopyUpperBytes(oneUpperBytes)
					oneLowerBytes = oneCombo.CopyBytes(oneLowerBytes)
					oneTotalBitCount = oneCombo.GetBitCount()
					oneByteCount = oneCombo.GetByteCount()
					oneByteIndex = 0
				}
				//put some or all of the bytes into a uint64
				count := 8
				oneUpper = 0
				oneLower = 0
				if count < oneByteCount {
					oneBitCount = BitCount(count << 3)
					oneTotalBitCount -= oneBitCount
					oneByteCount -= count
					for count > 0 {
						count--
						upperByte := oneUpperBytes[oneByteIndex]
						lowerByte := oneLowerBytes[oneByteIndex]
						oneByteIndex++
						oneUpper = (oneUpper << 1) | uint64(upperByte)
						oneLower = (oneLower << 1) | uint64(lowerByte)
					}
				} else {
					shortCount := oneByteCount - 1
					lastBitsCount := oneTotalBitCount - (BitCount(shortCount) << 3)
					for shortCount > 0 {
						shortCount--
						upperByte := oneUpperBytes[oneByteIndex]
						lowerByte := oneLowerBytes[oneByteIndex]
						oneByteIndex++
						oneUpper = (oneUpper << 8) | uint64(upperByte)
						oneLower = (oneLower << 8) | uint64(lowerByte)
					}
					upperByte := oneUpperBytes[oneByteIndex]
					lowerByte := oneLowerBytes[oneByteIndex]
					oneByteIndex++
					oneUpper = (oneUpper << uint(lastBitsCount)) | uint64(upperByte>>uint(8-lastBitsCount))
					oneLower = (oneLower << uint(lastBitsCount)) | uint64(lowerByte>>uint(8-lastBitsCount))
					oneBitCount = oneTotalBitCount
					oneTotalBitCount = 0
					oneByteCount = 0
				}
			}
			if twoBitCount == 0 {
				if twoByteCount == 0 {
					twoCombo := twoSeries.GetGenericDivision(twoIndex)
					twoIndex++
					twoUpperBytes = twoCombo.CopyUpperBytes(twoUpperBytes)
					twoLowerBytes = twoCombo.CopyBytes(twoLowerBytes)
					twoTotalBitCount = twoCombo.GetBitCount()
					twoByteCount = twoCombo.GetByteCount()
					twoByteIndex = 0
				}
				//put some or all of the bytes into a long
				count := 8
				twoUpper = 0
				twoLower = 0
				if count < twoByteCount {
					twoBitCount = BitCount(count << 3)
					twoTotalBitCount -= twoBitCount
					twoByteCount -= count
					for count > 0 {
						count--
						upperByte := twoUpperBytes[twoByteIndex]
						lowerByte := twoLowerBytes[twoByteIndex]
						twoByteIndex++
						twoUpper = (twoUpper << 8) | uint64(upperByte)
						twoLower = (twoLower << 8) | uint64(lowerByte)
					}
				} else {
					shortCount := twoByteCount - 1
					lastBitsCount := twoTotalBitCount - (BitCount(shortCount) << 3)
					for shortCount > 0 {
						shortCount--
						upperByte := twoUpperBytes[twoByteIndex]
						lowerByte := twoLowerBytes[twoByteIndex]
						twoByteIndex++
						twoUpper = (twoUpper << 8) | uint64(upperByte)
						twoLower = (twoLower << 8) | uint64(lowerByte)
					}
					upperByte := twoUpperBytes[twoByteIndex]
					lowerByte := twoLowerBytes[twoByteIndex]
					twoByteIndex++
					twoUpper = (twoUpper << uint(lastBitsCount)) | uint64(upperByte>>uint(8-lastBitsCount))
					twoLower = (twoLower << uint(lastBitsCount)) | uint64(lowerByte>>uint(8-lastBitsCount))
					twoBitCount = twoTotalBitCount
					twoTotalBitCount = 0
					twoByteCount = 0
				}
			}
		}
		oneResultUpper := oneUpper
		oneResultLower := oneLower
		twoResultUpper := twoUpper
		twoResultLower := twoLower
		if twoBitCount == oneBitCount {
			//no adjustment required, compare the values straight up
			oneBitCount = 0
			twoBitCount = 0
		} else {
			diffBits := twoBitCount - oneBitCount
			if diffBits > 0 {
				twoResultUpper >>= uint(diffBits) //look at the high bits only (we are comparing left to right, high to low)
				twoResultLower >>= uint(diffBits)
				mask := ^(^uint64(0) << uint(diffBits))
				twoUpper &= mask
				twoLower &= mask
				twoBitCount = diffBits
				oneBitCount = 0
			} else {
				diffBits = -diffBits
				oneResultUpper >>= uint(diffBits)
				oneResultLower >>= uint(diffBits)
				mask := ^(^uint64(0) << uint(diffBits))
				oneUpper &= mask
				oneLower &= mask
				oneBitCount = diffBits
				twoBitCount = 0
			}
		}
		result := comp.compareValues(oneResultUpper, oneResultLower, twoResultUpper, twoResultLower)
		if result != 0 {
			return result
		}
	}
	return 0
}

func (countComparator) compareSegValues(oneUpper, oneLower, twoUpper, twoLower SegInt) int {
	size1 := oneUpper - oneLower
	size2 := twoUpper - twoLower
	if size1 == size2 {
		//the size of the range is the same, so just compare either upper or lower values
		if oneLower == twoLower {
			return 0
		} else if oneLower > twoLower {
			return 1
		}
	} else if size1 > size2 {
		return 1
	}
	return -1
}

func (countComparator) compareValues(oneUpper, oneLower, twoUpper, twoLower uint64) int {
	size1 := oneUpper - oneLower
	size2 := twoUpper - twoLower
	if size1 == size2 {
		//the size of the range is the same, so just compare either upper or lower values
		if oneLower == twoLower {
			return 0
		} else if oneLower > twoLower {
			return 1
		}
	} else if size1 > size2 {
		return 1
	}
	return -1
}

func (countComparator) compareLargeValues(oneUpper, oneLower, twoUpper, twoLower *big.Int) (result int) {
	oneUpper.Sub(oneUpper, oneLower)
	twoUpper.Sub(twoUpper, twoLower)
	result = oneUpper.Cmp(twoUpper)
	if result == 0 {
		//the size of the range is the same, so just compare either upper or lower values
		result = oneLower.Cmp(twoLower)
	}
	return
}

func compareDivBitCounts(oneSeries, twoSeries AddressDivisionSeries) int {
	//when this is called we know the two series have the same bit-size, we want to check that the divisions
	//also have the same bit size (which of course also implies that there are the same number of divisions)
	count := oneSeries.GetDivisionCount()
	result := count - twoSeries.GetDivisionCount()
	if result == 0 {
		for i := 0; i < count; i++ {
			result = int(oneSeries.GetGenericDivision(i).GetBitCount() - twoSeries.GetGenericDivision(i).GetBitCount())
			if result != 0 {
				break
			}
		}
	}
	return result
}

func compareCount(one, two AddressDivisionSeries) int {
	return one.CompareSize(two)
}
