//
// Copyright 2020-2022 Sean C Foley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package ipaddr

import (
	"container/list"
	"math/bits"
)

// getSpanningPrefixBlocks returns the smallest set of prefix blocks that spans both this and the supplied address or subnet.
func getSpanningPrefixBlocks(
	first,
	other ExtendedIPSegmentSeries,
) []ExtendedIPSegmentSeries {
	result := checkPrefixBlockContainment(first, other)
	if result != nil {
		return wrapNonNilInSlice(result)
	}
	return applyOperatorToLowerUpper(
		first,
		other,
		true,
		splitIntoPrefixBlocks)
}

func getSpanningSequentialBlocks(
	first,
	other ExtendedIPSegmentSeries,
) []ExtendedIPSegmentSeries {
	result := checkSequentialBlockContainment(first, other)
	if result != nil {
		return wrapNonNilInSlice(result)
	}
	return applyOperatorToLowerUpper(
		first,
		other,
		true,
		splitIntoSequentialBlocks)
}

func checkPrefixBlockContainment(
	first,
	other ExtendedIPSegmentSeries,
) ExtendedIPSegmentSeries {
	if first.Contains(other) {
		return checkPrefixBlockFormat(first, other, true)
		//return checkPrefixBlockFormat(first, other, true, prefixAdder, arrayProducer);
		//return cloneToIPSections(checkPrefixBlockFormat(first, other, true,
		//	func(series AddressSegmentSeries) AddressSegmentSeries { return prefixAdder(series.(*IPAddressSection)) },
		//))
	} else if other.Contains(first) {
		return checkPrefixBlockFormat(other, first, false)
		//return checkPrefixBlockFormat(other, first, false, prefixAdder, arrayProducer);
		//return cloneToIPSections(checkPrefixBlockFormat(other, first, false,
		//	func(series AddressSegmentSeries) AddressSegmentSeries { return prefixAdder(series.(*IPAddressSection)) },
		//))
	}
	return nil
}

func wrapNonNilInSlice(result ExtendedIPSegmentSeries) []ExtendedIPSegmentSeries {
	if result != nil {
		return []ExtendedIPSegmentSeries{result}
	}
	return nil
}

func checkSequentialBlockContainment(
	first,
	other ExtendedIPSegmentSeries,
) ExtendedIPSegmentSeries {
	if first.Contains(other) {
		return checkSequentialBlockFormat(first, other, true)
		//	return checkSequentialBlockFormat(first, other, true, prefixRemover, arrayProducer);
	} else if other.Contains(first) {
		//return checkSequentialBlockFormat(other, first, false, prefixRemover, arrayProducer);
		return checkSequentialBlockFormat(other, first, false)
	}
	return nil
}

func checkPrefixBlockFormat(
	container,
	contained ExtendedIPSegmentSeries,
	checkEqual bool,
) (result ExtendedIPSegmentSeries) {
	if container.IsPrefixed() && container.IsSinglePrefixBlock() {
		result = container
	} else if checkEqual && contained.IsPrefixed() && container.CompareSize(contained) == 0 && contained.IsSinglePrefixBlock() {
		result = contained
	} else {
		result = container.AssignPrefixForSingleBlock() // this returns nil if cannot be a prefix block
	}
	return
}

func checkSequentialBlockFormat(
	container,
	contained ExtendedIPSegmentSeries,
	checkEqual bool,
) (result ExtendedIPSegmentSeries) {
	if !container.IsPrefixed() {
		if container.IsSequential() {
			result = container
		}
	} else if checkEqual && !contained.IsPrefixed() && container.CompareSize(contained) == 0 {
		if contained.IsSequential() {
			result = contained
		}
	} else if container.IsSequential() {
		result = container.WithoutPrefixLen()
	}
	return
}

func splitIntoSequentialBlocks(
	lower,
	upper ExtendedIPSegmentSeries) (blocks []ExtendedIPSegmentSeries) {

	segCount := lower.GetDivisionCount()
	if segCount == 0 {
		//all segments match, it's just a single series
		//blocks.add(lower);
		return []ExtendedIPSegmentSeries{lower}
	}
	blocks = make([]ExtendedIPSegmentSeries, 0, IPv6SegmentCount)
	var previousSegmentBits BitCount
	var currentSegment int
	bitsPerSegment := lower.GetBitsPerSegment()
	var segSegment int
	var lowerValue, upperValue SegInt
	var stack seriesStack
	var toAdd list.List
	toAdd.Init()
	for {
		for {
			segSegment = currentSegment
			lowerSeg := lower.GetGenericSegment(currentSegment)
			upperSeg := upper.GetGenericSegment(currentSegment)
			currentSegment++
			lowerValue = lowerSeg.GetSegmentValue() // these are single addresses, so lower or upper value no different here
			upperValue = upperSeg.GetSegmentValue()
			previousSegmentBits += bitsPerSegment
			if lowerValue != upperValue || currentSegment >= segCount {
				break
			}
		}
		if lowerValue == upperValue {
			blocks = append(blocks, lower)
		} else {
			lowerIsLowest := lower.IncludesZeroHostLen(previousSegmentBits)
			higherIsHighest := upper.IncludesMaxHostLen(previousSegmentBits)
			if lowerIsLowest {
				if higherIsHighest {
					// full range
					series := lower.ToBlock(segSegment, lowerValue, upperValue)
					blocks = append(blocks, series)
				} else {
					topLower, _ := upper.ToZeroHostLen(previousSegmentBits)
					middleUpper := topLower.Increment(-1)
					series := lower.ToBlock(segSegment, lowerValue, middleUpper.GetGenericSegment(segSegment).GetSegmentValue())
					blocks = append(blocks, series)
					lower = topLower
					continue
				}
			} else if higherIsHighest {
				bottomUpper, _ := lower.ToMaxHostLen(previousSegmentBits)
				topLower := bottomUpper.Increment(1)
				series := topLower.ToBlock(segSegment, topLower.GetGenericSegment(segSegment).GetSegmentValue(), upperValue)
				toAdd.PushFront(series)
				upper = bottomUpper
				continue
			} else {
				//from top to bottom we have: top - topLower - middleUpper - middleLower - bottomUpper - lower
				topLower, _ := upper.ToZeroHostLen(previousSegmentBits)
				middleUpper := topLower.Increment(-1)
				bottomUpper, _ := lower.ToMaxHostLen(previousSegmentBits)
				middleLower := bottomUpper.Increment(1)
				if LowValueComparator.CompareSeries(middleLower, middleUpper) <= 0 {
					series := middleLower.ToBlock(
						segSegment,
						middleLower.GetGenericSegment(segSegment).GetSegmentValue(),
						middleUpper.GetGenericSegment(segSegment).GetSegmentValue())
					toAdd.PushFront(series)
				}

				stack.init(IPv6SegmentCount)

				stack.push(topLower, upper, previousSegmentBits, currentSegment) // do this one later
				upper = bottomUpper
				continue
			}
		}
		if toAdd.Len() != 0 {
			for {
				saved := toAdd.Front()
				if saved == nil {
					break
				}
				toAdd.Remove(saved)
				blocks = append(blocks, saved.Value.(ExtendedIPSegmentSeries))
			}
		}
		var popped bool
		if popped, lower, upper, previousSegmentBits, currentSegment = stack.pop(); !popped {
			return blocks
		}
	}
}

func splitIntoPrefixBlocks(
	lower,
	upper ExtendedIPSegmentSeries) (blocks []ExtendedIPSegmentSeries) {

	blocks = make([]ExtendedIPSegmentSeries, 0, IPv6BitCount)

	var previousSegmentBits BitCount
	var currentSegment int
	var stack seriesStack

	segCount := lower.GetDivisionCount()
	bitsPerSegment := lower.GetBitsPerSegment()
	for {
		//Find first non-matching bit.
		var differing SegInt
		for ; currentSegment < segCount; currentSegment++ {
			lowerSeg := lower.GetGenericSegment(currentSegment)
			upperSeg := upper.GetGenericSegment(currentSegment)
			lowerValue := lowerSeg.GetSegmentValue() //these are single addresses, so lower or upper value no different here
			upperValue := upperSeg.GetSegmentValue()
			differing = lowerValue ^ upperValue
			if differing != 0 {
				break
			}
			previousSegmentBits += bitsPerSegment
		}
		if differing == 0 {
			//all bits match, it's just a single address
			blocks = append(blocks, lower.ToPrefixBlockLen(lower.GetBitCount()))
		} else {
			differingIsLowestBit := differing == 1
			if differingIsLowestBit && currentSegment+1 == segCount {
				//only the very last bit differs, so we have a prefix block right there
				blocks = append(blocks, lower.ToPrefixBlockLen(lower.GetBitCount()-1))
			} else {
				highestDifferingBitInRange := BitCount(bits.LeadingZeros32(uint32(differing))) - (32 - bitsPerSegment)
				differingBitPrefixLen := highestDifferingBitInRange + previousSegmentBits
				if lower.IncludesZeroHostLen(differingBitPrefixLen) && upper.IncludesMaxHostLen(differingBitPrefixLen) {
					//full range at the differing bit, we have a single prefix block
					blocks = append(blocks, lower.ToPrefixBlockLen(differingBitPrefixLen))
				} else {
					//neither a prefix block nor a single address
					//we split into two new ranges to continue
					//starting from the differing bit,
					//lower top becomes 1000000...
					//upper bottom becomes 01111111...
					//so in each new range, the differing bit is at least one further to the right (or more)
					lowerTop, _ := upper.ToZeroHostLen(differingBitPrefixLen + 1)
					upperBottom := lowerTop.Increment(-1)
					if differingIsLowestBit {
						previousSegmentBits += bitsPerSegment
						currentSegment++
					}
					stack.init(int(IPv6BitCount))
					stack.push(lowerTop, upper, previousSegmentBits, currentSegment) // do upper one later
					upper = upperBottom                                              // do lower one now
					continue
				}
			}
		}
		var popped bool
		if popped, lower, upper, previousSegmentBits, currentSegment = stack.pop(); !popped {
			return blocks
		}
	}
}

func applyOperatorToLowerUpper(
	first,
	other ExtendedIPSegmentSeries,
	removePrefixes bool,
	operatorFunctor func(lower, upper ExtendedIPSegmentSeries) []ExtendedIPSegmentSeries) []ExtendedIPSegmentSeries {
	var lower, upper ExtendedIPSegmentSeries
	if seriesValsSame(first, other) {
		if removePrefixes && first.IsPrefixed() {
			if other.IsPrefixed() {
				lower = first.WithoutPrefixLen()
			} else {
				lower = other
			}
		} else {
			lower = first
		}
		upper = lower.GetUpper()
		lower = lower.GetLower()
	} else {
		firstLower := first.GetLower()
		otherLower := other.GetLower()
		firstUpper := first.GetUpper()
		otherUpper := other.GetUpper()
		if LowValueComparator.CompareSeries(firstLower, otherLower) > 0 {
			lower = otherLower
		} else {
			lower = firstLower
		}
		if LowValueComparator.CompareSeries(firstUpper, otherUpper) < 0 {
			upper = otherUpper
		} else {
			upper = firstUpper
		}
		if removePrefixes {
			lower = lower.WithoutPrefixLen()
			upper = upper.WithoutPrefixLen()
		}
	}
	return operatorFunctor(lower, upper)
}

type seriesStack struct {
	seriesPairs []ExtendedIPSegmentSeries // stack items
	indexes     []int                     // stack items
	bits        []BitCount                // stack items
}

// grows to have capacity at least as large as size
func (stack *seriesStack) init(size int) {
	if stack.seriesPairs == nil {
		stack.seriesPairs = make([]ExtendedIPSegmentSeries, 0, size<<1)
		stack.indexes = make([]int, 0, size)
		stack.bits = make([]BitCount, 0, size)
	}
}

func (stack *seriesStack) push(lower, upper ExtendedIPSegmentSeries, previousSegmentBits BitCount, currentSegment int) {
	stack.seriesPairs = append(stack.seriesPairs, lower, upper)
	stack.indexes = append(stack.indexes, currentSegment)
	stack.bits = append(stack.bits, previousSegmentBits)
}

func (stack *seriesStack) pop() (popped bool, lower, upper ExtendedIPSegmentSeries, previousSegmentBits BitCount, currentSegment int) {
	seriesPairs := stack.seriesPairs
	length := len(seriesPairs)
	if length <= 0 {
		return
	}
	length--
	upper = seriesPairs[length]
	length--
	lower = seriesPairs[length]
	stack.seriesPairs = seriesPairs[:length]
	indexes := stack.indexes
	length = len(indexes) - 1
	currentSegment = indexes[length]
	stack.indexes = indexes[:length]
	stackbits := stack.bits
	previousSegmentBits = stackbits[length]
	stack.bits = stackbits[:length]
	popped = true
	return
}

func spanWithPrefixBlocks(orig ExtendedIPSegmentSeries) (list []ExtendedIPSegmentSeries) {
	iterator := orig.SequentialBlockIterator()
	for iterator.HasNext() {
		list = append(list, iterator.Next().SpanWithPrefixBlocks()...)
	}
	return list
}

func spanWithSequentialBlocks(orig ExtendedIPSegmentSeries) (list []ExtendedIPSegmentSeries) {
	iterator := orig.SequentialBlockIterator()
	for iterator.HasNext() {
		list = append(list, iterator.Next())
	}
	return list
}
