//
// Copyright 2020-2021 Sean C Foley
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
	//getLower,
	//getUpper func(*IPAddressSection) *IPAddressSection,
	//comparator func(IPAddressSegmentSeries, IPAddressSegmentSeries) int,
	//prefixAdder,
	//prefixRemover func(*IPAddressSection) *IPAddressSection
) []ExtendedIPSegmentSeries {
	//IntFunction<R[]> arrayProducer) []*IPAddressSection {

	result := checkPrefixBlockContainment(first, other)
	//result := checkPrefixBlockContainment(first, other, prefixAdder)
	if result != nil {
		return wrapNonNilInSlice(result)
	}
	return applyOperatorToLowerUpper(
		first,
		other,
		//func(series AddressSegmentSeries) AddressSegmentSeries { return getLower(series.(*IPAddressSection)) },
		//func(series AddressSegmentSeries) AddressSegmentSeries { return getUpper(series.(*IPAddressSection)) },
		//func(one, two ExtendedIPSegmentSeries) int {
		//	return comparator(one.(*IPAddressSection), two.(*IPAddressSection))
		//},
		//comparator,
		true,
		//func(series AddressSegmentSeries) AddressSegmentSeries {
		//	return prefixRemover(series.(*IPAddressSection))
		//},
		//func(orig, lower, upper ExtendedIPSegmentSeries) interface{} {
		//	return splitIntoPrefixBlocks(lower, upper)
		//}
		splitIntoPrefixBlocks)
	//);
	//return blocks.([]ExtendedIPSegmentSeries)
	//return cloneToIPSections(blocks.([]AddressSegmentSeries)), nil
	//List<IPAddressSegmentSeries> blocks = applyOperatorToLowerUpper(first, other, getLower, getUpper, comparator, prefixRemover, (orig, lower, upper) -> IPAddressSection.splitIntoPrefixBlocks(lower, upper));
	//result = blocks.toArray(arrayProducer.apply(blocks.size()));
	//return result;

	//blocks := applyOperatorToLowerUpper(
	//	first,
	//	other,
	//	//func(series AddressSegmentSeries) AddressSegmentSeries { return getLower(series.(*IPAddressSection)) },
	//	//func(series AddressSegmentSeries) AddressSegmentSeries { return getUpper(series.(*IPAddressSection)) },
	//	//func(one, two ExtendedIPSegmentSeries) int {
	//	//	return comparator(one.(*IPAddressSection), two.(*IPAddressSection))
	//	//},
	//	//comparator,
	//	true,
	//	//func(series AddressSegmentSeries) AddressSegmentSeries {
	//	//	return prefixRemover(series.(*IPAddressSection))
	//	//},
	//	func(orig, lower, upper ExtendedIPSegmentSeries) interface{} {
	//		return splitIntoPrefixBlocks(lower, upper)
	//	})
	////);
	//return blocks.([]ExtendedIPSegmentSeries)
	////return cloneToIPSections(blocks.([]AddressSegmentSeries)), nil
	////List<IPAddressSegmentSeries> blocks = applyOperatorToLowerUpper(first, other, getLower, getUpper, comparator, prefixRemover, (orig, lower, upper) -> IPAddressSection.splitIntoPrefixBlocks(lower, upper));
	////result = blocks.toArray(arrayProducer.apply(blocks.size()));
	////return result;
}

func getSpanningSequentialBlocks(
	first,
	other ExtendedIPSegmentSeries,
	//UnaryOperator<R> getLower,
	//UnaryOperator<R> getUpper,
	//Comparator<R> comparator,
	//UnaryOperator<R> prefixRemover,
	//ipAddressCreator<?, R, ?, S, ?> creator
) []ExtendedIPSegmentSeries {
	result := checkSequentialBlockContainment(first, other)
	if result != nil {
		return wrapNonNilInSlice(result)
	}
	return applyOperatorToLowerUpper(
		first,
		other,
		//func(series AddressSegmentSeries) AddressSegmentSeries { return getLower(series.(*IPAddressSection)) },
		//func(series AddressSegmentSeries) AddressSegmentSeries { return getUpper(series.(*IPAddressSection)) },
		//func(one, two ExtendedIPSegmentSeries) int {
		//	return comparator(one.(*IPAddressSection), two.(*IPAddressSection))
		//},
		//comparator,
		true,
		//func(series AddressSegmentSeries) AddressSegmentSeries {
		//	return prefixRemover(series.(*IPAddressSection))
		//},
		//func(orig, lower, upper ExtendedIPSegmentSeries) interface{} {
		//	return splitIntoSequentialBlocks(lower, upper)
		//}
		splitIntoSequentialBlocks)

	//TriFunction<R, List<IPAddressSegmentSeries>> operatorFunctor = (orig, one, two) -> IPAddressSection.splitIntoSequentialBlocks(one, two, creator::createSequentialBlockSection);
	//List<IPAddressSegmentSeries> blocks = applyOperatorToLowerUpper(first, other, getLower, getUpper, comparator, prefixRemover, operatorFunctor);
	//return blocks.toArray(creator.createSectionArray(blocks.size()));
	//return blocks.([]ExtendedIPSegmentSeries)

	//blocks := applyOperatorToLowerUpper(
	//	first,
	//	other,
	//	//func(series AddressSegmentSeries) AddressSegmentSeries { return getLower(series.(*IPAddressSection)) },
	//	//func(series AddressSegmentSeries) AddressSegmentSeries { return getUpper(series.(*IPAddressSection)) },
	//	//func(one, two ExtendedIPSegmentSeries) int {
	//	//	return comparator(one.(*IPAddressSection), two.(*IPAddressSection))
	//	//},
	//	//comparator,
	//	true,
	//	//func(series AddressSegmentSeries) AddressSegmentSeries {
	//	//	return prefixRemover(series.(*IPAddressSection))
	//	//},
	//	func(orig, lower, upper ExtendedIPSegmentSeries) interface{} {
	//		return splitIntoSequentialBlocks(lower, upper)
	//	})
	//
	////TriFunction<R, List<IPAddressSegmentSeries>> operatorFunctor = (orig, one, two) -> IPAddressSection.splitIntoSequentialBlocks(one, two, creator::createSequentialBlockSection);
	////List<IPAddressSegmentSeries> blocks = applyOperatorToLowerUpper(first, other, getLower, getUpper, comparator, prefixRemover, operatorFunctor);
	////return blocks.toArray(creator.createSectionArray(blocks.size()));
	//return blocks.([]ExtendedIPSegmentSeries)
}

//protected static <T extends IPAddress, S extends IPAddressSegment> T[] getSpanningSequentialBlocks(
//		T first,
//		T other,
//		UnaryOperator<T> getLower,
//		UnaryOperator<T> getUpper,
//		Comparator<T> comparator,
//		UnaryOperator<T> prefixRemover,
//		ipAddressCreator<T, ?, ?, S, ?> creator) {
//	T[] result = checkSequentialBlockContainment(first, other, prefixRemover, creator::createAddressArray);
//	if(result != null) {
//		return result;
//	}
//	SeriesCreator seriesCreator = creator::createSequentialBlockAddress;
//	TriFunction<T, List<IPAddressSegmentSeries>> operatorFunctor = (orig, one, two) -> IPAddressSection.splitIntoSequentialBlocks(one, two, seriesCreator);
//	List<IPAddressSegmentSeries> blocks = IPAddressSection.applyOperatorToLowerUpper(first, other, getLower, getUpper, comparator, prefixRemover, operatorFunctor);
//	return blocks.toArray(creator.createAddressArray(blocks.size()));
//}

func checkPrefixBlockContainment(
	first,
	other ExtendedIPSegmentSeries,
	//prefixAdder func(*IPAddressSection) *IPAddressSection
) ExtendedIPSegmentSeries {
	//IntFunction<R[]> arrayProducer) []*IPAddressSection {
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
	//UnaryOperator<T> prefixRemover,
	//IntFunction<T[]> arrayProducer
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

//func checkPrefixBlockFormat(
//	container,
//	contained ExtendedIPSegmentSeries,
//	checkEqual bool,
//) []ExtendedIPSegmentSeries {
//	//prefixAdder func(AddressSegmentSeries) AddressSegmentSeries) []AddressSegmentSeries {
//	//IntFunction<T[]> arrayProducer) {
//	var result ExtendedIPSegmentSeries
//	if container.IsPrefixed() {
//		if container.IsSinglePrefixBlock() {
//			result = container
//		}
//	} else if checkEqual && contained.IsPrefixed() && container.CompareSize(contained) == 0 && contained.IsSinglePrefixBlock() {
//		result = contained
//	} else {
//		result = container.AssignPrefixForSingleBlock() // this returns nil if cannot be a prefix block
//		//result = prefixAdder(container) // this returns nil if cannot be a prefix block
//	}
//	if result != nil {
//		return []ExtendedIPSegmentSeries{result}
//		//T resultArray[] = arrayProducer.apply(1);
//		//resultArray[0] = result;
//		//return resultArray;
//	}
//	return nil
//	//return null;
//}

func checkPrefixBlockFormat(
	container,
	contained ExtendedIPSegmentSeries,
	checkEqual bool,
) (result ExtendedIPSegmentSeries) {
	//prefixAdder func(AddressSegmentSeries) AddressSegmentSeries) []AddressSegmentSeries {
	//IntFunction<T[]> arrayProducer) {
	//xxx is this right?  if first is prefixed but prefix len does not match block len
	//then second might have prfix len that does
	if container.IsPrefixed() && container.IsSinglePrefixBlock() {
		result = container
	} else if checkEqual && contained.IsPrefixed() && container.CompareSize(contained) == 0 && contained.IsSinglePrefixBlock() {
		result = contained
	} else {
		result = container.AssignPrefixForSingleBlock() // this returns nil if cannot be a prefix block
		//result = prefixAdder(container) // this returns nil if cannot be a prefix block
	}
	return
	//if result != nil {
	//	return []ExtendedIPSegmentSeries{result}
	//	//T resultArray[] = arrayProducer.apply(1);
	//	//resultArray[0] = result;
	//	//return resultArray;
	//}
	//return nil
	//return null;
}

func checkSequentialBlockFormat(
	container,
	contained ExtendedIPSegmentSeries,
	checkEqual bool,
	//UnaryOperator<T> prefixRemover,
	//IntFunction<T[]> arrayProducer
) (result ExtendedIPSegmentSeries) {
	//var result ExtendedIPSegmentSeries
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
		//result = prefixRemover.apply(container)
	}
	return
	//if result != nil {
	//	return []ExtendedIPSegmentSeries{result}
	//	//T resultArray[] = arrayProducer.apply(1);
	//	//resultArray[0] = result;
	//	//return resultArray;
	//}
	//return nil
}

//
//func checkSequentialBlockFormat(
//	container,
//	contained ExtendedIPSegmentSeries,
//	checkEqual bool,
//	//UnaryOperator<T> prefixRemover,
//	//IntFunction<T[]> arrayProducer
//) []ExtendedIPSegmentSeries {
//	var result ExtendedIPSegmentSeries
//	if !container.IsPrefixed() {
//		if container.IsSequential() {
//			result = container
//		}
//	} else if checkEqual && !contained.IsPrefixed() && container.CompareSize(contained) == 0 {
//		if contained.IsSequential() {
//			result = contained
//		}
//	} else if container.IsSequential() {
//		result = container.WithoutPrefixLen()
//		//result = prefixRemover.apply(container)
//	}
//	if result != nil {
//		return []ExtendedIPSegmentSeries{result}
//		//T resultArray[] = arrayProducer.apply(1);
//		//resultArray[0] = result;
//		//return resultArray;
//	}
//	return nil
//}

//private static <R extends IPAddressSection> R[] checkSequentialBlockContainment(
//			R first,
//			R other,
//			UnaryOperator<R> prefixRemover,
//			IntFunction<R[]> arrayProducer) {
//		if(first.contains(other)) {
//			return IPAddress.checkSequentialBlockFormat(first, other, true, prefixRemover, arrayProducer);
//		} else if(other.contains(first)) {
//			return IPAddress.checkSequentialBlockFormat(other, first, false, prefixRemover, arrayProducer);
//		}
//		return null;
//	}

//
//	@FunctionalInterface
//	public interface SeriesCreator {
//		IPAddressSegmentSeries apply(IPAddressSegmentSeries segmentSeries, int index, int lowerVal, int upperVal);
//	}
//
//SeriesCreator seriesCreator
func splitIntoSequentialBlocks(
	lower,
	upper ExtendedIPSegmentSeries) (blocks []ExtendedIPSegmentSeries) {
	//ArrayList<IPAddressSegmentSeries> blocks = new ArrayList<>(IPv6Address.SEGMENT_COUNT);

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
	//seriesStack stack = null;
	var stack seriesStack
	var toAdd list.List
	toAdd.Init()
	//Deque<IPAddressSegmentSeries> toAdd = null;
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
			//fmt.Printf("block a %v\n", lower)
			blocks = append(blocks, lower)
		} else {
			lowerIsLowest := lower.IncludesZeroHostLen(previousSegmentBits)
			higherIsHighest := upper.IncludesMaxHostLen(previousSegmentBits)
			if lowerIsLowest {
				if higherIsHighest {
					// full range
					series := lower.ToBlock(segSegment, lowerValue, upperValue)
					//fmt.Printf("block b %v\n", series)
					blocks = append(blocks, series)
				} else {
					topLower, _ := upper.ToZeroHostLen(previousSegmentBits)
					middleUpper := topLower.Increment(-1)
					series := lower.ToBlock(segSegment, lowerValue, middleUpper.GetGenericSegment(segSegment).GetSegmentValue())
					//IPAddressSegmentSeries series = seriesCreator.apply(lower, segSegment, lowerValue, middleUpper.getSegment(segSegment).getSegmentValue());
					blocks = append(blocks, series)
					//fmt.Printf("split %v - %v to %v - %v / %v and %v - %v\n", lower, upper, lower, middleUpper, series, topLower, upper)
					//fmt.Printf("block c %v\n", series)
					lower = topLower
					continue
				}
			} else if higherIsHighest {
				bottomUpper, _ := lower.ToMaxHostLen(previousSegmentBits)
				topLower := bottomUpper.Increment(1)
				//series := topLower.ToBlock(segSegment, topLower.GetGenericSegment(segSegment).GetSegmentValue(), upperValue)
				series := topLower.ToBlock(segSegment, topLower.GetGenericSegment(segSegment).GetSegmentValue(), upperValue)
				//IPAddressSegmentSeries series = seriesCreator.apply(topLower, segSegment,
				//	topLower.getSegment(segSegment).getSegmentValue(), upperValue);
				//if(toAdd == null) {
				//	toAdd = new ArrayDeque<>(IPv6Address.SEGMENT_COUNT);
				//}
				//toAdd.addFirst(series);
				toAdd.PushFront(series)
				//fmt.Printf("split %v - %v to %v - %v and %v - %v / %v\n", lower, upper, lower, bottomUpper, topLower, upper, series)
				//fmt.Printf("block d %v\n", series)
				upper = bottomUpper
				continue
			} else { //lower 2:3:ffff:5:: to upper 2:4:1:5::      2:3:ffff:5:: to 2:3:ffff:ffff:ffff:ffff:ffff:ffff and 2:4:: to 2:3:ffff:ffff:ffff:ffff:ffff:ffff and 2:4:: to 2:4:1:5::
				//from top to bottom we have: top - topLower - middleUpper - middleLower - bottomUpper - lower
				topLower, _ := upper.ToZeroHostLen(previousSegmentBits)   //2:4::
				middleUpper := topLower.Increment(-1)                     //2:3:ffff:ffff:ffff:ffff:ffff:ffff
				bottomUpper, _ := lower.ToMaxHostLen(previousSegmentBits) //2:3:ffff:ffff:ffff:ffff:ffff:ffff
				middleLower := bottomUpper.Increment(1)                   //2:4::
				//fmt.Printf("split %v - %v to %v - %v and %v - %v\n", lower, upper, lower, bottomUpper, topLower, upper)
				if LowValueComparator.CompareSeries(middleLower, middleUpper) <= 0 {
					//if(middleLower.Compare(middleUpper) <= 0) {
					series := middleLower.ToBlock(
						segSegment,
						middleLower.GetGenericSegment(segSegment).GetSegmentValue(),
						middleUpper.GetGenericSegment(segSegment).GetSegmentValue())
					//IPAddressSegmentSeries series = seriesCreator.apply(middleLower,
					//	segSegment,
					//	middleLower.getSegment(segSegment).getSegmentValue(),
					//	middleUpper.getSegment(segSegment).getSegmentValue());
					//if(toAdd == null) {
					//	toAdd = new ArrayDeque<>(IPv6Address.SEGMENT_COUNT);
					//}
					//toAdd.addFirst(series);
					//fmt.Printf("block e %v\n", series)
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

// I think it makes sense to wrap the address or section type:
//The benefit is that I can avoid implementing dup methods of ToPrefixBlockLen and others everywhere
//However, we need a new wrapped type for each type we want to wrap (actually no, just one for each base type, IPAddress and IPAddressSection), so we do duplicate those methods to an extent.
//So, what about the interface, it seems clear we have the "wrapped" methods and the non-wrapped.
//So we really do not want to make some framework type with all those methods in IPAddressSegmentSeries
// just the ones we use here, that is all
// I would say a new interface called ExtendedIPSegmentSeries
// And two new structs, WrappedIPAddress and WrappedIPSection
// This would actually help in Java where the "contains" methods causes duplicate methods
// but over there, we would then have to implement all the other wrapped methods, a PITA
// so maybe just here can we also eliminate contains and have one set of methods
// Pretty cool... cleans up my ugly code above with all the funcs being wrapped

// ToPrefixBlockLen(BitCount), ToZeroHost(BitCount), ToMaxHost(BitCount), Increment(int64)
/*
type wrappedType struct {
	IPAddressSection // anon field so we get all the other IPAddressSegmentSeries methods
}

// IPAddressSegmentSeries methods that return something of same type, like increment, like ToPrefixBlockLen
//

func (w wrappedType) ToPrefixBlockLen() IPAddressSegmentSeries {
	return wrappedType{w.IPAddressSection.ToPrefixBlockLen()}
}
*/

func splitIntoPrefixBlocks(
	lower,
	upper ExtendedIPSegmentSeries) (blocks []ExtendedIPSegmentSeries) {

	blocks = make([]ExtendedIPSegmentSeries, 0, IPv6BitCount)
	//
	//		ArrayList<IPAddressSegmentSeries> blocks = new ArrayList<>();
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
			differingIsLowestBit := (differing == 1)
			if differingIsLowestBit && currentSegment+1 == segCount {
				//only the very last bit differs, so we have a prefix block right there
				//fmt.Printf("pref block a %v\n", lower)
				blocks = append(blocks, lower.ToPrefixBlockLen(lower.GetBitCount()-1))
			} else {
				highestDifferingBitInRange := BitCount(bits.LeadingZeros32(uint32(differing))) - (32 - bitsPerSegment)
				differingBitPrefixLen := highestDifferingBitInRange + previousSegmentBits
				if lower.IncludesZeroHostLen(differingBitPrefixLen) && upper.IncludesMaxHostLen(differingBitPrefixLen) {
					//full range at the differing bit, we have a single prefix block
					//fmt.Printf("pref block b %v\n", lower)
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
					//fmt.Printf("split %v - %v to %v - %v  and %v - %v\n", lower, upper, lowerTop, upper, lower, upperBottom)
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
	//static <R extends IPAddressSegmentSeries, OperatorResult> OperatorResult applyOperatorToLowerUpper(
	first,
	other ExtendedIPSegmentSeries,
	//getLower,
	//getUpper func(AddressSegmentSeries) AddressSegmentSeries,
	//comparator func(IPAddressSegmentSeries, IPAddressSegmentSeries) int,
	//prefixRemover func(AddressSegmentSeries) AddressSegmentSeries,
	removePrefixes bool,
	operatorFunctor func(lower, upper ExtendedIPSegmentSeries) []ExtendedIPSegmentSeries) []ExtendedIPSegmentSeries {
	var lower, upper ExtendedIPSegmentSeries
	//isFirst, isOther := true, true
	if seriesValsSame(first, other) {
		//if first.Equal(other) {
		if removePrefixes && first.IsPrefixed() {
			if other.IsPrefixed() {
				lower = first.WithoutPrefixLen()
				//isOther = false
				//isFirst = false
			} else {
				lower = other
				//isFirst = false
			}
		} else {
			//isOther = false
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
			//if firstLower.Compare(otherLower) > 0 {
			lower = otherLower
			//isFirst = false
		} else {
			lower = firstLower
			//isOther = false
		}
		if LowValueComparator.CompareSeries(firstUpper, otherUpper) < 0 {
			//if firstUpper.Compare(otherUpper) < 0 {
			upper = otherUpper
			//isFirst = false
		} else {
			upper = firstUpper
			//isOther = false
		}
		if removePrefixes {
			lower = lower.WithoutPrefixLen()
			upper = upper.WithoutPrefixLen()
		}
	}
	// We pass the first arg to the operator func if both the lower and upper args came from the first arg.
	// In the case of coverWithPrefixBlock, if the lower and upper are both from the first, and the first is a prefix block, then the first can be reused,
	// rather than create a new prefix block each time.
	// In other words, when passing in a prefix block as the original, we reuse it.
	//var sourceLowerUpper ExtendedIPSegmentSeries
	//if isFirst {
	//	sourceLowerUpper = first
	//} else if isOther {
	//	sourceLowerUpper = other
	//}
	return operatorFunctor(lower, upper)
}

//func applyOperatorToLowerUpper(
////static <R extends IPAddressSegmentSeries, OperatorResult> OperatorResult applyOperatorToLowerUpper(
//	first,
//	other ExtendedIPSegmentSeries,
////getLower,
////getUpper func(AddressSegmentSeries) AddressSegmentSeries,
////comparator func(IPAddressSegmentSeries, IPAddressSegmentSeries) int,
////prefixRemover func(AddressSegmentSeries) AddressSegmentSeries,
//	removePrefixes bool,
//	operatorFunctor func(sourceLowerUpper, lower, upper ExtendedIPSegmentSeries) interface{}) interface{} {
//	var lower, upper ExtendedIPSegmentSeries
//	isFirst, isOther := true, true
//	if seriesValsSame(first, other) {
//		//if first.Equal(other) {
//		if removePrefixes && first.IsPrefixed() {
//			if other.IsPrefixed() {
//				lower = first.WithoutPrefixLen()
//				isOther = false
//				isFirst = false
//			} else {
//				lower = other
//				isFirst = false
//			}
//		} else {
//			isOther = false
//			lower = first
//		}
//		upper = lower.GetUpper()
//		lower = lower.GetLower()
//	} else {
//		firstLower := first.GetLower()
//		otherLower := other.GetLower()
//		firstUpper := first.GetUpper()
//		otherUpper := other.GetUpper()
//		if LowValueComparator.CompareSeries(firstLower, otherLower) > 0 {
//			//if firstLower.Compare(otherLower) > 0 {
//			lower = otherLower
//			isFirst = false
//		} else {
//			lower = firstLower
//			isOther = false
//		}
//		if LowValueComparator.CompareSeries(firstUpper, otherUpper) < 0 {
//			//if firstUpper.Compare(otherUpper) < 0 {
//			upper = otherUpper
//			isFirst = false
//		} else {
//			upper = firstUpper
//			isOther = false
//		}
//		if removePrefixes {
//			lower = lower.WithoutPrefixLen()
//			upper = upper.WithoutPrefixLen()
//		}
//	}
//	// We pass the first arg to the operator func if both the lower and upper args came from the first arg.
//	// In the case of coverWithPrefixBlock, if the lower and upper are both from the first, and the first is a prefix block, then the first can be reused,
//	// rather than create a new prefix block each time.
//	// In other words, when passing in a prefix block as the original, we reuse it.
//	var sourceLowerUpper ExtendedIPSegmentSeries
//	if isFirst {
//		sourceLowerUpper = first
//	} else if isOther {
//		sourceLowerUpper = other
//	}
//	return operatorFunctor(sourceLowerUpper, lower, upper)
//}

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
