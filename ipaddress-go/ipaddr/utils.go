package ipaddr

import "math/big"

func cloneInts(orig []int) []int {
	return append(make([]int, 0, len(orig)), orig...)
}

func cloneDivs(orig []*AddressDivision) []*AddressDivision {
	return append(make([]*AddressDivision, 0, len(orig)), orig...)
}

func cloneBytes(orig []byte) []byte {
	return append(make([]byte, 0, len(orig)), orig...)
}

// copies cached into bytes, unless bytes is too small, in which case cached is cloned
func getBytesCopy(bytes, cached []byte) []byte {
	if bytes == nil || len(bytes) < len(cached) {
		return cloneBytes(cached)
	}
	copy(bytes, cached)
	return bytes
}

// note: only to be used when you already know the total size fits into a long
func longCount(section *AddressSection, segCount int) uint64 {
	result := getLongCount(func(index int) uint64 { return section.GetSegment(index).GetValueCount() }, segCount)
	return result
}

func getLongCount(segmentCountProvider func(index int) uint64, segCount int) uint64 {
	if segCount == 0 {
		return 1
	}
	result := segmentCountProvider(0)
	for i := 1; i < segCount; i++ {
		result *= segmentCountProvider(i)
	}
	return result
}

// note: only to be used when you already know the total size fits into a long
func longPrefixCount(section *AddressSection, prefixLength BitCount) uint64 {
	bitsPerSegment := section.GetBitsPerSegment()
	bytesPerSegment := section.GetBytesPerSegment()
	networkSegmentIndex := getNetworkSegmentIndex(prefixLength, bytesPerSegment, bitsPerSegment)
	hostSegmentIndex := getHostSegmentIndex(prefixLength, bytesPerSegment, bitsPerSegment)
	return getLongCount(func(index int) uint64 {
		if (networkSegmentIndex == hostSegmentIndex) && index == networkSegmentIndex {
			segmentPrefixLength := getPrefixedSegmentPrefixLength(section.GetBitsPerSegment(), prefixLength, index)
			return getPrefixValueCount(section.GetSegment(index), *segmentPrefixLength)
		}
		return section.GetSegment(index).GetValueCount()
	}, networkSegmentIndex+1)
}

func mult(currentResult *big.Int, newResult uint64) *big.Int {
	if newResult == 1 {
		return currentResult
	}
	newBig := bigZero().SetUint64(newResult)
	return currentResult.Mul(currentResult, newBig)
}

// only called when isMultiple() is true, so segCount >= 1
func count(segmentCountProvider func(index int) uint64, segCount, safeMultiplies int, safeLimit uint64) *big.Int {
	result := bigOne()
	if segCount == 0 {
		return result
	}
	i := 0
	for {
		curResult := segmentCountProvider(i)
		i++
		if i == segCount {
			return mult(result, curResult)
		}
		limit := i + safeMultiplies
		if segCount <= limit {
			// all multiplies are safe
			for i < segCount {
				curResult *= segmentCountProvider(i)
				i++
			}
			return mult(result, curResult)
		}
		// do the safe multiplies which cannot overflow
		for i < limit {
			curResult *= segmentCountProvider(i)
			i++
		}
		// do as many additional multiplies as current result allows
		for curResult <= safeLimit {
			curResult *= segmentCountProvider(i)
			i++
			if i == segCount {
				return mult(result, curResult)
			}
		}
		result = mult(result, curResult)
	}
}
