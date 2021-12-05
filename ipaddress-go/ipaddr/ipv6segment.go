package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

type IPv6SegInt uint16
type IPv6SegmentValueProvider func(segmentIndex int) IPv6SegInt

func WrappedIPv6SegmentValueProvider(f IPv6SegmentValueProvider) SegmentValueProvider {
	if f == nil {
		return nil
	}
	return func(segmentIndex int) SegInt {
		return SegInt(f(segmentIndex))
	}
}

func WrappedSegmentValueProviderForIPv6(f SegmentValueProvider) IPv6SegmentValueProvider {
	if f == nil {
		return nil
	}
	return func(segmentIndex int) IPv6SegInt {
		return IPv6SegInt(f(segmentIndex))
	}
}

const useIPv6SegmentCache = true

type ipv6SegmentValues struct {
	value      IPv6SegInt
	upperValue IPv6SegInt
	prefLen    PrefixLen
	cache      divCache
}

func (seg *ipv6SegmentValues) getAddrType() addrType {
	return ipv6Type
}

func (seg *ipv6SegmentValues) includesZero() bool {
	return seg.value == 0
}

func (seg *ipv6SegmentValues) includesMax() bool {
	return seg.upperValue == 0xffff
}

func (seg *ipv6SegmentValues) isMultiple() bool {
	return seg.value != seg.upperValue
}

func (seg *ipv6SegmentValues) getCount() *big.Int {
	return big.NewInt(int64((seg.upperValue - seg.value)) + 1)
}

func (seg *ipv6SegmentValues) getBitCount() BitCount {
	return IPv6BitsPerSegment
}

func (seg *ipv6SegmentValues) getByteCount() int {
	return IPv6BytesPerSegment
}

func (seg *ipv6SegmentValues) getValue() *BigDivInt {
	return big.NewInt(int64(seg.value))
}

func (seg *ipv6SegmentValues) getUpperValue() *BigDivInt {
	return big.NewInt(int64(seg.upperValue))
}

func (seg *ipv6SegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg *ipv6SegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg *ipv6SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg *ipv6SegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg *ipv6SegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg *ipv6SegmentValues) calcBytesInternal() (bytes, upperBytes []byte) {
	bytes = []byte{byte(seg.value >> 8), byte(seg.value)}
	if seg.isMultiple() {
		upperBytes = []byte{byte(seg.upperValue >> 8), byte(seg.upperValue)}
	} else {
		upperBytes = bytes
	}
	return
}

func (seg *ipv6SegmentValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentPrefixedValues(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen)
}

func (seg *ipv6SegmentValues) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentPrefixedVal(IPv6SegInt(val), prefLen)
}

func (seg *ipv6SegmentValues) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return newIPv6SegmentPrefixedValues(IPv6SegInt(val), IPv6SegInt(upperVal), prefLen)
}

func (seg *ipv6SegmentValues) getCache() *divCache {
	return &seg.cache
}

var _ divisionValues = &ipv6SegmentValues{}

var zeroIPv6Seg = NewIPv6Segment(0)

type IPv6AddressSegment struct {
	ipAddressSegmentInternal
}

func (seg *IPv6AddressSegment) init() *IPv6AddressSegment {
	if seg.divisionValues == nil {
		return zeroIPv6Seg
	}
	return seg
}

func (seg *IPv6AddressSegment) Contains(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToAddressSegment() == nil
	}
	return seg.init().contains(other)
}

func (seg *IPv6AddressSegment) Equal(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToAddressDivision() == nil
	}
	return seg.init().equal(other)
}

func (seg *IPv6AddressSegment) Compare(item AddressItem) int {
	if seg != nil {
		seg = seg.init()
	}
	return CountComparator.Compare(seg, item)
}

func (seg *IPv6AddressSegment) GetBitCount() BitCount {
	return IPv6BitsPerSegment
}

func (seg *IPv6AddressSegment) GetByteCount() int {
	return IPv6BytesPerSegment
}

func (seg *IPv6AddressSegment) GetMaxValue() IPv6SegInt {
	return 0xffff
}

func (seg *IPv6AddressSegment) GetLower() *IPv6AddressSegment {
	return seg.getLower().ToIPv6AddressSegment()
}

func (seg *IPv6AddressSegment) GetUpper() *IPv6AddressSegment {
	return seg.getUpper().ToIPv6AddressSegment()
}

func (seg *IPv6AddressSegment) IsMultiple() bool {
	return seg != nil && seg.isMultiple()
}

func (seg *IPv6AddressSegment) GetCount() *big.Int {
	if seg == nil {
		return bigZero()
	}
	return seg.getCount()
}

func (seg *IPv6AddressSegment) ToPrefixedNetworkSegment(segmentPrefixLength PrefixLen) *IPv6AddressSegment {
	return seg.toPrefixedNetworkDivision(segmentPrefixLength).ToIPv6AddressSegment()
}

func (seg *IPv6AddressSegment) ToNetworkSegment(segmentPrefixLength PrefixLen) *IPv6AddressSegment {
	return seg.toNetworkDivision(segmentPrefixLength, false).ToIPv6AddressSegment()
}

func (seg *IPv6AddressSegment) ToPrefixedHostSegment(segmentPrefixLength PrefixLen) *IPv6AddressSegment {
	return seg.toPrefixedHostDivision(segmentPrefixLength).ToIPv6AddressSegment()
}

func (seg *IPv6AddressSegment) ToHostSegment(segmentPrefixLength PrefixLen) *IPv6AddressSegment {
	return seg.toHostDivision(segmentPrefixLength, false).ToIPv6AddressSegment()
}

func (seg *IPv6AddressSegment) Iterator() IPv6SegmentIterator {
	if seg == nil {
		return ipv6SegmentIterator{nilSegIterator()}
	}
	return ipv6SegmentIterator{seg.iterator()}
}

func (seg *IPv6AddressSegment) PrefixBlockIterator() IPv6SegmentIterator {
	return ipv6SegmentIterator{seg.prefixBlockIterator()}
}

func (seg *IPv6AddressSegment) PrefixedBlockIterator(segmentPrefixLen BitCount) IPv6SegmentIterator {
	return ipv6SegmentIterator{seg.prefixedBlockIterator(segmentPrefixLen)}
}

func (seg *IPv6AddressSegment) PrefixIterator() IPv6SegmentIterator {
	return ipv6SegmentIterator{seg.prefixIterator()}
}

func (seg *IPv6AddressSegment) IsPrefixed() bool {
	return seg != nil && seg.isPrefixed()
}

func (seg *IPv6AddressSegment) WithoutPrefixLen() *IPv6AddressSegment {
	if !seg.IsPrefixed() {
		return seg
	}
	return seg.withoutPrefixLen().ToIPv6AddressSegment()
}

//// Converts this IPv6 address segment into smaller segments,
//// copying them into the given array starting at the given index.
////
//// If a segment does not fit into the array because the segment index in the array is out of bounds of the array,
//// then it is not copied.
//func (seg *IPv6AddressSegment) visitSplitSegments(target func(index int, div *IPv4AddressSegment), boundaryIndex, index int) {
//	if !seg.isMult() {
//		bitSizeSplit := BitCount(IPv6BitsPerSegment >> 1)
//		myPrefix := seg.GetSegmentPrefixLen()
//		highPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 0)
//		lowPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 1)
//		if index >= 0 && index < boundaryIndex {
//			seg := NewIPv4PrefixedSegment(IPv4SegInt(seg.highByte()), highPrefixBits)
//			target(index, seg)
//		}
//		index++
//		if index >= 0 && index < boundaryIndex {
//			seg := NewIPv4PrefixedSegment(IPv4SegInt(seg.lowByte()), lowPrefixBits)
//			target(index, seg)
//		}
//	} else {
//		seg.visitSplitSegmentsMultiple(target, boundaryIndex, index)
//	}
//}
//
//func (seg *IPv6AddressSegment) visitSplitSegmentsMultiple(target func(index int, div *IPv4AddressSegment), boundaryIndex, index int) {
//	myPrefix := seg.GetSegmentPrefixLen()
//	bitSizeSplit := BitCount(IPv6BitsPerSegment >> 1)
//	if index >= 0 && index < boundaryIndex {
//		highLower := highByteIpv6(seg.GetSegmentValue())
//		highUpper := highByteIpv6(seg.GetUpperSegmentValue())
//		highPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 0)
//		if highLower == highUpper {
//			seg := NewIPv4PrefixedSegment(IPv4SegInt(highLower), highPrefixBits)
//			target(index, seg)
//		} else {
//			seg := NewIPv4RangePrefixedSegment(IPv4SegInt(highLower), IPv4SegInt(highUpper), highPrefixBits)
//			target(index, seg)
//		}
//	}
//	index++
//	if index >= 0 && index < boundaryIndex {
//		lowLower := lowByteIpv6(seg.GetSegmentValue())
//		lowUpper := lowByteIpv6(seg.GetUpperSegmentValue())
//		lowPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 1)
//		if lowLower == lowUpper {
//			seg := NewIPv4PrefixedSegment(IPv4SegInt(lowLower), lowPrefixBits)
//			target(index, seg)
//		} else {
//			seg := NewIPv4RangePrefixedSegment(IPv4SegInt(lowLower), IPv4SegInt(lowUpper), lowPrefixBits)
//			target(index, seg)
//		}
//	}
//}

// Converts this IPv6 address segment into smaller segments,
// copying them into the given array starting at the given index.
//
// If a segment does not fit into the array because the segment index in the array is out of bounds of the array,
// then it is not copied.
//
// Used to create both IPv4 and MACSize segments
func (seg *IPv6AddressSegment) visitSplitSegments(creator func(index int, value, upperValue SegInt, prefLen PrefixLen)) IncompatibleAddressError {
	//func (seg *IPv6AddressSegment) visitSplitSegments(target func(index int, div *IPv4AddressSegment), boundaryIndex, index int) {
	if seg.isMultiple() {
		return seg.visitSplitSegmentsMultiple(creator)
	} else {
		index := 0
		bitSizeSplit := IPv6BitsPerSegment >> 1
		myPrefix := seg.GetSegmentPrefixLen()
		val := seg.highByte()
		highPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 0)
		creator(index, val, val, highPrefixBits)
		index++
		val = seg.lowByte()
		lowPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 1)
		creator(index, val, val, lowPrefixBits)
		return nil
	}
}

//func (seg *IPv6AddressSegment) visitSplitSegments(creator func(index int, value, upperValue SegInt, prefLen PrefixLen), boundaryIndex, index int) IncompatibleAddressError {
//	//func (seg *IPv6AddressSegment) visitSplitSegments(target func(index int, div *IPv4AddressSegment), boundaryIndex, index int) {
//	if seg.isMult() {
//		return seg.visitSplitSegmentsMultiple(creator, boundaryIndex, index)
//	} else {
//		bitSizeSplit := IPv6BitsPerSegment >> 1
//		myPrefix := seg.GetSegmentPrefixLen()
//		if index >= 0 && index < boundaryIndex {
//			val := seg.highByte()
//			highPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 0)
//			creator(index, val, val, highPrefixBits)
//		}
//		index++
//		if index >= 0 && index < boundaryIndex {
//			val := seg.lowByte()
//			lowPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 1)
//			creator(index, val, val, lowPrefixBits)
//		}
//		return nil
//	}
//}

func (seg *IPv6AddressSegment) splitSegValues() (highLower, highUpper, lowLower, lowUpper SegInt, err IncompatibleAddressError) {
	val := seg.GetSegmentValue()
	upperVal := seg.GetUpperSegmentValue()
	highLower = highByteIpv6(val)
	highUpper = highByteIpv6(upperVal)
	lowLower = lowByteIpv6(val)
	lowUpper = lowByteIpv6(upperVal)
	if (highLower != highUpper) && (lowLower != 0 || lowUpper != 0xff) {
		err = &incompatibleAddressError{addressError{key: "ipaddress.error.splitSeg"}}
	}
	return
}

// Used to create both IPv4 and MACSize segments
func (seg *IPv6AddressSegment) visitSplitSegmentsMultiple(creator func(index int, value, upperValue SegInt, prefLen PrefixLen)) IncompatibleAddressError {
	myPrefix := seg.GetSegmentPrefixLen()
	bitSizeSplit := BitCount(IPv6BitsPerSegment >> 1)
	highLower, highUpper, lowLower, lowUpper, err := seg.splitSegValues()
	if err != nil {
		return err
	}
	highPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 0)
	lowPrefixBits := getSegmentPrefixLength(bitSizeSplit, myPrefix, 1)
	creator(0, highLower, highUpper, highPrefixBits)
	creator(1, lowLower, lowUpper, lowPrefixBits)
	return nil
}

//func (seg *IPv6AddressSegment) visitSplitSegmentsMultiple(creator func(index int, value, upperValue SegInt, prefLen PrefixLen), boundaryIndex, index int) IncompatibleAddressError {
//	myPrefix := seg.GetSegmentPrefixLen()
//	bitSizeSplit := BitCount(IPv6BitsPerSegment >> 1)
//	var highLower, highUpper, lowLower, lowUpper SegInt
//	var highPrefixBits, lowPrefixBits PrefixLen
//	lowIndex, highIndex := -1, -1
//	var isHighMult bool
//	if index >= 0 && index < boundaryIndex {
//		highLower = highByteIpv6(seg.GetSegmentValue())
//		highUpper = highByteIpv6(seg.GetUpperSegmentValue())
//		highPrefixBits = getSegmentPrefixLength(bitSizeSplit, myPrefix, 0)
//		highIndex = index
//		isHighMult = highLower != highUpper
//	}
//	index++
//	if index >= 0 && index < boundaryIndex {
//		lowLower = lowByteIpv6(seg.GetSegmentValue())
//		lowUpper = lowByteIpv6(seg.GetUpperSegmentValue())
//		lowPrefixBits = getSegmentPrefixLength(bitSizeSplit, myPrefix, 1)
//		lowIndex = index
//	}
//	if isHighMult && (lowLower != 0 || lowUpper != 0xff) {
//		return &incompatibleAddressError{addressError{key: "ipaddress.error.splitSeg"}}
//	}
//	if highIndex >= 0 {
//		creator(highIndex, highLower, highUpper, highPrefixBits)
//	}
//	if lowIndex >= 0 {
//		creator(lowIndex, lowLower, lowUpper, lowPrefixBits)
//	}
//	return nil
//}

func (seg *IPv6AddressSegment) highByte() SegInt {
	return highByteIpv6(seg.GetSegmentValue())
}

func (seg *IPv6AddressSegment) lowByte() SegInt {
	return lowByteIpv6(seg.GetSegmentValue())
}

func highByteIpv6(value SegInt) SegInt {
	return value >> 8
}

func lowByteIpv6(value SegInt) SegInt {
	return value & 0xff
}

// Converts this IPv6 address segment into smaller segments,
// copying them into the given array starting at the given index
//
// If a segment does not fit into the array because the segment index in the array is out of bounds of the array,
// then it is not copied.
func (seg *IPv6AddressSegment) GetSplitSegments(segs []*IPv4AddressSegment, startIndex int) IncompatibleAddressError {
	//return seg.visitSplitSegments(func(index int, div *IPv4AddressSegment) { segs[index] = div }, len(segs), index)
	return seg.visitSplitSegments(func(index int, value, upperValue SegInt, prefLen PrefixLen) {
		if ind := startIndex + index; ind < len(segs) {
			segs[ind] = NewIPv4RangePrefixedSegment(IPv4SegInt(value), IPv4SegInt(upperValue), prefLen)
		}
	})
}

//func (seg *IPv6AddressSegment) GetSplitSegments(segs []*IPv4AddressSegment, startIndex int) IncompatibleAddressError {
//	//return seg.visitSplitSegments(func(index int, div *IPv4AddressSegment) { segs[index] = div }, len(segs), index)
//	return seg.visitSplitSegments(func(index int, value, upperValue SegInt, prefLen PrefixLen) {
//		segs[index] = NewIPv4RangePrefixedSegment(IPv4SegInt(value), IPv4SegInt(upperValue), prefLen)
//	}, len(segs), index)
//}

//TODO these should not be public,  The first duplicates the above.  Both use AddressDivision rather than the more specific type MACSegment or IPV4Segment.  So you might want to create a mac equivlaent to the above.
func (seg *IPv6AddressSegment) SplitIntoIPv4Segments(segs []*AddressDivision, startIndex int) IncompatibleAddressError {
	//return seg.visitSplitSegments(func(index int, div *IPv4AddressSegment) { segs[index] = div.ToAddressDivision() }, len(segs), index)
	return seg.visitSplitSegments(func(index int, value, upperValue SegInt, prefLen PrefixLen) {
		if ind := startIndex + index; ind < len(segs) {
			segs[ind] = NewIPv4RangePrefixedSegment(IPv4SegInt(value), IPv4SegInt(upperValue), prefLen).ToAddressDivision()
		}
	})
}

func (seg *IPv6AddressSegment) SplitIntoMACSegments(segs []*AddressDivision, startIndex int) IncompatibleAddressError {
	//return seg.visitSplitSegments(func(index int, div *IPv4AddressSegment) { segs[index] = div.ToAddressDivision() }, len(segs), index)
	return seg.visitSplitSegments(func(index int, value, upperValue SegInt, prefLen PrefixLen) {
		if ind := startIndex + index; ind < len(segs) {
			segs[ind] = NewMACRangeSegment(MACSegInt(value), MACSegInt(upperValue)).ToAddressDivision()
		}
	})
}

func (seg *IPv6AddressSegment) ReverseBits(perByte bool) (res *IPv6AddressSegment, err IncompatibleAddressError) {
	if seg.divisionValues == nil {
		res = seg
		return
	}
	if seg.isMultiple() {
		var addrSeg *AddressSegment
		addrSeg, err = seg.reverseMultiValSeg(perByte)
		res = addrSeg.ToIPv6AddressSegment()
		return
	}
	oldVal := IPv6SegInt(seg.GetSegmentValue())
	val := IPv6SegInt(reverseUint16(uint16(oldVal)))
	if perByte {
		val = ((val & 0xff) << 8) | (val >> 8)
	}
	if oldVal == val && !seg.isPrefixed() {
		res = seg
	} else {
		res = NewIPv6Segment(val)
	}
	return
}

func (seg *IPv6AddressSegment) ReverseBytes() (res *IPv6AddressSegment, err IncompatibleAddressError) {
	if seg.divisionValues == nil {
		res = seg
		return
	}
	if seg.isMultiple() {
		var addrSeg *AddressSegment
		addrSeg, err = seg.reverseMultiValSeg(false)
		res = addrSeg.ToIPv6AddressSegment()
		return
	}
	oldVal := IPv6SegInt(seg.GetSegmentValue())
	val := IPv6SegInt(reverseUint16(uint16(oldVal)))
	if oldVal == val && !seg.isPrefixed() {
		res = seg
	} else {
		res = NewIPv6Segment(val)
	}
	return
}

func (seg *IPv6AddressSegment) ToAddressDivision() *AddressDivision {
	return seg.ToAddressSegment().ToAddressDivision()
}

func (seg *IPv6AddressSegment) ToAddressSegment() *AddressSegment {
	return seg.ToIPAddressSegment().ToAddressSegment()
}

func (seg *IPv6AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	if seg == nil {
		return nil
	}
	return (*IPAddressSegment)(seg.init())
}

func (seg *IPv6AddressSegment) String() string {
	if seg == nil {
		return nilString()
	}
	return seg.toString()
}

func NewIPv6Segment(val IPv6SegInt) *IPv6AddressSegment {
	return newIPv6Segment(newIPv6SegmentVal(val))
}

func NewIPv6RangeSegment(val, upperVal IPv6SegInt) *IPv6AddressSegment {
	return newIPv6Segment(newIPv6SegmentPrefixedValues(val, upperVal, nil))
}

func NewIPv6PrefixedSegment(val IPv6SegInt, prefixLen PrefixLen) *IPv6AddressSegment {
	return newIPv6Segment(newIPv6SegmentPrefixedVal(val, prefixLen))
}

func NewIPv6RangePrefixedSegment(val, upperVal IPv6SegInt, prefixLen PrefixLen) *IPv6AddressSegment {
	return newIPv6Segment(newIPv6SegmentPrefixedValues(val, upperVal, prefixLen))
}

func newIPv6Segment(vals *ipv6SegmentValues) *IPv6AddressSegment {
	return &IPv6AddressSegment{
		ipAddressSegmentInternal{
			addressSegmentInternal{
				addressDivisionInternal{
					addressDivisionBase{vals},
				},
			},
		},
	}
}

type ipv6DivsBlock struct {
	block []ipv6SegmentValues
}

type ipv6DivsPartition struct {
	block []*ipv6DivsBlock
}

var (
	allRangeValsIPv6 = &ipv6SegmentValues{
		upperValue: IPv6MaxValuePerSegment,
		cache: divCache{
			isSinglePrefBlock: &falseVal,
		},
	}
	allPrefixedCacheIPv6 = makePrefixCacheIPv6()

	// single-valued no-prefix cache.
	// there are 0x10000 (ie 0xffff + 1 or 64k) possible segment values in IPv6.  We break the cache into 0x100 blocks of size 0x100
	segmentCacheIPv6 = make([]*ipv6DivsBlock, (IPv6MaxValuePerSegment>>8)+1)

	// single-valued cache for each prefix.
	segmentPrefixCacheIPv6 = make([]*ipv6DivsPartition, IPv6BitsPerSegment+1) // for each prefix, all segment values, 0x100 blocks of size 0x100

	// prefix-block cache: all the prefix blocks for each prefix.
	// for each prefix, all prefix blocks.
	// For a given prefix, you shift left by 8 bits for the blocks of size 0x100, the remaining bits to the left are the number of blocks.
	//
	// For prefix of size 8, 1 block of size 0x100
	// For prefix of size < 8, 1 block of size (1 << prefix)
	// For prefix of size > 8, (1 << (prefix - 8)) blocks of size 0x100.
	//
	// So, you start with the prefix to get the right ipv6DivsPartition.
	// Then, you use the formula above to look up the block index.
	// For the first two above, the whole prefix finds the index into the single block.
	// For the third, the 8 rightmost bits in the prefix give the index into the block of size ff,
	// while the leftmost bits in the prefix select that block.
	prefixBlocksCacheIPv6 = make([]*ipv6DivsPartition, IPv6BitsPerSegment+1)
)

func makePrefixCacheIPv6() (allPrefixedCacheIPv6 []ipv6SegmentValues) {
	if useIPv6SegmentCache {
		allPrefixedCacheIPv6 = make([]ipv6SegmentValues, IPv6BitsPerSegment+1)
		for i := range allPrefixedCacheIPv6 {
			vals := &allPrefixedCacheIPv6[i]
			vals.upperValue = IPv6MaxValuePerSegment
			vals.prefLen = cacheBits(i)
			vals.cache.isSinglePrefBlock = &falseVal
		}
		allPrefixedCacheIPv6[0].cache.isSinglePrefBlock = &trueVal
	}
	return
}

func newIPv6SegmentVal(value IPv6SegInt) *ipv6SegmentValues {
	if useIPv6SegmentCache {
		cache := segmentCacheIPv6
		blockIndex := value >> 8 // divide by 0x100
		firstBlockVal := blockIndex << 8
		resultIndex := value - firstBlockVal // mod 0x100
		block := cache[blockIndex]
		if block == nil {
			block = &ipv6DivsBlock{make([]ipv6SegmentValues, 0x100)}
			vals := block.block
			for i := range vals {
				item := &vals[i]
				itemVal := firstBlockVal | IPv6SegInt(i)
				item.value = itemVal
				item.upperValue = itemVal
				item.cache.isSinglePrefBlock = &falseVal
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[blockIndex]))
			atomic.StorePointer(dataLoc, unsafe.Pointer(block))
		}
		result := &block.block[resultIndex]
		checkValues(value, value, result)
		return result
	}
	return &ipv6SegmentValues{
		value:      value,
		upperValue: value,
		cache: divCache{
			isSinglePrefBlock: &falseVal,
		},
	}
}

func newIPv6SegmentPrefixedVal(value IPv6SegInt, prefLen PrefixLen) (result *ipv6SegmentValues) {
	if prefLen == nil {
		return newIPv6SegmentVal(value)
	}
	prefixIndex := *prefLen
	if prefixIndex < 0 {
		prefixIndex = 0
	} else if prefixIndex > IPv6BitsPerSegment {
		prefixIndex = IPv6BitsPerSegment
	}
	prefLen = cacheBitCount(prefixIndex) // this ensures we use the prefix length cache for all segments
	if useIPv6SegmentCache {
		cache := segmentPrefixCacheIPv6
		prefixCache := cache[prefixIndex]
		if prefixCache == nil {
			prefixCache = &ipv6DivsPartition{make([]*ipv6DivsBlock, (IPv6MaxValuePerSegment>>8)+1)}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
			atomic.StorePointer(dataLoc, unsafe.Pointer(prefixCache))
		}
		blockIndex := value >> 8 // divide by 0x100
		firstBlockVal := blockIndex << 8
		resultIndex := value - (firstBlockVal) // mod 0x100
		blockCache := prefixCache.block[blockIndex]
		if blockCache == nil {
			blockCache = &ipv6DivsBlock{make([]ipv6SegmentValues, (IPv6MaxValuePerSegment>>8)+1)}
			vals := blockCache.block
			var isSinglePrefBlock *bool
			if prefixIndex == IPv6BitsPerSegment {
				isSinglePrefBlock = &trueVal
			} else {
				isSinglePrefBlock = &falseVal
			}
			for i := range vals {
				item := &vals[i]
				itemVal := firstBlockVal | IPv6SegInt(i)
				item.value = itemVal
				item.upperValue = itemVal
				item.prefLen = prefLen
				item.cache.isSinglePrefBlock = isSinglePrefBlock
				//item.cache.isSinglePrefBlock = &falseVal xxxxx wrong when prefLen is 16 they are all prefix blocks xxxx
			}
			//vals[IPv6BitsPerSegment].cache.isSinglePrefBlock = &trueVal xxxxx wrong when prefLen is 16 they are all prefix blocks xxxx
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&prefixCache.block[blockIndex]))
			atomic.StorePointer(dataLoc, unsafe.Pointer(blockCache))
		}
		result := &blockCache.block[resultIndex]
		checkValues(value, value, result)
		return result
	}
	var isSinglePrefBlock *bool
	if prefixIndex == IPv6BitsPerSegment {
		isSinglePrefBlock = &trueVal
	} else {
		isSinglePrefBlock = &falseVal
	}
	return &ipv6SegmentValues{
		value:      value,
		upperValue: value,
		prefLen:    prefLen,
		cache: divCache{
			isSinglePrefBlock: isSinglePrefBlock,
		},
	}
}

func checkValuesMAC(value, upperValue MACSegInt, result *macSegmentValues) { //TODO remove eventually, this is just verifying that the code creating the values is good
	if result.value != value || result.upperValue != upperValue {
		panic("huh")
	}
}

func checkValues(value, upperValue IPv6SegInt, result *ipv6SegmentValues) { //TODO remove eventually, this is just verifying that the code creating the values is good
	if result.value != value || result.upperValue != upperValue {
		panic("huh")
	}
	if result.cache.isSinglePrefBlock != nil {
		seg := newIPv6Segment(result)
		var isSinglePBlock bool
		if prefLen := seg.GetSegmentPrefixLen(); prefLen != nil {
			isSinglePBlock = seg.isSinglePrefixBlock(seg.getDivisionValue(), seg.getUpperDivisionValue(), *prefLen)
		}
		if isSinglePBlock != *result.cache.isSinglePrefBlock {
			if prefLen := seg.GetSegmentPrefixLen(); prefLen != nil {
				isSinglePBlock = seg.isSinglePrefixBlock(seg.getDivisionValue(), seg.getUpperDivisionValue(), *prefLen)
			}
			panic("why")
		}
	}
}

func checkValuesIPv4(value, upperValue IPv4SegInt, result *ipv4SegmentValues) { //TODO remove eventually, this is just verifying that the code creating the values is good
	if result.value != value || result.upperValue != upperValue {
		panic("huh")
	}
	if result.cache.isSinglePrefBlock != nil {
		seg := newIPv4Segment(result)
		var isSinglePBlock bool
		if prefLen := seg.GetSegmentPrefixLen(); prefLen != nil {
			isSinglePBlock = seg.isSinglePrefixBlock(seg.getDivisionValue(), seg.getUpperDivisionValue(), *prefLen)
		}
		if isSinglePBlock != *result.cache.isSinglePrefBlock {
			if prefLen := seg.GetSegmentPrefixLen(); prefLen != nil {
				isSinglePBlock = seg.isSinglePrefixBlock(seg.getDivisionValue(), seg.getUpperDivisionValue(), *prefLen)
			}
			panic("why")
		}
	}
}

func newIPv6SegmentPrefixedValues(value, upperValue IPv6SegInt, prefLen PrefixLen) *ipv6SegmentValues {
	var isSinglePrefBlock *bool
	if prefLen == nil {
		if value == upperValue {
			return newIPv6SegmentVal(value)
		} else if value > upperValue {
			value, upperValue = upperValue, value
		}
		if useIPv6SegmentCache && value == 0 && upperValue == IPv6MaxValuePerSegment {
			return allRangeValsIPv6
		}
		isSinglePrefBlock = &falseVal
	} else {
		if value == upperValue {
			return newIPv6SegmentPrefixedVal(value, prefLen)
		} else if value > upperValue {
			value, upperValue = upperValue, value
		}
		prefixIndex := *prefLen
		if prefixIndex < 0 {
			prefixIndex = 0
		} else if prefixIndex > IPv6BitsPerSegment {
			prefixIndex = IPv6BitsPerSegment
		}
		prefLen = cacheBitCount(prefixIndex) // this ensures we use the prefix length cache for all segments
		if useIPv6SegmentCache {
			shiftBits := uint(IPv6BitsPerSegment - prefixIndex)
			nmask := ^IPv6SegInt(0) << shiftBits
			prefixBlockLower := value & nmask
			hmask := ^nmask
			prefixBlockUpper := value | hmask
			if value == prefixBlockLower && upperValue == prefixBlockUpper {
				// cache is the prefix block for any prefix length
				cache := prefixBlocksCacheIPv6
				prefixCache := cache[prefixIndex]
				if prefixCache == nil {
					if prefixIndex <= 8 { // 1 block of size (1 << prefix)
						prefixCache = &ipv6DivsPartition{make([]*ipv6DivsBlock, 1)}
					} else { // (1 << (prefix - 8)) blocks of size 0x100.
						prefixCache = &ipv6DivsPartition{make([]*ipv6DivsBlock, 1<<uint(prefixIndex-8))}
					}
					dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
					atomic.StorePointer(dataLoc, unsafe.Pointer(prefixCache))
				}
				valueIndex := value >> shiftBits
				blockIndex := valueIndex >> 8 // divide by 0x100
				firstBlockVal := blockIndex << 8
				resultIndex := valueIndex - (firstBlockVal) // mod 0x100
				blockCache := prefixCache.block[blockIndex]
				if blockCache == nil {
					if prefixIndex <= 8 { // 1 block of size (1 << prefix)
						blockCache = &ipv6DivsBlock{make([]ipv6SegmentValues, 1<<uint(prefixIndex))}
					} else { // (1 << (prefix - 8)) blocks of size 0x100.
						blockCache = &ipv6DivsBlock{make([]ipv6SegmentValues, 1<<8)}
					}
					vals := blockCache.block
					for i := range vals {
						item := &vals[i]
						itemVal := (firstBlockVal | IPv6SegInt(i)) << shiftBits
						item.value = itemVal
						item.upperValue = itemVal | hmask
						item.prefLen = prefLen
						item.cache.isSinglePrefBlock = &trueVal
					}
					dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&prefixCache.block[blockIndex]))
					atomic.StorePointer(dataLoc, unsafe.Pointer(blockCache))
				}
				result := &blockCache.block[resultIndex]
				checkValues(value, upperValue, result)
				return result
			}
			if value == 0 {
				// cache is 0-0xffff for any prefix length
				if upperValue == IPv6MaxValuePerSegment {
					result := &allPrefixedCacheIPv6[prefixIndex]
					checkValues(value, upperValue, result)
					return result
				}
			}
			isSinglePrefBlock = &falseVal
		}
	}
	return &ipv6SegmentValues{
		value:      value,
		upperValue: upperValue,
		prefLen:    prefLen,
		cache: divCache{
			isSinglePrefBlock: isSinglePrefBlock,
		},
	}
}
