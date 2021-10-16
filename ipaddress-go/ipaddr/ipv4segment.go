package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

type IPv4SegInt uint8
type IPv4SegmentValueProvider func(segmentIndex int) IPv4SegInt

func WrappedIPv4SegmentValueProvider(f IPv4SegmentValueProvider) SegmentValueProvider {
	if f == nil {
		return nil
	}
	return func(segmentIndex int) SegInt {
		return SegInt(f(segmentIndex))
	}
}

func WrappedSegmentValueProviderForIPv4(f SegmentValueProvider) IPv4SegmentValueProvider {
	if f == nil {
		return nil
	}
	return func(segmentIndex int) IPv4SegInt {
		return IPv4SegInt(f(segmentIndex))
	}
}

const useIPv4SegmentCache = true

type ipv4SegmentValues struct {
	value      IPv4SegInt
	upperValue IPv4SegInt
	prefLen    PrefixLen
	cache      divCache
}

func (seg *ipv4SegmentValues) getAddrType() addrType {
	return ipv4Type
}

func (seg *ipv4SegmentValues) includesZero() bool {
	return seg.value == 0
}

func (seg *ipv4SegmentValues) includesMax() bool {
	return seg.upperValue == 0xff
}

func (seg *ipv4SegmentValues) isMultiple() bool {
	return seg.value != seg.upperValue
}

func (seg *ipv4SegmentValues) getCount() *big.Int {
	return big.NewInt(int64((seg.upperValue - seg.value)) + 1)
}

func (seg *ipv4SegmentValues) getBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg *ipv4SegmentValues) getByteCount() int {
	return IPv4BytesPerSegment
}

func (seg *ipv4SegmentValues) getValue() *BigDivInt {
	return big.NewInt(int64(seg.value))
}

func (seg *ipv4SegmentValues) getUpperValue() *BigDivInt {
	return big.NewInt(int64(seg.upperValue))
}

func (seg *ipv4SegmentValues) getDivisionValue() DivInt {
	return DivInt(seg.value)
}

func (seg *ipv4SegmentValues) getUpperDivisionValue() DivInt {
	return DivInt(seg.upperValue)
}

func (seg *ipv4SegmentValues) getDivisionPrefixLength() PrefixLen {
	return seg.prefLen
}

func (seg *ipv4SegmentValues) deriveNew(val, upperVal DivInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentPrefixedValues(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen)
}

func (seg *ipv4SegmentValues) deriveNewSeg(val SegInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentPrefixedVal(IPv4SegInt(val), prefLen)
}

func (seg *ipv4SegmentValues) deriveNewMultiSeg(val, upperVal SegInt, prefLen PrefixLen) divisionValues {
	return newIPv4SegmentPrefixedValues(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen)
}

func (seg *ipv4SegmentValues) getCache() *divCache {
	return &seg.cache
}

func (seg *ipv4SegmentValues) getSegmentValue() SegInt {
	return SegInt(seg.value)
}

func (seg *ipv4SegmentValues) getUpperSegmentValue() SegInt {
	return SegInt(seg.upperValue)
}

func (seg *ipv4SegmentValues) calcBytesInternal() (bytes, upperBytes []byte) {
	bytes = []byte{byte(seg.value)}
	if seg.isMultiple() {
		upperBytes = []byte{byte(seg.upperValue)}
	} else {
		upperBytes = bytes
	}
	return
}

var _ divisionValues = &ipv4SegmentValues{}

var zeroIPv4Seg = NewIPv4Segment(0)

type IPv4AddressSegment struct {
	ipAddressSegmentInternal
}

func (seg *IPv4AddressSegment) init() *IPv4AddressSegment {
	if seg.divisionValues == nil {
		return zeroIPv4Seg
	}
	return seg
}

// We must override getBitCount, getByteCount and others for the case when we construct as the zero value and there are no divisionValues

//func (seg *IPv4AddressSegment) Equals(other DivisionType) bool {
//	if seg == nil {
//		return seg.getAddrType() == ipv4Type && other.(StandardDivisionType).ToAddressDivision() == nil
//	}
//	return seg.init().equals(other)
//}
//
//func (seg *IPv4AddressSegment) CompareTo(item AddressItem) int {
//	if seg != nil {
//		seg = seg.init()
//	}
//	return CountComparator.Compare(seg, item)
//}

func (seg *IPv4AddressSegment) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg *IPv4AddressSegment) GetByteCount() int {
	return IPv4BytesPerSegment
}

func (seg *IPv4AddressSegment) GetMaxValue() IPv4SegInt {
	return 0xff
}

func (seg *IPv4AddressSegment) GetLower() *IPv4AddressSegment {
	return seg.getLower().ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) GetUpper() *IPv4AddressSegment {
	return seg.getUpper().ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) ToPrefixedNetworkSegment(segmentPrefixLength PrefixLen) *IPv4AddressSegment {
	return seg.toPrefixedNetworkDivision(segmentPrefixLength).ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) ToNetworkSegment(segmentPrefixLength PrefixLen) *IPv4AddressSegment {
	return seg.toNetworkDivision(segmentPrefixLength, false).ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) ToPrefixedHostSegment(segmentPrefixLength PrefixLen) *IPv4AddressSegment {
	return seg.toPrefixedHostDivision(segmentPrefixLength).ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) ToHostSegment(segmentPrefixLength PrefixLen) *IPv4AddressSegment {
	return seg.toHostDivision(segmentPrefixLength, false).ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) Iterator() IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.iterator()}
}

func (seg *IPv4AddressSegment) PrefixBlockIterator() IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.prefixBlockIterator()}
}

func (seg *IPv4AddressSegment) PrefixedBlockIterator(segmentPrefixLen BitCount) IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.prefixedBlockIterator(segmentPrefixLen)}
}

func (seg *IPv4AddressSegment) PrefixIterator() IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.prefixIterator()}
}

func (seg *IPv4AddressSegment) WithoutPrefixLen() *IPv4AddressSegment {
	return seg.withoutPrefixLen().ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) ReverseBits(_ bool) (res *IPv4AddressSegment, err IncompatibleAddressError) {
	if seg.divisionValues == nil {
		res = seg
		return
	}
	if seg.IsMultiple() {
		if isReversible := seg.isReversibleRange(false); isReversible {
			res = seg.WithoutPrefixLen()
			return
		}
		err = &incompatibleAddressError{addressError{key: "ipaddress.error.reverseRange"}}
		return
	}
	oldVal := IPv4SegInt(seg.GetSegmentValue())
	val := IPv4SegInt(reverseUint8(uint8(oldVal)))
	if oldVal == val && !seg.isPrefixed() {
		res = seg
	} else {
		res = NewIPv4Segment(val)
	}
	return
}

func (seg *IPv4AddressSegment) ReverseBytes() (*IPv4AddressSegment, IncompatibleAddressError) {
	return seg, nil
}

func (seg *IPv4AddressSegment) isJoinableTo(low *IPv4AddressSegment) bool {
	// if the high segment has a range, the low segment must match the full range,
	// otherwise it is not possible to create an equivalent range when joining
	return !seg.IsMultiple() || low.IsFullRange()
}

//TODO think some more about whether Join should be public.  The case in MACAddressSegment might be stronger.  Public seems ok here.  Not sure.

// Join joins with another IPv4 segment to produce a IPv6 segment.
func (seg *IPv4AddressSegment) Join(low *IPv4AddressSegment) (*IPv6AddressSegment, IncompatibleAddressError) {
	prefixLength := seg.getJoinedSegmentPrefixLen(low.GetSegmentPrefixLen())
	if !seg.isJoinableTo(low) {
		return nil, &incompatibleAddressError{addressError: addressError{key: "ipaddress.error.invalidMixedRange"}}
	}
	return NewIPv6RangePrefixedSegment(
		IPv6SegInt((seg.GetSegmentValue()<<8)|low.getSegmentValue()),
		IPv6SegInt((seg.GetUpperSegmentValue()<<8)|low.getUpperSegmentValue()),
		prefixLength), nil
}

func (seg *IPv4AddressSegment) getJoinedSegmentPrefixLen(lowBits PrefixLen) PrefixLen {
	highBits := seg.GetSegmentPrefixLen()
	if lowBits == nil {
		return nil
	}
	if *lowBits == 0 {
		return highBits
	}
	return cacheBitCount(*lowBits + IPv4BitsPerSegment)
}

func (seg *IPv4AddressSegment) ToAddressSegment() *AddressSegment {
	return seg.ToIPAddressSegment().ToAddressSegment()
}

func (seg *IPv4AddressSegment) ToIPAddressSegment() *IPAddressSegment {
	if seg == nil {
		return nil
	}
	return (*IPAddressSegment)(seg.init())
}

func NewIPv4Segment(val IPv4SegInt) *IPv4AddressSegment {
	return newIPv4Segment(newIPv4SegmentVal(val))
}

func NewIPv4RangeSegment(val, upperVal IPv4SegInt) *IPv4AddressSegment {
	return newIPv4Segment(newIPv4SegmentPrefixedValues(val, upperVal, nil))
}

func NewIPv4PrefixedSegment(val IPv4SegInt, prefixLen PrefixLen) *IPv4AddressSegment {
	return newIPv4Segment(newIPv4SegmentPrefixedVal(val, prefixLen))
}

func NewIPv4RangePrefixedSegment(val, upperVal IPv4SegInt, prefixLen PrefixLen) *IPv4AddressSegment {
	return newIPv4Segment(newIPv4SegmentPrefixedValues(val, upperVal, prefixLen))
}

func newIPv4Segment(vals *ipv4SegmentValues) *IPv4AddressSegment {
	return &IPv4AddressSegment{
		ipAddressSegmentInternal{
			addressSegmentInternal{
				addressDivisionInternal{
					addressDivisionBase{
						vals,
					},
				},
			},
		},
	}
}

type ipv4DivsBlock struct {
	block []ipv4SegmentValues
}

var (
	allRangeValsIPv4 = &ipv4SegmentValues{
		upperValue: IPv4MaxValuePerSegment,
		cache: divCache{
			isSinglePrefBlock: &falseVal,
		},
	}
	allPrefixedCacheIPv4   = makePrefixCache()
	segmentCacheIPv4       = makeSegmentCache()
	segmentPrefixCacheIPv4 = makeDivsBlock()
	prefixBlocksCacheIPv4  = makeDivsBlock()
)

func makeDivsBlock() []*ipv4DivsBlock {
	if useIPv4SegmentCache {
		return make([]*ipv4DivsBlock, IPv4BitsPerSegment+1)
	}
	return nil
}

func makePrefixCache() (allPrefixedCacheIPv4 []ipv4SegmentValues) {
	if useIPv4SegmentCache {
		allPrefixedCacheIPv4 = make([]ipv4SegmentValues, IPv4BitsPerSegment+1)
		for i := range allPrefixedCacheIPv4 {
			vals := &allPrefixedCacheIPv4[i]
			vals.upperValue = IPv4MaxValuePerSegment
			vals.prefLen = cacheBits(i)
			vals.cache.isSinglePrefBlock = &falseVal
		}
		allPrefixedCacheIPv4[0].cache.isSinglePrefBlock = &trueVal
	}
	return
}

func makeSegmentCache() (segmentCacheIPv4 []ipv4SegmentValues) {
	if useIPv4SegmentCache {
		segmentCacheIPv4 = make([]ipv4SegmentValues, IPv4MaxValuePerSegment+1)
		for i := range segmentCacheIPv4 {
			vals := &segmentCacheIPv4[i]
			segi := IPv4SegInt(i)
			vals.value = segi
			vals.upperValue = segi
			vals.cache.isSinglePrefBlock = &falseVal
		}
	}
	return
}

func newIPv4SegmentVal(value IPv4SegInt) *ipv4SegmentValues {
	if useIPv4SegmentCache {
		result := &segmentCacheIPv4[value]
		checkValuesIPv4(value, value, result)
		return result
	}
	return &ipv4SegmentValues{
		value:      value,
		upperValue: value,
		cache: divCache{
			isSinglePrefBlock: &falseVal,
		},
	}
}

func newIPv4SegmentPrefixedVal(value IPv4SegInt, prefLen PrefixLen) (result *ipv4SegmentValues) {
	if prefLen == nil {
		return newIPv4SegmentVal(value)
	}
	segmentPrefixLength := *prefLen
	if segmentPrefixLength < 0 {
		segmentPrefixLength = 0
	} else if segmentPrefixLength > IPv4BitsPerSegment {
		segmentPrefixLength = IPv4BitsPerSegment
	}
	prefLen = cacheBitCount(segmentPrefixLength) // this ensures we use the prefix length cache for all segments
	if useIPv4SegmentCache {
		prefixIndex := segmentPrefixLength
		cache := segmentPrefixCacheIPv4
		block := cache[prefixIndex]
		if block == nil {
			block = &ipv4DivsBlock{make([]ipv4SegmentValues, IPv4MaxValuePerSegment+1)}
			vals := block.block
			var isSinglePrefBlock *bool
			if prefixIndex == IPv4BitsPerSegment {
				isSinglePrefBlock = &trueVal
			} else {
				isSinglePrefBlock = &falseVal
			}
			for i := range vals {
				value := &vals[i]
				segi := IPv4SegInt(i)
				value.value = segi
				value.upperValue = segi
				value.prefLen = prefLen
				value.cache.isSinglePrefBlock = isSinglePrefBlock
				//value.cache.isSinglePrefBlock = &falseVal xxxxx wrong when prefLen is 8 they are all prefix blocks xxxx
			}
			//vals[IPv4BitsPerSegment].cache.isSinglePrefBlock = &trueVal xxxxx wrong when prefLen is 8 they are all prefix blocks xxxx
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
			atomic.StorePointer(dataLoc, unsafe.Pointer(block))
		}
		result = &block.block[value]
		checkValuesIPv4(value, value, result) //xxx getting wrong cached answer for value 0 and prefLen 8
		return result
	}
	var isSinglePrefBlock *bool
	if segmentPrefixLength == IPv4BitsPerSegment {
		isSinglePrefBlock = &trueVal
	} else {
		isSinglePrefBlock = &falseVal
	}
	return &ipv4SegmentValues{
		value:      value,
		upperValue: value,
		prefLen:    prefLen,
		cache: divCache{
			isSinglePrefBlock: isSinglePrefBlock,
		},
	}
}

func newIPv4SegmentPrefixedValues(value, upperValue IPv4SegInt, prefLen PrefixLen) *ipv4SegmentValues {
	var isSinglePrefBlock *bool
	if prefLen == nil {
		if value == upperValue {
			return newIPv4SegmentVal(value)
		} else if value > upperValue {
			value, upperValue = upperValue, value
		}
		if useIPv4SegmentCache && value == 0 && upperValue == IPv4MaxValuePerSegment {
			return allRangeValsIPv4
		}
		isSinglePrefBlock = &falseVal
	} else {
		if value == upperValue {
			return newIPv4SegmentPrefixedVal(value, prefLen)
		} else if value > upperValue {
			value, upperValue = upperValue, value
		}
		segmentPrefixLength := *prefLen
		if segmentPrefixLength < 0 {
			segmentPrefixLength = 0
		} else if segmentPrefixLength > IPv4BitsPerSegment {
			segmentPrefixLength = IPv4BitsPerSegment
		}
		prefLen = cacheBitCount(segmentPrefixLength) // this ensures we use the prefix length cache for all segments
		if useIPv4SegmentCache {
			// cache is the prefix block for any prefix length
			shiftBits := uint(IPv4BitsPerSegment - segmentPrefixLength)
			nmask := ^IPv4SegInt(0) << shiftBits
			prefixBlockLower := value & nmask
			hmask := ^nmask
			prefixBlockUpper := value | hmask
			if value == prefixBlockLower && upperValue == prefixBlockUpper {
				valueIndex := value >> shiftBits
				cache := prefixBlocksCacheIPv4
				prefixIndex := segmentPrefixLength
				block := cache[prefixIndex]
				var result *ipv4SegmentValues
				if block == nil {
					block = &ipv4DivsBlock{make([]ipv4SegmentValues, 1<<uint(segmentPrefixLength))}
					vals := block.block
					for i := range vals {
						value := &vals[i]
						segi := IPv4SegInt(i << shiftBits)
						value.value = segi
						value.upperValue = segi | hmask
						value.prefLen = prefLen
						value.cache.isSinglePrefBlock = &trueVal
					}
					dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
					atomic.StorePointer(dataLoc, unsafe.Pointer(block))
				}
				result = &block.block[valueIndex]
				checkValuesIPv4(value, upperValue, result)
				return result
			}
			if value == 0 {
				// cache is 0-255 for any prefix length
				if upperValue == IPv4MaxValuePerSegment {
					result := &allPrefixedCacheIPv4[segmentPrefixLength]
					checkValuesIPv4(value, upperValue, result)
					return result
				}
			}
			isSinglePrefBlock = &falseVal
		}
	}
	return &ipv4SegmentValues{
		value:      value,
		upperValue: upperValue,
		prefLen:    prefLen,
		cache: divCache{
			isSinglePrefBlock: isSinglePrefBlock,
		},
	}
}
