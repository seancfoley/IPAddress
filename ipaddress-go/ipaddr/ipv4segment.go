package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

type IPv4SegInt uint8

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

func (seg *IPv4AddressSegment) GetBitCount() BitCount {
	return IPv4BitsPerSegment
}

func (seg *IPv4AddressSegment) GetByteCount() int {
	return IPv4BytesPerSegment
}

func (seg *IPv4AddressSegment) GetMaxValue() IPv4SegInt {
	return 0xff
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
		if isReversible, _ := seg.isReversibleRange(false); isReversible {
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

func NewIPv4PrefixSegment(val IPv4SegInt, prefixLen PrefixLen) *IPv4AddressSegment {
	return newIPv4Segment(newIPv4SegmentPrefixedVal(val, prefixLen))
}

func NewIPv4RangePrefixSegment(val, upperVal IPv4SegInt, prefixLen PrefixLen) *IPv4AddressSegment {
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
	block []*ipv4SegmentValues
}

var (
	allRangeValsIPv4 = &ipv4SegmentValues{
		upperValue: IPv4MaxValuePerSegment,
	}
	allPrefixedCacheIPv4   = make([]*ipv4SegmentValues, IPv4BitsPerSegment+1)
	segmentCacheIPv4       = make([]*ipv4SegmentValues, IPv4MaxValuePerSegment+1)
	segmentPrefixCacheIPv4 = make([]*ipv4DivsBlock, IPv4BitsPerSegment+1)
	prefixBlocksCacheIPv4  = make([]*ipv4DivsBlock, IPv4BitsPerSegment+1)
)

//func newIPv4SegmentVal(value IPv4SegInt) *ipv4SegmentValues {
//	res := newIPv4SegmentValX(value)
//	if res == nil {
//		newIPv4SegmentValX(value)
//		panic("hi")
//	}
//	return res
//}

func newIPv4SegmentVal(value IPv4SegInt) *ipv4SegmentValues {
	if useIPv4SegmentCache {
		cache := segmentCacheIPv4
		result := cache[value]
		if result == nil {
			result = &ipv4SegmentValues{
				value:      value,
				upperValue: value,
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[value]))
			atomic.StorePointer(dataLoc, unsafe.Pointer(result))
		}
		return result
	}
	return &ipv4SegmentValues{
		value:      value,
		upperValue: value,
	}
}

//func newIPv4SegmentPrefixedVal(value IPv4SegInt, prefLen PrefixLen) (result *ipv4SegmentValues) {
//	res := newIPv4SegmentPrefixedValX(value, prefLen)
//	if res == nil {
//		res = newIPv4SegmentPrefixedValX(value, prefLen)
//		panic("hi")
//	}
//	return res
//}

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
		valueIndex := value
		cache := segmentPrefixCacheIPv4
		block := cache[prefixIndex]
		if block == nil {
			block = &ipv4DivsBlock{make([]*ipv4SegmentValues, IPv4MaxValuePerSegment+1)}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
			atomic.StorePointer(dataLoc, unsafe.Pointer(block))
			result = &ipv4SegmentValues{
				value:      value,
				upperValue: value,
				prefLen:    prefLen,
			}
			dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&block.block[valueIndex]))
			atomic.StorePointer(dataLoc, unsafe.Pointer(result))
		} else {
			result = block.block[valueIndex]
			if result == nil {
				result = &ipv4SegmentValues{
					value:      value,
					upperValue: value,
					prefLen:    prefLen,
				}
				dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&block.block[valueIndex]))
				atomic.StorePointer(dataLoc, unsafe.Pointer(result))
			}
		}
		return result
	}
	return &ipv4SegmentValues{
		value:      value,
		upperValue: value,
		prefLen:    prefLen,
	}
}

//func newIPv4SegmentPrefixedValues(value, upperValue IPv4SegInt, prefLen PrefixLen) *ipv4SegmentValues {
//	res := newIPv4SegmentPrefixedValuesX(value, upperValue, prefLen)
//	if res == nil {
//		newIPv4SegmentPrefixedValuesX(value, upperValue, prefLen)
//		panic("hi")
//	}
//	return res
//}

func newIPv4SegmentPrefixedValues(value, upperValue IPv4SegInt, prefLen PrefixLen) *ipv4SegmentValues {
	if prefLen == nil {
		if value == upperValue {
			return newIPv4SegmentVal(value)
		}
		if useIPv4SegmentCache && value == 0 && upperValue == IPv4MaxValuePerSegment {
			return allRangeValsIPv4
		}
	} else {
		if value == upperValue {
			return newIPv4SegmentPrefixedVal(value, prefLen)
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
			shiftBits := uint(8 - segmentPrefixLength)
			prefixBlockUpper := value | ^(^IPv4SegInt(0) << shiftBits)
			if upperValue == prefixBlockUpper {
				valueIndex := value >> shiftBits
				cache := prefixBlocksCacheIPv4
				prefixIndex := segmentPrefixLength
				block := cache[prefixIndex]
				var result *ipv4SegmentValues
				if block == nil {
					block = &ipv4DivsBlock{make([]*ipv4SegmentValues, 1<<uint(segmentPrefixLength))}
					dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
					atomic.StorePointer(dataLoc, unsafe.Pointer(block))
					result = &ipv4SegmentValues{
						value:      value,
						upperValue: upperValue,
						prefLen:    prefLen,
					}
					dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&block.block[valueIndex]))
					atomic.StorePointer(dataLoc, unsafe.Pointer(result))
				} else {
					result = block.block[valueIndex]
					if result == nil {
						result = &ipv4SegmentValues{
							value:      value,
							upperValue: value,
							prefLen:    prefLen,
						}
						dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&block.block[valueIndex]))
						atomic.StorePointer(dataLoc, unsafe.Pointer(result))
					}
				}
				return result
			}
			if value == 0 {
				// cache is 0-255 for any prefix length
				if upperValue == IPv4MaxValuePerSegment {
					prefixIndex := segmentPrefixLength
					cache := allPrefixedCacheIPv4
					result := cache[prefixIndex]
					if result == nil {
						result = &ipv4SegmentValues{
							upperValue: IPv4MaxValuePerSegment,
							prefLen:    prefLen,
						}
						dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[prefixIndex]))
						atomic.StorePointer(dataLoc, unsafe.Pointer(result))
					}
					return result
				}
			}
		}
	}
	return &ipv4SegmentValues{
		value:      value,
		upperValue: upperValue,
		prefLen:    prefLen,
	}
}
