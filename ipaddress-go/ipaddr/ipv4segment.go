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
	prefLen    PrefixLen //TODO maybe use one prefixlen type for api, and a second here to restrict the size of the int
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
	return big.NewInt(int64(seg.upperValue-seg.value) + 1)
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
var zeroIPv4SegZeroPrefix = NewIPv4PrefixedSegment(0, cacheBitCount(0))
var zeroIPv4SegPrefixBlock = NewIPv4RangePrefixedSegment(0, IPv4MaxValuePerSegment, cacheBitCount(0))

type IPv4AddressSegment struct {
	ipAddressSegmentInternal
}

func (seg *IPv4AddressSegment) init() *IPv4AddressSegment {
	if seg.divisionValues == nil {
		return zeroIPv4Seg
	}
	return seg
}

func (seg *IPv4AddressSegment) Contains(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToAddressSegment() == nil
	}
	return seg.init().contains(other)
}

func (seg *IPv4AddressSegment) Equal(other AddressSegmentType) bool {
	if seg == nil {
		return other == nil || other.ToAddressDivision() == nil
	}
	return seg.init().equal(other)
}

func (seg *IPv4AddressSegment) Compare(item AddressItem) int {
	if seg != nil {
		seg = seg.init()
	}
	return CountComparator.Compare(seg, item)
}

// PrefixEquals returns whether the range of the given prefix bits contains the same bits of the given segment.
func (seg *IPv4AddressSegment) PrefixContains(other AddressSegmentType, prefixLength BitCount) bool {
	return seg.init().ipAddressSegmentInternal.PrefixContains(other, prefixLength)
}

// PrefixEquals returns whether the given prefix bits match the same bits of the given segment.
func (seg *IPv4AddressSegment) PrefixEqual(other AddressSegmentType, prefixLength BitCount) bool {
	return seg.init().ipAddressSegmentInternal.PrefixEqual(other, prefixLength)
}

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
	return seg.init().getLower().ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) GetUpper() *IPv4AddressSegment {
	return seg.init().getUpper().ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) IsMultiple() bool {
	return seg != nil && seg.isMultiple()
}

func (seg *IPv4AddressSegment) GetCount() *big.Int {
	if seg == nil {
		return bigZero()
	}
	return seg.getCount()
}

func (seg *IPv4AddressSegment) GetPrefixCountLen(segmentPrefixLength BitCount) *big.Int {
	return seg.init().ipAddressSegmentInternal.GetPrefixCountLen(segmentPrefixLength)
}

func (seg *IPv4AddressSegment) GetPrefixValueCountLen(segmentPrefixLength BitCount) SegIntCount {
	return seg.init().ipAddressSegmentInternal.GetPrefixValueCountLen(segmentPrefixLength)
}

// Returns true if the bit in the lower value of this segment at the given index is 1, where index 0 is the most significant bit.
func (seg *IPv4AddressSegment) IsOneBit(segmentBitIndex BitCount) bool {
	return seg.init().ipAddressSegmentInternal.IsOneBit(segmentBitIndex)
}

func (seg *IPv4AddressSegment) GetBytes() []byte {
	return seg.init().ipAddressSegmentInternal.GetBytes()
}

func (seg *IPv4AddressSegment) GetUpperBytes() []byte {
	return seg.init().ipAddressSegmentInternal.GetUpperBytes()
}

func (seg *IPv4AddressSegment) CopyBytes(bytes []byte) []byte {
	return seg.init().ipAddressSegmentInternal.CopyBytes(bytes)
}

func (seg *IPv4AddressSegment) CopyUpperBytes(bytes []byte) []byte {
	return seg.init().ipAddressSegmentInternal.CopyUpperBytes(bytes)
}

func (seg *IPv4AddressSegment) GetPrefixValueCount() SegIntCount {
	return seg.init().ipAddressSegmentInternal.GetPrefixValueCount()
}

func (seg *IPv4AddressSegment) MatchesWithPrefixMask(value IPv4SegInt, networkBits BitCount) bool {
	return seg.init().ipAddressSegmentInternal.MatchesWithPrefixMask(SegInt(value), networkBits)
}

// GetBlockMaskPrefixLen returns the prefix length if this address section is equivalent to the mask for a CIDR prefix block.
// Otherwise, it returns null.
// A CIDR network mask is an address with all 1s in the network section and then all 0s in the host section.
// A CIDR host mask is an address with all 0s in the network section and then all 1s in the host section.
// The prefix length is the length of the network section.
//
// Also, keep in mind that the prefix length returned by this method is not equivalent to the prefix length of this object,
// indicating the network and host section of this address.
// The prefix length returned here indicates the whether the value of this address can be used as a mask for the network and host
// section of any other address.  Therefore the two values can be different values, or one can be null while the other is not.
//
// This method applies only to the lower value of the range if this section represents multiple values.
func (seg *IPv4AddressSegment) GetBlockMaskPrefixLen(network bool) PrefixLen {
	return seg.init().ipAddressSegmentInternal.GetBlockMaskPrefixLen(network)
}

// GetTrailingBitCount returns the number of consecutive trailing one or zero bits.
// If ones is true, returns the number of consecutive trailing zero bits.
// Otherwise, returns the number of consecutive trailing one bits.
//
// This method applies only to the lower value of the range if this segment represents multiple values.
func (seg *IPv4AddressSegment) GetTrailingBitCount(ones bool) BitCount {
	return seg.init().ipAddressSegmentInternal.GetTrailingBitCount(ones)
}

//	GetLeadingBitCount returns the number of consecutive leading one or zero bits.
// If ones is true, returns the number of consecutive leading one bits.
// Otherwise, returns the number of consecutive leading zero bits.
//
// This method applies only to the lower value of the range if this segment represents multiple values.
func (seg *IPv4AddressSegment) GetLeadingBitCount(ones bool) BitCount {
	return seg.init().ipAddressSegmentInternal.GetLeadingBitCount(ones)
}

func (seg *IPv4AddressSegment) ToPrefixedNetworkSegment(segmentPrefixLength PrefixLen) *IPv4AddressSegment {
	return seg.init().toPrefixedNetworkDivision(segmentPrefixLength).ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) ToNetworkSegment(segmentPrefixLength PrefixLen) *IPv4AddressSegment {
	return seg.init().toNetworkDivision(segmentPrefixLength, false).ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) ToPrefixedHostSegment(segmentPrefixLength PrefixLen) *IPv4AddressSegment {
	return seg.init().toPrefixedHostDivision(segmentPrefixLength).ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) ToHostSegment(segmentPrefixLength PrefixLen) *IPv4AddressSegment {
	return seg.init().toHostDivision(segmentPrefixLength, false).ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) Iterator() IPv4SegmentIterator {
	if seg == nil {
		return ipv4SegmentIterator{nilSegIterator()}
	}
	return ipv4SegmentIterator{seg.init().iterator()}
}

func (seg *IPv4AddressSegment) PrefixBlockIterator() IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.init().prefixBlockIterator()}
}

func (seg *IPv4AddressSegment) PrefixedBlockIterator(segmentPrefixLen BitCount) IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.init().prefixedBlockIterator(segmentPrefixLen)}
}

func (seg *IPv4AddressSegment) PrefixIterator() IPv4SegmentIterator {
	return ipv4SegmentIterator{seg.init().prefixIterator()}
}

func (seg *IPv4AddressSegment) IsPrefixed() bool {
	return seg != nil && seg.isPrefixed()
}

func (seg *IPv4AddressSegment) WithoutPrefixLen() *IPv4AddressSegment {
	if !seg.IsPrefixed() {
		return seg
	}
	return seg.withoutPrefixLen().ToIPv4AddressSegment()
}

func (seg *IPv4AddressSegment) ReverseBits(_ bool) (res *IPv4AddressSegment, err IncompatibleAddressError) {
	if seg.divisionValues == nil {
		res = seg
		return
	}
	if seg.isMultiple() {
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
	return !seg.isMultiple() || low.IsFullRange()
}

// join joins with another IPv4 segment to produce a IPv6 segment.
func (seg *IPv4AddressSegment) join(low *IPv4AddressSegment) (*IPv6AddressSegment, IncompatibleAddressError) {
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

func (seg *IPv4AddressSegment) ToAddressDivision() *AddressDivision {
	return seg.ToAddressSegment().ToAddressDivision()
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

func (seg *IPv4AddressSegment) GetString() string {
	if seg == nil {
		return nilString()
	}
	return seg.init().getString()
}

func (seg *IPv4AddressSegment) GetWildcardString() string {
	if seg == nil {
		return nilString()
	}
	return seg.init().getWildcardString()
}

func (seg *IPv4AddressSegment) String() string {
	if seg == nil {
		return nilString()
	}
	return seg.init().toString()
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
