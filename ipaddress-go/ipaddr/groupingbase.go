package ipaddr

import (
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"unsafe"
)

type addressDivisionGroupingBase struct {
	// the non-cache elements are assigned at creation and are immutable
	divisions    divArray  // either standard or large
	prefixLength PrefixLen // must align with the divisions if they store prefix lengths
	isMultiple   bool

	// When a top-level section is created, it is assigned an address type, IPv4, IPv6, or MAC,
	// and determines if an *AddressDivisionGrouping can be converted back to a section of the original type.
	//
	// Type-specific functions in IPAddressSection and lower levels, such as functions returning strings,
	// can rely on this field.
	addrType addrType

	// TODO make sure we always check cache for nil, one way is to change name and check each access
	// assigned on creation only; for zero-value groupings it is never assigned, but in that case it is not needed since there is nothing to cache
	cache *valueCache
}

// TODO for large will need to add methods in java AddressItem (porting those same methods in AddressItem using BigINteger to use big.int should do it):
// isSinglePrefixBlock, isPrefixBlock, containsPrefixBlock(int), containsSinglePrefixBlock(int), getMinPrefixLengthForBlock() bitcount, getPrefixLengthForSingleBlock() prefixlen

func (grouping *addressDivisionGroupingBase) getAddrType() addrType {
	return grouping.addrType
}

// hasNoDivisions() returns whether this grouping is the zero grouping,
// which is what you get when contructing a grouping or section with no divisions
func (grouping *addressDivisionGroupingBase) hasNoDivisions() bool {
	divisions := grouping.divisions
	return divisions == nil || divisions.getDivisionCount() == 0
}

// GetBitCount returns the total number of bits across all divisions
func (grouping addressDivisionGroupingBase) GetBitCount() (res BitCount) { //TODO if we end up using this a lot, consider storing it on grouping construction
	for i := 0; i < grouping.GetDivisionCount(); i++ {
		res += grouping.getDivision(i).GetBitCount()
	}
	return
}

// GetBitCount returns the total number of bytes across all divisions (rounded up)
func (grouping addressDivisionGroupingBase) GetByteCount() int {
	return (int(grouping.GetBitCount()) + 7) >> 3
}

// getDivision returns the division or panics if the index is negative or it is too large
func (grouping *addressDivisionGroupingBase) getDivision(index int) *addressDivisionBase {
	return grouping.divisions.getDivision(index)
}

//// GetStringDivision returns the division as a common interface AddressStringDivision,
//// which allows all division types and aggregated division types to be represented by a single type
//// that is used for string generation.
//func (grouping *addressDivisionGroupingBase) GetStringDivision(index int) AddressStringDivision {
//	return grouping.getDivision(index)
//}

// GetGenericDivision returns the division as an AddressGenericDivision,
// allowing all division types and aggregated division types to be represented by a single type,
// useful for comparisons and other common uses.
func (grouping *addressDivisionGroupingBase) GetGenericDivision(index int) AddressGenericDivision {
	return grouping.divisions.getGenericDivision(index)
}

func (grouping *addressDivisionGroupingBase) GetDivisionCount() int {
	divisions := grouping.divisions
	if divisions != nil {
		return divisions.getDivisionCount()
	}
	return 0
}

func (grouping *addressDivisionGroupingBase) matchesStructure(other GenericGroupingType) (matches bool, count int) {
	count = grouping.GetDivisionCount()
	if count != other.GetDivisionCount() {
		return
	} else if grouping.getAddrType() != other.getAddrType() {
		return
	}
	matches = true
	return
}

func (grouping *addressDivisionGroupingBase) Equals(other GenericGroupingType) bool {
	matches, count := grouping.matchesStructure(other)
	if !matches || count != other.GetDivisionCount() {
		return false
	} else {
		for i := 0; i < count; i++ {
			one := grouping.GetGenericDivision(i)
			two := other.GetGenericDivision(i)
			if !one.Equals(two) { //this checks the division types and also the bit counts
				return false
			}
		}
	}
	return true
}

func (grouping *addressDivisionGroupingBase) IsZero() bool {
	divCount := grouping.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		if !grouping.getDivision(i).IsZero() {
			return false
		}
	}
	return true
}

func (grouping *addressDivisionGroupingBase) IncludesZero() bool {
	divCount := grouping.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		if !grouping.getDivision(i).IncludesZero() {
			return false
		}
	}
	return true
}

func (grouping *addressDivisionGroupingBase) IsMax() bool {
	divCount := grouping.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		if !grouping.getDivision(i).IsMax() {
			return false
		}
	}
	return true
}

func (grouping *addressDivisionGroupingBase) IncludesMax() bool {
	divCount := grouping.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		if !grouping.getDivision(i).IncludesMax() {
			return false
		}
	}
	return true
}

func (grouping *addressDivisionGroupingBase) IsFullRange() bool {
	divCount := grouping.GetDivisionCount()
	for i := 0; i < divCount; i++ {
		if !grouping.getDivision(i).IsFullRange() {
			return false
		}
	}
	return true
}

/**
 * Gets the minimal segment index for which all following segments are full-range blocks.
 * <p>
 * The segment at this index is not a full-range block unless all segments are full-range.
 * The segment at this index and all following segments form a sequential range.
 * For the full series to be sequential, the preceding segments must be single-valued.
 *
 * @return
 */
func (grouping *addressDivisionGroupingBase) GetSequentialBlockIndex() int {
	segCount := grouping.GetDivisionCount()
	if segCount > 0 {
		for segCount--; segCount > 0 && grouping.getDivision(segCount).IsFullRange(); segCount-- {
		}
	}
	return segCount
}

func (grouping *addressDivisionGroupingBase) getCountBig() *big.Int {
	res := bigOne()
	count := grouping.GetDivisionCount()
	if count > 0 {
		for i := 0; i < count; i++ {
			div := grouping.getDivision(i)
			if div.IsMultiple() {
				res.Mul(res, div.GetCount())
			}
		}
	}
	return res
}

func (grouping *addressDivisionGroupingBase) getPrefixCountBig() *big.Int {
	prefixLen := grouping.prefixLength
	if prefixLen == nil {
		return grouping.getCountBig()
	}
	return grouping.getPrefixCountLenBig(*prefixLen)
}

func (grouping *addressDivisionGroupingBase) getPrefixCountLenBig(prefixLen BitCount) *big.Int {
	if prefixLen <= 0 {
		return bigOne()
	} else if prefixLen >= grouping.GetBitCount() {
		return grouping.getCountBig()
	}
	res := bigOne()
	if grouping.IsMultiple() {
		divisionCount := grouping.GetDivisionCount()
		divPrefixLength := prefixLen
		for i := 0; i < divisionCount; i++ {
			div := grouping.getDivision(i)
			divBitCount := div.getBitCount()
			if div.IsMultiple() {
				var divCount *big.Int
				if divPrefixLength < divBitCount {
					divCount = div.GetPrefixCount(divPrefixLength)
				} else {
					divCount = div.GetCount()
				}
				res.Mul(res, divCount)
			}
			if divPrefixLength <= divBitCount {
				break
			}
			divPrefixLength -= divBitCount
		}
	}
	return res
}

func (grouping *addressDivisionGroupingBase) CompareSize(other AddressDivisionSeries) int {
	if !grouping.IsMultiple() {
		if other.IsMultiple() {
			return -1
		}
		return 0
	}
	if !other.IsMultiple() {
		return 1
	}
	return grouping.GetCount().CmpAbs(other.GetCount())
}

func (grouping *addressDivisionGroupingBase) GetCount() *big.Int {
	return grouping.cacheCount(grouping.getCountBig)
}

func (grouping *addressDivisionGroupingBase) GetPrefixCount() *big.Int {
	return grouping.cachePrefixCount(grouping.getPrefixCountBig)
}

func (grouping *addressDivisionGroupingBase) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	return grouping.calcCount(func() *big.Int { return grouping.getPrefixCountLenBig(prefixLen) })
}

func (grouping *addressDivisionGroupingBase) cacheCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache // IsMultiple checks prior to this ensures cache no nil here
	count := cache.cachedCount
	if count == nil {
		count = grouping.calcCount(counter)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
	}
	return new(big.Int).Set(cache.cachedCount)
}

func (grouping *addressDivisionGroupingBase) calcCount(counter func() *big.Int) *big.Int {
	if !grouping.IsMultiple() {
		return bigOne()
	}
	return counter()
}

func (grouping *addressDivisionGroupingBase) cachePrefixCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache // IsMultiple checks prior to this ensures cache no nil here
	count := cache.cachedPrefixCount
	if count == nil {
		count = grouping.calcPrefixCount(counter)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedPrefixCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
	}
	return new(big.Int).Set(cache.cachedPrefixCount)
}

func (grouping *addressDivisionGroupingBase) calcPrefixCount(counter func() *big.Int) *big.Int {
	if !grouping.IsMultiple() {
		return bigOne()
	}
	prefixLen := grouping.prefixLength
	if prefixLen == nil || *prefixLen >= grouping.GetBitCount() {
		return grouping.GetCount()
	}
	return counter()
}

func (grouping *addressDivisionGroupingBase) getCachedBytes(calcBytes func() (bytes, upperBytes []byte)) (bytes, upperBytes []byte) {
	cache := grouping.cache
	if cache == nil {
		return emptyBytes, emptyBytes
	}
	cache.cacheLock.RLock()
	bytes, upperBytes = cache.lowerBytes, cache.upperBytes
	cache.cacheLock.RUnlock()
	if bytes != nil {
		return
	}
	cache.cacheLock.Lock()
	bytes, upperBytes = cache.lowerBytes, cache.upperBytes
	if bytes == nil {
		bytes, upperBytes = calcBytes()
		cache.lowerBytes, cache.upperBytes = bytes, upperBytes
	}
	cache.cacheLock.Unlock()
	return
}

// IsMultiple returns whether this address or grouping represents more than one address or grouping.
// Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
func (grouping *addressDivisionGroupingBase) IsMultiple() bool {
	return grouping.isMultiple
}

type valueCache struct {
	//	Cache lock is used for some fields, but not all, most use atomic reads/writes of pointers
	cacheLock sync.RWMutex

	cachedCount, cachedPrefixCount *big.Int

	cachedMaskLens *maskLenSetting

	lowerBytes, upperBytes         []byte
	cachedLowerVal, cachedUpperVal *uint32

	zeroVals *zeroRangeCache

	stringCache stringCache

	sectionCache groupingCache

	defaultMixedAddressSection *IPv6v4MixedAddressSection
	embeddedIPv4Section        *IPv4AddressSection
}

type ipStringCache struct {
	normalizedWildcardString,
	fullString,
	sqlWildcardString,

	reverseDNSString,

	octalString, octalStringPrefixed,
	binaryString, binaryStringPrefixed,

	segmentedBinaryString *string
}

type ipv4StringCache struct {
	inetAtonOctalString,
	inetAtonHexString *string
}

type ipv6StringCache struct {
	normalizedIPv6String,
	compressedIPv6String,
	mixedString,
	compressedWildcardString,
	canonicalWildcardString,
	networkPrefixLengthString,
	base85String *string
}

type macStringCache struct {
	normalizedMACString,
	compressedMACString,
	dottedString,
	spaceDelimitedString *string
}

type stringCache struct {
	canonicalString *string

	hexString, hexStringPrefixed *string

	*ipv6StringCache

	*ipv4StringCache

	*ipStringCache

	*macStringCache
}

var zeroStringCache stringCache

type groupingCache struct {
	lower, upper *AddressSection
}

type zeroRangeCache struct {
	zeroSegments, zeroRangeSegments RangeList
}

type maskLenSetting struct {
	networkMaskLen, hostMaskLen PrefixLen
}

//type countSetting struct { //TODO just use big.Int, no need for this struct
//	//x     atomicFlag
//	count *big.Int
//}

type divArray interface {
	// TODO if this returned an interface, maybe it would be more useful, could move more stuff into groupingbase from grouping
	// Or merge it with getGenericDivision
	// Or make those calls use getGenericDivision instead.
	getDivision(index int) *addressDivisionBase

	getGenericDivision(index int) AddressGenericDivision

	getDivisionCount() int

	fmt.Stringer
}

var zeroDivs = make([]*AddressDivision, 0)
var zeroStandardDivArray = standardDivArray{zeroDivs}

type standardDivArray struct {
	divisions []*AddressDivision
}

func (grouping standardDivArray) getDivisionCount() int {
	return len(grouping.divisions)
}

func (grouping standardDivArray) getDivision(index int) *addressDivisionBase {
	return (*addressDivisionBase)(unsafe.Pointer(grouping.divisions[index]))
}

func (grouping standardDivArray) getGenericDivision(index int) AddressGenericDivision {
	return grouping.divisions[index]
}

func (grouping standardDivArray) copySubDivisions(start, end int, divs []*AddressDivision) (count int) {
	return copy(divs, grouping.divisions[start:end])
}

func (grouping standardDivArray) copyDivisions(divs []*AddressDivision) (count int) {
	return copy(divs, grouping.divisions)
}

func (grouping standardDivArray) init() standardDivArray {
	if grouping.divisions == nil {
		return zeroStandardDivArray
	}
	return grouping
}

func (grouping standardDivArray) String() string {
	return fmt.Sprintf("%v", grouping.init().divisions)
}
