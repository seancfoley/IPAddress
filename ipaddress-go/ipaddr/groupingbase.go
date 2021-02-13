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

func (grouping *addressDivisionGroupingBase) GetGenericDivision(index int) AddressGenericDivision {
	return grouping.getDivision(index)
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

func (grouping *addressDivisionGroupingBase) getBigCount() *big.Int {
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

func (grouping *addressDivisionGroupingBase) IsMore(other AddressDivisionSeries) int {
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
	if !grouping.IsMultiple() {
		return bigOne()
	}
	return grouping.cacheCount(grouping.getBigCount)
}

func (grouping *addressDivisionGroupingBase) cacheCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache // IsMultiple checks prior to this ensures cache no nil here
	count := cache.cachedCount
	if count == nil {
		count = &countSetting{counter()}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
	}
	//if cache.cachedCount.isNotSetNoSync() {
	//	cache.cacheLock.Lock()
	//	if cache.cachedCount.isNotSetNoSync() {
	//		cache.cachedCount.count = counter()
	//		cache.cachedCount.set()
	//	}
	//	cache.cacheLock.Unlock()
	//}
	return new(big.Int).Set(cache.cachedCount.count)
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
	//	All writing done after locking the cacheLock.
	//	Reading can be done by using the read lock of the cachelock,
	//	or instead using a specific atomic flag covering a specific set of cache fields.
	cacheLock sync.RWMutex

	cachedCount, cachedPrefixCount *countSetting // use BitLen() or len(x.Bits()) to check if value is set, or maybe check for 0

	cachedMaskLens *maskLenSetting

	lowerBytes, upperBytes []byte
	cachedLowerVal         uint32

	stringCache stringCache

	sectionCache groupingCache
}

type stringCache struct {
	string1, string2 string //TODO the various strings will go here
}

type groupingCache struct {
	lower, upper *AddressSection
}

type maskLenSetting struct {
	//x                           atomicFlag
	networkMaskLen, hostMaskLen PrefixLen
}

type countSetting struct {
	//x     atomicFlag
	count *big.Int
}

type divArray interface {
	getDivision(index int) *addressDivisionBase

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
