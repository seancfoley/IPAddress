package ipaddr

import (
	"fmt"
	"math/big"
	"sync"
	"unsafe"
)

type addressDivisionGroupingBase struct {
	// the non-cache elements are assigned at creation and are immutable
	divisions    divArray  // either standard or large
	prefixLength PrefixLen // must align with the divisions if they store prefix lengths
	isMultiple   bool

	// TODO make sure we always check cache for nil, one way is to change name and check each access
	// assigned on creation only; for zero-value groupings it is never assigned, but in that case it is not needed since there is nothing to cache
	cache *valueCache
}

// hasNoDivisions() returns whether this grouping is the zero grouping,
// which is what you get when contructing a grouping or section with no divisions
func (grouping *addressDivisionGroupingBase) hasNoDivisions() bool {
	divisions := grouping.divisions
	return divisions == nil || divisions.getDivisionCount() == 0
}

// GetBitCount returns the total number of bits across all divisions
func (grouping addressDivisionGroupingBase) GetBitCount() (res BitCount) { //TODO if we end up using this a lot, consider storing it on grouping construction
	for i := 0; i < grouping.getDivisionCount(); i++ {
		res += grouping.getDivision(i).GetBitCount()
	}
	return
}

// GetBitCount returns the total number of bytes across all divisions (rounded up)
func (grouping addressDivisionGroupingBase) GetByteCount() BitCount {
	return (grouping.GetBitCount() + 7) >> 3
}

// getDivision returns the division or panics if the index is negative or it is too large
func (grouping *addressDivisionGroupingBase) getDivision(index int) *addressDivisionBase {
	return grouping.divisions.getDivision(index)
}

func (grouping *addressDivisionGroupingBase) getDivisionCount() int {
	divisions := grouping.divisions
	if divisions != nil {
		return divisions.getDivisionCount()
	}
	return 0
}

func (grouping *addressDivisionGroupingBase) getBigCount() *big.Int {
	res := bigOne()
	count := grouping.getDivisionCount()
	if count > 0 {
		for i := 0; i < count; i++ {
			div := grouping.getDivision(i)
			if div.IsMultiple() {
				divCount := div.GetCount()
				res.Mul(res, divCount)
			}
		}
	}
	return res
}

func (grouping *addressDivisionGroupingBase) GetCount() *big.Int {
	if !grouping.IsMultiple() {
		return bigOne()
	}
	return grouping.cacheCount(grouping.getBigCount)
}

func (grouping *addressDivisionGroupingBase) cacheCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache
	if !cache.cachedCount.isSetNoSync() {
		cache.cacheLock.Lock()
		if !cache.cachedCount.isSetNoSync() {
			cache.cachedCount.count = *counter()
			cache.cachedCount.set()
		}
		cache.cacheLock.Unlock()
	}
	return &cache.cachedCount.count
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

	cachedCount, cachedPrefixCount countSetting // use BitLen() or len(x.Bits()) to check if value is set, or maybe check for 0

	cachedMaskLens maskLenSetting

	lowerBytes, upperBytes []byte

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
	atomicFlag
	networkMaskLen, hostMaskLen PrefixLen
}

type countSetting struct {
	atomicFlag
	count big.Int
}

type divArray interface {
	getDivision(index int) *addressDivisionBase

	getDivisionCount() int

	fmt.Stringer
}

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

func (grouping standardDivArray) String() string {
	return fmt.Sprintf("%v", grouping.divisions)
}
