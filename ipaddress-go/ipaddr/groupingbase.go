package ipaddr

import (
	"fmt"
	"math/big"
	"sync/atomic"
	"unsafe"
)

// option 1
//type PrefixLen struct {
//	bitCount *BitCount
//}
//
// option 2
//type BitCount struct {
//	bitCount int16
//}
// type PrefixLen *BitCount
//
// option 3
//type PrefixLen struct {
// isSet bool
// bitCount BitCount
//}
//
//
//option 4
//type PrefixLen *PrefixBitCount
//
//type PrefixBitCount struct {
//	bitCount bitCountInternal
//}
//
//type BitCount = int
//type bitCountInternal = int16

type addressDivisionGroupingBase struct {
	// the non-cacheBitCountx elements are assigned at creation and are immutable
	divisions divArray // either standard or large

	//  in places where you assign prefix length, you need to use our own cached values, because the pointed prefix value can change.
	// We already do this for cached segments using cacheBitCount.
	// Not only that, wherever you return prefix lengths, you have the same problem, the returned value points to the stored field.
	// Callers could then change the stored field.  So you'd have to allocate a new int on the heap and point to it!  ouch.
	// This is just bad all around.  How did you not think of this before?  It just goes to show, you need to write code of a library to get a taste for it.
	//
	// What if you changed prefixLen to be a struct of a private value?  In fact, it would be a struct of a pointer?
	// cacheBitCount could be avoided everywhere!
	// the zero prefix would then be nil!  I like it.
	// Tempting.  Very tempting.
	// You could then give it its own methods instead of what you did with BitCount pointer methods.
	// But then, everywhere you supply nil for a prefix, compile error.  It would have to be replaced with Prefix{}
	// You could no longer use "nil" which is a bit more intuitive perhaps.
	// HOwever, you cannot currently do &32 and that is annoying! Makes you do p0, p1, etc which you are doing in the tests.
	// Soon you could soon do ipaddr.PrefixLength(32) which is nice!
	// And you could have ipaddr.NoPrefix() which returns Prefix{} - or use a public variable ipaddr.NoPrefix (which is better? hard to say - Both? probably the constant)
	// YOu can still derefence, you just do *p.bitCount
	// What we're doing now with the prefix values in tests, p0, p1, ... is what everyone will do, or should do, and that is lame
	// An altrnative is to change bitcount to be the struct
	// that way you can still use all the same as now, with nil prefix as zero value, but once again you get the safety
	// to dereference you do (*p).bitCount
	// I think the first is a bit better, because the second makes BitCount awkward.
	// The second means you must define some BitCount struct tht is somewhat meaningless, the thing prefixes point to,
	// but all your methods thst take BitCount will not want to use this struct instead, so the struct is somewhat lame
	// The only upside is you can continue using "nil" prefixes
	// In fact, the second doesn't really work because you can still alter the prefix length pointers
	//  PrefixLen: I think I've settle on option 1 above Actually maybe 3 is better, avoids ptr dereference, takes advantage of memory localization
	// maybe use one prefixlen type for api, and a second here to restrict the size of the int to int16

	prefixLength PrefixLen // must align with the divisions if they store prefix lengths
	isMult       bool

	// When a top-level section is created, it is assigned an address type, IPv4, IPv6, or MACSize,
	// and determines if an *AddressDivisionGrouping can be converted back to a section of the original type.
	//
	// Type-specific functions in IPAddressSection and lower levels, such as functions returning strings,
	// can rely on this field.
	addrType addrType

	// assigned on creation only; for zero-value groupings it is never assigned, but in that case it is not needed since there is nothing to cache
	cache *valueCache
}

// TODO LATER for large will need to add methods in java AddressItem (porting those same methods in AddressItem using BigINteger to use big.int should do it):
// isSinglePrefixBlock, isPrefixBlock, containsPrefixBlock(int), containsSinglePrefixBlock(int), GetMinPrefixLenForBlock() bitcount, GetPrefixLenForSingleBlock() prefixlen

func (grouping *addressDivisionGroupingBase) getAddrType() addrType {
	//if grouping == nil {
	//	return zeroType
	//}
	return grouping.addrType
}

// hasNoDivisions() returns whether this grouping is the zero grouping,
// which is what you get when contructing a grouping or section with no divisions
func (grouping *addressDivisionGroupingBase) hasNoDivisions() bool {
	divisions := grouping.divisions
	return divisions == nil || divisions.getDivisionCount() == 0
}

// GetBitCount returns the total number of bits across all divisions
func (grouping addressDivisionGroupingBase) GetBitCount() (res BitCount) {
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

// GetGenericDivision returns the division as an DivisionType,
// allowing all division types and aggregated division types to be represented by a single type,
// useful for comparisons and other common uses.
func (grouping *addressDivisionGroupingBase) GetGenericDivision(index int) DivisionType {
	return grouping.divisions.getGenericDivision(index)
}

func (grouping *addressDivisionGroupingBase) GetDivisionCount() int {
	divisions := grouping.divisions
	if divisions != nil {
		return divisions.getDivisionCount()
	}
	return 0
}

//func (grouping *addressDivisionGroupingBase) matchesTypeAndCount(other GenericGroupingType) (matches bool, count int) {
//	count = grouping.GetDivisionCount()
//	if count != other.GetDivisionCount() {
//		return
//	} else if grouping.getAddrType() != other.getAddrType() {
//		return
//	}
//	matches = true
//	return
//}
//
//func (grouping *addressDivisionGroupingBase) Equal(other GenericGroupingType) bool {
//	matches, count := grouping.matchesTypeAndCount(other)
//	if !matches || count != other.GetDivisionCount() {
//		return false
//	} else {
//		for i := 0; i < count; i++ {
//			one := grouping.GetGenericDivision(i)
//			two := other.GetGenericDivision(i)
//			if !one.Equal(two) { //this checks the division types and also the bit counts
//				return false
//			}
//		}
//	}
//	return true
//}

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

// Gets the minimal segment index for which all following segments are full-range blocks.
// The segment at this index is not a full-range block unless all segments are full-range.
// The segment at this index and all following segments form a sequential range.
// For the full series to be sequential, the preceding segments must be single-valued.
func (grouping *addressDivisionGroupingBase) GetSequentialBlockIndex() int {
	divCount := grouping.GetDivisionCount()
	if divCount > 0 {
		for divCount--; divCount > 0 && grouping.getDivision(divCount).IsFullRange(); divCount-- {
		}
	}
	return divCount
}

func (grouping *addressDivisionGroupingBase) GetSequentialBlockCount() *big.Int {
	sequentialSegCount := grouping.GetSequentialBlockIndex()
	prefixLen := BitCount(0)
	for i := 0; i < sequentialSegCount; i++ {
		prefixLen += grouping.getDivision(i).GetBitCount()
	}
	return grouping.GetPrefixCountLen(prefixLen) // 0-1.0-1.*.* gives 1 as seq block index, and then you count only previous segments
}

func (grouping *addressDivisionGroupingBase) getCountBig() *big.Int {
	res := bigOne()
	count := grouping.GetDivisionCount()
	if count > 0 {
		for i := 0; i < count; i++ {
			div := grouping.getDivision(i)
			if div.isMultiple() {
				res.Mul(res, div.getCount())
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
	return grouping.getPrefixCountLenBig(prefixLen.bitCount())
}

func (grouping *addressDivisionGroupingBase) getPrefixCountLenBig(prefixLen BitCount) *big.Int {
	if prefixLen <= 0 {
		return bigOne()
	} else if prefixLen >= grouping.GetBitCount() {
		return grouping.getCountBig()
	}
	res := bigOne()
	if grouping.isMultiple() {
		divisionCount := grouping.GetDivisionCount()
		divPrefixLength := prefixLen
		for i := 0; i < divisionCount; i++ {
			div := grouping.getDivision(i)
			divBitCount := div.getBitCount()
			if div.isMultiple() {
				var divCount *big.Int
				if divPrefixLength < divBitCount {
					divCount = div.GetPrefixCountLen(divPrefixLength)
				} else {
					divCount = div.getCount()
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

func (grouping *addressDivisionGroupingBase) getBlockCountBig(segmentCount int) *big.Int {
	if segmentCount <= 0 {
		return bigOne()
	}
	divCount := grouping.GetDivisionCount()
	if segmentCount >= divCount {
		return grouping.getCountBig()
	}
	res := bigOne()
	if grouping.isMultiple() {
		for i := 0; i < divCount; i++ {
			division := grouping.getDivision(i)
			if division.isMultiple() {
				res.Mul(res, division.getCount())
			}
		}
	}
	return res
}

//func (grouping *addressDivisionGroupingBase) CompareSize(other AddressDivisionSeries) int {
//	if !grouping.isMultiple() {
//		if other.IsMultiple() {
//			return -1
//		}
//		return 0
//	}
//	if !other.IsMultiple() {
//		return 1
//	}
//	return grouping.getCount().CmpAbs(other.GetCount())
//}

func (grouping *addressDivisionGroupingBase) getCount() *big.Int {
	return grouping.cacheCount(grouping.getCountBig)
}

func (grouping *addressDivisionGroupingBase) GetPrefixCount() *big.Int {
	return grouping.cachePrefixCount(grouping.getPrefixCountBig)
}

func (grouping *addressDivisionGroupingBase) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	return grouping.calcCount(func() *big.Int { return grouping.getPrefixCountLenBig(prefixLen) })
}

// GetBlockCount returns the count of values in the initial (higher) count of divisions.
func (grouping *addressDivisionGroupingBase) GetBlockCount(divisionCount int) *big.Int {
	return grouping.calcCount(func() *big.Int { return grouping.getBlockCountBig(divisionCount) })
}

func (grouping *addressDivisionGroupingBase) cacheCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache // isMult checks prior to this ensures cacheBitCountx no nil here
	if cache == nil {
		return grouping.calcCount(counter)
	}
	count := cache.cachedCount
	if count == nil {
		count = grouping.calcCount(counter)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
	}
	return new(big.Int).Set(count)
}

func (grouping *addressDivisionGroupingBase) calcCount(counter func() *big.Int) *big.Int {
	if grouping != nil && !grouping.isMultiple() {
		return bigOne()
	}
	return counter()
}

func (grouping *addressDivisionGroupingBase) cachePrefixCount(counter func() *big.Int) *big.Int {
	cache := grouping.cache // isMult checks prior to this ensures cache not nil here
	if cache == nil {
		return grouping.calcPrefixCount(counter)
	}
	count := cache.cachedPrefixCount
	if count == nil {
		count = grouping.calcPrefixCount(counter)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedPrefixCount))
		atomic.StorePointer(dataLoc, unsafe.Pointer(count))
	}
	return new(big.Int).Set(count)
}

func (grouping *addressDivisionGroupingBase) calcPrefixCount(counter func() *big.Int) *big.Int {
	if !grouping.isMultiple() {
		return bigOne()
	}
	prefixLen := grouping.prefixLength
	if prefixLen == nil || prefixLen.bitCount() >= grouping.GetBitCount() {
		return grouping.getCount()
	}
	return counter()
}

func (grouping *addressDivisionGroupingBase) getCachedBytes(calcBytes func() (bytes, upperBytes []byte)) (bytes, upperBytes []byte) {
	cache := grouping.cache
	if cache == nil {
		return emptyBytes, emptyBytes
	}
	cached := cache.bytesCache
	if cached == nil {
		bytes, upperBytes = calcBytes()
		cached = &bytesCache{
			lowerBytes: bytes,
			upperBytes: upperBytes,
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.bytesCache))
		atomic.StorePointer(dataLoc, unsafe.Pointer(cached))
	}
	bytes = cached.lowerBytes
	upperBytes = cached.upperBytes
	return
}

// isMultiple returns whether this address or grouping represents more than one address or grouping.
// Such addresses include CIDR/IP addresses (eg 1.2.3.4/11) or wildcard addresses (eg 1.2.*.4) or range addresses (eg 1.2.3-4.5)
func (grouping *addressDivisionGroupingBase) isMultiple() bool {
	return grouping.isMult
}

type mixedCache struct {
	defaultMixedAddressSection *IPv6v4MixedAddressGrouping
	embeddedIPv4Section        *IPv4AddressSection
	embeddedIPv6Section        *EmbeddedIPv6AddressSection
}

type valueCache struct {
	cachedCount, cachedPrefixCount *big.Int

	cachedMaskLens *maskLenSetting

	bytesCache *bytesCache

	intsCache *intsCache

	zeroVals *zeroRangeCache

	stringCache stringCache

	sectionCache *groupingCache

	mixed *mixedCache

	minPrefix PrefixLen

	equivalentPrefix *PrefixLen

	isSinglePrefixBlock *bool
}

type ipStringCache struct {
	normalizedWildcardString,
	fullString,
	sqlWildcardString,

	reverseDNSString,

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

	octalString, octalStringPrefixed,
	binaryString, binaryStringPrefixed,
	hexString, hexStringPrefixed *string

	*ipv6StringCache

	*ipv4StringCache

	*ipStringCache

	*macStringCache
}

var zeroStringCache = stringCache{
	ipv6StringCache: &ipv6StringCache{},
	ipv4StringCache: &ipv4StringCache{},
	ipStringCache:   &ipStringCache{},
	macStringCache:  &macStringCache{},
}

type groupingCache struct {
	lower, upper *AddressSection
}

type zeroRangeCache struct {
	zeroSegments, zeroRangeSegments RangeList
}

type intsCache struct {
	cachedLowerVal, cachedUpperVal uint32
}

type maskLenSetting struct {
	networkMaskLen, hostMaskLen PrefixLen
}

type divArray interface {
	getDivision(index int) *addressDivisionBase

	getGenericDivision(index int) DivisionType

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

func (grouping standardDivArray) getGenericDivision(index int) DivisionType {
	return grouping.divisions[index]
}

//func (grouping standardDivArray) copySubDivisions(start, end int, divs []*AddressDivision) (count int) {
//	return copy(divs, grouping.divisions[start:end])
//}
//
func (grouping standardDivArray) copyDivisions(divs []*AddressDivision) (count int) {
	return copy(divs, grouping.divisions)
}

func (grouping standardDivArray) copySubDivisions(start, end int, divs []*AddressDivision) (count int) {
	return copy(divs, grouping.divisions[start:end])
}

func (grouping standardDivArray) getSubDivisions(index, endIndex int) (divs []*AddressDivision) {
	return grouping.divisions[index:endIndex]
}

func (grouping standardDivArray) getDivisions() (divs []*AddressDivision) {
	return grouping.divisions
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
