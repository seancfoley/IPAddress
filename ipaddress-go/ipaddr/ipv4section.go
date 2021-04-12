package ipaddr

import (
	"math/big"
	"sync/atomic"
	"unsafe"
)

func createIPv4Section(segments []*AddressDivision) *IPv4AddressSection {
	return &IPv4AddressSection{
		ipAddressSectionInternal{
			addressSectionInternal{
				addressDivisionGroupingInternal{
					addressDivisionGroupingBase: addressDivisionGroupingBase{
						divisions: standardDivArray{segments},
						addrType:  ipv4Type,
						cache: &valueCache{
							stringCache: stringCache{
								ipStringCache: &ipStringCache{},
							},
						},
					},
				},
			},
		},
	}
}

// error returned for invalid segment count, nil sements, segments with invalid bit size, or inconsistent prefixes
func newIPv4AddressSection(segments []*AddressDivision /*cloneSegments bool,*/, normalizeSegments bool) (res *IPv4AddressSection, err AddressValueException) {
	segsLen := len(segments)
	if segsLen > IPv4SegmentCount {
		err = &addressValueException{val: segsLen, key: "ipaddress.error.exceeds.size"}
		return
	}
	res = createIPv4Section(segments)
	if err = res.init(); err != nil {
		res = nil
		return
	}
	prefLen := res.prefixLength
	if normalizeSegments && prefLen != nil {
		normalizePrefixBoundary(*prefLen, segments, IPv4BitsPerSegment, IPv4BytesPerSegment, func(val, upperVal SegInt, prefLen PrefixLen) *AddressDivision {
			return NewIPv4RangePrefixSegment(IPv4SegInt(val), IPv4SegInt(upperVal), prefLen).ToAddressDivision()
		})
	}
	return
}

//TODO need the public equivalent of this that takes IPv4AddressSegment

func newIPv4AddressSectionSingle(segments []*AddressDivision /* cloneSegments bool,*/, prefixLength PrefixLen, singleOnly bool) (res *IPv4AddressSection, err AddressValueException) {
	res, err = newIPv4AddressSection(segments /*cloneSegments,*/, prefixLength == nil)
	if err == nil && prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(len(segments)<<3), IPv4BitCount)
	}
	return
}

func NewIPv4AddressSectionFromBytes(bytes []byte) (res *IPv4AddressSection, err AddressValueException) {
	return newIPv4AddressSectionFromBytes(bytes, len(bytes), nil, false)
}

// Useful if the byte array has leading zeros or leading sign extension
func NewIPv4AddressSectionFromSegmentedBytes(bytes []byte, segmentCount int) (res *IPv4AddressSection, err AddressValueException) {
	return newIPv4AddressSectionFromBytes(bytes, segmentCount, nil, false)
}

func NewIPv4AddressSectionFromPrefixedBytes(bytes []byte, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection, err AddressValueException) {
	return newIPv4AddressSectionFromBytes(bytes, segmentCount, prefixLength, false)
}

func newIPv4AddressSectionFromBytes(bytes []byte, segmentCount int, prefixLength PrefixLen /* boolean cloneBytes,*/, singleOnly bool) (res *IPv4AddressSection, err AddressValueException) {
	if segmentCount < 0 {
		segmentCount = len(bytes)
	}
	expectedByteCount := segmentCount
	segments, err := toSegments(
		bytes,
		segmentCount,
		IPv4BytesPerSegment,
		IPv4BitsPerSegment,
		expectedByteCount,
		DefaultIPv4Network.GetIPv4AddressCreator(),
		prefixLength)
	if err == nil {
		res = createIPv4Section(segments)
		if prefixLength != nil {
			assignPrefix(prefixLength, segments, res.ToIPAddressSection(), singleOnly, BitCount(segmentCount<<3), IPv4BitCount)
		}
		if expectedByteCount == len(bytes) {
			bytes = cloneBytes(bytes)
			res.cache.lowerBytes = bytes
			if !res.isMultiple {
				res.cache.upperBytes = bytes
			}
		}
	}
	return
}

func NewIPv4AddressSectionFromValues(vals SegmentValueProvider, segmentCount int) (res *IPv4AddressSection) {
	res = NewIPv4AddressSectionFromPrefixedRangeValues(vals, nil, segmentCount, nil)
	return
}

func NewIPv4AddressSectionFromPrefixedValues(vals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection) {
	return NewIPv4AddressSectionFromPrefixedRangeValues(vals, nil, segmentCount, prefixLength)
}

func NewIPv4AddressSectionFromRangeValues(vals, upperVals SegmentValueProvider, segmentCount int) (res *IPv4AddressSection) {
	res = NewIPv4AddressSectionFromPrefixedRangeValues(vals, upperVals, segmentCount, nil)
	return
}

func NewIPv4AddressSectionFromPrefixedRangeValues(vals, upperVals SegmentValueProvider, segmentCount int, prefixLength PrefixLen) (res *IPv4AddressSection) {
	if segmentCount < 0 {
		segmentCount = 0
	}
	segments, isMultiple := createSegments(
		vals, upperVals,
		segmentCount,
		IPv4BitsPerSegment,
		DefaultIPv4Network.GetIPv4AddressCreator(),
		prefixLength)
	res = createIPv4Section(segments)
	res.isMultiple = isMultiple
	if prefixLength != nil {
		assignPrefix(prefixLength, segments, res.ToIPAddressSection(), false, BitCount(segmentCount<<3), IPv4BitCount)
	}
	return
}

// IPv4AddressSection represents a section of an IPv4 address comprising 0 to 4 IPv4 address segments.
// The zero values is a section with zero segments.
type IPv4AddressSection struct {
	ipAddressSectionInternal
}

func (section *IPv4AddressSection) GetIPVersion() IPVersion {
	return IPv4
}

func (section *IPv4AddressSection) GetCount() *big.Int {
	return section.cacheCount(func() *big.Int {
		return bigZero().SetUint64(section.GetIPv4Count())
	})
}

func (section *IPv4AddressSection) GetPrefixCount() *big.Int {
	return section.cachePrefixCount(func() *big.Int {
		return bigZero().SetUint64(section.GetIPv4PrefixCount())
	})
}

func (section *IPv4AddressSection) GetPrefixCountLen(prefixLen BitCount) *big.Int {
	if prefixLen <= 0 {
		return bigOne()
	} else if bc := section.GetBitCount(); prefixLen > bc {
		prefixLen = bc
	}
	return section.calcCount(func() *big.Int { return new(big.Int).SetUint64(section.GetIPv4PrefixCountLen(prefixLen)) })
}

//This was added so count available as a long and not as BigInteger
func (section *IPv4AddressSection) GetIPv4PrefixCountLen(prefixLength BitCount) uint64 {
	if !section.IsMultiple() {
		return 1
	} else if prefixLength >= section.GetBitCount() {
		return section.GetIPv4Count()
	}
	return longPrefixCount(section.ToAddressSection(), prefixLength)
}

func (section *IPv4AddressSection) GetIPv4PrefixCount() uint64 {
	prefixLength := section.GetPrefixLength()
	if prefixLength == nil {
		return section.GetIPv4Count()
	}
	return section.GetIPv4PrefixCountLen(*prefixLength)
}

func (section *IPv4AddressSection) GetIPv4Count() uint64 {
	if !section.IsMultiple() {
		return 1
	}
	return longCount(section.ToAddressSection(), section.GetSegmentCount())
}

func (section *IPv4AddressSection) GetSegment(index int) *IPv4AddressSegment {
	return section.getDivision(index).ToIPv4AddressSegment()
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (section *IPv4AddressSection) GetTrailingSection(index int) *IPv4AddressSection {
	return section.GetSubSection(index, section.GetSegmentCount())
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (section *IPv4AddressSection) GetSubSection(index, endIndex int) *IPv4AddressSection {
	return section.getSubSection(index, endIndex).ToIPv4AddressSection()
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPv4AddressSection) CopySubSegments(start, end int, segs []*IPv4AddressSegment) (count int) {
	return section.visitSubSegments(start, end, func(index int, div *AddressDivision) bool { segs[index] = div.ToIPv4AddressSegment(); return false }, len(segs))
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (section *IPv4AddressSection) CopySegments(segs []*IPv4AddressSegment) (count int) {
	return section.visitSegments(func(index int, div *AddressDivision) bool { segs[index] = div.ToIPv4AddressSegment(); return false }, len(segs))
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (section *IPv4AddressSection) GetSegments() (res []*IPv4AddressSegment) {
	res = make([]*IPv4AddressSegment, section.GetSegmentCount())
	section.CopySegments(res)
	return
}

func (section *IPv4AddressSection) Mask(other *IPv4AddressSection) (res *IPv4AddressSection, err error) {
	return section.MaskPrefixed(other, false)
}

func (section *IPv4AddressSection) MaskPrefixed(other *IPv4AddressSection, retainPrefix bool) (res *IPv4AddressSection, err error) {
	sec, err := section.mask(other.ToIPAddressSection(), retainPrefix)
	if err == nil {
		res = sec.ToIPv4AddressSection()
	}
	return
}

func (section *IPv4AddressSection) GetLower() *IPv4AddressSection {
	return section.getLowestOrHighestSection(true).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) GetUpper() *IPv4AddressSection {
	return section.getLowestOrHighestSection(false).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) IntValue() uint32 {
	return section.getIntValue(true)
}

func (section *IPv4AddressSection) UpperIntValue() uint32 {
	return section.getIntValue(false)
}

func (section *IPv4AddressSection) getIntValue(lower bool) (result uint32) {
	segCount := section.GetSegmentCount()
	if segCount == 0 {
		return 0
	}
	cache := section.cache
	var val *uint32
	if lower {
		val = cache.cachedLowerVal
	} else {
		val = cache.cachedUpperVal
	}
	if val != nil {
		return *val
	}
	if segCount == 4 {
		if lower {
			result = (uint32(section.GetSegment(0).GetSegmentValue()) << 24) |
				(uint32(section.GetSegment(1).GetSegmentValue()) << 16) |
				(uint32(section.GetSegment(2).GetSegmentValue()) << 8) |
				uint32(section.GetSegment(3).GetSegmentValue())
		} else {
			result = (uint32(section.GetSegment(0).GetUpperSegmentValue()) << 24) |
				(uint32(section.GetSegment(1).GetUpperSegmentValue()) << 16) |
				(uint32(section.GetSegment(2).GetUpperSegmentValue()) << 8) |
				uint32(section.GetSegment(3).GetUpperSegmentValue())
		}
	} else {
		result = uint32(section.GetSegment(0).GetUpperSegmentValue())
		bitsPerSegment := section.GetBitsPerSegment()
		for i := 1; i < segCount; i++ {
			result = (result << bitsPerSegment)
			seg := section.GetSegment(i)
			if lower {
				result |= uint32(seg.GetSegmentValue())
			} else {
				result |= uint32(seg.GetUpperSegmentValue())
			}
		}
	}
	var dataLoc *unsafe.Pointer
	if lower {
		dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedLowerVal))
	} else {
		dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&cache.cachedUpperVal))
	}
	atomic.StorePointer(dataLoc, unsafe.Pointer(&result))
	return result
}

func (section *IPv4AddressSection) ToPrefixBlock() *IPv4AddressSection {
	return section.toPrefixBlock().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) ToPrefixBlockLen(prefLen BitCount) *IPv4AddressSection {
	return section.toPrefixBlockLen(prefLen).ToIPv4AddressSection()
}

func (section *IPv4AddressSection) WithoutPrefixLength() *IPv4AddressSection {
	return section.withoutPrefixLength().ToIPv4AddressSection()
}

func (section *IPv4AddressSection) Iterator() IPv4SectionIterator {
	return ipv4SectionIterator{section.sectionIterator(nil)}
}

func (section *IPv4AddressSection) PrefixIterator() IPv4SectionIterator {
	return ipv4SectionIterator{section.prefixIterator(false)}
}

func (section *IPv4AddressSection) PrefixBlockIterator() IPv4SectionIterator {
	return ipv4SectionIterator{section.prefixIterator(true)}
}

func (section *IPv4AddressSection) BlockIterator(segmentCount int) IPv4SectionIterator {
	return ipv4SectionIterator{section.blockIterator(segmentCount)}
}

func (section *IPv4AddressSection) SequentialBlockIterator() IPv4SectionIterator {
	return ipv4SectionIterator{section.sequentialBlockIterator()}
}

func (section *IPv4AddressSection) ToIPAddressSection() *IPAddressSection {
	return (*IPAddressSection)(unsafe.Pointer(section))
}

var (
	ipv4CanonicalParams          = NewIPv4StringOptionsBuilder().ToOptions()
	ipv4FullParams               = NewIPv4StringOptionsBuilder().SetExpandedSegments(true).SetWildcardOptions(wildcardsRangeOnlyNetworkOnly).ToOptions()
	ipv4NormalizedWildcardParams = NewIPv4StringOptionsBuilder().SetWildcardOptions(allWildcards).ToOptions()
	ipv4SqlWildcardParams        = NewIPv4StringOptionsBuilder().SetWildcardOptions(allSQLWildcards).ToOptions()

	inetAtonOctalParams       = NewIPv4StringOptionsBuilder().SetRadix(inet_aton_radix_octal.GetRadix()).SetSegmentStrPrefix(inet_aton_radix_octal.GetSegmentStrPrefix()).ToOptions()
	inetAtonHexParams         = NewIPv4StringOptionsBuilder().SetRadix(inet_aton_radix_hex.GetRadix()).SetSegmentStrPrefix(inet_aton_radix_hex.GetSegmentStrPrefix()).ToOptions()
	ipv4ReverseDNSParams      = NewIPv4StringOptionsBuilder().SetWildcardOptions(allWildcards).SetReverse(true).SetAddressSuffix(IPv4ReverseDnsSuffix).ToOptions()
	ipv4SegmentedBinaryParams = new(IPStringOptionsBuilder).SetRadix(2).SetSeparator(IPv4SegmentSeparator).SetSegmentStrPrefix(BinaryStrPrefix).ToOptions()
)

// ToCanonicalString produces a canonical string.
//
//If this section has a prefix length, it will be included in the string.
func (section *IPv4AddressSection) ToCanonicalString() string {
	return cacheStr(&section.getStringCache().canonicalString,
		func() string {
			return section.toNormalizedString(ipv4CanonicalParams)
		})
}

// ToNormalizedString produces a normalized string.
//
//If this section has a prefix length, it will be included in the string.
func (section *IPv4AddressSection) ToNormalizedString() string {
	return section.ToCanonicalString()
}

func (section *IPv4AddressSection) ToCompressedString() string {
	return section.ToCanonicalString()
}

func (section *IPv4AddressSection) ToNormalizedWildcardString() string {
	return cacheStr(&section.getStringCache().normalizedWildcardString,
		func() string {
			return section.toNormalizedString(ipv4NormalizedWildcardParams)
		})
}

func (section *IPv4AddressSection) ToCanonicalWildcardString() string {
	return section.ToNormalizedWildcardString()
}

func (section *IPv4AddressSection) ToSegmentedBinaryString() string {
	return cacheStr(&section.getStringCache().segmentedBinaryString,
		func() string {
			return section.toNormalizedString(ipv4SegmentedBinaryParams)
		})
}

func (section *IPv4AddressSection) ToSQLWildcardString() string {
	return cacheStr(&section.getStringCache().sqlWildcardString,
		func() string {
			return section.toNormalizedString(ipv4SqlWildcardParams)
		})
}

func (section *IPv4AddressSection) ToFullString() string {
	return cacheStr(&section.getStringCache().fullString,
		func() string {
			return section.toNormalizedString(ipv4FullParams)
		})
}

func (section *IPv4AddressSection) ToReverseDNSString() string {
	return cacheStr(&section.getStringCache().reverseDNSString,
		func() string {
			return section.toNormalizedString(ipv4ReverseDNSParams)
		})
}

func (section *IPv4AddressSection) ToPrefixLenString() string {
	return section.ToCanonicalString()
}

func (section *IPv4AddressSection) ToSubnetString() string {
	return section.ToNormalizedWildcardString()
}

func (section *IPv4AddressSection) ToCompressedWildcardString() string {
	return section.ToNormalizedWildcardString()
}

//TODO NEXT
// 4. do the rest of the string methods - divs are done.  addresses and sections.
// MAybe do the inet aton, to ensure your absence of ipaddressdivisiongrouping is not a problem
// so you must combine ipstringparams with addressdivisiongrouping
// OK, I laid the groundwork for inet aton, I made ipstringParams work with addressDivisionSeries
// So need to create someting like the IPv4JOinedSegments and use that with ipStringParams

//TODO NEXT string methods:
// You do not need to override in ipv6 to get zones, but you do need a separate method for each in section for addr to call with zone
// In some cases you do need to override since the strings are different in each, and for ipv6 in particular you typically need to add compression options
//MAC:
//	colonDelimited
//	DONE compressed
//	dashed
//	dotted
//	space
//	DONE hex with bool
//  DONE normalized
//  DONE canonical
//
//IPv4
//	DONE canonicalWildcard
//	DONE compressed
//	DONE compressedWildcard
//	DONE full
//	InetAton(radix, segs) //this requires AddressDivisionGrouping
//	DONE normalizedWildcard
//	DONE prefixLength // yeah, I cannot remember putting that in there
//	DONE reverseDNS
//	DONE segmentedBinary
//	DONE sqlWildcard
//	DONE subnet
//  DONE normalized
//  DONE canonical
//
//IPv6
//	base85
//	DONE mixed
//
//	DONE canonicalWildcard
//	DONE compressed
//	DONE compressedWildcard
//	DONE full
//	DONE normalizedWildcard
//	DONE prefixLength // yeah, I cannot remember putting that in there
//	DONE reverseDNS
//	DONE segmentedBinary
//	DONE sqlWildcard
//	DONE subnet
//  DONE normalized
//  DONE canonical
//
//base IP
//	DONE binary
//	DONE octal with bool
//	DONE hex with bool

func (section *IPv4AddressSection) toNormalizedString(stringOptions IPStringOptions) string {
	return toNormalizedIPString(stringOptions, section)
}

type inet_aton_radix int

func (rad inet_aton_radix) GetRadix() int {
	return int(rad)
}

func (rad inet_aton_radix) GetSegmentStrPrefix() string {
	if rad == inet_aton_radix_octal {
		return OctalPrefix
	} else if rad == inet_aton_radix_hex {
		return HexPrefix
	}
	return ""
}

func (rad inet_aton_radix) String() string {
	if rad == inet_aton_radix_octal {
		return "octal"
	} else if rad == inet_aton_radix_hex {
		return "hexadecimal"
	}
	return "decimal"
}

const (
	inet_aton_radix_octal   inet_aton_radix = 8
	inet_aton_radix_hex     inet_aton_radix = 16
	inet_aton_radix_decimal inet_aton_radix = 10
)
