package ipaddr

import (
	//"net"
	"math/bits"
	"strings"
	"unsafe"
)

//
//
type ipAddressSegmentInternal struct {
	addressSegmentInternal
}

func (seg *ipAddressSegmentInternal) ToAddressSegment() *AddressSegment {
	return (*AddressSegment)(unsafe.Pointer(seg))
}

func (seg *ipAddressSegmentInternal) IsPrefixed() bool {
	return seg.GetDivisionPrefixLength() != nil
}

func (seg *ipAddressSegmentInternal) IsPrefixBlock() bool {
	return seg.isPrefixBlock()
}

func (seg *ipAddressSegmentInternal) IsSinglePrefixBlock() bool {
	if prefLen := seg.GetDivisionPrefixLength(); prefLen != nil {
		return seg.isSinglePrefixBlock(seg.getDivisionValue(), seg.getUpperDivisionValue(), *prefLen)
	}
	return false
}

func (seg *ipAddressSegmentInternal) withoutPrefixLen() *IPAddressSegment {
	if seg.IsPrefixed() {
		vals := seg.deriveNewMultiSeg(seg.GetSegmentValue(), seg.GetUpperSegmentValue(), nil)
		return createAddressDivision(vals).ToIPAddressSegment()
	}
	return seg.toIPAddressSegment()
}

func (seg *ipAddressSegmentInternal) GetPrefixValueCount() SegIntCount {
	prefixLength := seg.GetDivisionPrefixLength()
	if prefixLength == nil {
		return seg.GetValueCount()
	}
	return getPrefixValueCount(seg.toAddressSegment(), *prefixLength)
}

func (seg *ipAddressSegmentInternal) GetDivisionPrefixLength() PrefixLen { //TODO rename to GetSegmentPrefixLength
	return seg.getDivisionPrefixLength()
}

func (seg *ipAddressSegmentInternal) checkForPrefixMask() (networkMaskLen, hostMaskLen PrefixLen) {
	val := seg.GetSegmentValue()
	if val == 0 {
		networkMaskLen, hostMaskLen = cacheBits(0), cacheBitCount(seg.GetBitCount())
	} else {
		maxVal := seg.GetMaxValue()
		if val == maxVal {
			networkMaskLen, hostMaskLen = cacheBitCount(seg.GetBitCount()), cacheBits(0)
		} else {
			var shifted SegInt
			trailingOnes := seg.GetTrailingBitCount(true)
			if trailingOnes == 0 {
				// can only be 11110000 and not 00000000
				trailingZeros := seg.GetTrailingBitCount(false)
				shifted = (^val & maxVal) >> trailingZeros
				if shifted == 0 {
					networkMaskLen = cacheBitCount(seg.GetBitCount() - trailingZeros)
				}
			} else {
				// can only be 00001111 and not 11111111
				shifted = val >> trailingOnes
				if shifted == 0 {
					hostMaskLen = cacheBitCount(seg.GetBitCount() - trailingOnes)
				}
			}
		}
	}
	return
}

// GetBlockMaskPrefixLength returns the prefix length if this address section is equivalent to the mask for a CIDR prefix block.
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
func (seg *ipAddressSegmentInternal) GetBlockMaskPrefixLength(network bool) PrefixLen {
	hostLength := seg.GetTrailingBitCount(network)
	var shifted SegInt
	val := seg.GetSegmentValue()
	if network {
		shifted = (^val & seg.GetMaxValue()) >> hostLength
	} else {
		shifted = val >> hostLength
	}
	if shifted == 0 {
		return cacheBitCount(seg.GetBitCount() - hostLength)
	}
	return nil
}

// GetTrailingBitCount returns the number of consecutive trailing one or zero bits.
// If network is true, returns the number of consecutive trailing zero bits.
// Otherwise, returns the number of consecutive trailing one bits.
//
// This method applies only to the lower value of the range if this segment represents multiple values.
func (seg *ipAddressSegmentInternal) GetTrailingBitCount(network bool) BitCount {
	val := seg.GetSegmentValue()
	if network {
		//trailing zeros
		return BitCount(bits.TrailingZeros32(uint32(val | (^SegInt(0) << seg.GetBitCount()))))
	}
	// trailing ones
	return BitCount(bits.TrailingZeros32(uint32(^val)))
}

//	GetLeadingBitCount returns the number of consecutive leading one or zero bits.
// If network is true, returns the number of consecutive leading one bits.
// Otherwise, returns the number of consecutive leading zero bits.
//
// This method applies only to the lower value of the range if this segment represents multiple values.
func (seg *ipAddressSegmentInternal) GetLeadingBitCount(network bool) BitCount {
	extraLeading := 32 - seg.GetBitCount()
	val := seg.GetSegmentValue()
	if network {
		//leading ones
		return BitCount(bits.LeadingZeros32(uint32(^val&seg.GetMaxValue()))) - extraLeading
	}
	// leading zeros
	return BitCount(bits.LeadingZeros32(uint32(val))) - extraLeading
}

func (seg *ipAddressSegmentInternal) getUpperStringMasked(radix int, uppercase bool, appendable *strings.Builder) {
	if seg.IsPrefixed() {
		upperValue := seg.GetUpperSegmentValue()
		mask := seg.GetSegmentNetworkMask(*seg.GetDivisionPrefixLength())
		upperValue &= mask
		toUnsignedStringCased(DivInt(upperValue), radix, 0, uppercase, appendable)
	} else {
		seg.getUpperString(radix, uppercase, appendable)
	}
}

func (seg *ipAddressSegmentInternal) getStringAsLower() string {
	if seg.divisionValues != nil {
		if cache := seg.getCache(); cache != nil {
			return cacheStr(&cache.cachedString, seg.getDefaultLowerString)
		}
	}
	return seg.getDefaultLowerString()
}

func (seg *ipAddressSegmentInternal) GetString() string {
	stringer := func() string {
		if !seg.IsMultiple() || seg.IsSinglePrefixBlock() { //covers the case of !isMultiple, ie single addresses, when there is no prefix or the prefix is the bit count
			return seg.getDefaultLowerString()
		} else if seg.IsFullRange() {
			return seg.getDefaultSegmentWildcardString()
		}
		upperValue := seg.getUpperSegmentValue()
		if seg.IsPrefixBlock() {
			upperValue &= seg.GetSegmentNetworkMask(*seg.getDivisionPrefixLength())
		}
		return seg.getDefaultRangeStringVals(seg.getDivisionValue(), DivInt(upperValue), seg.getDefaultTextualRadix())
	}
	if seg.divisionValues != nil {
		if cache := seg.getCache(); cache != nil {
			return cacheStr(&cache.cachedString, stringer)
		}
	}
	return stringer()
}

func (seg *ipAddressSegmentInternal) GetWildcardString() string {
	stringer := func() string {
		if !seg.IsPrefixed() || !seg.IsMultiple() {
			return seg.GetString()
		} else if seg.IsFullRange() {
			return seg.getDefaultSegmentWildcardString()
		}
		return seg.getDefaultRangeString()
	}
	if seg.divisionValues != nil {
		if cache := seg.getCache(); cache != nil {
			return cacheStr(&cache.cachedWildcardString, stringer)
		}
	}
	return stringer()
}

func (seg *ipAddressSegmentInternal) GetSegmentNetworkMask(bits BitCount) SegInt {
	bc := seg.GetBitCount()
	bits = checkBitCount(bits, bc)
	return seg.GetMaxValue() & (^SegInt(0) << (bc - bits))
}

func (seg *ipAddressSegmentInternal) GetSegmentHostMask(bits BitCount) SegInt {
	bc := seg.GetBitCount()
	bits = checkBitCount(bits, bc)
	return ^(^SegInt(0) << (bc - bits))
}

func (seg *ipAddressSegmentInternal) toIPAddressSegment() *IPAddressSegment {
	return (*IPAddressSegment)(unsafe.Pointer(seg))
}

type IPAddressSegment struct {
	ipAddressSegmentInternal
}

func (seg *IPAddressSegment) ContainsPrefixBlock(divisionPrefixLen BitCount) bool {
	return seg.containsPrefixBlock(divisionPrefixLen)
}

func (seg *IPAddressSegment) ToPrefixedNetworkSegment(segmentPrefixLength PrefixLen) *IPAddressSegment {
	return seg.toPrefixedNetworkDivision(segmentPrefixLength).ToIPAddressSegment()
}

func (seg *IPAddressSegment) ToNetworkSegment(segmentPrefixLength PrefixLen, withPrefixLength bool) *IPAddressSegment {
	return seg.toNetworkDivision(segmentPrefixLength, withPrefixLength).ToIPAddressSegment()
}

//	func (seg *IPAddressSegment)  ToHostSegment(segmentPrefixLength PrefixLen) *IPAddressSegment { TODO ToHostSegment (see getHostSection for code that does the proper masking)
//	if isHostChangedByPrefix(bits) {
//		return super.toHostSegment(bits, getSegmentCreator())
//	}
//	return this
//}

func (seg *IPAddressSegment) Iterator() IPSegmentIterator {
	return ipSegmentIterator{seg.iterator()}
}

func (seg *IPAddressSegment) PrefixBlockIterator() IPSegmentIterator {
	return ipSegmentIterator{seg.prefixBlockIterator()}
}

func (seg *IPAddressSegment) PrefixedBlockIterator(segmentPrefixLen BitCount) IPSegmentIterator {
	return ipSegmentIterator{seg.prefixedBlockIterator(segmentPrefixLen)}
}

func (seg *IPAddressSegment) PrefixIterator() IPSegmentIterator {
	return ipSegmentIterator{seg.prefixIterator()}
}

func (seg *IPAddressSegment) WithoutPrefixLen() *IPAddressSegment {
	return seg.withoutPrefixLen()
}

func (seg *IPAddressSegment) IsIPv4AddressSegment() bool {
	return seg != nil && seg.matchesIPv4Segment()
}

func (seg *IPAddressSegment) IsIPv6AddressSegment() bool {
	return seg != nil && seg.matchesIPv6Segment()
}

func (seg *IPAddressSegment) ToIPv4AddressSegment() *IPv4AddressSegment {
	if seg.IsIPv4AddressSegment() {
		return (*IPv4AddressSegment)(unsafe.Pointer(seg))
	}
	return nil
}

func (seg *IPAddressSegment) ToIPv6AddressSegment() *IPv6AddressSegment {
	if seg.IsIPv6AddressSegment() {
		return (*IPv6AddressSegment)(unsafe.Pointer(seg))
	}
	return nil
}
