package ipaddr

import (
	"math/big"
	"net"
	"sync/atomic"
	"unsafe"
)

type IPVersion string

const (
	PrefixLenSeparator = '/'

	IndeterminateIPVersion IPVersion = ""
	IPv4                   IPVersion = "IPv4"
	IPv6                   IPVersion = "IPv6"
)

func (version IPVersion) isIPv6() bool {
	return version == IPv6
}

func (version IPVersion) isIPv4() bool {
	return version == IPv4
}

func (version IPVersion) isIndeterminate() bool {
	return version == IndeterminateIPVersion
}

// returns an index starting from 0 with IndeterminateIPVersion being the highest
func (version IPVersion) index() int {
	if version.isIPv4() {
		return 0
	} else if version.isIPv6() {
		return 1
	}
	return 2
}

func (version IPVersion) String() string {
	return string(version)
}

func (version IPVersion) getNetwork() (network IPAddressNetwork) {
	if version.isIPv6() {
		network = DefaultIPv6Network
	} else if version.isIPv4() {
		network = DefaultIPv4Network
	}
	return
}

func (version IPVersion) toType() (t addrType) {
	if version.isIPv6() {
		t = ipv4Type
	} else if version.isIPv4() {
		t = ipv6Type
	}
	return
}

func GetMaxSegmentValue(version IPVersion) SegInt {
	if version.isIPv4() {
		return IPv4MaxValuePerSegment
	}
	return IPv6MaxValuePerSegment
}

func GetBytesPerSegment(version IPVersion) int {
	if version.isIPv4() {
		return IPv4BytesPerSegment
	}
	return IPv6BytesPerSegment
}

func GetBitsPerSegment(version IPVersion) BitCount {
	if version.isIPv4() {
		return IPv4BitsPerSegment
	}
	return IPv6BitsPerSegment
}

func GetByteCount(version IPVersion) int {
	if version.isIPv4() {
		return IPv4ByteCount
	}
	return IPv6ByteCount
}

func GetSegmentCount(version IPVersion) int {
	if version.isIPv4() {
		return IPv4SegmentCount
	}
	return IPv6SegmentCount
}

func GetBitCount(version IPVersion) BitCount {
	if version.isIPv4() {
		return IPv4BitCount
	}
	return IPv6BitCount
}

func createIPAddress(section *AddressSection, zone Zone) *IPAddress {
	return &IPAddress{
		ipAddressInternal{
			addressInternal{
				section: section,
				zone:    zone,
				cache:   &addressCache{},
			},
		},
	}
}

func newIPAddressZoned(section *IPAddressSection, zone Zone) *IPAddress {
	result := createIPAddress(section.ToAddressSection(), zone)
	if zone != NoZone { // will need to cache its own strings
		result.cache.stringCache = &stringCache{}
	}
	return result
}

// necessary to avoid direct access to IPAddress
type ipAddressInternal struct {
	addressInternal
}

func (addr *ipAddressInternal) ToAddress() *Address {
	return (*Address)(addr)
}

func (addr *ipAddressInternal) toIPAddress() *IPAddress {
	return (*IPAddress)(unsafe.Pointer(addr))
}

func (addr *ipAddressInternal) getIPVersion() IPVersion {
	if addr.isIPv4() {
		return IPv4
	} else if addr.isIPv6() {
		return IPv6
	}
	return IndeterminateIPVersion
}

func (addr *ipAddressInternal) GetNetworkPrefixLength() PrefixLen {
	section := addr.section
	if section == nil {
		return nil
	}
	return section.ToIPAddressSection().GetNetworkPrefixLength()
}

func (addr *ipAddressInternal) IncludesZeroHost() bool {
	section := addr.section
	if section == nil {
		return false
	}
	return section.ToIPAddressSection().IncludesZeroHost()
}

func (addr *ipAddressInternal) includesZeroHostLen(networkPrefixLength BitCount) bool {
	return addr.section.ToIPAddressSection().IncludesZeroHostLen(networkPrefixLength)
}

func (addr *ipAddressInternal) IncludesMaxHost() bool {
	section := addr.section
	if section == nil {
		return false
	}
	return section.ToIPAddressSection().IncludesMaxHost()
}

func (addr *ipAddressInternal) includesMaxHostLen(networkPrefixLength BitCount) bool {
	return addr.section.ToIPAddressSection().IncludesMaxHostLen(networkPrefixLength)
}

// IsSingleNetwork returns whether the network section of the address, the prefix, consists of a single value
func (addr *ipAddressInternal) IsSingleNetwork() bool {
	section := addr.section
	return section == nil || section.ToIPAddressSection().IsSingleNetwork()
}

// IsZeroHost returns whether this section has a prefix length and if so,
// whether the host section is zero for this section or all sections in this set of address sections.
// If the host section is zero length (there are no host bits at all), returns false.
func (addr *ipAddressInternal) IsZeroHost() bool {
	section := addr.section
	return section != nil && section.ToIPAddressSection().IsZeroHost()
}

// IsZeroHostLen returns whether the host is zero for the given prefix length for this section or all sections in this set of address sections.
// If this section already has a prefix length, then that prefix length is ignored.
// If the host section is zero length (there are no host bits at all), returns false.
func (addr *ipAddressInternal) IsZeroHostLen(prefLen BitCount) bool {
	section := addr.section
	return section == nil || section.ToIPAddressSection().IsZeroHostLen(prefLen)
}

// when boundariesOnly is true, there will be no error
func (addr *ipAddressInternal) toZeroHost(boundariesOnly bool) (res *IPAddress, err IncompatibleAddressError) {
	section, err := addr.section.toIPAddressSection().toZeroHost(boundariesOnly)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) toZeroHostLen(prefixLength BitCount) (res *IPAddress, err IncompatibleAddressError) {
	section, err := addr.section.toIPAddressSection().toZeroHostLen(prefixLength)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) toZeroNetwork() *IPAddress {
	return addr.checkIdentity(addr.section.toIPAddressSection().toZeroNetwork())
}

func (addr *ipAddressInternal) toMaxHost() (res *IPAddress, err IncompatibleAddressError) {
	section, err := addr.section.toIPAddressSection().toMaxHost()
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) toMaxHostLen(prefixLength BitCount) (res *IPAddress, err IncompatibleAddressError) {
	section, err := addr.section.toIPAddressSection().toMaxHostLen(prefixLength)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) checkIdentity(section *IPAddressSection) *IPAddress {
	sect := section.ToAddressSection()
	if sect == addr.section {
		return addr.toIPAddress()
	}
	return createIPAddress(sect, addr.zone)
}

func (addr *ipAddressInternal) adjustPrefixLen(prefixLen BitCount) *IPAddress {
	return addr.checkIdentity(addr.section.toIPAddressSection().adjustPrefixLen(prefixLen))
}

func (addr *ipAddressInternal) adjustPrefixLenZeroed(prefixLen BitCount) (res *IPAddress, err IncompatibleAddressError) {
	section, err := addr.section.toIPAddressSection().adjustPrefixLenZeroed(prefixLen)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) GetBlockMaskPrefixLen(network bool) PrefixLen {
	section := addr.section
	if section == nil {
		return nil
	}
	return section.ToIPAddressSection().GetBlockMaskPrefixLen(network)
}

func (addr *ipAddressInternal) GetSegment(index int) *IPAddressSegment {
	return addr.getSegment(index).ToIPAddressSegment()
}

func (addr *ipAddressInternal) spanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	wrapped := WrappedIPAddress{addr.toIPAddress()}
	if addr.IsSequential() {
		if addr.IsSinglePrefixBlock() {
			return []ExtendedIPSegmentSeries{wrapped}
		}
		return getSpanningPrefixBlocks(wrapped, wrapped)
	}
	return spanWithPrefixBlocks(wrapped)
}

func (addr *ipAddressInternal) spanWithSequentialBlocks() []ExtendedIPSegmentSeries {
	wrapped := WrappedIPAddress{addr.toIPAddress()}
	if addr.IsSequential() {
		return []ExtendedIPSegmentSeries{wrapped}
	}
	return spanWithSequentialBlocks(wrapped)
}

func (addr *ipAddressInternal) coverSeriesWithPrefixBlock() ExtendedIPSegmentSeries {
	// call from wrapper
	if addr.IsSinglePrefixBlock() {
		return WrappedIPAddress{addr.toIPAddress()}
	}
	return coverWithPrefixBlock(
		WrappedIPAddress{addr.getLower().ToIPAddress()},
		WrappedIPAddress{addr.getUpper().ToIPAddress()},
	)
}

func (addr *ipAddressInternal) coverWithPrefixBlock() *IPAddress {
	// call from ip ipv4 ipv6
	if addr.IsSinglePrefixBlock() {
		return addr.toIPAddress()
	}
	res := coverWithPrefixBlock(
		WrappedIPAddress{addr.getLower().ToIPAddress()},
		WrappedIPAddress{addr.getUpper().ToIPAddress()},
	)
	return res.(WrappedIPAddress).IPAddress
}

func (addr *ipAddressInternal) coverWithPrefixBlockTo(other *IPAddress) *IPAddress {
	res := getCoveringPrefixBlock(
		WrappedIPAddress{addr.toIPAddress()},
		WrappedIPAddress{other},
	)
	return res.(WrappedIPAddress).IPAddress
}

func (addr *ipAddressInternal) getNetworkMask(network IPAddressNetwork) *IPAddress {
	var prefLen BitCount
	if addr.IsPrefixed() {
		prefLen = *addr.GetNetworkPrefixLength()
	} else {
		prefLen = addr.GetBitCount()
	}
	return network.GetNetworkMask(prefLen)
}

func (addr *ipAddressInternal) getHostMask(network IPAddressNetwork) *IPAddress {
	var prefLen BitCount
	if addr.IsPrefixed() {
		prefLen = *addr.GetNetworkPrefixLength()
	}
	return network.GetNetworkMask(prefLen)
}

func (addr *ipAddressInternal) toOctalString(with0Prefix bool) (string, IncompatibleAddressError) {
	if addr.hasZone() {
		var cacheField **string
		if with0Prefix {
			cacheField = &addr.getStringCache().octalStringPrefixed
		} else {
			cacheField = &addr.getStringCache().octalString
		}
		return cacheStrErr(cacheField,
			func() (string, IncompatibleAddressError) {
				return addr.section.ToIPAddressSection().toOctalStringZoned(with0Prefix, addr.zone)
			})
	}
	return addr.section.ToIPAddressSection().ToOctalString(with0Prefix)
}

func (addr *ipAddressInternal) toBinaryString(with0bPrefix bool) (string, IncompatibleAddressError) {
	if addr.hasZone() {
		var cacheField **string
		if with0bPrefix {
			cacheField = &addr.getStringCache().binaryStringPrefixed
		} else {
			cacheField = &addr.getStringCache().binaryString
		}
		return cacheStrErr(cacheField,
			func() (string, IncompatibleAddressError) {
				return addr.section.ToIPAddressSection().toBinaryStringZoned(with0bPrefix, addr.zone)
			})
	}
	return addr.section.ToIPAddressSection().ToBinaryString(with0bPrefix)
}

func (addr *ipAddressInternal) toCanonicalWildcardString() string {
	if addr.hasZone() {
		return cacheStr(&addr.getStringCache().canonicalWildcardString,
			func() string {
				return addr.section.ToIPv6AddressSection().toCanonicalWildcardStringZoned(addr.zone)
			})
	}
	return addr.section.ToIPAddressSection().ToCanonicalWildcardString()
}

func (addr *ipAddressInternal) toNormalizedWildcardString() string {
	if addr.hasZone() {
		return cacheStr(&addr.getStringCache().normalizedWildcardString,
			func() string {
				return addr.section.ToIPv6AddressSection().toNormalizedWildcardStringZoned(addr.zone)
			})
	}
	return addr.section.ToIPAddressSection().ToNormalizedWildcardString()
}

func (addr *ipAddressInternal) toSegmentedBinaryString() string {
	if addr.hasZone() {
		return cacheStr(&addr.getStringCache().segmentedBinaryString,
			func() string {
				return addr.section.ToIPv6AddressSection().toSegmentedBinaryStringZoned(addr.zone)
			})
	}
	return addr.section.ToIPAddressSection().ToSegmentedBinaryString()
}

func (addr *ipAddressInternal) toSQLWildcardString() string {
	if addr.hasZone() {
		return cacheStr(&addr.getStringCache().sqlWildcardString,
			func() string {
				return addr.section.ToIPv6AddressSection().toSQLWildcardStringZoned(addr.zone)
			})
	}
	return addr.section.ToIPAddressSection().ToSQLWildcardString()
}

func (addr *ipAddressInternal) toFullString() string {
	if addr.hasZone() {
		return cacheStr(&addr.getStringCache().fullString,
			func() string {
				return addr.section.ToIPv6AddressSection().toFullStringZoned(addr.zone)
			})
	}
	return addr.section.ToIPAddressSection().ToFullString()
}

func (addr *ipAddressInternal) toReverseDNSString() (string, IncompatibleAddressError) {
	if addr.hasZone() {
		return cacheStrErr(&addr.getStringCache().reverseDNSString,
			func() (string, IncompatibleAddressError) {
				return addr.section.ToIPv6AddressSection().toReverseDNSStringZoned(addr.zone)
			})
	}
	return addr.section.ToIPAddressSection().ToReverseDNSString()
}

func (addr *ipAddressInternal) toPrefixLenString() string {
	if addr.hasZone() {
		return cacheStr(&addr.getStringCache().networkPrefixLengthString,
			func() string {
				return addr.section.ToIPv6AddressSection().toPrefixLenStringZoned(addr.zone)
			})
	}
	return addr.section.ToIPAddressSection().ToPrefixLenString()
}

func (addr *ipAddressInternal) toSubnetString() string {
	if addr.hasZone() {
		return addr.toPrefixLenString()
	}
	return addr.section.ToIPAddressSection().ToSubnetString()
}

func (addr *ipAddressInternal) toCompressedWildcardString() string {
	if addr.hasZone() {
		return cacheStr(&addr.getStringCache().compressedWildcardString,
			func() string {
				return addr.section.ToIPv6AddressSection().toCompressedWildcardStringZoned(addr.zone)
			})
	}
	return addr.section.ToIPAddressSection().ToCompressedWildcardString()
}

//func (addr *ipAddressInternal) GetGenericIPDivision(index int) IPAddressGenericDivision {
//	return addr.GetSegment(index)
//}

func (addr *ipAddressInternal) CompareSize(other AddressDivisionSeries) int {
	return addr.toIPAddress().CompareSize(other)
}

var zeroIPAddr = createIPAddress(zeroSection, NoZone)

//
//
// IPAddress represents an IPAddress, either IPv4 or IPv6.
// Only the zero-value IPAddress can be neither IPv4 or IPv6.
// The zero value has no segments, which is not compatible with zero value for ivp4 or ipv6.
type IPAddress struct {
	ipAddressInternal
}

func (addr *IPAddress) init() *IPAddress {
	if addr.section == nil {
		return zeroIPAddr // this has a zero section
	}
	return addr
}

func (addr *IPAddress) getProvider() ipAddressProvider {
	if addr.IsPrefixed() {
		if !addr.IsPrefixBlock() {
			return getProviderFor(addr, addr.WithoutPrefixLen())
		}
		zeroedAddr, _ := addr.toZeroHost(true)
		return getProviderFor(addr, zeroedAddr.WithoutPrefixLen())
	}
	return getProviderFor(addr, addr)

}

func (addr IPAddress) String() string {
	return addr.init().ipAddressInternal.String()
}

func (addr *IPAddress) GetSection() *IPAddressSection {
	return addr.init().section.ToIPAddressSection()
}

// Gets the subsection from the series starting from the given index
// The first segment is at index 0.
func (addr *IPAddress) GetTrailingSection(index int) *IPAddressSection {
	return addr.GetSection().GetTrailingSection(index)
}

//// Gets the subsection from the series starting from the given index and ending just before the give endIndex
//// The first segment is at index 0.
func (addr *IPAddress) GetSubSection(index, endIndex int) *IPAddressSection {
	return addr.GetSection().GetSubSection(index, endIndex)
}

func (addr *IPAddress) GetNetworkSection() *IPAddressSection {
	return addr.GetSection().GetNetworkSection()
}

func (addr *IPAddress) GetNetworkSectionLen(prefLen BitCount) *IPAddressSection {
	return addr.GetSection().GetNetworkSectionLen(prefLen)
}

func (addr *IPAddress) GetHostSection() *IPAddressSection {
	return addr.GetSection().GetHostSection()
}

func (addr *IPAddress) GetHostSectionLen(prefLen BitCount) *IPAddressSection {
	return addr.GetSection().GetHostSectionLen(prefLen)
}

func (addr *IPAddress) getNetwork() IPAddressNetwork {
	return addr.GetSection().getNetwork()
}

func (addr *IPAddress) GetNetworkMask() *IPAddress {
	return addr.getNetworkMask(addr.getNetwork())
}

func (addr *IPAddress) GetHostMask() *IPAddress {
	return addr.getHostMask(addr.getNetwork())
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *IPAddress) CopySubSegments(start, end int, segs []*IPAddressSegment) (count int) {
	return addr.GetSection().CopySubSegments(start, end, segs)
}

// CopySubSegments copies the existing segments from the given start index until but not including the segment at the given end index,
// into the given slice, as much as can be fit into the slice, returning the number of segments copied
func (addr *IPAddress) CopySegments(segs []*IPAddressSegment) (count int) {
	return addr.GetSection().CopySegments(segs)
}

// GetSegments returns a slice with the address segments.  The returned slice is not backed by the same array as this section.
func (addr *IPAddress) GetSegments() []*IPAddressSegment {
	return addr.GetSection().GetSegments()
}

// GetSegment returns the segment at the given index
func (addr *IPAddress) GetSegment(index int) *IPAddressSegment {
	return addr.getSegment(index).ToIPAddressSegment()
}

// GetSegmentCount returns the segment count
func (addr *IPAddress) GetSegmentCount() int {
	return addr.getDivisionCount()
}

// GetGenericDivision returns the segment at the given index as an DivisionType
func (addr *IPAddress) GetGenericDivision(index int) DivisionType {
	return addr.getDivision(index)
}

// GetGenericSegment returns the segment at the given index as an AddressSegmentType
func (addr *IPAddress) GetGenericSegment(index int) AddressSegmentType {
	return addr.getSegment(index)
}

// GetDivision returns the segment count
func (addr *IPAddress) GetDivisionCount() int {
	return addr.getDivisionCount()
}

func (addr *IPAddress) GetBitCount() BitCount {
	if address := addr.ToIPv4Address(); address != nil {
		return address.GetBitCount()
	} else if address := addr.ToIPv6Address(); address != nil {
		return address.GetBitCount()
	}
	return addr.addressInternal.GetBitCount()
}

func (addr *IPAddress) GetByteCount() int {
	if address := addr.ToIPv4Address(); address != nil {
		return address.GetByteCount()
	} else if address := addr.ToIPv6Address(); address != nil {
		return address.GetByteCount()
	}
	return addr.addressInternal.GetByteCount()
}

// GetLowerIPAddress implements the IPAddressRange interface, and is equivalent to GetLower()
func (addr *IPAddress) GetLowerIPAddress() *IPAddress {
	return addr.GetLower()
}

// GetUpperIPAddress implements the IPAddressRange interface, and is equivalent to GetUpper()
func (addr *IPAddress) GetUpperIPAddress() *IPAddress {
	return addr.GetUpper()
}

func (addr *IPAddress) GetLower() *IPAddress {
	return addr.init().getLower().ToIPAddress()
}

func (addr *IPAddress) GetUpper() *IPAddress {
	return addr.init().getUpper().ToIPAddress()
}

func (addr *IPAddress) ToZeroHost() (*IPAddress, IncompatibleAddressError) {
	return addr.init().toZeroHost(false)
}

func (addr *IPAddress) ToZeroHostLen(prefixLength BitCount) (*IPAddress, IncompatibleAddressError) {
	return addr.init().toZeroHostLen(prefixLength)
}

func (addr *IPAddress) ToZeroNetwork() *IPAddress {
	return addr.init().toZeroNetwork()
}

func (addr *IPAddress) ToMaxHost() (*IPAddress, IncompatibleAddressError) {
	return addr.init().toMaxHost()
}

func (addr *IPAddress) ToMaxHostLen(prefixLength BitCount) (*IPAddress, IncompatibleAddressError) {
	return addr.init().toMaxHostLen(prefixLength)
}

func (addr *IPAddress) ToPrefixBlock() *IPAddress {
	return addr.init().toPrefixBlock().ToIPAddress()
}

func (addr *IPAddress) ToPrefixBlockLen(prefLen BitCount) *IPAddress {
	return addr.init().toPrefixBlockLen(prefLen).ToIPAddress()
}

func (addr *IPAddress) ToBlock(segmentIndex int, lower, upper SegInt) *IPAddress {
	return addr.init().toBlock(segmentIndex, lower, upper).ToIPAddress()
}

func (addr *IPAddress) WithoutPrefixLen() *IPAddress {
	return addr.withoutPrefixLen().ToIPAddress()
}

func (addr *IPAddress) SetPrefixLen(prefixLen BitCount) *IPAddress {
	return addr.init().setPrefixLen(prefixLen).ToIPAddress()
}

func (addr *IPAddress) SetPrefixLenZeroed(prefixLen BitCount) (*IPAddress, IncompatibleAddressError) {
	res, err := addr.init().setPrefixLenZeroed(prefixLen)
	return res.ToIPAddress(), err
}

func (addr *IPAddress) AdjustPrefixLen(prefixLen BitCount) *IPAddress {
	return addr.init().adjustPrefixLen(prefixLen).ToIPAddress()
}

func (addr *IPAddress) AdjustPrefixLenZeroed(prefixLen BitCount) (*IPAddress, IncompatibleAddressError) {
	res, err := addr.init().adjustPrefixLenZeroed(prefixLen)
	return res.ToIPAddress(), err
}

func (addr *IPAddress) AssignPrefixForSingleBlock() *IPAddress {
	return addr.init().assignPrefixForSingleBlock().ToIPAddress()
}

func (addr *IPAddress) AssignMinPrefixForBlock() *IPAddress {
	return addr.init().assignMinPrefixForBlock().ToIPAddress()
}

// CompareSize returns whether this subnet has more elements than the other, returning -1 if this subnet has less, 1 if more, and 0 if both have the same count of individual addresses
func (addr *IPAddress) CompareSize(other AddressDivisionSeries) int { // this is here to take advantage of the CompareSize in IPAddressSection
	return addr.GetSection().CompareSize(other)
}

func (addr *IPAddress) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

func (addr *IPAddress) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

func (addr *IPAddress) GetIPAddr() net.IPAddr {
	return net.IPAddr{
		IP:   addr.GetIP(),
		Zone: string(addr.zone),
	}
}

func (addr *IPAddress) GetIP() net.IP {
	return addr.GetBytes()
}

func (addr *IPAddress) CopyIP(bytes net.IP) net.IP {
	return addr.CopyBytes(bytes)
}

func (addr *IPAddress) GetUpperIP() net.IP {
	return addr.GetUpperBytes()
}

func (addr *IPAddress) CopyUpperIP(bytes net.IP) net.IP {
	return addr.CopyUpperBytes(bytes)
}

func (addr *IPAddress) GetBytes() []byte {
	return addr.init().section.GetBytes()
}

func (addr *IPAddress) GetUpperBytes() []byte {
	return addr.init().section.GetUpperBytes()
}

func (addr *IPAddress) CopyBytes(bytes []byte) []byte {
	return addr.init().section.CopyBytes(bytes)
}

func (addr *IPAddress) CopyUpperBytes(bytes []byte) []byte {
	return addr.init().section.CopyUpperBytes(bytes)
}

func (addr *IPAddress) IsMax() bool {
	return addr.init().section.IsMax()
}

func (addr *IPAddress) IncludesMax() bool {
	return addr.init().section.IncludesMax()
}

// TestBit computes (this & (1 << n)) != 0), using the lower value of this segment.
func (addr *IPAddress) TestBit(n BitCount) bool {
	return addr.init().testBit(n)
}

// Returns true if the bit in the lower value of this segment at the given index is 1, where index 0 is the most significant bit.
func (addr *IPAddress) IsOneBit(bitIndex BitCount) bool {
	return addr.init().isOneBit(bitIndex)
}

func (addr *IPAddress) CompareTo(item AddressItem) int {
	return CountComparator.Compare(addr.init(), item)
}

func (addr *IPAddress) PrefixEquals(other AddressType) bool {
	return addr.init().prefixEquals(other)
}

func (addr *IPAddress) PrefixContains(other AddressType) bool {
	return addr.init().prefixContains(other)
}

func (addr *IPAddress) Contains(other AddressType) bool {
	return addr.init().contains(other)
}

func (addr *IPAddress) Equals(other AddressType) bool {
	return addr.init().equals(other)
}

func (addr *IPAddress) MatchesWithMask(other *IPAddress, mask *IPAddress) bool {
	if thisAddr := addr.ToIPv4Address(); thisAddr != nil {
		if oth := other.ToIPv4Address(); oth != nil {
			if msk := mask.ToIPv4Address(); mask != nil {
				return thisAddr.MatchesWithMask(oth, msk)
			}
		}
	} else if thisAddr := addr.ToIPv6Address(); thisAddr != nil {
		if oth := other.ToIPv6Address(); oth != nil {
			if msk := mask.ToIPv6Address(); mask != nil {
				return thisAddr.MatchesWithMask(oth, msk)
			}
		}
	}
	return false
}

func (addr *IPAddress) IsIPv4() bool {
	return addr.isIPv4()
}

func (addr *IPAddress) IsIPv6() bool {
	return addr.isIPv6()
}

func (addr *IPAddress) GetIPVersion() IPVersion {
	return addr.getIPVersion()
}

func (addr *IPAddress) ToIPAddress() *IPAddress {
	return addr
}

func (addr *IPAddress) ToIPv6Address() *IPv6Address {
	if addr != nil && addr.IsIPv6() {
		return (*IPv6Address)(addr)
	}
	return nil
}

func (addr *IPAddress) ToIPv4Address() *IPv4Address {
	if addr != nil && addr.IsIPv4() {
		return (*IPv4Address)(addr)
	}
	return nil
}

func (addr *IPAddress) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

func (addr *IPAddress) Iterator() IPAddressIterator {
	return ipAddrIterator{addr.init().addrIterator(nil)}
}

func (addr *IPAddress) PrefixIterator() IPAddressIterator {
	return ipAddrIterator{addr.init().prefixIterator(false)}
}

func (addr *IPAddress) PrefixBlockIterator() IPAddressIterator {
	return ipAddrIterator{addr.init().prefixIterator(true)}
}

func (addr *IPAddress) BlockIterator(segmentCount int) IPAddressIterator {
	return ipAddrIterator{addr.init().blockIterator(segmentCount)}
}

func (addr *IPAddress) SequentialBlockIterator() IPAddressIterator {
	return ipAddrIterator{addr.init().sequentialBlockIterator()}
}

func (addr *IPAddress) GetSequentialBlockIndex() int {
	return addr.getSequentialBlockIndex()
}

func (addr *IPAddress) GetSequentialBlockCount() *big.Int {
	return addr.getSequentialBlockCount()
}

func (addr *IPAddress) ToSequentialRange() *IPAddressSeqRange {
	if addr != nil {
		if addr.IsIPv4() {
			return addr.ToIPv4Address().ToSequentialRange().ToIPAddressSeqRange()
		} else if addr.IsIPv6() {
			return addr.ToIPv6Address().ToSequentialRange().ToIPAddressSeqRange()
		}
	}
	return nil
}

func (addr *IPAddress) toSequentialRangeUnchecked() *IPAddressSeqRange {
	// no prefix, no zone
	return newSeqRangeUnchecked(addr.GetLower(), addr.GetUpper(), addr.IsMultiple())
}

func (addr *IPAddress) IncrementBoundary(increment int64) *IPAddress {
	return addr.init().incrementBoundary(increment).ToIPAddress()
}

func (addr *IPAddress) Increment(increment int64) *IPAddress {
	return addr.init().increment(increment).ToIPAddress()
}

func (addr *IPAddress) SpanWithRange(other *IPAddress) (*IPAddressSeqRange, IncompatibleAddressError) {
	if thisAddr := addr.ToIPv4Address(); thisAddr != nil {
		if oth := other.ToIPv4Address(); oth != nil {
			return thisAddr.SpanWithRange(oth).ToIPAddressSeqRange(), nil
		}
	} else if thisAddr := addr.ToIPv6Address(); thisAddr != nil {
		if oth := other.ToIPv6Address(); oth != nil {
			return thisAddr.SpanWithRange(oth).ToIPAddressSeqRange(), nil
		}
	}
	return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipVersionMismatch"}}
}

// Mask applies the given mask to all addresses represented by this IPAddress.
// The mask is applied to all individual addresses.
// Any existing prefix length is removed beforehand.  If the retainPrefix argument is true, then the existing prefix length will be applied to the result.
//
// If the mask is a different version than this, then an error is returned
//
// If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
// that cannot be represented as a contiguous range within each segment, then an error is returned
func (addr *IPAddress) Mask(other *IPAddress) (masked *IPAddress, err IncompatibleAddressError) {
	return addr.maskPrefixed(other, false)
}

func (addr *IPAddress) MaskPrefixed(other *IPAddress) (masked *IPAddress, err IncompatibleAddressError) {
	return addr.maskPrefixed(other, true)
}

func (addr *IPAddress) maskPrefixed(other *IPAddress, retainPrefix bool) (*IPAddress, IncompatibleAddressError) {
	if thisAddr := addr.ToIPv4Address(); thisAddr != nil {
		if oth := other.ToIPv4Address(); oth != nil {
			result, err := thisAddr.maskPrefixed(oth, retainPrefix)
			return result.ToIPAddress(), err
		}
	} else if thisAddr := addr.ToIPv6Address(); thisAddr != nil {
		if oth := other.ToIPv6Address(); oth != nil {
			result, err := thisAddr.maskPrefixed(oth, retainPrefix)
			return result.ToIPAddress(), err
		}
	}
	return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipMismatch"}}
}

func (addr *IPAddress) BitwiseOr(other *IPAddress) (masked *IPAddress, err IncompatibleAddressError) {
	return addr.bitwiseOrPrefixed(other, false)
}

func (addr *IPAddress) BitwiseOrPrefixed(other *IPAddress) (masked *IPAddress, err IncompatibleAddressError) {
	return addr.bitwiseOrPrefixed(other, true)
}

func (addr *IPAddress) bitwiseOrPrefixed(other *IPAddress, retainPrefix bool) (*IPAddress, IncompatibleAddressError) {
	if thisAddr := addr.ToIPv4Address(); thisAddr != nil {
		if oth := other.ToIPv4Address(); oth != nil {
			result, err := thisAddr.bitwiseOrPrefixed(oth, retainPrefix)
			return result.ToIPAddress(), err
		}
	} else if thisAddr := addr.ToIPv6Address(); thisAddr != nil {
		if oth := other.ToIPv6Address(); oth != nil {
			result, err := thisAddr.bitwiseOrPrefixed(oth, retainPrefix)
			return result.ToIPAddress(), err
		}
	}
	return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipMismatch"}}
}

func (addr *IPAddress) Intersect(other *IPAddress) *IPAddress {
	if thisAddr := addr.ToIPv4Address(); thisAddr != nil {
		if oth := other.ToIPv4Address(); oth != nil {
			return thisAddr.Intersect(oth).ToIPAddress()
		}
	} else if thisAddr := addr.ToIPv6Address(); thisAddr != nil {
		if oth := other.ToIPv6Address(); oth != nil {
			return thisAddr.Intersect(oth).ToIPAddress()
		}
	}
	return nil
}

func (addr *IPAddress) Subtract(other *IPAddress) []*IPAddress {
	addr = addr.init()
	sects, _ := addr.GetSection().subtract(other.GetSection())
	sectLen := len(sects)
	if sectLen == 1 {
		sec := sects[0]
		if sec.ToAddressSection() == addr.section {
			return []*IPAddress{addr}
		}
	}
	res := make([]*IPAddress, sectLen)
	for i, sect := range sects {
		res[i] = newIPAddressZoned(sect, addr.zone)
	}
	return res
}

// Returns whether the address is link local, whether unicast or multicast.
func (addr *IPAddress) IsLinkLocal() bool {
	if thisAddr := addr.ToIPv4Address(); thisAddr != nil {
		return thisAddr.IsLinkLocal()
	} else if thisAddr := addr.ToIPv6Address(); thisAddr != nil {
		return thisAddr.IsLinkLocal()
	}
	return false
}

// IsLocal returns true if the address is link local, site local, organization local, administered locally, or unspecified.
// This includes both unicast and multicast.
func (addr *IPAddress) IsLocal() bool {
	if thisAddr := addr.ToIPv4Address(); thisAddr != nil {
		return thisAddr.IsLocal()
	} else if thisAddr := addr.ToIPv6Address(); thisAddr != nil {
		return thisAddr.IsLocal()
	}
	return false
}

// The unspecified address is the address that is all zeros.
func (addr *IPAddress) IsUnspecified() bool {
	return addr.section != nil && addr.IsZero()
}

// Returns whether this address is the address which binds to any address on the local host.
// This is the address that has the value of 0, aka the unspecified address.
func (addr *IPAddress) IsAnyLocal() bool {
	return addr.section != nil && addr.IsZero()
}

// IsLoopback returns whether this address is a loopback address, such as
// [::1] (aka [0:0:0:0:0:0:0:1]) or 127.0.0.1
func (addr *IPAddress) IsLoopback() bool {
	if thisAddr := addr.ToIPv4Address(); thisAddr != nil {
		return thisAddr.IsLoopback()
	} else if thisAddr := addr.ToIPv6Address(); thisAddr != nil {
		return thisAddr.IsLoopback()
	}
	return false
}

// IsMulticast returns whether this address is multicast
func (addr *IPAddress) IsMulticast() bool {
	if thisAddr := addr.ToIPv4Address(); thisAddr != nil {
		return thisAddr.IsMulticast()
	} else if thisAddr := addr.ToIPv6Address(); thisAddr != nil {
		return thisAddr.IsMulticast()
	}
	return false
}

// toCanonicalHostName TODO but requires reverse name lookup, so we need to call into golang net code (net.LookupAddr or LookupCNAME) http://networkbit.ch/golang-dns-lookup/
// ToUNCHostName //TODO LATER
// TODO the static ToNormalizedString methods
// TODO the general conversion methods in IPAddressGenerator (here they will be "static", ie funcs not methods) which will include or use  addrFromIP and addrFromPrefixedIP

func versionsMatch(one, two *IPAddress) bool {
	return one.getAddrType() == two.getAddrType()
}

func allVersionsMatch(one *IPAddress, two []*IPAddress) bool {
	addrType := one.getAddrType()
	for _, addr := range two {
		if addr.getAddrType() != addrType {
			return false
		}
	}
	return true
}

//
// MergeToSequentialBlocks merges this with the list of addresses to produce the smallest array of blocks that are sequential
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (addr *IPAddress) MergeToSequentialBlocks(addrs ...*IPAddress) ([]*IPAddress, IncompatibleAddressError) {
	if !allVersionsMatch(addr, addrs) {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipVersionMismatch"}}
	}
	series := cloneIPAddrs(addr, addrs)
	blocks := getMergedSequentialBlocks(series)
	return cloneToIPAddrs(blocks), nil
}

//
// MergeToPrefixBlocks merges this with the list of sections to produce the smallest array of prefix blocks.
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
func (addr *IPAddress) MergeToPrefixBlocks(addrs ...*IPAddress) ([]*IPAddress, IncompatibleAddressError) {
	if !allVersionsMatch(addr, addrs) {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipVersionMismatch"}}
	}
	series := cloneIPAddrs(addr, addrs)
	blocks := getMergedPrefixBlocks(series)
	return cloneToIPAddrs(blocks), nil
}

func (addr *IPAddress) SpanWithPrefixBlocks() []*IPAddress {
	addr = addr.init()
	if addr.IsSequential() {
		if addr.IsSinglePrefixBlock() {
			return []*IPAddress{addr}
		}
		wrapped := WrappedIPAddress{addr}
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPAddrs(spanning)
	}
	wrapped := WrappedIPAddress{addr}
	return cloneToIPAddrs(spanWithPrefixBlocks(wrapped))
}

func (addr *IPAddress) SpanWithPrefixBlocksTo(other *IPAddress) ([]*IPAddress, IncompatibleAddressError) {
	if !versionsMatch(addr, other) {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipVersionMismatch"}}
	}
	return cloneToIPAddrs(
		getSpanningPrefixBlocks(
			WrappedIPAddress{addr.init()},
			WrappedIPAddress{other.init()},
		),
	), nil
}

func (addr *IPAddress) CoverWithPrefixBlockTo(other *IPAddress) (*IPAddress, IncompatibleAddressError) {
	if !versionsMatch(addr, other) {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipVersionMismatch"}}
	}
	return addr.init().coverWithPrefixBlockTo(other), nil
}

func (addr *IPAddress) CoverWithPrefixBlock() *IPAddress {
	return addr.init().coverWithPrefixBlock()
}

func (addr *IPAddress) SpanWithSequentialBlocks() []*IPAddress {
	addr = addr.init()
	if addr.IsSequential() {
		return []*IPAddress{addr}
	}
	wrapped := WrappedIPAddress{addr}
	return cloneToIPAddrs(spanWithSequentialBlocks(wrapped))
}

func (addr *IPAddress) SpanWithSequentialBlocksTo(other *IPAddress) ([]*IPAddress, IncompatibleAddressError) {
	addr = addr.init()
	other = other.init()
	if !versionsMatch(addr, other) {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipVersionMismatch"}}
	}
	return cloneToIPAddrs(
		getSpanningSequentialBlocks(
			WrappedIPAddress{addr.ToIPAddress()},
			WrappedIPAddress{other.ToIPAddress()},
		),
	), nil
}

func (addr *IPAddress) ReverseBytes() (*IPAddress, IncompatibleAddressError) {
	res, err := addr.init().reverseBytes()
	return res.ToIPAddress(), err
}

func (addr *IPAddress) ReverseBits(perByte bool) (*IPAddress, IncompatibleAddressError) {
	res, err := addr.init().reverseBits(perByte)
	return res.ToIPAddress(), err
}

func (addr *IPAddress) ReverseSegments() *IPAddress {
	return addr.init().reverseSegments().ToIPAddress()
}

func (addr *IPAddress) ToCanonicalString() string {
	return addr.init().toCanonicalString()
}

func (addr *IPAddress) ToCanonicalWildcardString() string {
	return addr.init().toCanonicalWildcardString()
}

func (addr *IPAddress) ToNormalizedString() string {
	return addr.init().toNormalizedString()
}

func (addr *IPAddress) ToCompressedString() string {
	return addr.init().toCompressedString()
}

func (addr *IPAddress) ToNormalizedWildcardString() string {
	return addr.init().toNormalizedWildcardString()
}

func (addr *IPAddress) ToSegmentedBinaryString() string {
	return addr.init().toSegmentedBinaryString()
}

func (addr *IPAddress) ToSQLWildcardString() string {
	return addr.init().toSQLWildcardString()
}

func (addr *IPAddress) ToFullString() string {
	return addr.init().toFullString()
}

func (addr *IPAddress) ToReverseDNSString() (string, IncompatibleAddressError) {
	return addr.init().toReverseDNSString()
}

func (addr *IPAddress) ToPrefixLenString() string {
	return addr.init().toPrefixLenString()
}

func (addr *IPAddress) ToSubnetString() string {
	return addr.init().toSubnetString()
}

func (addr *IPAddress) ToCompressedWildcardString() string {
	return addr.init().toCompressedWildcardString()
}

func (addr *IPAddress) ToHexString(with0xPrefix bool) (string, IncompatibleAddressError) {
	return addr.init().toHexString(with0xPrefix)
}

func (addr *IPAddress) ToOctalString(with0Prefix bool) (string, IncompatibleAddressError) {
	return addr.init().toOctalString(with0Prefix)
}

func (addr *IPAddress) ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressError) {
	return addr.init().toBinaryString(with0bPrefix)
}

// Generates an IPAddressString object for this IPAddress object.
//
// This same IPAddress object can be retrieved from the resulting IPAddressString object using {@link IPAddressString#getAddress()}
//
// In general, users are intended to create IPAddress objects from IPAddressString objects,
// while the reverse direction is generally not all that useful, except under specific circumstances.
//
// Not all IPAddressString objects can be converted to IPAddress objects,
// as is the case with IPAddressString objects corresponding to the types invalidType, emptyType and allType
//
// So it may be useful to store a set of address strings as a collection of IPAddressString objects,
// rather than IPAddress objects.
func (addr *IPAddress) ToAddressString() *IPAddressString {
	addr = addr.init()
	res := addr.cache.fromString
	if res == nil {
		//str := NewIPAddressString(addr.toCanonicalString())
		str := newIPAddressStringFromAddr(addr.toCanonicalString(), addr)
		dataLoc := &addr.cache.fromString
		atomic.StorePointer(dataLoc, unsafe.Pointer(str))
		return str
	}
	return (*IPAddressString)(res)
}

func (addr *IPAddress) IncludesZeroHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesZeroHostLen(networkPrefixLength)
}

func (addr *IPAddress) IncludesMaxHostLen(networkPrefixLength BitCount) bool {
	return addr.init().includesMaxHostLen(networkPrefixLength)
}

func (addr *IPAddress) GetLeadingBitCount(ones bool) BitCount {
	return addr.GetSection().GetLeadingBitCount(ones)
}

func (addr *IPAddress) GetTrailingBitCount(ones bool) BitCount {
	return addr.GetSection().GetTrailingBitCount(ones)
}

func IPAddressEquals(one, two *IPAddress) bool {
	if one == nil {
		return two == nil
	}
	return two != nil && one.Equals(two)
}

func addrFromIP(bytes net.IP) (addr *IPAddress, err AddressValueError) {
	addrLen := len(bytes)
	if addrLen <= IPv4ByteCount {
		var addr4 *IPv4Address
		addr4, err = NewIPv4AddressFromIP(bytes)
		addr = addr4.ToIPAddress()
	} else {
		var addr6 *IPv6Address
		addr6, err = NewIPv6AddressFromIP(bytes)
		addr = addr6.ToIPAddress()
	}
	return
}

func addrFromPrefixedIP(bytes net.IP, prefixLen PrefixLen) (addr *IPAddress, err AddressValueError) {
	addrLen := len(bytes)
	if addrLen <= IPv4ByteCount {
		var addr4 *IPv4Address
		addr4, err = NewIPv4AddressFromPrefixedIP(bytes, prefixLen)
		addr = addr4.ToIPAddress()
	} else {
		var addr6 *IPv6Address
		addr6, err = NewIPv6AddressFromPrefixedIP(bytes, prefixLen)
		addr = addr6.ToIPAddress()
	}
	return
}
