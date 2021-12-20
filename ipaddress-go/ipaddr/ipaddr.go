package ipaddr

import (
	"fmt"
	"math/big"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"unsafe"
)

type IPVersion string

const (
	PrefixLenSeparator    = '/'
	PrefixLenSeparatorStr = "/"

	IndeterminateIPVersion IPVersion = ""
	IPv4                   IPVersion = "IPv4"
	IPv6                   IPVersion = "IPv6"
)

func (version IPVersion) IsIPv6() bool {
	return strings.EqualFold(string(version), string(IPv6))
}

func (version IPVersion) IsIPv4() bool {
	return strings.EqualFold(string(version), string(IPv4))
}

func (version IPVersion) IsIndeterminate() bool {
	if len(version) == 4 {
		// we allow mixed case in the event code is converted a string to IPVersion
		dig := version[3]
		return (dig != '4' && dig != '6') || !strings.EqualFold(string(version[:3]), "IPv")
	}
	return true
}

// returns an index starting from 0 with IndeterminateIPVersion being the highest
func (version IPVersion) index() int {
	if version.IsIPv4() {
		return 0
	} else if version.IsIPv6() {
		return 1
	}
	return 2
}

func (version IPVersion) Equal(other IPVersion) bool {
	return strings.EqualFold(string(version), string(other)) || (version.IsIndeterminate() && other.IsIndeterminate())
}

func (version IPVersion) String() string {
	return string(version)
}

func (version IPVersion) getNetwork() (network IPAddressNetwork) {
	if version.IsIPv6() {
		network = IPv6Network
	} else if version.IsIPv4() {
		network = IPv4Network
	}
	return
}

func (version IPVersion) toType() (t addrType) {
	if version.IsIPv6() {
		t = ipv6Type
	} else if version.IsIPv4() {
		t = ipv4Type
	}
	return
}

func GetMaxSegmentValue(version IPVersion) SegInt {
	if version.IsIPv4() {
		return IPv4MaxValuePerSegment
	}
	return IPv6MaxValuePerSegment
}

func GetBytesPerSegment(version IPVersion) int {
	if version.IsIPv4() {
		return IPv4BytesPerSegment
	}
	return IPv6BytesPerSegment
}

func GetBitsPerSegment(version IPVersion) BitCount {
	if version.IsIPv4() {
		return IPv4BitsPerSegment
	}
	return IPv6BitsPerSegment
}

func GetByteCount(version IPVersion) int {
	if version.IsIPv4() {
		return IPv4ByteCount
	}
	return IPv6ByteCount
}

func GetSegmentCount(version IPVersion) int {
	if version.IsIPv4() {
		return IPv4SegmentCount
	}
	return IPv6SegmentCount
}

func GetBitCount(version IPVersion) BitCount {
	if version.IsIPv4() {
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
	result := createIPAddress(section.ToSectionBase(), zone)
	if zone != NoZone { // will need to cache its own strings
		result.cache.stringCache = &stringCache{}
	}
	return result
}

// necessary to avoid direct access to IPAddress
type ipAddressInternal struct {
	addressInternal
}

//func (addr *ipAddressInternal) ToAddress() *Address {
//	return (*Address)(addr)
//}

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

func (addr *ipAddressInternal) GetNetworkPrefixLen() PrefixLen {
	section := addr.section
	if section == nil {
		return nil
	}
	return section.ToIP().GetNetworkPrefixLen()
}

func (addr *ipAddressInternal) IncludesZeroHost() bool {
	section := addr.section
	if section == nil {
		return false
	}
	return section.ToIP().IncludesZeroHost()
}

func (addr *ipAddressInternal) includesZeroHostLen(networkPrefixLength BitCount) bool {
	return addr.getSection().IncludesZeroHostLen(networkPrefixLength)
}

func (addr *ipAddressInternal) IncludesMaxHost() bool {
	section := addr.section
	if section == nil {
		return false
	}
	return section.ToIP().IncludesMaxHost()
}

func (addr *ipAddressInternal) includesMaxHostLen(networkPrefixLength BitCount) bool {
	return addr.getSection().IncludesMaxHostLen(networkPrefixLength)
}

// IsSingleNetwork returns whether the network section of the address, the prefix, consists of a single value
func (addr *ipAddressInternal) IsSingleNetwork() bool {
	section := addr.section
	return section == nil || section.ToIP().IsSingleNetwork()
}

// IsMaxHost returns whether this section has a prefix length and if so,
// whether the host section is the max value.
func (addr *ipAddressInternal) IsMaxHost() bool {
	section := addr.section
	return section != nil && section.ToIP().IsMaxHost()
}

// IsMaxHostLen returns whether the host is zero for the given prefix length.
// If this address already has a prefix length, then that prefix length is ignored.
// If the host section is zero length (there are no host bits at all), returns true.
func (addr *ipAddressInternal) isMaxHostLen(prefLen BitCount) bool {
	return addr.getSection().IsMaxHostLen(prefLen)
}

// IsZeroHost returns whether this section has a prefix length and if so,
// whether the host section is zero.
func (addr *ipAddressInternal) IsZeroHost() bool {
	section := addr.section
	return section != nil && section.ToIP().IsZeroHost()
}

// IsZeroHostLen returns whether the host is zero for the given prefix length.
// If this address already has a prefix length, then that prefix length is ignored.
// If the host section is zero length (there are no host bits at all), returns true.
func (addr *ipAddressInternal) isZeroHostLen(prefLen BitCount) bool {
	return addr.getSection().IsZeroHostLen(prefLen)
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
	section, err := addr.getSection().toZeroHostLen(prefixLength)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) toZeroNetwork() *IPAddress {
	return addr.checkIdentity(addr.getSection().toZeroNetwork())
}

func (addr *ipAddressInternal) toMaxHost() (res *IPAddress, err IncompatibleAddressError) {
	section, err := addr.section.toIPAddressSection().toMaxHost()
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) toMaxHostLen(prefixLength BitCount) (res *IPAddress, err IncompatibleAddressError) {
	section, err := addr.getSection().toMaxHostLen(prefixLength)
	if err == nil {
		res = addr.checkIdentity(section)
	}
	return
}

func (addr *ipAddressInternal) checkIdentity(section *IPAddressSection) *IPAddress {
	if section == nil {
		return nil
	}
	sect := section.ToSectionBase()
	if sect == addr.section {
		return addr.toIPAddress()
	}
	return createIPAddress(sect, addr.zone)
}

func (addr *ipAddressInternal) getSection() *IPAddressSection {
	return addr.section.ToIP()
}

func (addr *ipAddressInternal) adjustPrefixLen(prefixLen BitCount) *IPAddress {
	return addr.checkIdentity(addr.getSection().adjustPrefixLen(prefixLen))
}

func (addr *ipAddressInternal) adjustPrefixLenZeroed(prefixLen BitCount) (res *IPAddress, err IncompatibleAddressError) {
	section, err := addr.getSection().adjustPrefixLenZeroed(prefixLen)
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
	return section.ToIP().GetBlockMaskPrefixLen(network)
}

func (addr *ipAddressInternal) GetSegment(index int) *IPAddressSegment {
	return addr.getSegment(index).ToIP()
}

func (addr *ipAddressInternal) spanWithPrefixBlocks() []ExtendedIPSegmentSeries {
	wrapped := addr.toIPAddress().Wrap()
	if addr.IsSequential() {
		if addr.IsSinglePrefixBlock() {
			return []ExtendedIPSegmentSeries{wrapped}
		}
		return getSpanningPrefixBlocks(wrapped, wrapped)
	}
	return spanWithPrefixBlocks(wrapped)
}

func (addr *ipAddressInternal) spanWithSequentialBlocks() []ExtendedIPSegmentSeries {
	wrapped := addr.toIPAddress().Wrap()
	if addr.IsSequential() {
		return []ExtendedIPSegmentSeries{wrapped}
	}
	return spanWithSequentialBlocks(wrapped)
}

func (addr *ipAddressInternal) coverSeriesWithPrefixBlock() ExtendedIPSegmentSeries {
	// call from wrapper
	if addr.IsSinglePrefixBlock() {
		return addr.toIPAddress().Wrap()
	}
	return coverWithPrefixBlock(
		addr.getLower().ToIPAddress().Wrap(),
		addr.getUpper().ToIPAddress().Wrap(),
	)
}

func (addr *ipAddressInternal) coverWithPrefixBlock() *IPAddress {
	// call from ip ipv4 ipv6
	if addr.IsSinglePrefixBlock() {
		return addr.toIPAddress()
	}
	res := coverWithPrefixBlock(
		addr.getLower().ToIPAddress().Wrap(),
		addr.getUpper().ToIPAddress().Wrap(),
	)
	return res.(WrappedIPAddress).IPAddress
}

func (addr *ipAddressInternal) coverWithPrefixBlockTo(other *IPAddress) *IPAddress {
	res := getCoveringPrefixBlock(
		addr.toIPAddress().Wrap(),
		other.Wrap(),
	)
	return res.(WrappedIPAddress).IPAddress
}

func (addr *ipAddressInternal) getNetworkMask(network IPAddressNetwork) *IPAddress {
	var prefLen BitCount
	if addr.isPrefixed() {
		prefLen = *addr.GetNetworkPrefixLen()
	} else {
		prefLen = addr.GetBitCount()
	}
	return network.GetNetworkMask(prefLen)
}

func (addr *ipAddressInternal) getHostMask(network IPAddressNetwork) *IPAddress {
	var prefLen BitCount
	if addr.isPrefixed() {
		prefLen = *addr.GetNetworkPrefixLen()
	}
	return network.GetHostMask(prefLen)
}

func (addr *ipAddressInternal) toCanonicalWildcardString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6().toCanonicalWildcardStringZoned(addr.zone)
		}
		return cacheStr(&cache.canonicalWildcardString,
			func() string {
				return addr.section.ToIPv6().toCanonicalWildcardStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToCanonicalWildcardString()
}

func (addr *ipAddressInternal) toNormalizedWildcardString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6().toNormalizedWildcardStringZoned(addr.zone)
		}
		return cacheStr(&cache.normalizedWildcardString,
			func() string {
				return addr.section.ToIPv6().toNormalizedWildcardStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToNormalizedWildcardString()
}

func (addr *ipAddressInternal) toSegmentedBinaryString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6().toSegmentedBinaryStringZoned(addr.zone)
		}
		return cacheStr(&cache.segmentedBinaryString,
			func() string {
				return addr.section.ToIPv6().toSegmentedBinaryStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToSegmentedBinaryString()
}

func (addr *ipAddressInternal) toSQLWildcardString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6().toSQLWildcardStringZoned(addr.zone)
		}
		return cacheStr(&cache.sqlWildcardString,
			func() string {
				return addr.section.ToIPv6().toSQLWildcardStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToSQLWildcardString()
}

func (addr *ipAddressInternal) toFullString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6().toFullStringZoned(addr.zone)
		}
		return cacheStr(&cache.fullString,
			func() string {
				return addr.section.ToIPv6().toFullStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToFullString()
}

func (addr *ipAddressInternal) toReverseDNSString() (string, IncompatibleAddressError) {
	return addr.getSection().ToReverseDNSString()
}

func (addr *ipAddressInternal) toPrefixLenString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6().toPrefixLenStringZoned(addr.zone)
		}
		return cacheStr(&cache.networkPrefixLengthString,
			func() string {
				return addr.section.ToIPv6().toPrefixLenStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToPrefixLenString()
}

func (addr *ipAddressInternal) toSubnetString() string {
	if addr.hasZone() {
		return addr.toPrefixLenString()
	}
	return addr.getSection().ToSubnetString()
}

func (addr *ipAddressInternal) toCompressedWildcardString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6().toCompressedWildcardStringZoned(addr.zone)
		}
		return cacheStr(&cache.compressedWildcardString,
			func() string {
				return addr.section.ToIPv6().toCompressedWildcardStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToCompressedWildcardString()
}

func (addr *ipAddressInternal) getNetwork() IPAddressNetwork {
	return addr.getSection().getNetwork()
}

//func (addr *ipAddressInternal) GetGenericIPDivision(index int) IPAddressGenericDivision {
//	return addr.GetSegment(index)
//}

//func (addr *ipAddressInternal) CompareSize(other AddressDivisionSeries) int {
//	return addr.toIPAddress().CompareSize(other)
//}

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

func (addr *IPAddress) GetCount() *big.Int {
	if addr == nil {
		return bigZero()
	}
	return addr.getCount()
}

func (addr *IPAddress) IsMultiple() bool {
	return addr != nil && addr.isMultiple()
}

func (addr IPAddress) Format(state fmt.State, verb rune) {
	addr.init().format(state, verb)
}

func (addr *IPAddress) String() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().ipAddressInternal.toString()
}

func (addr *IPAddress) GetSection() *IPAddressSection {
	return addr.init().section.ToIP()
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
	return addr.getSegment(index).ToIP()
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

func (addr *IPAddress) IsZeroHostLen(prefLen BitCount) bool {
	return addr.init().isZeroHostLen(prefLen)
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

func (addr *IPAddress) IsMaxHostLen(prefLen BitCount) bool {
	return addr.init().isMaxHostLen(prefLen)
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

func (addr *IPAddress) IsPrefixed() bool {
	return addr != nil && addr.isPrefixed()
}

func (addr *IPAddress) WithoutPrefixLen() *IPAddress {
	if !addr.IsPrefixed() {
		return addr
	}
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

func (addr *IPAddress) GetValue() *big.Int {
	return addr.init().section.GetValue()
}

func (addr *IPAddress) GetUpperValue() *big.Int {
	return addr.init().section.GetUpperValue()
}

func (addr *IPAddress) GetNetIPAddr() net.IPAddr {
	return net.IPAddr{
		IP:   addr.GetNetIP(),
		Zone: string(addr.zone),
	}
}

func (addr *IPAddress) GetNetIP() net.IP {
	return addr.GetBytes()
}

func (addr *IPAddress) CopyNetIP(ip net.IP) net.IP {
	if ipv4Addr := addr.ToIPv4Address(); ipv4Addr != nil {
		return ipv4Addr.CopyNetIP(ip) // this shrinks the arg to 4 bytes if it was 16, we need only 4
	}
	return addr.CopyBytes(ip)
}

func (addr *IPAddress) GetUpperNetIP() net.IP {
	return addr.GetUpperBytes()
}

func (addr *IPAddress) CopyUpperNetIP(ip net.IP) net.IP {
	if ipv4Addr := addr.ToIPv4Address(); ipv4Addr != nil {
		return ipv4Addr.CopyUpperNetIP(ip) // this shrinks the arg to 4 bytes if it was 16, we need only 4
	}
	return addr.CopyUpperBytes(ip)
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

func (addr *IPAddress) PrefixEqual(other AddressType) bool {
	return addr.init().prefixEquals(other)
}

func (addr *IPAddress) PrefixContains(other AddressType) bool {
	return addr.init().prefixContains(other)
}

func (addr *IPAddress) Contains(other AddressType) bool {
	if addr == nil {
		return other == nil || other.ToAddress() == nil
	}
	return addr.init().contains(other)
}

func (addr *IPAddress) Compare(item AddressItem) int {
	return CountComparator.Compare(addr, item)
}

func (addr *IPAddress) Equal(other AddressType) bool {
	if addr == nil {
		return other == nil || other.ToAddress() == nil
	}
	return addr.init().equals(other)
}

// CompareSize returns whether this subnet has more elements than the other, returning -1 if this subnet has less, 1 if more, and 0 if both have the same count of individual addresses
func (addr *IPAddress) CompareSize(other AddressType) int { // this is here to take advantage of the CompareSize in IPAddressSection
	if addr == nil {
		if other != nil && other.ToAddress() != nil {
			// we have size 0, other has size >= 1
			return -1
		}
		return 0
	}
	return addr.init().compareSize(other)
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
	return addr != nil && addr.isIPv4()
}

func (addr *IPAddress) IsIPv6() bool {
	return addr != nil && addr.isIPv6()
}

func (addr *IPAddress) GetIPVersion() IPVersion {
	return addr.getIPVersion()
}

func (addr *IPAddress) ToAddress() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *IPAddress) ToIPAddress() *IPAddress {
	return addr
}

// maybe rename ToIPv6(), then there is ToMac(), toIP(), and ToAddress - for sections youd would have the same and also ToSection() and ToGrouping()
// BUT remember I am also consider renaming GetIP to ToIP()
// This also makes sense because "ToIPv6Address" suggests a new address is being created.  "AsIPv6" might be a better choice, but, inconsistent with Java.
// Java used "to" because of the conversion that might happen.  I think "to" is probably fine.  Using "ToIPv6" is more consistent with Java.
// ALso consider code like this:
// t.createAddress(originalStr).GetAddress().ToAddress()
// the combination of using GetAddress/ToAddress in IPAddressString and the name ToAddress to downgrade to *Address is ugly.
// Maybe drop the "To" in this case?  Just .Address()?  or AsAddress?  nah to AsAddress, it's already an address.
// No, I need a better ToXXX really.
// ToBase()?  ToGeneric()?
// For sections and segments, use the same ToIPv6, ToMAC, ToIP(),
// There there are ToAddress(), ToSection(), ToDivGrouping(), ToSegment(), ToDiv()
// Is there some other common word I can use for ToAddress(), ToSection(), ToSegment()?  Because the ones above like ToIP() are all common.
// A word to say "no protocol"
// ToGen() for general or generic?  ToShared?  UnSpecified()? ToIndeterminate()?  ToIndistinct?  ToUnstipulated?
// I think there is a word for something that is not yet distinguished?  ToIndistinghuished?  nah, some other word
// A word for someone who has not yet become more ... what, unique?  Undiversified?  ToInterchangeable? ToUndifferentiated?  ToAdaptive?
// There is a word, something not yet specified... ToUndiversified?  ToCommon?  ToHomogenous?  ToUniform?  ToIndistinct?  ToNeutral?
// ToUnderived?  ToStandard?  toindisparate?  ToIndivergent?  ToUndifferentiated?  toindistinct?  ToUniform?  ToRegular?
// ToUndistinguised?  TOUnspecific?  ToCustomary?
// ToBasic is good  ToBase?  I kinda like ToBase
// ToUniform is good
// ToGeneric?  ToGenericAddr?
//
// TODO I think I have settled on ToAddressBase, ToIPv6, ToIPv4, ToMAC, ToIP()
// there are also the identity funcs like IsIPv4 to change
// ToIPAddressSeqRange become ToIP() and you need to change the ipv4/6 ToIP4SeqRange etc as well and the IsXXX too

func (addr *IPAddress) ToIPv6Address() *IPv6Address {
	if addr.IsIPv6() {
		return (*IPv6Address)(addr)
	}
	return nil
}

func (addr *IPAddress) ToIPv4Address() *IPv4Address {
	if addr.IsIPv4() {
		return (*IPv4Address)(addr)
	}
	return nil
}

func (addr *IPAddress) Wrap() WrappedIPAddress {
	return WrapIPAddress(addr)
}

func (addr *IPAddress) GetMaxSegmentValue() SegInt {
	return addr.init().getMaxSegmentValue()
}

func (addr *IPAddress) Iterator() IPAddressIterator {
	if addr == nil {
		return ipAddrIterator{nilAddrIterator()}
	}
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
	return newSeqRangeUnchecked(addr.GetLower(), addr.GetUpper(), addr.isMultiple())
}

func (addr *IPAddress) IncrementBoundary(increment int64) *IPAddress {
	return addr.init().incrementBoundary(increment).ToIPAddress()
}

func (addr *IPAddress) Increment(increment int64) *IPAddress {
	return addr.init().increment(increment).ToIPAddress()
}

// SpanWithRange produces an IPAddressRange instance that spans this subnet to the given subnet.
// If the other address is a different version than this, then the other is ignored, and the result is equivalent to calling ToSequentialRange()
func (addr *IPAddress) SpanWithRange(other *IPAddress) *IPAddressSeqRange {
	if thisAddr := addr.ToIPv4Address(); thisAddr != nil {
		if oth := other.ToIPv4Address(); oth != nil {
			return thisAddr.SpanWithRange(oth).ToIPAddressSeqRange()
		}
	} else if thisAddr := addr.ToIPv6Address(); thisAddr != nil {
		if oth := other.ToIPv6Address(); oth != nil {
			return thisAddr.SpanWithRange(oth).ToIPAddressSeqRange()
		}
	}
	return addr.ToSequentialRange()
}

// Mask applies the given mask to all addresses represented by this IPAddress.
// The mask is applied to all individual addresses.
//
// If the mask is a different version than this, then an error is returned
//
// If this represents multiple addresses, and applying the mask to all addresses creates a set of addresses
// that cannot be represented as a contiguous range within each segment, then an error is returned
func (addr *IPAddress) Mask(other *IPAddress) (masked *IPAddress, err IncompatibleAddressError) {
	return addr.maskPrefixed(other, true)
}

//func (addr *IPAddress) MaskPrefixed(other *IPAddress) (masked *IPAddress, err IncompatibleAddressError) {
//	return addr.maskPrefixed(other, true)
//}

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

// Subtract substracts the given subnet from this subnet, returning an array of subnets for the result (the subnets will not be contiguous so an array is required).
// Computes the subnet difference, the set of addresses in this address subnet but not in the provided subnet.  This is also known as the relative complement of the given argument in this subnet.
// This is set subtraction, not subtraction of segment values.  We have a subnet of addresses and we are removing those addresses found in the argument subnet.
// If there are no remaining addresses, nil is returned.
func (addr *IPAddress) Subtract(other *IPAddress) []*IPAddress {
	addr = addr.init()
	sects, _ := addr.GetSection().subtract(other.GetSection())
	sectLen := len(sects)
	if sectLen == 0 {
		return nil
	} else if sectLen == 1 {
		sec := sects[0]
		if sec.ToSectionBase() == addr.section {
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

// ToUNCHostName //TODO LATER ToUNCHostName since we are not yet parsing this

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
// Arguments that are not the same IP version are ignored.
func (addr *IPAddress) MergeToSequentialBlocks(addrs ...*IPAddress) []*IPAddress {
	series := filterCloneIPAddrs(addr, addrs)
	blocks := getMergedSequentialBlocks(series)
	return cloneToIPAddrs(blocks)
}

//
// MergeToPrefixBlocks merges this with the list of sections to produce the smallest array of prefix blocks.
//
// The resulting array is sorted from lowest address value to highest, regardless of the size of each prefix block.
// Arguments that are not the same IP version are ignored.
func (addr *IPAddress) MergeToPrefixBlocks(addrs ...*IPAddress) []*IPAddress {
	series := filterCloneIPAddrs(addr, addrs)
	blocks := getMergedPrefixBlocks(series)
	return cloneToIPAddrs(blocks)
}

func (addr *IPAddress) SpanWithPrefixBlocks() []*IPAddress {
	addr = addr.init()
	if addr.IsSequential() {
		if addr.IsSinglePrefixBlock() {
			return []*IPAddress{addr}
		}
		wrapped := addr.Wrap()
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPAddrs(spanning)
	}
	wrapped := addr.Wrap()
	return cloneToIPAddrs(spanWithPrefixBlocks(wrapped))
}

func (addr *IPAddress) SpanWithPrefixBlocksTo(other *IPAddress) []*IPAddress {
	//if !addr.GetIPVersion().Equal(other.GetIPVersion()){
	if !versionsMatch(addr, other) {
		return addr.SpanWithPrefixBlocks()
	}
	return cloneToIPAddrs(
		getSpanningPrefixBlocks(
			addr.init().Wrap(),
			other.init().Wrap(),
		),
	)
}

// CoverWithPrefixBlockTo provides a single prefix block that covers both the receiver and the argument.
// If the argument is not the same IP version as the receiver, the argument is ignored, and the result covers just the receiver.
func (addr *IPAddress) CoverWithPrefixBlockTo(other *IPAddress) *IPAddress {
	if !versionsMatch(addr, other) {
		return addr.CoverWithPrefixBlock()
	}
	return addr.init().coverWithPrefixBlockTo(other)
}

func (addr *IPAddress) CoverWithPrefixBlock() *IPAddress {
	return addr.init().coverWithPrefixBlock()
}

func (addr *IPAddress) SpanWithSequentialBlocks() []*IPAddress {
	addr = addr.init()
	if addr.IsSequential() {
		return []*IPAddress{addr}
	}
	return cloneToIPAddrs(spanWithSequentialBlocks(addr.Wrap()))
}

func (addr *IPAddress) SpanWithSequentialBlocksTo(other *IPAddress) []*IPAddress {
	if !versionsMatch(addr, other) {
		return addr.SpanWithSequentialBlocks()
	}
	return cloneToIPAddrs(
		getSpanningSequentialBlocks(
			addr.init().Wrap(),
			other.init().Wrap(),
		),
	)
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

func (addr *IPAddress) GetSegmentStrings() []string {
	if addr == nil {
		return nil
	}
	return addr.init().getSegmentStrings()
}

func (addr *IPAddress) ToCanonicalString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toCanonicalString()
}

func (addr *IPAddress) ToCanonicalWildcardString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toCanonicalWildcardString()
}

func (addr *IPAddress) ToNormalizedString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toNormalizedString()
}

func (addr *IPAddress) ToCompressedString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toCompressedString()
}

func (addr *IPAddress) ToNormalizedWildcardString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toNormalizedWildcardString()
}

func (addr *IPAddress) ToSegmentedBinaryString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toSegmentedBinaryString()
}

func (addr *IPAddress) ToSQLWildcardString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toSQLWildcardString()
}

func (addr *IPAddress) ToFullString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toFullString()
}

func (addr *IPAddress) ToReverseDNSString() (string, IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toReverseDNSString()
}

func (addr *IPAddress) ToPrefixLenString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toPrefixLenString()
}

func (addr *IPAddress) ToSubnetString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toSubnetString()
}

func (addr *IPAddress) ToCompressedWildcardString() string {
	if addr == nil {
		return nilString()
	}
	return addr.init().toCompressedWildcardString()
}

func (addr *IPAddress) ToHexString(with0xPrefix bool) (string, IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toHexString(with0xPrefix)
}

func (addr *IPAddress) ToOctalString(with0Prefix bool) (string, IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toOctalString(with0Prefix)
}

func (addr *IPAddress) ToBinaryString(with0bPrefix bool) (string, IncompatibleAddressError) {
	if addr == nil {
		return nilString(), nil
	}
	return addr.init().toBinaryString(with0bPrefix)
}

func (addr *IPAddress) ToCustomString(stringOptions IPStringOptions) string {
	if addr == nil {
		return nilString()
	}
	return addr.GetSection().toCustomZonedString(stringOptions, addr.zone)
}

// ToAddressString retrieves or generates an IPAddressString object for this IPAddress object.
// This may be the IPAddressString this instance was generated from, if it was generated from an IPAddressString.
//
// In general, users are intended to create IPAddress objects from IPAddressString objects,
// while the reverse direction is generally not all that useful, except under specific circumstances.
//
// Not all IPAddressString objects can be converted to IPAddress objects.
//
// So it may be useful to store a set of address strings as a collection of IPAddressString objects, rather than IPAddress objects,
// which is one reason you might wish to obtain an IPAddressString from an IPAddress.
func (addr *IPAddress) ToAddressString() *IPAddressString {
	addr = addr.init()
	cache := addr.cache
	if cache == nil {
		return newIPAddressStringFromAddr(addr.toCanonicalString(), addr)
	}
	res := cache.identifierStr
	if res == nil {
		str := newIPAddressStringFromAddr(addr.toCanonicalString(), addr)
		res = &IdentifierStr{str}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&addr.cache.identifierStr))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
		return str
	}
	hostIdStr := res.idStr
	if str, ok := hostIdStr.(*IPAddressString); ok {
		return str
	}
	return newIPAddressStringFromAddr(addr.toCanonicalString(), addr)
}

func (addr *IPAddress) ToHostName() *HostName {
	addr = addr.init()
	cache := addr.cache
	if cache != nil {
		res := cache.identifierStr
		if res != nil {
			hostIdStr := res.idStr
			if h, ok := hostIdStr.(*HostName); ok {
				return h
			}
		}
	}
	var h *HostName
	if !addr.isMultiple() {
		h, _ = addr.ToCanonicalHostName()
	}
	if h == nil {
		h = NewHostNameFromAddr(addr)
	}
	return h
}

func (addr *IPAddress) ToCanonicalHostName() (*HostName, error) {
	addr = addr.init()
	cache := addr.cache
	if cache == nil {
		return addr.lookupAddr()
	}
	res := cache.canonicalHost
	if res == nil {
		if addr.isMultiple() {
			return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.unavailable.numeric"}}
		}
		var err error
		res, err = addr.lookupAddr()
		if res == nil {
			return res, err
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache.canonicalHost))
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	return res, nil
}

func (addr *IPAddress) lookupAddr() (*HostName, error) {
	names, err := net.LookupAddr(addr.ToNormalizedWildcardString())
	if err != nil {
		return nil, err
	} else if len(names) == 0 {
		return nil, nil
	} else if names[0] == "" {
		return nil, nil
	}
	return NewHostName(names[0]), nil
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

func (addr *IPAddress) GetNetwork() IPAddressNetwork {
	return addr.getNetwork()
}

func ipAddressEquals(one, two *IPAddress) bool {
	if one == nil {
		return two == nil
	}
	return two != nil && one.Equal(two)
}

type IPAddressValueProvider interface {
	AddressValueProvider

	GetPrefixLen() PrefixLen // return nil if none

	GetIPVersion() IPVersion // should not return IndeterminateVersion

	GetZone() string // return "" or NoZone if none
}

func addrFromIP(ip net.IP) (addr *IPAddress, err AddressValueError) {
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	return addrFromBytes(ip)
}

func addrFromBytes(ip []byte) (addr *IPAddress, err AddressValueError) {
	addrLen := len(ip)
	if addrLen <= IPv4ByteCount {
		var addr4 *IPv4Address
		addr4, err = NewIPv4AddressFromBytes(ip)
		addr = addr4.ToIPAddress()
	} else if addrLen <= IPv6ByteCount {
		var addr6 *IPv6Address
		addr6, err = NewIPv6AddressFromBytes(ip)
		addr = addr6.ToIPAddress()
	}
	return
}

func addrFromPrefixedIP(ip net.IP, prefixLen PrefixLen) (addr *IPAddress, err AddressValueError) {
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	addrLen := len(ip)
	if addrLen <= IPv4ByteCount {
		var addr4 *IPv4Address
		addr4, err = NewIPv4AddressFromPrefixedBytes(ip, prefixLen)
		addr = addr4.ToIPAddress()
	} else if addrLen <= IPv6ByteCount {
		var addr6 *IPv6Address
		addr6, err = NewIPv6AddressFromPrefixedBytes(ip, prefixLen)
		addr = addr6.ToIPAddress()
	}
	return
}

type IPAddressCreator struct {
	IPVersion
}

func (creator IPAddressCreator) CreateSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *IPAddressSegment {
	if creator.IsIPv4() {
		return NewIPv4RangePrefixedSegment(IPv4SegInt(lower), IPv4SegInt(upper), segmentPrefixLength).ToIP()
	} else if creator.IsIPv6() {
		return NewIPv6RangePrefixedSegment(IPv6SegInt(lower), IPv6SegInt(upper), segmentPrefixLength).ToIP()
	}
	return nil
}

func (creator IPAddressCreator) CreateRangeSegment(lower, upper SegInt) *IPAddressSegment {
	if creator.IsIPv4() {
		return NewIPv4RangeSegment(IPv4SegInt(lower), IPv4SegInt(upper)).ToIP()
	} else if creator.IsIPv6() {
		return NewIPv6RangeSegment(IPv6SegInt(lower), IPv6SegInt(upper)).ToIP()
	}
	return nil
}

func (creator IPAddressCreator) CreatePrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *IPAddressSegment {
	if creator.IsIPv4() {
		return NewIPv4PrefixedSegment(IPv4SegInt(value), segmentPrefixLength).ToIP()
	} else if creator.IsIPv6() {
		return NewIPv6PrefixedSegment(IPv6SegInt(value), segmentPrefixLength).ToIP()
	}
	return nil
}

func (creator IPAddressCreator) NewIPSectionFromBytes(bytes []byte) *IPAddressSection {
	if creator.IsIPv4() {
		addr, _ := NewIPv4SectionFromBytes(bytes)
		return addr.ToIP()
	} else if creator.IsIPv6() {
		addr, _ := NewIPv6SectionFromBytes(bytes)
		return addr.ToIP()
	}
	return nil
}

func (creator IPAddressCreator) NewIPSectionFromSegmentBytes(bytes []byte, segmentCount int) *IPAddressSection {
	if creator.IsIPv4() {
		addr, _ := NewIPv4SectionFromSegmentedBytes(bytes, segmentCount)
		return addr.ToIP()
	} else if creator.IsIPv6() {
		addr, _ := NewIPv4SectionFromSegmentedBytes(bytes, segmentCount)
		return addr.ToIP()
	}
	return nil
}

func (creator IPAddressCreator) NewIPSectionFromPrefixedBytes(bytes []byte, segmentCount int, prefLen PrefixLen) *IPAddressSection {
	if creator.IsIPv4() {
		addr, _ := NewIPv4SectionFromPrefixedBytes(bytes, segmentCount, prefLen)
		return addr.ToIP()
	} else if creator.IsIPv6() {
		addr, _ := NewIPv4SectionFromPrefixedBytes(bytes, segmentCount, prefLen)
		return addr.ToIP()
	}
	return nil
}

// the reason this was not here before was that with the creator, the version field determines the version
// so, the creator is not needed for these two, you can just call the public functions
//func (creator IPAddressCreator) NewIPAddressFromIP(bytes net.IP) *IPAddress {
//	if creator.IsIPv4() {
//		addr, _ := NewIPv4AddressFromBytes(bytes)
//		return addr.ToIPAddress()
//	} else if creator.IsIPv6() {
//		addr, _ := NewIPv6AddressFromBytes(bytes)
//		return addr.ToIPAddress()
//	}
//	return nil
//}
//
//func (creator IPAddressCreator) NewIPAddressFromPrefixedIP(bytes net.IP, prefLen PrefixLen) *IPAddress {
//	if creator.IsIPv4() {
//		addr, _ := NewIPv4AddressFromPrefixedBytes(bytes, prefLen)
//		return addr.ToIPAddress()
//	} else if creator.IsIPv6() {
//		addr, _ := NewIPv6AddressFromPrefixedBytes(bytes, prefLen)
//		return addr.ToIPAddress()
//	}
//	return nil
//}

func (creator IPAddressCreator) NewIPAddressFromVals(lowerValueProvider SegmentValueProvider) *IPAddress {
	return NewIPAddressFromVals(creator.IPVersion, lowerValueProvider)
}

func (creator IPAddressCreator) NewIPAddressFromPrefixedVals(lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen) *IPAddress {
	return NewIPAddressFromPrefixedVals(creator.IPVersion, lowerValueProvider, upperValueProvider, prefixLength)
}

func (creator IPAddressCreator) NewIPAddressFromPrefixedZonedVals(lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen, zone string) *IPAddress {
	return NewIPAddressFromPrefixedZonedVals(creator.IPVersion, lowerValueProvider, upperValueProvider, prefixLength, zone)
}

func NewIPAddressFromNetIPMask(ip net.IPMask) *IPAddress {
	addr, _ := addrFromBytes(ip)
	return addr
}

func NewIPAddressFromNetIP(ip net.IP) *IPAddress {
	addr, _ := addrFromIP(ip)
	return addr
}

func NewIPAddressFromPrefixedNetIP(ip net.IP, prefixLength PrefixLen) *IPAddress {
	addr, _ := addrFromPrefixedIP(ip, prefixLength)
	return addr
}

func NewIPAddressFromNetIPAddr(addr *net.IPAddr) *IPAddress {
	ip := addr.IP
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	if len(ip) <= IPv4ByteCount {
		res, _ := NewIPv4AddressFromBytes(ip)
		return res.ToIPAddress()
	} else if len(ip) <= IPv6ByteCount {
		res, _ := NewIPv6AddressFromZonedBytes(ip, addr.Zone)
		return res.ToIPAddress()
	}
	return nil
}

func NewIPAddressFromPrefixedNetIPAddr(addr *net.IPAddr, prefixLength PrefixLen) *IPAddress {
	ip := addr.IP
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	if len(ip) <= IPv4ByteCount {
		res, _ := NewIPv4AddressFromPrefixedBytes(ip, prefixLength)
		return res.ToIPAddress()
	} else if len(ip) <= IPv6ByteCount {
		res, _ := NewIPv6AddressFromPrefixedZonedBytes(ip, prefixLength, addr.Zone)
		return res.ToIPAddress()
	}
	return nil
}

func NewIPAddressFromNetIPNet(ipnet net.IPNet) (*IPAddress, IncompatibleAddressError) {
	ip := ipnet.IP
	maskIp := ipnet.Mask
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
		if len(maskIp) == net.IPv6len {
			maskIp = maskIp[IPv6MixedOriginalByteCount:]
		}
	}
	addr, _ := addrFromBytes(ip)
	if addr == nil {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.exceeds.size"}}
	}
	mask := NewIPAddressFromNetIPMask(maskIp)
	if mask == nil {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.exceeds.size"}}
	} else if !addr.GetIPVersion().Equal(mask.GetIPVersion()) {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipMismatch"}}
	}
	prefLen := mask.GetBlockMaskPrefixLen(true)
	if prefLen == nil {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.notNetworkMask"}}
	}
	return addr.ToPrefixBlockLen(*prefLen), nil
}

func NewIPAddressFromVals(version IPVersion, lowerValueProvider SegmentValueProvider) *IPAddress {
	if version.IsIPv4() {
		return NewIPv4AddressFromVals(WrappedSegmentValueProviderForIPv4(lowerValueProvider)).ToIPAddress()
	} else if version.IsIPv6() {
		return NewIPv6AddressFromVals(WrappedSegmentValueProviderForIPv6(lowerValueProvider)).ToIPAddress()
	}
	return nil
}

func NewIPAddressFromPrefixedVals(version IPVersion, lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen) *IPAddress {
	return NewIPAddressFromPrefixedZonedVals(version, lowerValueProvider, upperValueProvider, prefixLength, "")
}

func NewIPAddressFromPrefixedZonedVals(version IPVersion, lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen, zone string) *IPAddress {
	if version.IsIPv4() {
		return NewIPv4AddressFromPrefixedRange(
			WrappedSegmentValueProviderForIPv4(lowerValueProvider),
			WrappedSegmentValueProviderForIPv4(upperValueProvider),
			prefixLength).ToIPAddress()
	} else if version.IsIPv6() {
		return NewIPv6AddressFromPrefixedZonedRange(
			WrappedSegmentValueProviderForIPv6(lowerValueProvider),
			WrappedSegmentValueProviderForIPv6(upperValueProvider),
			prefixLength,
			zone).ToIPAddress()
	}
	return nil
}

//func newIPAddressFromSegments(segs []*IPAddressSegment, sectionCreator func(isIPv4 bool, segs []*AddressDivision) *IPAddressSection) (res *IPAddress) {
//	xxx
//	if len(segs) > 0 {
//		if segs[0].IsIPv4() {
//			for _, seg := range segs[1:] {
//				if !seg.IsIPv4() {
//					return nil
//				}
//			}
//			xxxxx sect := sectionCreator(true, cloneIPSegsToDivs(segs))
//			addr, err := NewIPv4Address(sect.ToIPv4())
//			if err == nil {
//				res = addr.ToIPAddress()
//			}
//		} else if segs[0].IsIPv6() {
//			for _, seg := range segs[1:] {
//				if !seg.IsIPv6() {
//					return nil
//				}
//			}
//			xxxxx sect := sectionCreator(false, cloneIPSegsToDivs(segs))
//			addr, err := NewIPv6Address(sect.ToIPv6())
//			if err == nil {
//				res = addr.ToIPAddress()
//			}
//		}
//	}
//	return res
//}
//
//// NewIPAddressFromSegments creates an address from the given segments.
//// If the segments are not consistently IPv4 or IPv6, or if there is not the correct number for the version,
//// then nil is returned.  An error is not returned because it is not clear with version was intended and so any error may be misleading as to what was incorrect.
//func NewIPAddressFromSegments(segments []*IPAddressSegment) *IPAddress {
//	xxx
//	return newIPAddressFromSegments(segments, func(isIPv4 bool, segs []*AddressDivision) *IPAddressSection {
//		if isIPv4 {
//			sect, _ := newIPv4Section(segs, true)
//			return sect.ToIP()
//		} else {
//			sect, _ := newIPv6Section(segs, true)
//			return sect.ToIP()
//		}
//	})
//}
//
//// newIPAddressFromSegments creates an address from the given segments and prefix length.
//// If the segments are not consistently IPv4 or IPv6, or if there is not the correct number for the version,
//// then nil is returned.  An error is not returned because it is not clear with version was intended and so any error may be misleading as to what was incorrect.
//func NewIPAddressFromPrefixedSegments(segments []*IPAddressSegment, prefixLength PrefixLen) *IPAddress {
//	xxx
//	return newIPAddressFromSegments(segments, func(isIPv4 bool, segs []*AddressDivision) *IPAddressSection {
//		if isIPv4 {
//			sect, _ := newIPv4PrefixedSection(segs, prefixLength)
//			return sect.ToIP()
//		} else {
//			sect, _ := newIPv6PrefixedSection(segs, prefixLength)
//			return sect.ToIP()
//		}
//	})
//}
//
//func newIPAddressFromSegments(segs []*IPAddressSegment, sectionCreator func(isIPv4 bool, segs []*IPAddressSegment) *IPAddressSection) (res *IPAddress) {
//	if len(segs) > 0 {
//		if segs[0].IsIPv4() {
//			for _, seg := range segs[1:] {
//				if !seg.IsIPv4() {
//					return nil
//				}
//			}
//			sect := sectionCreator(true, segs)
//			addr, err := NewIPv4Address(sect.ToIPv4())
//			if err == nil {
//				res = addr.ToIPAddress()
//			}
//		} else if segs[0].IsIPv6() {
//			for _, seg := range segs[1:] {
//				if !seg.IsIPv6() {
//					return nil
//				}
//			}
//			sect := sectionCreator(false, segs)
//			addr, err := NewIPv6Address(sect.ToIPv6())
//			if err == nil {
//				res = addr.ToIPAddress()
//			}
//		}
//	}
//	return res
//}

// NewIPAddressFromSegments creates an address from the given segments.
// If the segments are not consistently IPv4 or IPv6, or if there is not the correct number for the version,
// then nil is returned.  An error is not returned because it is not clear with version was intended and so any error may be misleading as to what was incorrect.
func NewIPAddressFromSegments(segments []*IPAddressSegment) (res *IPAddress, err AddressValueError) {
	return NewIPAddressFromPrefixedSegments(segments, nil)
}

// newIPAddressFromSegments creates an address from the given segments and prefix length.
// If the segments are not consistently IPv4 or IPv6, or if there is not the correct number for the version,
// then nil is returned.  An error is not returned because it is not clear with version was intended and so any error may be misleading as to what was incorrect.
func NewIPAddressFromPrefixedSegments(segs []*IPAddressSegment, prefixLength PrefixLen) (res *IPAddress, err AddressValueError) {
	if len(segs) > 0 {
		if segs[0].IsIPv4() {
			for _, seg := range segs[1:] {
				if !seg.IsIPv4() {
					return
				}
			}
			sect := createIPSectionFromSegs(true, segs, prefixLength)
			//sect := sectionCreator(true, segs)
			addr, addrErr := NewIPv4Address(sect.ToIPv4())
			//if err == nil {
			res, err = addr.ToIPAddress(), addrErr
			//}
		} else if segs[0].IsIPv6() {
			for _, seg := range segs[1:] {
				if !seg.IsIPv6() {
					return
				}
			}
			sect := createIPSectionFromSegs(false, segs, prefixLength)
			//sect := sectionCreator(false, segs)
			addr, addrErr := NewIPv6Address(sect.ToIPv6())
			//if err == nil {
			//res = addr.ToIPAddress()
			//}
			res, err = addr.ToIPAddress(), addrErr
		}
	}
	return

	//return newIPAddressFromSegments(segments, func(isIPv4 bool, segs []*IPAddressSegment) *IPAddressSection {
	//	return createIPSectionFromSegs(isIPv4, segments, prefixLength)
	//
	//})
}

func NewIPAddressFromValueProvider(valueProvider IPAddressValueProvider) *IPAddress {
	if valueProvider.GetIPVersion().IsIPv4() {
		return NewIPv4AddressFromPrefixedRange(
			WrappedSegmentValueProviderForIPv4(valueProvider.GetValues()),
			WrappedSegmentValueProviderForIPv4(valueProvider.GetUpperValues()),
			valueProvider.GetPrefixLen()).ToIPAddress()
	} else if valueProvider.GetIPVersion().IsIPv6() {
		return NewIPv6AddressFromPrefixedZonedRange(
			WrappedSegmentValueProviderForIPv6(valueProvider.GetValues()),
			WrappedSegmentValueProviderForIPv6(valueProvider.GetUpperValues()),
			valueProvider.GetPrefixLen(),
			valueProvider.GetZone()).ToIPAddress()
	}
	return nil
}

// AddrsMatch checks if the two slices share the same list of addresses in any order, using address equality.
// The function can handle duplicates and nil addresses, which are both ignored.
func AddrsMatchUnordered(addrs1, addrs2 []*IPAddress) (result bool) {
	len1 := len(addrs1)
	len2 := len(addrs2)
	sameLen := len1 == len2
	if len1 == 0 || len2 == 0 {
		result = sameLen
	} else if len1 == 1 && sameLen {
		result = addrs1[0].Equal(addrs2[0])
	} else if len1 == 2 && sameLen {
		if addrs1[0].Equal(addrs2[0]) {
			result = addrs1[1].Equal(addrs2[1])
		} else if result = addrs1[0].Equal(addrs2[1]); result {
			result = addrs1[1].Equal(addrs2[0])
		}
	} else {
		result = reflect.DeepEqual(asMap(addrs1), asMap(addrs2))
	}
	return
}

// AddrsMatch checks if the two slices share the same ordered list of addresses using address equality.
func AddrsMatchOrdered(addrs1, addrs2 []*IPAddress) (result bool) {
	len1 := len(addrs1)
	len2 := len(addrs2)
	if len1 != len2 {
		return
	}
	for i, addr := range addrs1 {
		if !addr.Equal(addrs2[i]) {
			return
		}
	}
	return true
}

func asMap(addrs []*IPAddress) (result map[string]struct{}) {
	if addrLen := len(addrs); addrLen > 0 {
		result = make(map[string]struct{})
		for _, addr := range addrs {

			result[addr.ToNormalizedWildcardString()] = struct{}{}
		}
	}
	return
}
