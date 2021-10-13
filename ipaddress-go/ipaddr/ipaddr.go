package ipaddr

import (
	"math/big"
	"net"
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

func (version IPVersion) Equals(other IPVersion) bool {
	return strings.EqualFold(string(version), string(other)) || (version.IsIndeterminate() && other.IsIndeterminate())
}

func (version IPVersion) String() string {
	return string(version)
}

func (version IPVersion) getNetwork() (network IPAddressNetwork) {
	if version.IsIPv6() {
		network = DefaultIPv6Network
	} else if version.IsIPv4() {
		network = DefaultIPv4Network
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
	return section.ToIPAddressSection().GetNetworkPrefixLen()
}

func (addr *ipAddressInternal) IncludesZeroHost() bool {
	section := addr.section
	if section == nil {
		return false
	}
	return section.ToIPAddressSection().IncludesZeroHost()
}

func (addr *ipAddressInternal) includesZeroHostLen(networkPrefixLength BitCount) bool {
	return addr.getSection().IncludesZeroHostLen(networkPrefixLength)
}

func (addr *ipAddressInternal) IncludesMaxHost() bool {
	section := addr.section
	if section == nil {
		return false
	}
	return section.ToIPAddressSection().IncludesMaxHost()
}

func (addr *ipAddressInternal) includesMaxHostLen(networkPrefixLength BitCount) bool {
	return addr.getSection().IncludesMaxHostLen(networkPrefixLength)
}

// IsSingleNetwork returns whether the network section of the address, the prefix, consists of a single value
func (addr *ipAddressInternal) IsSingleNetwork() bool {
	section := addr.section
	return section == nil || section.ToIPAddressSection().IsSingleNetwork()
}

// IsMaxHost returns whether this section has a prefix length and if so,
// whether the host section is the max value.
func (addr *ipAddressInternal) IsMaxHost() bool {
	section := addr.section
	return section != nil && section.ToIPAddressSection().IsMaxHost()
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
	return section != nil && section.ToIPAddressSection().IsZeroHost()
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
	sect := section.ToAddressSection()
	if sect == addr.section {
		return addr.toIPAddress()
	}
	return createIPAddress(sect, addr.zone)
}

func (addr *ipAddressInternal) getSection() *IPAddressSection {
	return addr.section.ToIPAddressSection()
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
	return section.ToIPAddressSection().GetBlockMaskPrefixLen(network)
}

func (addr *ipAddressInternal) GetSegment(index int) *IPAddressSegment {
	return addr.getSegment(index).ToIPAddressSegment()
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
	if addr.IsPrefixed() {
		prefLen = *addr.GetNetworkPrefixLen()
	} else {
		prefLen = addr.GetBitCount()
	}
	return network.GetNetworkMask(prefLen)
}

func (addr *ipAddressInternal) getHostMask(network IPAddressNetwork) *IPAddress {
	var prefLen BitCount
	if addr.IsPrefixed() {
		prefLen = *addr.GetNetworkPrefixLen()
	}
	return network.GetHostMask(prefLen)
}

func (addr *ipAddressInternal) toOctalString(with0Prefix bool) (string, IncompatibleAddressError) {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.getSection().toOctalStringZoned(with0Prefix, addr.zone)
		}
		var cacheField **string
		if with0Prefix {
			cacheField = &cache.octalStringPrefixed
		} else {
			cacheField = &cache.octalString
		}
		return cacheStrErr(cacheField,
			func() (string, IncompatibleAddressError) {
				return addr.getSection().toOctalStringZoned(with0Prefix, addr.zone)
			})
	}
	return addr.getSection().ToOctalString(with0Prefix)
}

func (addr *ipAddressInternal) toBinaryString(with0bPrefix bool) (string, IncompatibleAddressError) {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.getSection().toBinaryStringZoned(with0bPrefix, addr.zone)
		}
		var cacheField **string
		if with0bPrefix {
			cacheField = &cache.binaryStringPrefixed
		} else {
			cacheField = &cache.binaryString
		}
		return cacheStrErr(cacheField,
			func() (string, IncompatibleAddressError) {
				return addr.getSection().toBinaryStringZoned(with0bPrefix, addr.zone)
			})
	}
	return addr.getSection().ToBinaryString(with0bPrefix)
}

func (addr *ipAddressInternal) toCanonicalWildcardString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6AddressSection().toCanonicalWildcardStringZoned(addr.zone)
		}
		return cacheStr(&cache.canonicalWildcardString,
			func() string {
				return addr.section.ToIPv6AddressSection().toCanonicalWildcardStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToCanonicalWildcardString()
}

func (addr *ipAddressInternal) toNormalizedWildcardString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6AddressSection().toNormalizedWildcardStringZoned(addr.zone)
		}
		return cacheStr(&cache.normalizedWildcardString,
			func() string {
				return addr.section.ToIPv6AddressSection().toNormalizedWildcardStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToNormalizedWildcardString()
}

func (addr *ipAddressInternal) toSegmentedBinaryString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6AddressSection().toSegmentedBinaryStringZoned(addr.zone)
		}
		return cacheStr(&cache.segmentedBinaryString,
			func() string {
				return addr.section.ToIPv6AddressSection().toSegmentedBinaryStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToSegmentedBinaryString()
}

func (addr *ipAddressInternal) toSQLWildcardString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6AddressSection().toSQLWildcardStringZoned(addr.zone)
		}
		return cacheStr(&cache.sqlWildcardString,
			func() string {
				return addr.section.ToIPv6AddressSection().toSQLWildcardStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToSQLWildcardString()
}

func (addr *ipAddressInternal) toFullString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6AddressSection().toFullStringZoned(addr.zone)
		}
		return cacheStr(&cache.fullString,
			func() string {
				return addr.section.ToIPv6AddressSection().toFullStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToFullString()
}

func (addr *ipAddressInternal) toReverseDNSString() (string, IncompatibleAddressError) {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6AddressSection().toReverseDNSStringZoned(addr.zone)
		}
		return cacheStrErr(&cache.reverseDNSString,
			func() (string, IncompatibleAddressError) {
				return addr.section.ToIPv6AddressSection().toReverseDNSStringZoned(addr.zone)
			})
	}
	return addr.getSection().ToReverseDNSString()
}

func (addr *ipAddressInternal) toPrefixLenString() string {
	if addr.hasZone() {
		cache := addr.getStringCache()
		if cache == nil {
			return addr.section.ToIPv6AddressSection().toPrefixLenStringZoned(addr.zone)
		}
		return cacheStr(&cache.networkPrefixLengthString,
			func() string {
				return addr.section.ToIPv6AddressSection().toPrefixLenStringZoned(addr.zone)
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
			return addr.section.ToIPv6AddressSection().toCompressedWildcardStringZoned(addr.zone)
		}
		return cacheStr(&cache.compressedWildcardString,
			func() string {
				return addr.section.ToIPv6AddressSection().toCompressedWildcardStringZoned(addr.zone)
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
	//if addr == nil {
	//	return nilAddress
	//}
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

func (addr *IPAddress) IsZeroHostLen(prefLen BitCount) bool {
	return addr.init().isZeroHostLen(prefLen)
}

func (addr *IPAddress) ToZeroHost() (*IPAddress, IncompatibleAddressError) {
	return addr.init().toZeroHost(false)
}

//func (addr *IPAddress) ToZeroHost() (*IPAddress, IncompatibleAddressError) {
//	res, err := addr.init().toZeroHost(false)
//	return res.ToIPAddress(), err
//}

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

func (addr *IPAddress) CopyIP(ip net.IP) net.IP {
	if ipv4Addr := addr.ToIPv4Address(); ipv4Addr != nil {
		return ipv4Addr.CopyBytes(ip)
	}
	return addr.CopyBytes(ip)
}

func (addr *IPAddress) GetUpperIP() net.IP {
	return addr.GetUpperBytes()
}

func (addr *IPAddress) CopyUpperIP(ip net.IP) net.IP {
	if ipv4Addr := addr.ToIPv4Address(); ipv4Addr != nil {
		return ipv4Addr.CopyBytes(ip)
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

func (addr *IPAddress) CompareTo(item AddressItem) int {
	//if addr != nil {
	//	addr = addr.init()
	//}
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
	//if addr == nil {
	//	return other.ToAddress() == nil
	//}
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

func (addr *IPAddress) ToAddress() *Address {
	if addr != nil {
		addr = addr.init()
	}
	return (*Address)(unsafe.Pointer(addr))
}

func (addr *IPAddress) ToIPAddress() *IPAddress {
	return addr
}

func (addr *IPAddress) ToIPv6Address() *IPv6Address { //TODO maybe rename to ToIPv6(), then there is ToMac(), toIP(), and ToAddress - for sections youd would have the same and also ToSection() and ToGrouping()
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

func (addr *IPAddress) Wrap() WrappedIPAddress {
	return WrappedIPAddress{addr}
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

//func (addr *IPAddress) BitwiseOrPrefixed(other *IPAddress) (masked *IPAddress, err IncompatibleAddressError) {
//	return addr.bitwiseOrPrefixed(other, true)
//}

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

// ToUNCHostName //TODO LATER since we are not yet parsing this

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
		wrapped := addr.Wrap()
		spanning := getSpanningPrefixBlocks(wrapped, wrapped)
		return cloneToIPAddrs(spanning)
	}
	wrapped := addr.Wrap()
	return cloneToIPAddrs(spanWithPrefixBlocks(wrapped))
}

func (addr *IPAddress) SpanWithPrefixBlocksTo(other *IPAddress) ([]*IPAddress, IncompatibleAddressError) {
	if !versionsMatch(addr, other) {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipVersionMismatch"}}
	}
	return cloneToIPAddrs(
		getSpanningPrefixBlocks(
			addr.init().Wrap(),
			other.init().Wrap(),
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
	return cloneToIPAddrs(spanWithSequentialBlocks(addr.Wrap()))
}

func (addr *IPAddress) SpanWithSequentialBlocksTo(other *IPAddress) ([]*IPAddress, IncompatibleAddressError) {
	addr = addr.init()
	other = other.init()
	if !versionsMatch(addr, other) {
		return nil, &incompatibleAddressError{addressError{key: "ipaddress.error.ipVersionMismatch"}}
	}
	return cloneToIPAddrs(
		getSpanningSequentialBlocks(
			addr.ToIPAddress().Wrap(),
			other.ToIPAddress().Wrap(),
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

func (addr *IPAddress) ToCustomString(stringOptions IPStringOptions) string {
	return addr.GetSection().toCustomString(stringOptions, addr.zone)
}

// Retrieves or generates an IPAddressString object for this IPAddress object.
//
// In general, users are intended to create IPAddress objects from IPAddressString objects,
// while the reverse direction is generally not all that useful, except under specific circumstances.
//
// Not all IPAddressString objects can be converted to IPAddress objects.
//
// So it may be useful to store a set of address strings as a collection of IPAddressString objects, rather than IPAddress objects,
// which is one reason you might wish to obtain an IPAddressString from an IPAddress.
func (addr *IPAddress) ToAddressString() *IPAddressString { //TODO rename FromString()
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
	return hostIdStr.(*HostName).AsAddressString()
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
	if !addr.IsMultiple() {
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
		if addr.IsMultiple() {
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
	return two != nil && one.Equals(two)
}

type IPAddressValueProvider interface {
	//PrefixedAddressValueProvider

	AddressValueProvider

	GetPrefixLen() PrefixLen // return nil if none

	GetIPVersion() IPVersion // should not return IndeterminateVersion

	GetZone() string // return "" or NoZone if none
}

//type PrefixedAddressValueProvider interface {
//	AddressValueProvider
//
//	GetPrefixLen() PrefixLen // return nil if none
//}

////// IPv4AddressValueProvider wraps a PrefixedAddressValueProvider to prodice an IPAddressValueProvider
////type IPv4AddressValueProvider struct {
////	PrefixedAddressValueProvider
////}
////
////func (IPv4AddressValueProvider) GetIPVersion() IPVersion {
////	return IPv4
////}
////
////func (IPv4AddressValueProvider) GetZone() string {
////	return NoZone
////}
////
////// IPv6AddressValueProvider wraps a PrefixedAddressValueProvider to produce an IPAddressValueProvider with no zone
////type IPv6AddressValueProvider struct {
////	PrefixedAddressValueProvider
////}
////
////func (IPv6AddressValueProvider) GetIPVersion() IPVersion {
////	return IPv6
////}
////
////func (IPv6AddressValueProvider) GetZone() string {
////	return NoZone
////}
//
//// BuildNormalizedString allows for the creation of a normalized string without creating a full IP address object first.
//// Instead you can implement the IPAddressValueProvider interface in whatever way is most efficient.
//// The string is appended to the provided Builder instance.
//func BuildNormalizedString(provider IPAddressValueProvider, builder *strings.Builder) {
//	version := provider.GetIPVersion()
//	if version.IsIPv4() {
//		BuildNormalizedIPv4String(provider.GetValues(), provider.GetUpperValues(), provider.GetPrefixLen(), builder)
//	} else if version.IsIPv6() {
//		BuildNormalizedIPv6String(provider.GetValues(), provider.GetUpperValues(), provider.GetPrefixLen(), provider.GetZone(), builder)
//	}
//}
//
////// ToNormalizedString Allows for the creation of a normalized string without creating a full IP address object first.
////// Instead you can implement the IPAddressValueProvider interface in whatever way is most efficient.
////func ToNormalizedString(provider IPAddressValueProvider) string {
////	version := provider.GetIPVersion()
////	if version.IsIPv4() {
////		return ToNormalizedIPv4String(provider.GetValues(), provider.GetUpperValues(), provider.GetPrefixLen())
////	} else if version.IsIPv6() {
////		return ToNormalizedIPv6String(provider.GetValues(), provider.GetUpperValues(), provider.GetPrefixLen(), provider.GetZone())
////	}
////	return ""
////}
//
////// Creates a normalized IPv4 string for an address without having to create the address objects first.
////func ToNormalizedIPv4String(lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen) string {
////	return createNormalizedString(lowerValueProvider, upperValueProvider, prefixLength, IPv4SegmentCount, IPv4BytesPerSegment, IPv4BitsPerSegment, IPv4MaxValuePerSegment, IPv4SegmentSeparator, IPv4DefaultTextualRadix, "")
////}
////
////// Creates a normalized IPv6 string for an address without having to create the address objects first.
////func ToNormalizedIPv6String(lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen, zone string) string {
////	return createNormalizedString(lowerValueProvider, upperValueProvider, prefixLength, IPv6SegmentCount, IPv6BytesPerSegment, IPv6BitsPerSegment, IPv6MaxValuePerSegment, IPv6SegmentSeparator, IPv6DefaultTextualRadix, zone)
////}
//
//// Builds a normalized IPv4 string for an address without having to create the address objects first.
//func BuildNormalizedIPv4String(lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen, builder *strings.Builder) {
//	buildNormalizedString(lowerValueProvider, upperValueProvider, prefixLength, IPv4SegmentCount, IPv4BytesPerSegment, IPv4BitsPerSegment, IPv4MaxValuePerSegment, IPv4SegmentSeparator, IPv4DefaultTextualRadix, "", builder)
//}
//
//// Builds a normalized IPv6 string for an address without having to create the address objects first.
//func BuildNormalizedIPv6String(lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen, zone string, builder *strings.Builder) {
//	buildNormalizedString(lowerValueProvider, upperValueProvider, prefixLength, IPv6SegmentCount, IPv6BytesPerSegment, IPv6BitsPerSegment, IPv6MaxValuePerSegment, IPv6SegmentSeparator, IPv6DefaultTextualRadix, zone, builder)
//}
//
//// Creates the normalized string for an address without having to create the address objects first.
//func createNormalizedString(
//	lowerValueProvider,
//	upperValueProvider SegmentValueProvider,
//	prefixLength PrefixLen,
//	segmentCount,
//	bytesPerSegment int,
//	bitsPerSegment BitCount,
//	segmentMaxValue SegInt,
//	separator byte,
//	radix int,
//	zone string) string {
//	length := buildNormalizedString(
//		lowerValueProvider,
//		upperValueProvider,
//		prefixLength,
//		segmentCount,
//		bytesPerSegment,
//		bitsPerSegment,
//		segmentMaxValue,
//		separator,
//		radix,
//		zone,
//		nil)
//	var builder strings.Builder
//	builder.Grow(length)
//	buildNormalizedString(
//		lowerValueProvider,
//		upperValueProvider,
//		prefixLength,
//		segmentCount,
//		bytesPerSegment,
//		bitsPerSegment,
//		segmentMaxValue,
//		separator,
//		radix,
//		zone,
//		&builder)
//	checkLengths(length, &builder)
//	return builder.String()
//}
//
//// you could call isPrefixSubnet to do prefixed strings, but then the strings not unique anymore
//// then just prior to the check if value == value2 {
////Integer segmentPrefixLength = IPAddressSection.getSegmentPrefixLength(bitsPerSegment, prefixLength, segmentIndex);
////if(segmentPrefixLength != null) {
////	int mask = ~0 << (bitsPerSegment - segmentPrefixLength);
////	value &= mask;
////	value2 &= mask;
////}
////this func (params *ipAddressStringParams) appendSegment shows how we normally do it, checking for prefix block and then single prefix block
//// But instead, here we can just check for the single prefix like in the above blurb
//// And I would like to change that appendSegment method too, no need to check for prefix block twice
//
//xxxxx change name to normalizedWildcardString then xxxxx
//xxxxx maybe you should cache the seg values rather than calling the provider multiple times
//xxxxx The more I think about this the more I dislike.  So do you want to avoid compression?
//xxxxx And then thre is the caching, with prefixsubnet check you would be getting values three times, unless cached.
//xxxxx getCompressIndexAndCount handles compression
//xxxxx You wanted this for keys to maps.  Not so sure going further is much benefit.  Maybe you should toss this whole thing.
//
//
//func buildNormalizedString(
//	lowerValueProvider,
//	upperValueProvider SegmentValueProvider,
//	prefixLength PrefixLen,
//	segmentCount,
//	bytesPerSegment int,
//	bitsPerSegment BitCount,
//	segmentMaxValue SegInt,
//	separator byte,
//	radix int,
//	zone string,
//	builder *strings.Builder) int {
//	var segmentIndex, count int
//	for {
//		var value, value2 SegInt
//		if lowerValueProvider == nil {
//			value = upperValueProvider(segmentIndex)
//			value2 = value
//		} else {
//			value = lowerValueProvider(segmentIndex)
//			if upperValueProvider != nil {
//				value2 = upperValueProvider(segmentIndex)
//			} else {
//				value2 = value
//			}
//		}
//			if value == value2 {
//				if builder == nil {
//					count += toUnsignedStringLength(uint64(value), radix)
//				} else {
//					toUnsignedString(uint64(value), radix, builder)
//				}
//			} else {
//				if value > value2 {
//					value, value2 = value2, value
//				}
//				if value == 0 && value2 == segmentMaxValue {
//					if builder == nil {
//						count++ // len(SegmentWildcardStr)
//					} else {
//						builder.WriteByte(SegmentWildcard)
//					}
//				} else {
//					if builder == nil {
//						count += toUnsignedStringLength(uint64(value), radix) +
//							toUnsignedStringLength(uint64(value2), radix) +
//							1 // len(RangeSeparatorStr)
//					} else {
//						toUnsignedString(uint64(value), radix, builder)
//						builder.WriteByte(RangeSeparator)
//						toUnsignedString(uint64(value2), radix, builder)
//					}
//				}
//			}
//		segmentIndex++
//		if segmentIndex >= segmentCount {
//			break
//		}
//		if builder != nil {
//			builder.WriteByte(separator)
//		} // else counting the separators happens just once outside the loop, just below
//	}
//	if builder == nil {
//		count += segmentCount // separators
//		count--               // no ending separator
//	}
//	if zone != "" {
//		if builder == nil {
//			count += len(zone) + 1
//		} else {
//			builder.WriteByte(IPv6ZoneSeparator)
//			builder.WriteString(zone)
//		}
//	}
//	if prefixLength != nil {
//		if builder == nil {
//			count += toUnsignedStringLength(uint64(*prefixLength), 10) + 1
//		} else {
//			builder.WriteByte(PrefixLenSeparator)
//			toUnsignedString(uint64(*prefixLength), 10, builder)
//		}
//	}
//	return count
//}

func addrFromIP(ip net.IP) (addr *IPAddress, err AddressValueError) {
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	addrLen := len(ip)
	if addrLen <= IPv4ByteCount {
		var addr4 *IPv4Address
		addr4, err = NewIPv4AddressFromIP(ip)
		addr = addr4.ToIPAddress()
	} else if addrLen <= IPv6ByteCount {
		var addr6 *IPv6Address
		addr6, err = NewIPv6AddressFromIP(ip)
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
		addr4, err = NewIPv4AddressFromPrefixedIP(ip, prefixLen)
		addr = addr4.ToIPAddress()
	} else if addrLen <= IPv6ByteCount {
		var addr6 *IPv6Address
		addr6, err = NewIPv6AddressFromPrefixedIP(ip, prefixLen)
		addr = addr6.ToIPAddress()
	}
	return
}

//TODO you could rename these to "New" methods instead of From, they're no different than the New methods construcitng ipv4/6
// so that would be NewIPAddressFromIP

func FromIP(ip net.IP) *IPAddress {
	addr, _ := addrFromIP(ip)
	return addr
}

func FromPrefixedIP(ip net.IP, prefixLength PrefixLen) *IPAddress {
	addr, _ := addrFromPrefixedIP(ip, prefixLength)
	return addr
}

func FromIPAddr(addr *net.IPAddr) *IPAddress {
	ip := addr.IP
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	if len(ip) <= IPv4ByteCount {
		res, _ := NewIPv4AddressFromIP(ip)
		return res.ToIPAddress()
	} else if len(ip) <= IPv6ByteCount {
		res, _ := NewIPv6AddressFromIPAddr(addr)
		return res.ToIPAddress()
	}
	return nil
}

func FromPrefixedIPAddr(addr *net.IPAddr, prefixLength PrefixLen) *IPAddress {
	ip := addr.IP
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	if len(ip) <= IPv4ByteCount {
		res, _ := NewIPv4AddressFromPrefixedIP(ip, prefixLength)
		return res.ToIPAddress()
	} else if len(ip) <= IPv6ByteCount {
		res, _ := NewIPv6AddressFromPrefixedIPAddr(addr, prefixLength)
		return res.ToIPAddress()
	}
	return nil
}

type IPAddressCreator struct {
	IPVersion
}

func (creator IPAddressCreator) FromPrefixedVals(lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen) *IPAddress {
	return FromPrefixedVals(creator.IPVersion, lowerValueProvider, upperValueProvider, prefixLength)
}

func (creator IPAddressCreator) FromPrefixedZonedVals(lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen, zone string) *IPAddress {
	return FromPrefixedZonedVals(creator.IPVersion, lowerValueProvider, upperValueProvider, prefixLength, zone)
}

func (creator IPAddressCreator) CreateSegment(lower, upper SegInt, segmentPrefixLength PrefixLen) *IPAddressSegment {
	if creator.IsIPv4() {
		return NewIPv4RangePrefixedSegment(IPv4SegInt(lower), IPv4SegInt(upper), segmentPrefixLength).ToIPAddressSegment()
	} else if creator.IsIPv6() {
		return NewIPv6RangePrefixedSegment(IPv6SegInt(lower), IPv6SegInt(upper), segmentPrefixLength).ToIPAddressSegment()
	}
	return nil
}

func (creator IPAddressCreator) CreateRangeSegment(lower, upper SegInt) *IPAddressSegment {
	if creator.IsIPv4() {
		return NewIPv4RangeSegment(IPv4SegInt(lower), IPv4SegInt(upper)).ToIPAddressSegment()
	} else if creator.IsIPv6() {
		return NewIPv6RangeSegment(IPv6SegInt(lower), IPv6SegInt(upper)).ToIPAddressSegment()
	}
	return nil
}

func (creator IPAddressCreator) CreatePrefixSegment(value SegInt, segmentPrefixLength PrefixLen) *IPAddressSegment {
	if creator.IsIPv4() {
		return NewIPv4PrefixedSegment(IPv4SegInt(value), segmentPrefixLength).ToIPAddressSegment()
	} else if creator.IsIPv6() {
		return NewIPv6PrefixedSegment(IPv6SegInt(value), segmentPrefixLength).ToIPAddressSegment()
	}
	return nil
}

func (creator IPAddressCreator) FromIP(bytes net.IP) *IPAddress {
	if creator.IsIPv4() {
		addr, _ := NewIPv4AddressFromIP(bytes)
		return addr.ToIPAddress()
	} else if creator.IsIPv6() {
		addr, _ := NewIPv6AddressFromIP(bytes)
		return addr.ToIPAddress()
	}
	return nil
}

func (creator IPAddressCreator) FromPrefixedIP(bytes net.IP, prefLen PrefixLen) *IPAddress {
	if creator.IsIPv4() {
		addr, _ := NewIPv4AddressFromPrefixedIP(bytes, prefLen)
		return addr.ToIPAddress()
	} else if creator.IsIPv6() {
		addr, _ := NewIPv6AddressFromPrefixedIP(bytes, prefLen)
		return addr.ToIPAddress()
	}
	return nil
}

//xxxx
//our creator object could store the version and then call these
//does it make sense to combine with the existing creator infrastructure?
//I am a little skeptical
//FOr one thing they use AddressDivision (not IPv4 or v6 Address Segment)
//For another thing, building up from divisions can be done in an anonymous way, but is far from ideal, much easier to just use values and byte slices
//Now, what about IPADdressProvider?
//well, for the small things like prefix, it is easier to pass things in to a creator method than to create more funcs
//So, that is all we need, start from a version, create the thing, use the thing
//xxx
//Our test code also wants to use a byte slice too
//Hmmm we could just call the static methods
//ok let us rewrite to us SegmentValueProvider, why not?  It is easier
//But you do want to test getBytes so let us do that instead
//xxxx

func FromPrefixedVals(version IPVersion, lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen) *IPAddress {
	return FromPrefixedZonedVals(version, lowerValueProvider, upperValueProvider, prefixLength, "")
}

func FromPrefixedZonedVals(version IPVersion, lowerValueProvider, upperValueProvider SegmentValueProvider, prefixLength PrefixLen, zone string) *IPAddress {
	if version.IsIPv4() {
		return NewIPv4AddressFromPrefixedRange(lowerValueProvider, upperValueProvider, prefixLength).ToIPAddress()
	} else if version.IsIPv6() {
		return NewIPv6AddressFromPrefixedZonedRange(lowerValueProvider, upperValueProvider, prefixLength, zone).ToIPAddress()
	}
	return nil
}

func FromValueProvider(valueProvider IPAddressValueProvider) *IPAddress {
	if valueProvider.GetIPVersion().IsIPv4() {
		return NewIPv4AddressFromPrefixedRange(valueProvider.GetValues(), valueProvider.GetUpperValues(), valueProvider.GetPrefixLen()).ToIPAddress()
	} else if valueProvider.GetIPVersion().IsIPv6() {
		return NewIPv6AddressFromPrefixedZonedRange(valueProvider.GetValues(), valueProvider.GetUpperValues(), valueProvider.GetPrefixLen(), valueProvider.GetZone()).ToIPAddress()
	}
	return nil
}
