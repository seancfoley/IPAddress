package ipaddr

/*
package main

import (
	"fmt"
)

type foo interface {
	bar() int
}

type x struct {
	x int
}

func (*x) bar() int {
	return 1
}

type y struct {
	x int
}

func (*y) bar() int {
	return 2
}

type z struct {
	x int
}

func (z) bar() int {
	return 1
}

func main() {
	one := x{1}
	same := x{1}

	two := y{1}

	var foo1, foo2 foo = &one, &two
	var foo3 = &one
	var foosame = &same

	fmt.Println("interfaces equal, types different", foo1 == foo2)
	fmt.Println("interfaces equal, same pointer ", foo1 == foo3)
	fmt.Println("interfaces equal, types same, values same, not same pointer ", foo1 == foosame)
	fmt.Println("structs equal, types same, values same", one == same)

	onez := z{1}
	samez := z{1}
	var foo1z, foosamez foo = onez, samez
	fmt.Println("interfaces equal, types same, values same, not pointer ", foo1z == foosamez)

}

// https://stackoverflow.com/questions/34245932/checking-equality-of-interface#34246225
*/

// All IP address strings corresponds to exactly one of these types.
// In cases where there is no corresponding default IPAddress value (INVALID, ALL, and possibly EMPTY), these types can be used for comparison.
// EMPTY means a zero-length string (useful for validation, we can set validation to allow empty strings) that has no corresponding IPAddress value (validation options allow you to map empty to the loopback)
// INVALID means it is known that it is not any of the other allowed types (validation options can restrict the allowed types)
// ALL means it is wildcard(s) with no separators, like "*", which represents all addresses, whether IPv4, IPv6 or other, and thus has no corresponding IPAddress value
// These constants are ordered by address space size, from smallest to largest, and the ordering affects comparisons
type IPType int

func fromVersion(version IPVersion) IPType {
	switch version {
	case IPv4:
		return IPV4
	case IPv6:
		return IPV6
	default:
	}
	return UNINITIALIZED_TYPE
}

func (t IPType) isUnknown() bool {
	return t == UNINITIALIZED_TYPE
}

const (
	UNINITIALIZED_TYPE IPType = iota
	INVALID
	EMPTY
	IPV4
	IPV6
	//PREFIX_ONLY
	ALL
)

//TODO rename later IPAddressProvider, IPType, and the IPType constants, all the creator classes, etc, so not public, also same for MACAddressProvider

type IPAddressProvider interface {
	getType() IPType

	getProviderHostAddress() (*IPAddress, IncompatibleAddressException)

	getProviderAddress() (*IPAddress, IncompatibleAddressException)

	getVersionedAddress(version IPVersion) (*IPAddress, IncompatibleAddressException)

	isSequential() bool

	getProviderSeqRange() *IPAddressSeqRange

	getProviderMask() *IPAddress

	// TODO getDivisionGrouping
	//default IPAddressDivisionSeries getDivisionGrouping() throws IncompatibleAddressException {
	//	return getProviderAddress();
	//}

	providerCompare(IPAddressProvider) (int, IncompatibleAddressException)

	providerEquals(IPAddressProvider) (bool, IncompatibleAddressException)

	getProviderIPVersion() IPVersion

	isProvidingIPAddress() bool

	isProvidingIPv4() bool

	isProvidingIPv6() bool

	isProvidingAllAddresses() bool

	isProvidingEmpty() bool

	isProvidingMixedIPv6() bool

	isProvidingBase85IPv6() bool

	getProviderNetworkPrefixLength() PrefixLen

	isInvalid() bool

	isUninitialized() bool

	// If the address was created by parsing, this provides the parameters used when creating the address,
	// otherwise nil
	getParameters() IPAddressStringParameters
}

// TODO optimized contains: add these later
//	/**
//	 * An optimized contains that does not need to create address objects to return an answer.
//	 * Unconventional addresses may require that the address objects are created, in such cases null is returned.
//	 *
//	 * Addresses constructed from canonical or normalized representations with no wildcards will not return null.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean contains(IPAddressProvider other) {
//		return null;
//	}
//
//	/**
//	 * An optimized contains that does not need to fully parse the other address to return an answer.
//	 *
//	 * Unconventional addresses may require full parsing, in such cases null is returned.
//	 *
//	 * Addresses constructed from canonical or normalized representations with no wildcards will not return null.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean contains(String other) {
//		return null;
//	}
//
//	/**
//	 * An optimized prefix comparison that does not need to fully parse the other address to return an answer.
//	 *
//	 * Unconventional addresses may require full parsing, in such cases null is returned.
//	 *
//	 * Addresses constructed from canonical or normalized representations with no wildcards will not return null.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean prefixEquals(String other) {
//		return null;
//	}
//
//	/**
//	 * An optimized prefix comparison that does not need to create addresses to return an answer.
//	 *
//	 * Unconventional addresses may require the address objects, in such cases null is returned.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean prefixEquals(IPAddressProvider other) {
//		return null;
//	}
//
//	/**
//	 * An optimized prefix comparison that does not need to create addresses to return an answer.
//	 *
//	 * Unconventional addresses may require the address objects, in such cases null is returned.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean prefixContains(String other) {
//		return null;
//	}
//
//	/**
//	 * An optimized prefix comparison that does not need to create addresses to return an answer.
//	 *
//	 * Unconventional addresses may require the address objects, in such cases null is returned.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean prefixContains(IPAddressProvider other) {
//		return null;
//	}
//
//	/**
//	 * An optimized equality comparison that does not need to create addresses to return an answer.
//	 *
//	 * Unconventional addresses may require the address objects, in such cases null is returned.
//	 *
//	 * @param other
//	 * @return
//	 */
//	default Boolean parsedEquals(IPAddressProvider other) {
//		return null;
//	}
//
//	default boolean hasPrefixSeparator() {
//		return getProviderNetworkPrefixLength() != null;
//	}

type ipAddrProvider struct{}

func (p *ipAddrProvider) getType() IPType {
	return UNINITIALIZED_TYPE
}

func (p *ipAddrProvider) isSequential() bool {
	return false
}

func (p *ipAddrProvider) getProviderHostAddress() (*IPAddress, IncompatibleAddressException) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderAddress() (*IPAddress, IncompatibleAddressException) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderSeqRange() *IPAddressSeqRange {
	return nil
}

func (p *ipAddrProvider) getVersionedAddress(version IPVersion) (*IPAddress, IncompatibleAddressException) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderMask() *IPAddress {
	return nil
}

func (p *ipAddrProvider) getProviderIPVersion() IPVersion {
	return INDETERMINATE_VERSION
}

func (p *ipAddrProvider) isProvidingIPAddress() bool {
	return false
}

func (p *ipAddrProvider) isProvidingIPv4() bool {
	return false
}

func (p *ipAddrProvider) isProvidingIPv6() bool {
	return false
}

func (p *ipAddrProvider) isProvidingAllAddresses() bool {
	return false
}

func (p *ipAddrProvider) isProvidingEmpty() bool {
	return false
}

func (p *ipAddrProvider) isInvalid() bool {
	return false
}

func (p *ipAddrProvider) isUninitialized() bool {
	return false
}

func (p *ipAddrProvider) isProvidingMixedIPv6() bool {
	return false
}

func (p *ipAddrProvider) isProvidingBase85IPv6() bool {
	return false
}

func (p *ipAddrProvider) getProviderNetworkPrefixLength() PrefixLen {
	return nil
}

func (p *ipAddrProvider) getParameters() IPAddressStringParameters {
	return nil
}

func providerCompare(p, other IPAddressProvider) (res int, err IncompatibleAddressException) {
	if p == other {
		return
	}
	value, err := p.getProviderAddress()
	if err != nil {
		return
	}
	if value != nil {
		var otherValue *IPAddress
		otherValue, err = other.getProviderAddress()
		if err != nil {
			return
		}
		if otherValue != nil {
			//TODO compareTo on address
			//return value.compareTo(otherValue);
		}
	}
	var thisType, otherType IPType = p.getType(), other.getType()
	res = int(thisType - otherType)
	return
}

/**
* When a value provider produces no value, equality and comparison are based on the enum IPType,
* which can by null.
* @param o
* @return
 */
func providerEquals(p, other IPAddressProvider) (res bool, err IncompatibleAddressException) {
	if p == other {
		res = true
		return
	}
	value, err := p.getProviderAddress()
	if err != nil {
		return
	}
	if value != nil {
		var otherValue *IPAddress
		otherValue, err = other.getProviderAddress()
		if err != nil {
			return
		}
		if otherValue != nil {
			// TODO equals, but also, think about struct ==, would be nice if that worked!
			// But won't with cache, UNLESS I make it so ALL addresses the same have same cache ALWAYS, which is possible!
			// Actually no, not possible, you would need a cache for every address, not every segment.  Too many.
			//
			// You gotta be careful, once you support it you don't want to renege
			// Seems common to have "equal" methods. eg https://godoc.org/bytes#Equal
			// There are vays, namely separate the stuff for comparison: https://stackoverflow.com/questions/47134293/compare-structs-except-one-field-golang
			// BUT note that == does not work on slices!  But it does work on arrays.  And you will likely use slices in sections.
			//https://stackoverflow.com/questions/15311969/checking-the-equality-of-two-slices
			//res = value.equals(otherValue)
			return
		} else {
			return
		}
	}
	res = p.getType() == other.getType()
	return
}

// if you have a type with 3 funcs, and 3 methods that defer to the funs
// then that is 4 decls, and then you can deine each of the 3 vars
// if you do a new type for each overridden method, that is 6 decls

type nullProvider struct {
	ipAddrProvider

	ipType                                    IPType
	isInvalidVal, isUninitializedVal, isEmpty bool
}

func (p *nullProvider) isInvalid() bool {
	return p.isInvalidVal
}

func (p *nullProvider) isUninitialized() bool {
	return p.isUninitializedVal
}

func (p *nullProvider) isProvidingEmpty() bool {
	return p.isEmpty
}

func (p *nullProvider) getType() IPType {
	return p.ipType
}

func (p *nullProvider) providerCompare(other IPAddressProvider) (int, IncompatibleAddressException) {
	return providerCompare(p, other)
}

func (p *nullProvider) providerEquals(other IPAddressProvider) (bool, IncompatibleAddressException) {
	return providerEquals(p, other)
}

var (
	INVALID_PROVIDER = &nullProvider{isInvalidVal: true, ipType: INVALID}
	//NO_TYPE_PROVIDER = &nullProvider{isUninitializedVal: true, ipType: UNINITIALIZED_TYPE}
	EMPTY_PROVIDER = &nullProvider{isEmpty: true, ipType: EMPTY}
)

type CachedIPAddresses struct {
	//address is 1.2.0.0/16 and hostAddress is 1.2.3.4 for the string 1.2.3.4/16
	address, hostAddress *IPAddress
}

func (cached *CachedIPAddresses) getAddress() *IPAddress {
	return cached.address
}

func (cached *CachedIPAddresses) getHostAddress() *IPAddress {
	return cached.hostAddress
}

///**
//	 * Wraps an IPAddress for IPAddressString in the cases where no parsing is provided, the address exists already
//	 * @param value
//	 * @return
//	 */
func getProviderFor(address, hostAddress *IPAddress) IPAddressProvider {
	return &CachedAddressProvider{values: CachedIPAddresses{address, hostAddress}}
}

type CachedAddressProvider struct {
	ipAddrProvider

	values CachedIPAddresses

	// addressCreator creates two addresses, the host address and address with prefix/mask, at the same time
	addressCreator func() CachedIPAddresses

	CreationLock
}

//TODO do not forget you also need these two in all top level classes, including ParsedIPAddress, the mask, all and empty providers
// they are needed becaue of virtual calls to getType() and getProviderAddress()

func (cached *CachedAddressProvider) providerCompare(other IPAddressProvider) (int, IncompatibleAddressException) {
	return providerCompare(cached, other)
}

func (cached *CachedAddressProvider) providerEquals(other IPAddressProvider) (bool, IncompatibleAddressException) {
	return providerEquals(cached, other)
}

func (cached *CachedAddressProvider) isProvidingIPAddress() bool {
	return true
}

func (cached *CachedAddressProvider) getVersionedAddress(version IPVersion) (*IPAddress, IncompatibleAddressException) {
	thisVersion := cached.getProviderIPVersion()
	if version != thisVersion {
		return nil, nil
	}
	return cached.getProviderAddress()
}

func (cached *CachedAddressProvider) getProviderHostAddress() (*IPAddress, IncompatibleAddressException) {
	return cached.getCachedAddresses().getHostAddress(), nil
}

func (cached *CachedAddressProvider) getProviderAddress() (*IPAddress, IncompatibleAddressException) {
	return cached.getCachedAddresses().getAddress(), nil
}

func (cached *CachedAddressProvider) getProviderSeqRange() *IPAddressSeqRange {
	addr, _ := cached.getProviderAddress()
	if addr != nil {
		return addr.ToSequentialRange()
	}
	return nil
}

func (cached *CachedAddressProvider) isSequential() bool {
	addr, _ := cached.getProviderAddress()
	if addr != nil {
		return addr.IsSequential()
	}
	return false
}

func (cached *CachedAddressProvider) hasCachedAddresses() bool {
	return cached.addressCreator == nil || cached.isItemCreated()
}

func (cached *CachedAddressProvider) getCachedAddresses() *CachedIPAddresses {
	if cached.addressCreator != nil && !cached.isItemCreated() {
		cached.create(func() {
			cached.values = cached.addressCreator()
		})
	}
	return &cached.values
}

func (cached *CachedAddressProvider) getProviderNetworkPrefixLength() (p PrefixLen) {
	addr, _ := cached.getProviderAddress()
	return addr.GetNetworkPrefixLength()
}

func (cached *CachedAddressProvider) getProviderIPVersion() IPVersion {
	addr, _ := cached.getProviderAddress()
	return addr.getIPVersion()
}

func (cached *CachedAddressProvider) getType() IPType {
	return fromVersion(cached.getProviderIPVersion())
}

func (cached *CachedAddressProvider) isProvidingIPv4() bool {
	addr, _ := cached.getProviderAddress()
	return addr.IsIPv4()
}

func (cached *CachedAddressProvider) isProvidingIPv6() bool {
	addr, _ := cached.getProviderAddress()
	return addr.IsIPv6()
}

type VersionedAddressCreator struct {
	CachedAddressProvider

	adjustedVersion IPVersion

	versionedAddressCreator func(IPVersion) *IPAddress
	createdVersioned        [2]CreationLock
	versionedValues         [2]*IPAddress

	parameters IPAddressStringParameters
}

func (versioned *VersionedAddressCreator) getParameters() IPAddressStringParameters {
	return versioned.parameters
}

func (versioned *VersionedAddressCreator) isProvidingIPAddress() bool {
	return versioned.adjustedVersion != INDETERMINATE_VERSION
}

func (versioned *VersionedAddressCreator) isProvidingIPv4() bool {
	return versioned.adjustedVersion == IPv4
}

func (versioned *VersionedAddressCreator) isProvidingIPv6() bool {
	return versioned.adjustedVersion == IPv6
}

func (versioned *VersionedAddressCreator) getProviderIPVersion() IPVersion {
	return versioned.adjustedVersion
}

func (versioned *VersionedAddressCreator) getType() IPType {
	return fromVersion(versioned.adjustedVersion)
}

func (versioned *VersionedAddressCreator) getVersionedAddress(version IPVersion) (addr *IPAddress, err IncompatibleAddressException) {
	index := version.index()
	if index >= INDETERMINATE_VERSION.index() {
		return
	}
	if versioned.versionedAddressCreator != nil && !versioned.createdVersioned[index].isItemCreated() {
		versioned.createdVersioned[index].create(func() {
			versioned.versionedValues[index] = versioned.versionedAddressCreator(version)
		})
	}
	addr = versioned.versionedValues[index]
	return
}

func newLoopbackCreator(options IPAddressStringParameters, zone string) *LoopbackCreator {
	// TODO an option to set preferred loopback here in IPAddressStringParameters, do the same in Java
	// the option will set one of three options, IPv4, IPv6, or INDETERMINATE_VERSION which is the default
	// In Go the default will be IPv4
	// There is another option I wanted to add, was in the validator code, I think allow empty zone with prefix like %/
	var preferIPv6 bool
	ipv6WithZoneLoop := func() *IPAddress {
		network := options.GetIPv6Parameters().GetNetwork()
		creator := network.GetIPAddressCreator()
		return creator.createAddressInternalFromBytes(network.GetLoopback().GetBytes(), zone)
	}
	ipv6Loop := func() *IPAddress {
		return options.GetIPv6Parameters().GetNetwork().GetLoopback()
	}
	ipv4Loop := func() *IPAddress {
		return options.GetIPv4Parameters().GetNetwork().GetLoopback()
	}
	double := func(one *IPAddress) CachedIPAddresses {
		return CachedIPAddresses{one, one}
	}
	var addrCreator func() CachedIPAddresses
	var version IPVersion
	if len(zone) > 0 && preferIPv6 {
		addrCreator = func() CachedIPAddresses { return double(ipv6WithZoneLoop()) }
		version = IPv6
	} else if preferIPv6 {
		addrCreator = func() CachedIPAddresses { return double(ipv6Loop()) }
		version = IPv6
	} else {
		addrCreator = func() CachedIPAddresses { return double(ipv4Loop()) }
		version = IPv4
	}
	cached := CachedAddressProvider{addressCreator: addrCreator}
	versionedAddressCreator := func(version IPVersion) *IPAddress {
		if cached.hasCachedAddresses() {
			addr := cached.values.address
			if version == addr.GetIPVersion() {
				return addr
			}
		}
		if version.isIPv4() {
			return ipv4Loop()
		} else if version.isIPv6() {
			if len(zone) > 0 {
				return ipv6WithZoneLoop()
			}
			return ipv6Loop()
		}
		return nil
	}
	return &LoopbackCreator{
		VersionedAddressCreator: VersionedAddressCreator{
			adjustedVersion:         version,
			parameters:              options,
			CachedAddressProvider:   cached,
			versionedAddressCreator: versionedAddressCreator,
		},
		zone: zone,
	}
}

type LoopbackCreator struct {
	VersionedAddressCreator

	zone string
}

func (loop *LoopbackCreator) providerCompare(other IPAddressProvider) (int, IncompatibleAddressException) {
	return providerCompare(loop, other)
}

func (loop *LoopbackCreator) providerEquals(other IPAddressProvider) (bool, IncompatibleAddressException) {
	return providerEquals(loop, other)
}

func (loop *LoopbackCreator) getProviderNetworkPrefixLength() PrefixLen {
	return nil
}

type AdjustedAddressCreator struct {
	VersionedAddressCreator

	networkPrefixLength PrefixLen
}

func (adjusted *AdjustedAddressCreator) getProviderNetworkPrefixLength() PrefixLen {
	return adjusted.networkPrefixLength
}

func (adjusted *AdjustedAddressCreator) getProviderAddress() (*IPAddress, IncompatibleAddressException) {
	if !adjusted.isProvidingIPAddress() {
		return nil, nil
	}
	return adjusted.VersionedAddressCreator.getProviderAddress()
}

func (adjusted *AdjustedAddressCreator) getProviderHostAddress() (*IPAddress, IncompatibleAddressException) {
	if !adjusted.isProvidingIPAddress() {
		return nil, nil
	}
	return adjusted.VersionedAddressCreator.getProviderHostAddress()
}

// TODO the adjusted version passed in is the one adjusted due to zone %, or mask version, or prefix len >= 32
// INside this function we will handle the cases where it is still not determined, and that will be based on our new rules
// involving (a) maybe when < 32 we default to IPv4, otherwise IPv6
//			(b) this behaviour can be overridden by a string parameters option

func newMaskCreator(options IPAddressStringParameters, adjustedVersion IPVersion, networkPrefixLength PrefixLen) *MaskCreator {
	// TODO use the option for  preferred loopback also for preferred mask, do the same in Java
	// TODO also, consider the idea of preflen < 32 defaulting to IPv4, >= 32 IPv6
	// Drop "prefix only" type - it was never a good idea anyway!  Better to prefer one over the other.

	var preferIPv6 bool

	if adjustedVersion == INDETERMINATE_VERSION {
		if preferIPv6 {
			adjustedVersion = IPv6
		} else {
			adjustedVersion = IPv4
		}
	}
	createVersionedMask := func(version IPVersion, prefLen PrefixLen, withPrefixLength bool) *IPAddress {
		if version == IPv4 {
			network := options.GetIPv4Parameters().GetNetwork()
			if withPrefixLength {
				return network.GetNetworkIPAddress(prefLen)
			}
			return network.GetNetworkMask(prefLen, false)
		} else if version == IPv6 {
			network := options.GetIPv6Parameters().GetNetwork()
			if withPrefixLength {
				return network.GetNetworkIPAddress(prefLen)
			}
			return network.GetNetworkMask(prefLen, false)
		}
		return nil
	}
	versionedAddressCreator := func(version IPVersion) *IPAddress {
		return createVersionedMask(version, networkPrefixLength, true)
	}
	addrCreator := func() CachedIPAddresses {
		prefLen := networkPrefixLength
		return CachedIPAddresses{
			address:     createVersionedMask(adjustedVersion, prefLen, true),
			hostAddress: createVersionedMask(adjustedVersion, prefLen, false),
		}
	}
	cached := CachedAddressProvider{addressCreator: addrCreator}
	return &MaskCreator{
		AdjustedAddressCreator{
			networkPrefixLength: networkPrefixLength,
			VersionedAddressCreator: VersionedAddressCreator{
				adjustedVersion:         adjustedVersion,
				parameters:              options,
				CachedAddressProvider:   cached,
				versionedAddressCreator: versionedAddressCreator,
			},
		},
	}
}

type MaskCreator struct {
	AdjustedAddressCreator
}

// TODO the adjusted version passed in is the one adjusted due to zone %, or mask version, or prefix len >= 32
// INside this function we will handle the cases where it is still not determined, and that will be based on our new rules
// involving (a) maybe when < 32 we default to IPv4, otherwise IPv6
//			(b) this behaviour can be overridden by a string parameters option

func newAllCreator(qualifier *ParsedHostIdentifierStringQualifier, adjustedVersion IPVersion, originator HostIdentifierString, options IPAddressStringParameters) *AllCreator {
	// TODO use the option for  preferred loopback also for preferred mask, do the same in Java
	// consider using zero value instead of loopback - zero string becomes zero value
	// TODO also, consider the idea of preflen < 32 defaulting to IPv4, >= 32 IPv6
	// Drop "prefix only" type - it was never a good idea anyway!  Better to prefer one over the other.

	var preferIPv6 bool
	if adjustedVersion == INDETERMINATE_VERSION {
		// TODO do we defer to a version for "*"?  I prefer not.  I like it as is.
		// But we do use the adjusting rules (not this block) and we use the prefix length rules (this block).
		if preferIPv6 { // TODO this amounts to checkign the prefix length
			adjustedVersion = IPv6
		} else {
			adjustedVersion = IPv4
		}
	}
	var addrCreator func() CachedIPAddresses
	if *qualifier == *NO_QUALIFIER {
		addrCreator = func() CachedIPAddresses {
			addr := createAllAddress(adjustedVersion, NO_QUALIFIER, originator, options)
			return CachedIPAddresses{addr, addr}
		}
	} else {
		addrCreator = func() CachedIPAddresses {
			addr := createAllAddress(adjustedVersion, qualifier, originator, options)
			if qualifier.zone == "" {
				hostAddr := createAllAddress(adjustedVersion, NO_QUALIFIER, originator, options)
				return CachedIPAddresses{addr, hostAddr}
			}
			qualifier2 := ParsedHostIdentifierStringQualifier{zone: qualifier.zone}
			hostAddr := createAllAddress(adjustedVersion, &qualifier2, originator, options)
			return CachedIPAddresses{addr, hostAddr}
		}
	}
	cached := CachedAddressProvider{addressCreator: addrCreator}
	return &AllCreator{
		AdjustedAddressCreator: AdjustedAddressCreator{
			networkPrefixLength: qualifier.getEquivalentPrefixLength(),
			VersionedAddressCreator: VersionedAddressCreator{
				adjustedVersion:       adjustedVersion,
				parameters:            options,
				CachedAddressProvider: cached,
				versionedAddressCreator: func(version IPVersion) *IPAddress {
					return createAllAddress(version, qualifier, originator, options)
				},
			},
		},
		originator: originator,
		qualifier:  *qualifier,
	}
}

type AllCreator struct {
	AdjustedAddressCreator

	originator HostIdentifierString
	qualifier  ParsedHostIdentifierStringQualifier //TODO copy the original to here
}

func (all *AllCreator) getType() IPType {
	if !all.adjustedVersion.isIndeterminate() {
		return fromVersion(all.adjustedVersion)
	}
	return ALL
}

func (all *AllCreator) isProvidingAllAddresses() bool {
	return all.adjustedVersion == INDETERMINATE_VERSION
}

func (all *AllCreator) getProviderNetworkPrefixLength() PrefixLen {
	return all.qualifier.getEquivalentPrefixLength()
}

func (all *AllCreator) getProviderMask() *IPAddress {
	return all.qualifier.getMaskLower()
}

// TODO the ones below later
//		@Override
//		public Boolean contains(IPAddressProvider otherProvider) {
//			if(otherProvider.isInvalid()) {
//				return Boolean.FALSE;
//			} else if(adjustedVersion == null) {
//				return Boolean.TRUE;
//			}
//			return adjustedVersion == otherProvider.getProviderIPVersion();
//		}

func (all *AllCreator) getProviderSeqRange() *IPAddressSeqRange {
	if all.isProvidingAllAddresses() {
		return nil
	}
	mask := all.getProviderMask()
	if mask != nil && mask.GetBlockMaskPrefixLength(true) == nil {
		// we must apply the mask
		all := createAllAddress(all.adjustedVersion, NO_QUALIFIER, nil, all.parameters)
		upper, _ := all.GetUpper().Mask(mask)
		lower := all.GetLower() //TODO apply the mask? maybe I have this wrong in Java too
		return lower.SpanWithRange(upper)
	}
	return all.CachedAddressProvider.getProviderSeqRange()
}

//
//		@Override
//		public boolean isSequential() {
//			return !isProvidingAllAddresses();
//		}
//
//		@Override
//		public IPAddressDivisionSeries getDivisionGrouping() throws IncompatibleAddressException {
//			if(isProvidingAllAddresses()) {
//				return null;
//			}
//			IPAddressNetwork<?, ?, ?, ?, ?> network = adjustedVersion.isIPv4() ?
//					options.getIPv4Parameters().getNetwork() : options.getIPv6Parameters().getNetwork();
//			IPAddress mask = getProviderMask();
//			if(mask != null && mask.getBlockMaskPrefixLength(true) == null) {
//				// there is a mask
//				Integer hostMaskPrefixLen = mask.getBlockMaskPrefixLength(false);
//				if(hostMaskPrefixLen == null) { // not a host mask
//					throw new IncompatibleAddressException(getProviderAddress(), mask, "ipaddress.error.maskMismatch");
//				}
//				IPAddress hostMask = network.getHostMask(hostMaskPrefixLen);
//				return hostMask.toPrefixBlock();
//			}
//			IPAddressDivisionSeries grouping;
//			if(adjustedVersion.isIPv4()) {
//				grouping = new IPAddressDivisionGrouping(new IPAddressBitsDivision[] {
//							new IPAddressBitsDivision(0, IPv4Address.MAX_VALUE, IPv4Address.BIT_COUNT, IPv4Address.DEFAULT_TEXTUAL_RADIX, network, qualifier.getEquivalentPrefixLength())
//						}, network);
//			} else if(adjustedVersion.isIPv6()) {
//				byte upperBytes[] = new byte[16];
//				Arrays.fill(upperBytes, (byte) 0xff);
//				grouping = new IPAddressLargeDivisionGrouping(new IPAddressLargeDivision[] {new IPAddressLargeDivision(new byte[IPv6Address.BYTE_COUNT], upperBytes, IPv6Address.BIT_COUNT, IPv6Address.DEFAULT_TEXTUAL_RADIX, network, qualifier.getEquivalentPrefixLength())}, network);
//			} else {
//				grouping = null;
//			}
//			return grouping;
//		}
//	}

// TODO NOW progress
// TODO NEXT NOW progress
// - Move towards address creation - need ipaddress provider types fleshed out, and in particular ParsedIPAddress
//
// - Then the mask stuff in parseQualifier can be done, which depends on address creation
// - here you might start putting in validation tests that check for parsing errors
// - then you can do the string methods in the address sections and addresses and segments
// - the you can add validation tests that use strings, in fact not sure if I do that much, I have some that check the string methods thought
// - things to target: contains()/equals(), iterators, increment, merge, span
// - I think next is Contains and Equals now that comparator done
//		So do you use Equals or Equal?  Compare or CompareTo?  Probably Equals and CompareTo, but hold on, Compare and Equal are quite common
//		needed by some of the contains methods such as SeqRange contains, also seq range creation needs compare
// https://golang.org/pkg/bytes/ Compare and Equal
// https://golang.org/pkg/strings/
// https://golang.org/pkg/reflect/ DeepEqual
// https://golang.org/pkg/math/big/ Cmp
// https://gist.github.com/asukakenji/ac8a05644a2e98f1d5ea8c299541fce9
// Those are funcs, not methods.  So, maybe stick with Equals and CompareTo
//
// - also segment prefixContains and prefixEquals
// - you might take the approach of implementing the use-cases (excluding streams and tries) from the wiki to get the important stuff in, then fill in the gaps later
// - finish off the ip address creator interfaces
// - finish HostName
