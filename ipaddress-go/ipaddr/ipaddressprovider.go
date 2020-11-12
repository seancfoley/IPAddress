package ipaddr

import "sync"

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
	PREFIX_ONLY
	ALL
)

//TODO rename later IPAddressProvider, IPType, and the IPType constants, all the creator classes, etc, so not public, also same for MACAddressProvider

type IPAddressProvider interface {
	getType() IPType

	getProviderHostAddress() (*IPAddress, IncompatibleAddressException)

	getProviderAddress() (*IPAddress, IncompatibleAddressException)

	getVersionedAddress(version IPVersion) (*IPAddress, IncompatibleAddressException)

	//TODO isSequential
	//isSequential() bool
	//
	//default boolean isSequential() {
	//	try {
	//		IPAddress addr = getProviderAddress();
	//		if(addr != null) {
	//			return addr.isSequential();
	//		}
	//	} catch(IncompatibleAddressException e) {}
	//	return false;
	//}

	// TODO what will be the nil sequential range?  An unversioned range, much like with addresses NO
	// ie it will have nil top and bottom
	// a nil address has a grouping with no segments
	// so a nil range will have no range boundaries, it will be empty

	//TODO getProviderSeqRange
	//default IPAddressSeqRange getProviderSeqRange() {
	//	IPAddress addr = getProviderAddress();
	//	if(addr != null) {
	//		return addr.toSequentialRange();
	//	}
	//	return null;
	//}
	//

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

	isProvidingPrefixOnly() bool

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

// TODO add these later
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

func (p *ipAddrProvider) getProviderHostAddress() (*IPAddress, IncompatibleAddressException) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderAddress() (*IPAddress, IncompatibleAddressException) {
	return nil, nil
}

func (p *ipAddrProvider) getVersionedAddress(version IPVersion) (*IPAddress, IncompatibleAddressException) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderMask() *IPAddress {
	return nil
}

func (p *ipAddrProvider) getProviderIPVersion() IPVersion {
	return UNKNOWN_VERSION
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

func (p *ipAddrProvider) isProvidingPrefixOnly() bool {
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
	if thisType == UNINITIALIZED_TYPE {
		if otherType == UNINITIALIZED_TYPE {
			return
		}
		res = -1
		return
	} else if otherType == UNINITIALIZED_TYPE {
		res = 1
		return
	}
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
			// But you gotta be careful, once you support it you don't want to renege
			// Seems common to have "equal" methods. eg https://godoc.org/bytes#Equal
			// There are vays, namely spearate the stuff for comparison: https://stackoverflow.com/questions/47134293/compare-structs-except-one-field-golang
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
	NO_TYPE_PROVIDER = &nullProvider{isUninitializedVal: true, ipType: UNINITIALIZED_TYPE}
	EMPTY_PROVIDER   = &nullProvider{isEmpty: true, ipType: EMPTY}
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

	//TODO you must assign the addressCreator when created as nested

	// addressCreator creates both host address and address with prefix/mask
	addressCreator func() CachedIPAddresses
	created        atomicFlag
	createLock     sync.Mutex
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

func (cached *CachedAddressProvider) hasCachedAddresses() bool {
	return cached.addressCreator == nil || cached.created.isSet()
}

func (cached *CachedAddressProvider) getCachedAddresses() *CachedIPAddresses {
	if cached.addressCreator != nil && !cached.created.isSet() {
		cached.createLock.Lock()
		if !cached.created.isSet() {
			cached.values = cached.addressCreator()
			cached.created.set()
		}
		cached.createLock.Unlock()
	}
	return &cached.values
}

func (cached *CachedAddressProvider) getProviderNetworkPrefixLength() (p PrefixLen) {
	addr, _ := cached.getProviderAddress()
	return addr.GetNetworkPrefixLength()
}

func (cached *CachedAddressProvider) getProviderIPVersion() IPVersion {
	addr, _ := cached.getProviderAddress()
	return addr.GetIPVersion()
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

	//TODO you must assign the versionedAddressCreator and options when created as nested

	versionedAddressCreator func(IPVersion) *IPAddress
	createdVersioned        [2]atomicFlag
	versionedValues         [2]*IPAddress

	parameters IPAddressStringParameters
}

func (versioned *VersionedAddressCreator) getParameters() IPAddressStringParameters {
	return versioned.parameters
}

func (versioned *VersionedAddressCreator) getVersionedAddress(version IPVersion) (addr *IPAddress, err IncompatibleAddressException) {
	index := version.index()
	if index >= UNKNOWN_VERSION.index() {
		return
	}
	if versioned.versionedAddressCreator != nil && !versioned.createdVersioned[index].isSet() {
		versioned.createLock.Lock()
		if !versioned.createdVersioned[index].isSet() {
			versioned.versionedValues[index] = versioned.versionedAddressCreator(version)
			versioned.createdVersioned[index].set()
		}
		versioned.createLock.Unlock()
	}
	addr = versioned.versionedValues[index]
	return
}

func newLoopbackCreator(options IPAddressStringParameters, zone string) *LoopbackCreator {
	// TODO an option to set preferred loopback here in IPAddressStringParameters, do the same in Java
	// the option will set one of three options, IPv4, IPv6, or UNKNOWN_VERSION which is the default
	// In Go the default will be IPv4
	// There is another option I wanted to add, was in the validator code, I think allow empty zone with prefix like %/
	var preferIPv6 bool
	var addrCreator func() CachedIPAddresses
	ipv6WithZoneLoop := func() *IPAddress {
		network := options.GetIPv6Parameters().GetNetwork()
		creator := network.GetIPAddressCreator()
		return creator.createAddressInternal(network.GetLoopback().getBytes(), zone)
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
	if len(zone) > 0 && preferIPv6 {
		addrCreator = func() CachedIPAddresses { return double(ipv6WithZoneLoop()) }
	} else if preferIPv6 {
		addrCreator = func() CachedIPAddresses { return double(ipv6Loop()) }
	} else {
		addrCreator = func() CachedIPAddresses { return double(ipv4Loop()) }
	}
	cached := CachedAddressProvider{addressCreator: addrCreator}
	return &LoopbackCreator{
		VersionedAddressCreator: VersionedAddressCreator{
			parameters:            options,
			CachedAddressProvider: cached,
			versionedAddressCreator: func(version IPVersion) *IPAddress {
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
			},
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

	//TODO you must assign the networkPrefixLength (could be nil) and in some cases the adjustedVersion

	adjustedVersion     IPVersion
	networkPrefixLength PrefixLen
}

func (adjusted *AdjustedAddressCreator) isProvidingIPAddress() bool {
	return adjusted.adjustedVersion != UNKNOWN_VERSION
}

func (adjusted *AdjustedAddressCreator) isProvidingIPv4() bool {
	return adjusted.adjustedVersion == IPv4
}

func (adjusted *AdjustedAddressCreator) isProvidingIPv6() bool {
	return adjusted.adjustedVersion == IPv6
}

func (adjusted *AdjustedAddressCreator) getProviderIPVersion() IPVersion {
	return adjusted.adjustedVersion
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

//TODO next: your other providers (All, mask, empty), culminating in parsedIPAddress
// next on the list is the versioned creator, then All, mask, empty, then parsedIPAddress

// TODO progress
// - Move towards address creation - need ipaddress provider types fleshed out, and in particular ParsedIPAddress
//	- parsedipaddress will need the start of the ip address creator interfaces
// - Then the mask stuff in parseQualifier can be done, which depends on address creation
// - then IPAddressString and HostName can be fleshed out
// - then you can link up the ip address creator interfaces with the address types
// - here you might start putting in validation tests that check for parsing errors
// - then you can do the string methods in the address sections and addresses and segments
// - the you can add validation tests that use strings, in fact not sure if I do that much, I have some that check the string methods thought
