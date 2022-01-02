//
// Copyright 2020-2021 Sean C Foley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package ipaddr

import (
	"sync/atomic"
	"unsafe"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrparam"
)

// All IP address strings corresponds to exactly one of these types.
// In cases where there is no corresponding default IPAddress value (invalidType, allType, and possibly emptyType), these types can be used for comparison.
// emptyType means a zero-length string (useful for validation, we can set validation to allow empty strings) that has no corresponding IPAddress value (validation options allow you to map empty to the loopback)
// invalidType means it is known that it is not any of the other allowed types (validation options can restrict the allowed types)
// allType means it is wildcard(s) with no separators, like "*", which represents all addresses, whether IPv4, IPv6 or other, and thus has no corresponding IPAddress value
// These constants are ordered by address space size, from smallest to largest, and the ordering affects comparisons
type ipType int

func fromVersion(version IPVersion) ipType {
	switch version {
	case IPv4:
		return ipv4AddrType
	case IPv6:
		return ipv6AddrType
	default:
	}
	return uninitializedType
}

func (t ipType) isUnknown() bool {
	return t == uninitializedType
}

const (
	uninitializedType ipType = iota
	invalidType
	emptyType
	ipv4AddrType
	ipv6AddrType
	//PREFIX_ONLY
	allType
)

type ipAddressProvider interface {
	getType() ipType

	getProviderHostAddress() (*IPAddress, addrerr.IncompatibleAddressError)

	getProviderAddress() (*IPAddress, addrerr.IncompatibleAddressError)

	getVersionedAddress(version IPVersion) (*IPAddress, addrerr.IncompatibleAddressError)

	isSequential() bool

	getProviderSeqRange() *IPAddressSeqRange

	getProviderMask() *IPAddress

	// TODO LATER getDivisionGrouping
	//default IPAddressDivisionSeries getDivisionGrouping() throwsaddrerr.IncompatibleAddressError {
	//	return getProviderAddress();
	//}

	providerCompare(ipAddressProvider) (int, addrerr.IncompatibleAddressError)

	providerEquals(ipAddressProvider) (bool, addrerr.IncompatibleAddressError)

	getProviderIPVersion() IPVersion

	isProvidingIPAddress() bool

	isProvidingIPv4() bool

	isProvidingIPv6() bool

	isProvidingAllAddresses() bool

	isProvidingEmpty() bool

	isProvidingMixedIPv6() bool

	isProvidingBase85IPv6() bool

	getProviderNetworkPrefixLen() PrefixLen

	isInvalid() bool

	// If the address was created by parsing, this provides the parameters used when creating the address,
	// otherwise nil
	getParameters() addrparam.IPAddressStringParams

	// containsProvider is an optimized contains that does not need to create address objects to return an answer.
	// Unconventional addresses may require that the address objects are created, in such cases null is returned.
	//
	// Addresses constructed from canonical or normalized representations with no wildcards will not return null.
	containsProvider(ipAddressProvider) boolSetting

	// contains is an optimized contains that does not need to fully parse the other address to return an answer.
	//
	// Unconventional addresses may require full parsing, in such cases null is returned.
	//
	// Addresses constructed from canonical or normalized representations with no wildcards will not return null.
	contains(string) boolSetting

	// prefixEquals is an optimized prefix comparison that does not need to fully parse the other address to return an answer.
	//
	// Unconventional addresses may require full parsing, in such cases null is returned.
	//
	// Addresses constructed from canonical or normalized representations with no wildcards will not return null.
	prefixEquals(string) boolSetting

	// prefixEqualsProvider is an optimized prefix comparison that does not need to create addresses to return an answer.
	//
	// Unconventional addresses may require the address objects, in such cases null is returned.
	prefixEqualsProvider(ipAddressProvider) boolSetting

	// prefixContains is an optimized prefix comparison that does not need to create addresses to return an answer.
	//
	// Unconventional addresses may require the address objects, in such cases null is returned.
	prefixContains(string) boolSetting

	// prefixContainsProvider is an optimized prefix comparison that does not need to create addresses to return an answer.
	//
	// Unconventional addresses may require the address objects, in such cases null is returned.
	prefixContainsProvider(ipAddressProvider) boolSetting

	// parsedEquals is an optimized equality comparison that does not need to create addresses to return an answer.
	//
	// Unconventional addresses may require the address objects, in such cases null is returned.
	parsedEquals(ipAddressProvider) boolSetting
}

type ipAddrProvider struct{}

func (p *ipAddrProvider) getType() ipType {
	return uninitializedType
}

func (p *ipAddrProvider) isSequential() bool {
	return false
}

func (p *ipAddrProvider) getProviderHostAddress() (*IPAddress, addrerr.IncompatibleAddressError) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderAddress() (*IPAddress, addrerr.IncompatibleAddressError) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderSeqRange() *IPAddressSeqRange {
	return nil
}

func (p *ipAddrProvider) getVersionedAddress(_ IPVersion) (*IPAddress, addrerr.IncompatibleAddressError) {
	return nil, nil
}

func (p *ipAddrProvider) getProviderMask() *IPAddress {
	return nil
}

func (p *ipAddrProvider) getProviderIPVersion() IPVersion {
	return IndeterminateIPVersion
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

func (p *ipAddrProvider) isProvidingMixedIPv6() bool {
	return false
}

func (p *ipAddrProvider) isProvidingBase85IPv6() bool {
	return false
}

func (p *ipAddrProvider) getProviderNetworkPrefixLen() PrefixLen {
	return nil
}

func (p *ipAddrProvider) getParameters() addrparam.IPAddressStringParams {
	return nil
}

func (p *ipAddrProvider) containsProvider(ipAddressProvider) boolSetting {
	return boolSetting{}
}

func (p *ipAddrProvider) contains(string) boolSetting {
	return boolSetting{}
}

func (p *ipAddrProvider) prefixEquals(string) boolSetting {
	return boolSetting{}
}

func (p *ipAddrProvider) prefixEqualsProvider(ipAddressProvider) boolSetting {
	return boolSetting{}
}

func (p *ipAddrProvider) prefixContains(string) boolSetting {
	return boolSetting{}
}

func (p *ipAddrProvider) prefixContainsProvider(ipAddressProvider) boolSetting {
	return boolSetting{}
}

func (p *ipAddrProvider) parsedEquals(ipAddressProvider) boolSetting {
	return boolSetting{}
}

func providerCompare(p, other ipAddressProvider) (res int, err addrerr.IncompatibleAddressError) {
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
			res = value.Compare(otherValue)
			return
		}
	}
	var thisType, otherType = p.getType(), other.getType()
	res = int(thisType - otherType)
	return
}

/**
* When a value provider produces no value, equality and comparison are based on the enum ipType,
* which can by null.
* @param o
* @return
 */
func providerEquals(p, other ipAddressProvider) (res bool, err addrerr.IncompatibleAddressError) {
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
			res = value.Equal(otherValue)
			return
		} else {
			return // returns false
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

	ipType                ipType
	isInvalidVal, isEmpty bool
	//isInvalidVal, isUninitializedVal, isEmpty bool
}

func (p *nullProvider) isInvalid() bool {
	return p.isInvalidVal
}

func (p *nullProvider) isProvidingEmpty() bool {
	return p.isEmpty
}

func (p *nullProvider) getType() ipType {
	return p.ipType
}

func (p *nullProvider) providerCompare(other ipAddressProvider) (int, addrerr.IncompatibleAddressError) {
	return providerCompare(p, other)
}

func (p *nullProvider) providerEquals(other ipAddressProvider) (bool, addrerr.IncompatibleAddressError) {
	return providerEquals(p, other)
}

var (
	invalidProvider = &nullProvider{isInvalidVal: true, ipType: invalidType}
	emptyProvider   = &nullProvider{isEmpty: true, ipType: emptyType}
)

///**
//	 * Wraps an IPAddress for IPAddressString in the cases where no parsing is provided, the address exists already
//	 * @param value
//	 * @return
//	 */
func getProviderFor(address, hostAddress *IPAddress) ipAddressProvider {
	return &cachedAddressProvider{addresses: &addressResult{address: address, hostAddress: hostAddress}}
}

type addressResult struct {
	address, hostAddress *IPAddress

	// addrErr applies to address, hostErr to hostAddress
	addrErr, hostErr addrerr.IncompatibleAddressError
}

type cachedAddressProvider struct {
	ipAddrProvider

	// addressCreator creates two addresses, the host address and address with prefix/mask, at the same time
	addressCreator func() (address, hostAddress *IPAddress, addrErr, hosterr addrerr.IncompatibleAddressError)

	addresses *addressResult
}

func (cached *cachedAddressProvider) providerCompare(other ipAddressProvider) (int, addrerr.IncompatibleAddressError) {
	return providerCompare(cached, other)
}

func (cached *cachedAddressProvider) providerEquals(other ipAddressProvider) (bool, addrerr.IncompatibleAddressError) {
	return providerEquals(cached, other)
}

func (cached *cachedAddressProvider) isProvidingIPAddress() bool {
	return true
}

func (cached *cachedAddressProvider) getVersionedAddress(version IPVersion) (*IPAddress, addrerr.IncompatibleAddressError) {
	thisVersion := cached.getProviderIPVersion()
	if version != thisVersion {
		return nil, nil
	}
	return cached.getProviderAddress()
}

func (cached *cachedAddressProvider) getProviderSeqRange() *IPAddressSeqRange {
	addr, _ := cached.getProviderAddress()
	if addr != nil {
		return addr.ToSequentialRange()
	}
	return nil
}

func (cached *cachedAddressProvider) isSequential() bool {
	addr, _ := cached.getProviderAddress()
	if addr != nil {
		return addr.IsSequential()
	}
	return false
}

//func (cached *cachedAddressProvider) hasCachedAddresses() bool {
//	return cached.addressCreator == nil || cached.isItemCreated()
//}

func (cached *cachedAddressProvider) getProviderHostAddress() (res *IPAddress, err addrerr.IncompatibleAddressError) {
	addrs := cached.addresses
	if addrs == nil {
		_, res, _, err = cached.getCachedAddresses() // sets cached.addresses
	} else {
		res, err = addrs.hostAddress, addrs.hostErr
	}
	return
}

func (cached *cachedAddressProvider) getProviderAddress() (res *IPAddress, err addrerr.IncompatibleAddressError) {
	addrs := cached.addresses
	if addrs == nil {
		res, _, err, _ = cached.getCachedAddresses() // sets cached.addresses
	} else {
		res, err = addrs.address, addrs.addrErr
	}
	return
}

func (cached *cachedAddressProvider) getCachedAddresses() (address, hostAddress *IPAddress, addrErr, hostErr addrerr.IncompatibleAddressError) {
	addrs := cached.addresses
	if addrs == nil {
		if cached.addressCreator != nil {
			address, hostAddress, addrErr, hostErr = cached.addressCreator()
			addresses := &addressResult{
				address:     address,
				hostAddress: hostAddress,
				addrErr:     addrErr,
				hostErr:     hostErr,
			}
			dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cached.addresses))
			atomic.StorePointer(dataLoc, unsafe.Pointer(addresses))
		}
	} else {
		address, hostAddress, addrErr, hostErr = addrs.address, addrs.hostAddress, addrs.addrErr, addrs.hostErr
	}
	return
}

func (cached *cachedAddressProvider) getProviderNetworkPrefixLen() (p PrefixLen) {
	if addr, _ := cached.getProviderAddress(); addr != nil {
		p = addr.getNetworkPrefixLen()
	}
	return
}

func (cached *cachedAddressProvider) getProviderIPVersion() IPVersion {
	if addr, _ := cached.getProviderAddress(); addr != nil {
		return addr.getIPVersion()
	}
	return IndeterminateIPVersion
}

func (cached *cachedAddressProvider) getType() ipType {
	return fromVersion(cached.getProviderIPVersion())
}

func (cached *cachedAddressProvider) isProvidingIPv4() bool {
	addr, _ := cached.getProviderAddress()
	return addr.IsIPv4()
}

func (cached *cachedAddressProvider) isProvidingIPv6() bool {
	addr, _ := cached.getProviderAddress()
	return addr.IsIPv6()
}

type versionedAddressCreator struct {
	cachedAddressProvider

	adjustedVersion IPVersion

	versionedAddressCreatorFunc func(IPVersion) (*IPAddress, addrerr.IncompatibleAddressError)

	versionedValues [2]*IPAddress

	parameters addrparam.IPAddressStringParams
}

func (versioned *versionedAddressCreator) getParameters() addrparam.IPAddressStringParams {
	return versioned.parameters
}

func (versioned *versionedAddressCreator) isProvidingIPAddress() bool {
	return versioned.adjustedVersion != IndeterminateIPVersion
}

func (versioned *versionedAddressCreator) isProvidingIPv4() bool {
	return versioned.adjustedVersion == IPv4
}

func (versioned *versionedAddressCreator) isProvidingIPv6() bool {
	return versioned.adjustedVersion == IPv6
}

func (versioned *versionedAddressCreator) getProviderIPVersion() IPVersion {
	return versioned.adjustedVersion
}

func (versioned *versionedAddressCreator) getType() ipType {
	return fromVersion(versioned.adjustedVersion)
}

func (versioned *versionedAddressCreator) getVersionedAddress(version IPVersion) (addr *IPAddress, err addrerr.IncompatibleAddressError) {
	index := version.index()
	if index >= IndeterminateIPVersion.index() {
		return
	}
	if versioned.versionedAddressCreatorFunc != nil {
		addr = versioned.versionedValues[index]
		if addr == nil {
			addr, err = versioned.versionedAddressCreatorFunc(version)
			if err == nil {
				dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&versioned.versionedValues[index]))
				atomic.StorePointer(dataLoc, unsafe.Pointer(addr))
			}
		}
	}
	addr = versioned.versionedValues[index]
	return
}

func emptyAddressCreator(emptyStrOption addrparam.EmptyStrOption, version IPVersion, zone Zone) (addrCreator func() (address, hostAddress *IPAddress), versionedCreator func() *IPAddress) {
	preferIPv6 := version.IsIPv6()
	double := func(one *IPAddress) (address, hostAddress *IPAddress) {
		return one, one
	}
	if emptyStrOption == addrparam.NoAddressOption {
		addrCreator = func() (*IPAddress, *IPAddress) { return double(nil) }
		versionedCreator = func() *IPAddress { return nil }
	} else if emptyStrOption == addrparam.LoopbackOption {
		if preferIPv6 {
			if len(zone) > 0 {
				ipv6WithZoneLoop := func() *IPAddress {
					network := IPv6Network
					creator := network.getIPAddressCreator()
					return creator.createAddressInternalFromBytes(network.GetLoopback().Bytes(), zone)
				}
				versionedCreator = ipv6WithZoneLoop
				addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv6WithZoneLoop()) }
			} else {
				ipv6Loop := func() *IPAddress {
					return IPv6Network.GetLoopback()
				}
				versionedCreator = ipv6Loop
				addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv6Loop()) }
			}
		} else {
			ipv4Loop := func() *IPAddress {
				return IPv4Network.GetLoopback()
			}
			addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv4Loop()) }
			versionedCreator = ipv4Loop
		}
	} else { // EmptyStrParsedAs() == ZeroAddressOption
		if preferIPv6 {
			if len(zone) > 0 {
				ipv6WithZoneZero := func() *IPAddress {
					network := IPv6Network
					creator := network.getIPAddressCreator()
					return creator.createAddressInternalFromBytes(zeroIPv6.Bytes(), zone)
				}
				versionedCreator = ipv6WithZoneZero
				addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv6WithZoneZero()) }
			} else {
				ipv6Zero := func() *IPAddress {
					return zeroIPv6.ToIP()
				}
				versionedCreator = ipv6Zero
				addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv6Zero()) }
			}
		} else {
			ipv4Zero := func() *IPAddress {
				return zeroIPv4.ToIP()
			}
			addrCreator = func() (*IPAddress, *IPAddress) { return double(ipv4Zero()) }
			versionedCreator = ipv4Zero
		}
	}
	return
}

func newLoopbackCreator(options addrparam.IPAddressStringParams, zone Zone) *loopbackCreator {
	var version = IPVersion(options.GetPreferredVersion())
	addrCreator, versionedCreator := emptyAddressCreator(options.EmptyStrParsedAs(), version, zone)
	cached := cachedAddressProvider{
		addressCreator: func() (address, hostAddress *IPAddress, addrErr, hosterr addrerr.IncompatibleAddressError) {
			address, hostAddress = addrCreator()
			return
		},
	}
	versionedCreatorFunc := func(v IPVersion) *IPAddress {
		addresses := cached.addresses
		if addresses != nil {
			addr := addresses.address
			if v == addr.GetIPVersion() {
				return addr
			}
		}
		if v.IsIndeterminate() {
			return versionedCreator()
		}
		_, vCreator := emptyAddressCreator(options.EmptyStrParsedAs(), v, zone)
		return vCreator()
		//return versionedCreator() xxxxx
	}
	versionedAddressCreatorFunc := func(version IPVersion) (*IPAddress, addrerr.IncompatibleAddressError) {
		return versionedCreatorFunc(version), nil
	}
	return &loopbackCreator{
		versionedAddressCreator: versionedAddressCreator{
			adjustedVersion:             version,
			parameters:                  options,
			cachedAddressProvider:       cached,
			versionedAddressCreatorFunc: versionedAddressCreatorFunc,
		},
		zone: zone,
	}
}

type loopbackCreator struct {
	versionedAddressCreator

	zone Zone
}

func (loop *loopbackCreator) providerCompare(other ipAddressProvider) (int, addrerr.IncompatibleAddressError) {
	return providerCompare(loop, other)
}

func (loop *loopbackCreator) providerEquals(other ipAddressProvider) (bool, addrerr.IncompatibleAddressError) {
	return providerEquals(loop, other)
}

func (loop *loopbackCreator) getProviderNetworkPrefixLen() PrefixLen {
	return nil
}

type adjustedAddressCreator struct {
	versionedAddressCreator

	networkPrefixLength PrefixLen
}

func (adjusted *adjustedAddressCreator) getProviderNetworkPrefixLen() PrefixLen {
	return adjusted.networkPrefixLength
}

func (adjusted *adjustedAddressCreator) getProviderAddress() (*IPAddress, addrerr.IncompatibleAddressError) {
	if !adjusted.isProvidingIPAddress() {
		return nil, nil
	}
	return adjusted.versionedAddressCreator.getProviderAddress()
}

func (adjusted *adjustedAddressCreator) getProviderHostAddress() (*IPAddress, addrerr.IncompatibleAddressError) {
	if !adjusted.isProvidingIPAddress() {
		return nil, nil
	}
	return adjusted.versionedAddressCreator.getProviderHostAddress()
}

func newMaskCreator(options addrparam.IPAddressStringParams, adjustedVersion IPVersion, networkPrefixLength PrefixLen) *maskCreator {
	if adjustedVersion == IndeterminateIPVersion {
		adjustedVersion = IPVersion(options.GetPreferredVersion())
	}
	createVersionedMask := func(version IPVersion, prefLen PrefixLen, withPrefixLength bool) *IPAddress {
		if version == IPv4 {
			network := IPv4Network
			return network.GetNetworkMask(prefLen.bitCount())
		} else if version == IPv6 {
			network := IPv6Network
			return network.GetNetworkMask(prefLen.bitCount())
		}
		return nil
	}
	versionedAddressCreatorFunc := func(version IPVersion) (*IPAddress, addrerr.IncompatibleAddressError) {
		return createVersionedMask(version, networkPrefixLength, true), nil
	}
	maskCreatorFunc := func() (address, hostAddress *IPAddress) {
		prefLen := networkPrefixLength
		return createVersionedMask(adjustedVersion, prefLen, true),
			createVersionedMask(adjustedVersion, prefLen, false)
	}
	addrCreator := func() (address, hostAddress *IPAddress, addrErr, hosterr addrerr.IncompatibleAddressError) {
		address, hostAddress = maskCreatorFunc()
		return
	}
	cached := cachedAddressProvider{addressCreator: addrCreator}
	return &maskCreator{
		adjustedAddressCreator{
			networkPrefixLength: networkPrefixLength,
			versionedAddressCreator: versionedAddressCreator{
				adjustedVersion:             adjustedVersion,
				parameters:                  options,
				cachedAddressProvider:       cached,
				versionedAddressCreatorFunc: versionedAddressCreatorFunc,
			},
		},
	}
}

type maskCreator struct {
	adjustedAddressCreator
}

func newAllCreator(qualifier *parsedHostIdentifierStringQualifier, adjustedVersion IPVersion, originator HostIdentifierString, options addrparam.IPAddressStringParams) ipAddressProvider {
	result := &allCreator{
		adjustedAddressCreator: adjustedAddressCreator{
			networkPrefixLength: qualifier.getEquivalentPrefixLen(),
			versionedAddressCreator: versionedAddressCreator{
				adjustedVersion: adjustedVersion,
				parameters:      options,
			},
		},
		originator: originator,
		qualifier:  *qualifier,
	}
	result.addressCreator = result.createAddrs
	result.versionedAddressCreatorFunc = result.versionedCreate
	return result
}

type allCreator struct {
	adjustedAddressCreator

	originator HostIdentifierString
	qualifier  parsedHostIdentifierStringQualifier

	rng *IPAddressSeqRange
}

func (all *allCreator) getType() ipType {
	if !all.adjustedVersion.IsIndeterminate() {
		return fromVersion(all.adjustedVersion)
	}
	return allType
}

func (all *allCreator) providerCompare(other ipAddressProvider) (int, addrerr.IncompatibleAddressError) {
	return providerCompare(all, other)
}

func (all *allCreator) providerEquals(other ipAddressProvider) (bool, addrerr.IncompatibleAddressError) {
	return providerEquals(all, other)
}

func (all *allCreator) isProvidingAllAddresses() bool {
	return all.adjustedVersion == IndeterminateIPVersion
}

func (all *allCreator) getProviderNetworkPrefixLen() PrefixLen {
	return all.qualifier.getEquivalentPrefixLen()
}

func (all *allCreator) getProviderMask() *IPAddress {
	return all.qualifier.getMaskLower()
}

func (all *allCreator) createAll() (rng *IPAddressSeqRange, addr *IPAddress, hostAddr *IPAddress, addrErr, hostErr addrerr.IncompatibleAddressError) {
	rng = all.rng
	addrs := all.addresses
	if rng == nil || addrs == nil {
		var lower, upper *IPAddress
		addr, hostAddr, lower, upper, addrErr = createAllAddress(
			all.adjustedVersion,
			&all.qualifier,
			all.originator)
		rng = lower.SpanWithRange(upper)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&all.rng))
		atomic.StorePointer(dataLoc, unsafe.Pointer(rng))
		addresses := &addressResult{
			address:     addr,
			hostAddress: hostAddr,
			addrErr:     addrErr,
			hostErr:     hostErr,
		}
		dataLoc = (*unsafe.Pointer)(unsafe.Pointer(&all.addresses))
		atomic.StorePointer(dataLoc, unsafe.Pointer(addresses))
	} else {
		addr, hostAddr, addrErr, hostErr = addrs.address, addrs.hostAddress, addrs.addrErr, addrs.hostErr
	}
	return
}

func (all *allCreator) createRange() (rng *IPAddressSeqRange) {
	rng, _, _, _, _ = all.createAll()
	return
}

func (all *allCreator) createAddrs() (addr *IPAddress, hostAddr *IPAddress, addrErr, hostErr addrerr.IncompatibleAddressError) {
	_, addr, hostAddr, addrErr, hostErr = all.createAll()
	return
}

func (all *allCreator) versionedCreate(version IPVersion) (addr *IPAddress, addrErr addrerr.IncompatibleAddressError) {
	if version == all.adjustedVersion {
		return all.getProviderAddress()
	} else if all.adjustedVersion != IndeterminateIPVersion {
		return nil, nil
	}
	addr, _, _, _, addrErr = createAllAddress(
		version,
		&all.qualifier,
		all.originator)
	return
}

func (all *allCreator) getProviderSeqRange() *IPAddressSeqRange {
	if all.isProvidingAllAddresses() {
		return nil
	}
	rng := all.rng
	if rng == nil {
		rng = all.createRange()
	}
	return rng
}

func (all *allCreator) prefixContainsProvider(otherProvider ipAddressProvider) boolSetting {
	return all.containsProviderFunc(otherProvider, (*IPAddress).prefixContains)
}

func (all *allCreator) containsProvider(otherProvider ipAddressProvider) (res boolSetting) {
	return all.containsProviderFunc(otherProvider, (*IPAddress).contains)
}

func (all *allCreator) containsProviderFunc(otherProvider ipAddressProvider, functor func(*IPAddress, AddressType) bool) (res boolSetting) {
	if otherProvider.isInvalid() {
		return boolSetting{true, false}
	} else if all.adjustedVersion == IndeterminateIPVersion {
		return boolSetting{true, true}
	} else if all.adjustedVersion != otherProvider.getProviderIPVersion() {
		return boolSetting{true, false}
	} else if all.qualifier.getMaskLower() == nil && all.qualifier.getZone() == NoZone {
		return boolSetting{true, true}
	} else if addr, err := all.getProviderAddress(); err != nil {
		return boolSetting{true, false}
	} else if otherAddr, err := all.getProviderAddress(); err != nil {
		return boolSetting{true, false}
	} else {
		return boolSetting{true, functor(addr, otherAddr)}
		//return boolSetting{true, addr.Contains(otherAddr)}
	}
}

// TODO LATER getDivisionGrouping()
//
//		@Override
//		public IPAddressDivisionSeries getDivisionGrouping() throwsaddrerr.IncompatibleAddressError {
//			if(isProvidingAllAddresses()) {
//				return null;
//			}
//			IPAddressNetwork<?, ?, ?, ?, ?> network = adjustedVersion.IsIPv4() ?
//					options.getIPv4Parameters().getNetwork() : options.getIPv6Parameters().getNetwork();
//			IPAddress mask = getProviderMask();
//			if(mask != null && mask.getBlockMaskPrefixLen(true) == null) {
//				// there is a mask
//				Integer hostMaskPrefixLen = mask.getBlockMaskPrefixLen(false);
//				if(hostMaskPrefixLen == null) { // not a host mask
//					throw newaddrerr.IncompatibleAddressError(getProviderAddress(), mask, "ipaddress.error.maskMismatch");
//				}
//				IPAddress hostMask = network.getHostMask(hostMaskPrefixLen);
//				return hostMask.toPrefixBlock();
//			}
//			IPAddressDivisionSeries grouping;
//			if(adjustedVersion.IsIPv4()) {
//				grouping = new IPAddressDivisionGrouping(new IPAddressBitsDivision[] {
//							new IPAddressBitsDivision(0, IPv4Address.MAX_VALUE, IPv4Address.BIT_COUNT, IPv4Address.DEFAULT_TEXTUAL_RADIX, network, qualifier.getEquivalentPrefixLength())
//						}, network);
//			} else if(adjustedVersion.IsIPv6()) {
//				byte upperBytes[] = new byte[16];
//				Arrays.fill(upperBytes, (byte) 0xff);
//				grouping = new IPAddressLargeDivisionGrouping(new IPAddressLargeDivision[] {new IPAddressLargeDivision(new byte[IPv6Address.BYTE_COUNT], upperBytes, IPv6Address.BIT_COUNT, IPv6Address.DEFAULT_TEXTUAL_RADIX, network, qualifier.getEquivalentPrefixLength())}, network);
//			} else {
//				grouping = null;
//			}
//			return grouping;
//		}
//	}

// TODO NEXT progress
//
// - go over the java to-dos as some might make sense in golang too
// - go over the goland warnings, they do help a bit to find issues
// - clean up

// Look into splitting this up.  Can we move the framework into new package? iterators?
// How do you group the constructors with their associated types?
//  it seems that constructors with errors must use error for godoc to group them properly
//	Are there ways around this?  Should we simplify our errors?  Group constructors into their own type (this is a lame idea)?
// Can we make godoc recognize errors?
// source might be here: https://github.com/golang/pkgsite/blob/51e9505d354ca32c3b505a62c0c143969000577d/internal/godoc/internal/doc/reader.go
// note "fixlist" in above source
// this line: https://github.com/golang/pkgsite/blob/51e9505d354ca32c3b505a62c0c143969000577d/internal/godoc/internal/doc/reader.go#L411
// Code suggests that if imported, that would be influential
// Yeah, I think that is key.  It is not about error.  It is about imported types.  ALso predeclared types, like int8, which also includes error too.
// So moving them into another package would do the trick I think.
//  builders and params separated
// pkgs: addrerr, addrfwork, addriter or iter, maybe addrformat (iterators, string parameters/builders, framework interfaces)
// kind leaning to putting them all in addrformat to match Java
// OK, iterators will not work.  Because of cycle.  base points to iterators.  Next() of each iterator points to base.
// In fact, this is a big reason why you ended up using one package.
// string parameters/builders: should be separable.
// framework interfaces: the checks for each framework interface not separable (actually, they are, IF you have the sub depending on the base, which is the reverse of what we have for addrerr).
// So, it depends which way we want that dependency to go.  We probably want it to go like addrerr.  NOPE.  We have plenty of dependencies in the framework on the base.
// But some interfaces in the framework used by the base!
// We are screwed.  The two are intertwined.
// so that leaves the string params and builders.
// There is a dependency on constances like IPVersion.  And a reverse dependency on constants like EmptyStrOption
//
//xxx TODO change addrparam to addrstrparam - maybe other can be addrstrgen xxx maybe addrstringparam addrstringgen
// maybe addrstring and addrstringparam - this pair in the lead I think
// or addrstr and addrstrparam YEAH
// TODO package names addrstr and addrparam, I think I want to keep them separate, but, hard time picking package names
// addrstr would apply to both, addrinstr and addroutstr?  nah  strparams?  nah

//
//  rename addrFormat addrParams, then recreate addrFormat
//  it looks like you can realize your goal of moving address framework into addrFormat by moving all the basic types in there
// ACTUALLY, still not possible, due to stuff like: ToAddressBase() *Address
// Parts of the framework we use cannot be moved (actually no, it is the reverse direction we need to be careful about)
// we can only move:
// BitCount
// PrefixLen
//
// AddressItem
// AddressComponent
// AddressDivisionSeries
//
// DivisionType
// Does not seem worth it
// Nor do I think that base types like BitCount belong in addrformat
//  it does like look perhaps you can split off StringOptions, StringOptionsBuilder - which would split off about 17 types, not bad
//
//  figure out why my license not being detected - https://pkg.go.dev/github.com/google/licensecheck#section-documentation
// It may simply be because in local mode it skips the license check
//  it seems the godoc doesn't list GetPrefixCount for IPv4Address, but it does for MACAddress.  Huh?
// Is this because it only goes down one level?  Do I need to accomodate this (ie add to ipaddressInternal stuff from addressInternal?)
// Yes.

// TODO figure out whether you go for a separate repo or not
// Basically I discovered that version names seem to map directly to tags
// discussion here on multiple modules per repo: https://research.swtch.com/vgo-module#multiple-module_repositories
/*
It seems that go mandates the same format for tags.
Because it must follow semantic versioning. Been unable to see how tag could differ from version, but even if it did, conflicting with existing tags may be lame.

So, you'd have to reuse your existing ones to start from version 1. You could also start using new tags with "java' for future java releases, and start golang at version 6.
https://go.dev/ref/mod
https://go.dev/blog/using-go-modules

https://github.com/golang/go/issues/47757

Options
You could rename all your java tags. Unfortunately, this would likely require you to redo all your github releases.check github for an easier option.
Actually, maybe not.  Create the dup tag first, edit the release to the new tag, and you are good. So there ya go, you could do it that way.

https://huongdanjava.com/rename-tag-git.html

https://gist.github.com/da-n/9998623

https://stackoverflow.com/questions/1028649/how-do-you-rename-a-git-tag

this link is just interesting:
https://donatstudios.com/Go-v2-Modules

Or you use a separate project. Which still allows you to leverage google, using your other link... use the same docs and wiki.

Same repo:
Pros Shared
- higher stars
- google ranking
- shared wiki, shared web pages
- already we support multi languages
- emphasis on similarity
- same repo name, ie "IPAddress", although even then, you include the extra "ipaddress-go" in the path

Pros separate
- a little unusual, no need to keep them same repo
- versioning / tags / branching
- you can still make use of one of the google rankings by sharing the docs
- versioning becomes more complicated with same repo.
- no downloading extra code
- shorter import path
- can see different stats and traffic for each
- another popular URL for google

The original plan was to use same repo, in part for more stars
*/
