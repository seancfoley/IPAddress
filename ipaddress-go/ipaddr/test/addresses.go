//
// Copyright 2020-2022 Sean C Foley
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

package test

import (
	"net"
	"sync"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrstrparam"
)

var (
	hostOptions = new(addrstrparam.HostNameParamsBuilder).
			AllowEmpty(false).
			NormalizeToLowercase(true).
			AllowPort(true).
			AllowService(true).
			AllowBracketedIPv6(true).
			AllowBracketedIPv4(true).
			GetIPAddressParamsBuilder().
			AllowPrefix(true).
			AllowMask(true).
			SetRangeParams(addrstrparam.NoRange).
			Allow_inet_aton(false).
			AllowEmpty(false).
			AllowAll(false).
			AllowSingleSegment(false).
			GetIPv4AddressParamsBuilder().
			AllowLeadingZeros(true).
			AllowUnlimitedLeadingZeros(false).
			AllowPrefixLenLeadingZeros(true).
			AllowPrefixesBeyondAddressSize(false).
			AllowWildcardedSeparator(true).
			AllowBinary(true).
			GetParentBuilder().
			GetIPv6AddressParamsBuilder().
			AllowLeadingZeros(true).
			AllowUnlimitedLeadingZeros(false).
			AllowPrefixLenLeadingZeros(true).
			AllowPrefixesBeyondAddressSize(false).
			AllowWildcardedSeparator(true).
			AllowMixed(true).
			AllowZone(true).
			AllowBinary(true).
			GetParentBuilder().GetParentBuilder().ToParams()

	hostInetAtonOptions = new(addrstrparam.HostNameParamsBuilder).Set(hostOptions).GetIPAddressParamsBuilder().Allow_inet_aton(true).AllowSingleSegment(true).GetParentBuilder().ToParams()

	addressOptions = new(addrstrparam.IPAddressStringParamsBuilder).Set(hostOptions.GetIPAddressParams()).ToParams()

	macAddressOptions = new(addrstrparam.MACAddressStringParamsBuilder).
				AllowEmpty(false).
				AllowAll(false).
				GetFormatParamsBuilder().
				SetRangeParams(addrstrparam.NoRange).
				AllowLeadingZeros(true).
				AllowUnlimitedLeadingZeros(false).
				AllowWildcardedSeparator(true).
				AllowShortSegments(true).
				GetParentBuilder().
				ToParams()
)

type testAddresses interface {
	createAddress(string) *ipaddr.IPAddressString

	createInetAtonAddress(string) *ipaddr.IPAddressString

	createParametrizedAddress(string, addrstrparam.RangeParams) *ipaddr.IPAddressString

	createParamsAddress(string, addrstrparam.IPAddressStringParams) *ipaddr.IPAddressString

	createAddressFromIP(ip net.IP) *ipaddr.IPAddress

	createIPv4Address(uint32) *ipaddr.IPv4Address

	createIPv6Address(high, low uint64) *ipaddr.IPv6Address

	createDoubleParametrizedAddress(str string, ipv4Params, ipv6Params addrstrparam.RangeParams) *ipaddr.IPAddressString

	createHost(string) *ipaddr.HostName

	createInetAtonHost(string) *ipaddr.HostName

	createParamsHost(string, addrstrparam.HostNameParams) *ipaddr.HostName

	createMACAddress(string) *ipaddr.MACAddressString

	createMACAddressFromBytes(bytes net.HardwareAddr) *ipaddr.MACAddress

	createMACAddressFromUint64(bytes uint64, extended bool) *ipaddr.MACAddress

	createMACParamsAddress(string, addrstrparam.MACAddressStringParams) *ipaddr.MACAddressString

	isLenient() bool

	allowsRange() bool
}

type addresses struct {
	caching bool

	strIPAddressStrCache     map[string]*ipaddr.IPAddressString
	strIPAddressStrCacheLock *sync.Mutex

	inetAtonStrIPAddressStrCache     map[string]*ipaddr.IPAddressString
	inetAtonStrIPAddressStrCacheLock *sync.Mutex

	netIPv4AddressCache     map[[4]byte]*ipaddr.IPAddress
	netIPv4AddressCacheLock *sync.Mutex
	netIPv6AddressCache     map[[16]byte]*ipaddr.IPAddress
	netIPv6AddressCacheLock *sync.Mutex

	intIPv4AddressCache     map[uint32]*ipaddr.IPv4Address
	intIPv4AddressCacheLock *sync.Mutex

	intsIPv6AddressCache     map[[2]uint64]*ipaddr.IPv6Address
	intsIPv6AddressCacheLock *sync.Mutex

	strMACAddressStrCache     map[string]*ipaddr.MACAddressString
	strMACAddressStrCacheLock *sync.Mutex

	netMACAddressCache        map[[6]byte]*ipaddr.MACAddress
	netMACAddressCacheLock    *sync.Mutex
	netMACExtAddressCache     map[[8]byte]*ipaddr.MACAddress
	netMACExtAddressCacheLock *sync.Mutex

	uint64MACAddressCache        map[uint64]*ipaddr.MACAddress
	uint64MACAddressCacheLock    *sync.Mutex
	uint64MACExtAddressCache     map[uint64]*ipaddr.MACAddress
	uint64MACExtAddressCacheLock *sync.Mutex

	strHostStrCache     map[string]*ipaddr.HostName
	strHostStrCacheLock *sync.Mutex

	inetAtonStrHostStrCache      map[string]*ipaddr.HostName
	inetAtonStrIHostStrCacheLock *sync.Mutex

	strParamsIPAddressStrCache     map[addrstrparam.IPAddressStringParams]map[string]*ipaddr.IPAddressString
	strParamsIPAddressStrCacheLock *sync.Mutex

	strParamsMACAddressStrCache     map[addrstrparam.MACAddressStringParams]map[string]*ipaddr.MACAddressString
	strParamsMACAddressStrCacheLock *sync.Mutex

	strParamsHostStrCache     map[addrstrparam.HostNameParams]map[string]*ipaddr.HostName
	strParamsHostStrCacheLock *sync.Mutex
}

func (t *addresses) useCache(use bool) {
	if use {
		t.caching = use
		t.strIPAddressStrCache = make(map[string]*ipaddr.IPAddressString)
		t.strIPAddressStrCacheLock = &sync.Mutex{}
		t.inetAtonStrIPAddressStrCache = make(map[string]*ipaddr.IPAddressString)
		t.inetAtonStrIPAddressStrCacheLock = &sync.Mutex{}
		t.netIPv4AddressCache = make(map[[4]byte]*ipaddr.IPAddress)
		t.netIPv4AddressCacheLock = &sync.Mutex{}
		t.netIPv6AddressCache = make(map[[16]byte]*ipaddr.IPAddress)
		t.netIPv6AddressCacheLock = &sync.Mutex{}
		t.intIPv4AddressCache = make(map[uint32]*ipaddr.IPv4Address)
		t.intIPv4AddressCacheLock = &sync.Mutex{}
		t.intsIPv6AddressCache = make(map[[2]uint64]*ipaddr.IPv6Address)
		t.intsIPv6AddressCacheLock = &sync.Mutex{}

		t.strMACAddressStrCache = make(map[string]*ipaddr.MACAddressString)
		t.strMACAddressStrCacheLock = &sync.Mutex{}

		t.netMACAddressCache = make(map[[6]byte]*ipaddr.MACAddress)
		t.netMACAddressCacheLock = &sync.Mutex{}
		t.netMACExtAddressCache = make(map[[8]byte]*ipaddr.MACAddress)
		t.netMACExtAddressCacheLock = &sync.Mutex{}

		t.uint64MACAddressCache = make(map[uint64]*ipaddr.MACAddress)
		t.uint64MACAddressCacheLock = &sync.Mutex{}
		t.uint64MACExtAddressCache = make(map[uint64]*ipaddr.MACAddress)
		t.uint64MACExtAddressCacheLock = &sync.Mutex{}

		t.strHostStrCache = make(map[string]*ipaddr.HostName)
		t.strHostStrCacheLock = &sync.Mutex{}

		t.inetAtonStrHostStrCache = make(map[string]*ipaddr.HostName)
		t.inetAtonStrIHostStrCacheLock = &sync.Mutex{}

		t.strParamsIPAddressStrCache = make(map[addrstrparam.IPAddressStringParams]map[string]*ipaddr.IPAddressString)
		t.strParamsIPAddressStrCacheLock = &sync.Mutex{}

		t.strParamsMACAddressStrCache = make(map[addrstrparam.MACAddressStringParams]map[string]*ipaddr.MACAddressString)
		t.strParamsMACAddressStrCacheLock = &sync.Mutex{}

		t.strParamsHostStrCache = make(map[addrstrparam.HostNameParams]map[string]*ipaddr.HostName)
		t.strParamsHostStrCacheLock = &sync.Mutex{}
	} else {
		*t = addresses{}
	}
}

func (t *addresses) createParametrizedAddress(str string, params addrstrparam.RangeParams) *ipaddr.IPAddressString {
	var opts addrstrparam.IPAddressStringParams
	if params == addrstrparam.NoRange {
		opts = noRangeAddressOptions
	} else if params == addrstrparam.WildcardOnly {
		opts = wildcardOnlyAddressOptions
	} else if params == addrstrparam.WildcardAndRange {
		opts = wildcardAndRangeAddressOptions
	} else {
		opts = new(addrstrparam.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).
			SetRangeParams(params).ToParams()
	}
	if t.caching {
		return t.createParamsAddress(str, opts)
	}
	return ipaddr.NewIPAddressStringParams(str, opts)
}

func (t *addresses) createParamsAddress(str string, opts addrstrparam.IPAddressStringParams) (res *ipaddr.IPAddressString) {
	if t.caching {
		t.strParamsIPAddressStrCacheLock.Lock()
		defer t.strParamsIPAddressStrCacheLock.Unlock()
		mp := t.strParamsIPAddressStrCache[opts]
		if mp == nil {
			t.strParamsIPAddressStrCache[opts] = make(map[string]*ipaddr.IPAddressString)
		} else {
			res = mp[str]
			if res != nil {
				return
			}
		}
	}
	res = ipaddr.NewIPAddressStringParams(str, opts)
	if t.caching {
		t.strParamsIPAddressStrCache[opts][str] = res
	}
	return
}

func (t *addresses) createDoubleParametrizedAddress(str string, ipv4Params, ipv6Params addrstrparam.RangeParams) *ipaddr.IPAddressString {
	var opts addrstrparam.IPAddressStringParams
	if ipv4Params == ipv6Params {
		if ipv4Params == addrstrparam.NoRange {
			opts = noRangeAddressOptions
		} else if ipv4Params == addrstrparam.WildcardOnly {
			opts = wildcardOnlyAddressOptions
		} else if ipv4Params == addrstrparam.WildcardAndRange {
			opts = wildcardAndRangeAddressOptions
		}
	}
	if opts == nil {
		opts = new(addrstrparam.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).
			GetIPv4AddressParamsBuilder().SetRangeParams(ipv4Params).GetParentBuilder().
			GetIPv6AddressParamsBuilder().SetRangeParams(ipv6Params).GetParentBuilder().ToParams()
	}
	if t.caching {
		return t.createParamsAddress(str, opts)
	}
	return ipaddr.NewIPAddressStringParams(str, opts)
}

func (t *addresses) createAddress(str string) (res *ipaddr.IPAddressString) {
	if t.caching {
		t.strIPAddressStrCacheLock.Lock()
		defer t.strIPAddressStrCacheLock.Unlock()
		res = t.strIPAddressStrCache[str]
		if res != nil {
			//fmt.Printf("reusing %v\n", res)
			return
		}
	}
	res = ipaddr.NewIPAddressStringParams(str, addressOptions)
	if t.caching {
		t.strIPAddressStrCache[str] = res
	}
	return
}

func (t *addresses) createInetAtonAddress(str string) (res *ipaddr.IPAddressString) {
	if t.caching {
		t.inetAtonStrIPAddressStrCacheLock.Lock()
		defer t.inetAtonStrIPAddressStrCacheLock.Unlock()
		res = t.inetAtonStrIPAddressStrCache[str]
		if res != nil {
			return
		}
	}
	res = ipaddr.NewIPAddressStringParams(str, inetAtonwildcardAndRangeOptions)
	if t.caching {
		t.inetAtonStrIPAddressStrCache[str] = res
	}
	return
}

func (t *addresses) createAddressFromIP(ip net.IP) (res *ipaddr.IPAddress) {
	if t.caching {
		if ipv4 := ip.To4(); ipv4 != nil {
			t.netIPv4AddressCacheLock.Lock()
			defer t.netIPv4AddressCacheLock.Unlock()
			var key [4]byte
			copy(key[:], ipv4)
			res = t.netIPv4AddressCache[key]
			if res != nil {
				return
			}
			res, _ = ipaddr.NewIPAddressFromNetIP(ip)
			t.netIPv4AddressCache[key] = res
		} else if len(ip) == 16 {
			t.netIPv6AddressCacheLock.Lock()
			defer t.netIPv6AddressCacheLock.Unlock()
			var key [16]byte
			copy(key[:], ip)
			res = t.netIPv6AddressCache[key]
			if res != nil {
				return
			}
			res, _ = ipaddr.NewIPAddressFromNetIP(ip)
			t.netIPv6AddressCache[key] = res
		} else {
			res, _ = ipaddr.NewIPAddressFromNetIP(ip)
		}
		return
	}
	res, _ = ipaddr.NewIPAddressFromNetIP(ip)
	return
}

func (t *addresses) createIPv4Address(val uint32) (res *ipaddr.IPv4Address) {
	if t.caching {
		t.intIPv4AddressCacheLock.Lock()
		defer t.intIPv4AddressCacheLock.Unlock()
		res = t.intIPv4AddressCache[val]
		if res != nil {
			return
		}
	}
	res = ipaddr.NewIPv4AddressFromUint32(val)
	if t.caching {
		t.intIPv4AddressCache[val] = res
	}
	return
}

func (t *addresses) createIPv6Address(high, low uint64) (res *ipaddr.IPv6Address) {
	if t.caching {
		t.intsIPv6AddressCacheLock.Lock()
		defer t.intsIPv6AddressCacheLock.Unlock()
		var key [2]uint64
		key[0], key[1] = low, high
		res = t.intsIPv6AddressCache[key]
		if res != nil {
			return
		}
		res = ipaddr.NewIPv6AddressFromUint64(high, low)
		t.intsIPv6AddressCache[key] = res
		return
	}
	return ipaddr.NewIPv6AddressFromUint64(high, low)
}

func (t *addresses) createMACAddress(str string) (res *ipaddr.MACAddressString) {
	if t.caching {
		t.strMACAddressStrCacheLock.Lock()
		defer t.strMACAddressStrCacheLock.Unlock()
		res = t.strMACAddressStrCache[str]
		if res != nil {
			//fmt.Printf("reusing %v\n", res)
			return
		}
	}
	res = ipaddr.NewMACAddressStringParams(str, macAddressOptions)
	if t.caching {
		t.strMACAddressStrCache[str] = res
	}
	return
}

func (t *addresses) createMACAddressFromBytes(bytes net.HardwareAddr) (res *ipaddr.MACAddress) {
	if t.caching {
		if len(bytes) == 6 {
			t.netMACAddressCacheLock.Lock()
			defer t.netMACAddressCacheLock.Unlock()
			var key [6]byte
			copy(key[:], bytes)
			res = t.netMACAddressCache[key]
			if res != nil {
				return
			}
			res, _ = ipaddr.NewMACAddressFromBytes(bytes)
			t.netMACAddressCache[key] = res
		} else if len(bytes) == 8 {
			t.netMACExtAddressCacheLock.Lock()
			defer t.netMACExtAddressCacheLock.Unlock()
			var key [8]byte
			copy(key[:], bytes)
			res = t.netMACExtAddressCache[key]
			if res != nil {
				return
			}
			res, _ = ipaddr.NewMACAddressFromBytes(bytes)
			t.netMACExtAddressCache[key] = res
		} else {
			res, _ = ipaddr.NewMACAddressFromBytes(bytes)
		}
		return
	}
	res, _ = ipaddr.NewMACAddressFromBytes(bytes)
	return
}

func (t *addresses) createMACAddressFromUint64(bytes uint64, extended bool) (res *ipaddr.MACAddress) {
	if t.caching {
		if extended {
			t.uint64MACExtAddressCacheLock.Lock()
			defer t.uint64MACExtAddressCacheLock.Unlock()
			res = t.uint64MACExtAddressCache[bytes]
			if res != nil {
				return
			}
			res = ipaddr.NewMACAddressFromUint64Ext(bytes, extended)
			t.uint64MACExtAddressCache[bytes] = res
		} else {
			t.uint64MACAddressCacheLock.Lock()
			defer t.uint64MACAddressCacheLock.Unlock()
			res = t.uint64MACAddressCache[bytes]
			if res != nil {
				return
			}
			res = ipaddr.NewMACAddressFromUint64Ext(bytes, extended)
			t.uint64MACAddressCache[bytes] = res
		}
		return
	}
	res = ipaddr.NewMACAddressFromUint64Ext(bytes, extended)
	return
}

func (t *addresses) createMACParamsAddress(str string, opts addrstrparam.MACAddressStringParams) (res *ipaddr.MACAddressString) {
	if t.caching {
		t.strParamsMACAddressStrCacheLock.Lock()
		defer t.strParamsMACAddressStrCacheLock.Unlock()
		mp := t.strParamsMACAddressStrCache[opts]
		if mp == nil {
			t.strParamsMACAddressStrCache[opts] = make(map[string]*ipaddr.MACAddressString)
		} else {
			res = mp[str]
			if res != nil {
				return
			}
		}
	}
	res = ipaddr.NewMACAddressStringParams(str, opts)
	if t.caching {
		t.strParamsMACAddressStrCache[opts][str] = res
	}
	return
}

func (t *addresses) createHost(str string) (res *ipaddr.HostName) {
	if t.caching {
		t.strHostStrCacheLock.Lock()
		defer t.strHostStrCacheLock.Unlock()
		res = t.strHostStrCache[str]
		if res != nil {
			//fmt.Printf("reusing %v\n", res)
			return
		}
	}
	res = ipaddr.NewHostNameParams(str, hostOptions)
	if t.caching {
		t.strHostStrCache[str] = res
	}
	return
}

func (t *addresses) createInetAtonHost(str string) (res *ipaddr.HostName) {
	if t.caching {
		t.inetAtonStrIHostStrCacheLock.Lock()
		defer t.inetAtonStrIHostStrCacheLock.Unlock()
		res = t.inetAtonStrHostStrCache[str]
		if res != nil {
			return
		}
	}
	res = ipaddr.NewHostNameParams(str, hostInetAtonOptions)
	if t.caching {
		t.inetAtonStrHostStrCache[str] = res
	}
	return
}

func (t *addresses) createParamsHost(str string, opts addrstrparam.HostNameParams) (res *ipaddr.HostName) {
	if t.caching {
		t.strParamsHostStrCacheLock.Lock()
		defer t.strParamsHostStrCacheLock.Unlock()
		mp := t.strParamsHostStrCache[opts]
		if mp == nil {
			t.strParamsHostStrCache[opts] = make(map[string]*ipaddr.HostName)
		} else {
			res = mp[str]
			if res != nil {
				return
			}
		}
	}
	res = ipaddr.NewHostNameParams(str, opts)
	if t.caching {
		t.strParamsHostStrCache[opts][str] = res
	}
	return
}

func (t *addresses) isLenient() bool {
	return false
}

func (t *addresses) allowsRange() bool {
	return false
}

type rangedAddresses struct {
	addresses

	rstrIPAddressStrCache     map[string]*ipaddr.IPAddressString
	rstrIPAddressStrCacheLock *sync.Mutex

	rstrMACAddressStrCache     map[string]*ipaddr.MACAddressString
	rstrMACAddressStrCacheLock *sync.Mutex

	rstrHostStrCache     map[string]*ipaddr.HostName
	rstrHostStrCacheLock *sync.Mutex

	rinetAtonStrHostStrCache      map[string]*ipaddr.HostName
	rinetAtonStrIHostStrCacheLock *sync.Mutex
}

func (t *rangedAddresses) useCache(use bool) {
	if use {
		t.rstrIPAddressStrCache = make(map[string]*ipaddr.IPAddressString)
		t.rstrIPAddressStrCacheLock = &sync.Mutex{}

		t.rstrMACAddressStrCache = make(map[string]*ipaddr.MACAddressString)
		t.rstrMACAddressStrCacheLock = &sync.Mutex{}

		t.rstrHostStrCache = make(map[string]*ipaddr.HostName)
		t.rstrHostStrCacheLock = &sync.Mutex{}

		t.rinetAtonStrHostStrCache = make(map[string]*ipaddr.HostName)
		t.rinetAtonStrIHostStrCacheLock = &sync.Mutex{}
	} else {
		*t = rangedAddresses{}
	}
	t.addresses.useCache(use)
}

var (
	wildcardAndRangeAddressOptions = new(addrstrparam.IPAddressStringParamsBuilder).Set(addressOptions).AllowAll(true).SetRangeParams(addrstrparam.WildcardAndRange).ToParams()
	wildcardOnlyAddressOptions     = new(addrstrparam.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParams(addrstrparam.WildcardOnly).ToParams()
	noRangeAddressOptions          = new(addrstrparam.IPAddressStringParamsBuilder).Set(wildcardAndRangeAddressOptions).SetRangeParams(addrstrparam.NoRange).ToParams()

	wildcardAndRangeMACAddressOptions = new(addrstrparam.MACAddressStringParamsBuilder).Set(macAddressOptions).AllowAll(true).GetFormatParamsBuilder().SetRangeParams(addrstrparam.WildcardAndRange).GetParentBuilder().ToParams()

	hostInetAtonwildcardAndRangeOptions = new(addrstrparam.HostNameParamsBuilder).
						AllowEmpty(false).
						NormalizeToLowercase(true).
						AllowBracketedIPv6(true).
						AllowBracketedIPv4(true).GetIPAddressParamsBuilder().
						AllowPrefix(true).
						AllowMask(true).
						SetRangeParams(addrstrparam.WildcardAndRange).
						Allow_inet_aton(true).
						AllowEmpty(false).
						AllowAll(true).
						GetIPv4AddressParamsBuilder().
						AllowPrefixLenLeadingZeros(true).
						AllowPrefixesBeyondAddressSize(false).
						AllowWildcardedSeparator(true).
						GetParentBuilder().GetParentBuilder().ToParams()

	inetAtonwildcardAndRangeOptions = new(addrstrparam.IPAddressStringParamsBuilder).Set(hostInetAtonwildcardAndRangeOptions.GetIPAddressParams()).ToParams()

	hostWildcardOptions = new(addrstrparam.HostNameParamsBuilder).Set(hostOptions).GetIPAddressParamsBuilder().
				AllowAll(true).SetRangeParams(addrstrparam.WildcardOnly).GetParentBuilder().ToParams()

	hostOnlyOptions = new(addrstrparam.HostNameParamsBuilder).Set(hostOptions).AllowIPAddress(false).ToParams()

	hostWildcardAndRangeOptions = new(addrstrparam.HostNameParamsBuilder).Set(hostWildcardOptions).GetIPAddressParamsBuilder().SetRangeParams(addrstrparam.WildcardAndRange).GetParentBuilder().ToParams()

	hostWildcardAndRangeInetAtonOptions = new(addrstrparam.HostNameParamsBuilder).Set(hostWildcardOptions).GetIPAddressParamsBuilder().SetRangeParams(addrstrparam.WildcardAndRange).Allow_inet_aton(true).GetParentBuilder().ToParams()
)

func (t *rangedAddresses) createAddress(str string) (res *ipaddr.IPAddressString) {
	if t.caching {
		t.rstrIPAddressStrCacheLock.Lock()
		defer t.rstrIPAddressStrCacheLock.Unlock()
		res = t.rstrIPAddressStrCache[str]
		if res != nil {
			return
		}
	}
	res = ipaddr.NewIPAddressStringParams(str, wildcardAndRangeAddressOptions)
	if t.caching {
		t.rstrIPAddressStrCache[str] = res
	}
	return
}

func (t *rangedAddresses) createMACAddress(str string) (res *ipaddr.MACAddressString) {
	if t.caching {
		t.rstrMACAddressStrCacheLock.Lock()
		defer t.rstrMACAddressStrCacheLock.Unlock()
		res = t.rstrMACAddressStrCache[str]
		if res != nil {
			return
		}
	}
	res = ipaddr.NewMACAddressStringParams(str, wildcardAndRangeMACAddressOptions)
	if t.caching {
		t.rstrMACAddressStrCache[str] = res
	}
	return
}

func (t *rangedAddresses) createHost(str string) (res *ipaddr.HostName) {
	if t.caching {
		t.rstrHostStrCacheLock.Lock()
		defer t.rstrHostStrCacheLock.Unlock()
		res = t.rstrHostStrCache[str]
		if res != nil {
			return
		}
	}
	res = ipaddr.NewHostNameParams(str, hostWildcardOptions)
	if t.caching {
		t.rstrHostStrCache[str] = res
	}
	return
}

func (t *rangedAddresses) createInetAtonHost(str string) (res *ipaddr.HostName) {
	if t.caching {
		t.rinetAtonStrIHostStrCacheLock.Lock()
		defer t.rinetAtonStrIHostStrCacheLock.Unlock()
		res = t.rinetAtonStrHostStrCache[str]
		if res != nil {
			return
		}
	}
	res = ipaddr.NewHostNameParams(str, hostInetAtonwildcardAndRangeOptions)
	if t.caching {
		t.rinetAtonStrHostStrCache[str] = res
	}
	return
}

func (t *rangedAddresses) allowsRange() bool {
	return true
}

var (
	defaultOptions     = new(addrstrparam.IPAddressStringParamsBuilder).ToParams()
	defaultHostOptions = new(addrstrparam.HostNameParamsBuilder).ToParams()
)

type allAddresses struct {
	rangedAddresses

	astrIPAddressStrCache     map[string]*ipaddr.IPAddressString
	astrIPAddressStrCacheLock *sync.Mutex

	astrHostStrCache     map[string]*ipaddr.HostName
	astrHostStrCacheLock *sync.Mutex

	ainetAtonStrHostStrCache      map[string]*ipaddr.HostName
	ainetAtonStrIHostStrCacheLock *sync.Mutex
}

func (t *allAddresses) useCache(use bool) {
	if use {
		t.astrIPAddressStrCache = make(map[string]*ipaddr.IPAddressString)
		t.astrIPAddressStrCacheLock = &sync.Mutex{}

		t.astrHostStrCache = make(map[string]*ipaddr.HostName)
		t.astrHostStrCacheLock = &sync.Mutex{}

		t.ainetAtonStrHostStrCache = make(map[string]*ipaddr.HostName)
		t.ainetAtonStrIHostStrCacheLock = &sync.Mutex{}
	} else {
		*t = allAddresses{}
	}
	t.rangedAddresses.useCache(use)
}

func (t *allAddresses) createAddress(str string) (res *ipaddr.IPAddressString) {
	if t.caching {
		t.astrIPAddressStrCacheLock.Lock()
		defer t.astrIPAddressStrCacheLock.Unlock()
		res = t.astrIPAddressStrCache[str]
		if res != nil {
			return
		}
	}
	res = ipaddr.NewIPAddressStringParams(str, defaultOptions)
	if t.caching {
		t.astrIPAddressStrCache[str] = res
	}
	return
}

func (t *allAddresses) createInetAtonAddress(str string) *ipaddr.IPAddressString {
	return t.createAddress(str)
}

func (t *allAddresses) createHost(str string) (res *ipaddr.HostName) {
	if t.caching {
		t.astrHostStrCacheLock.Lock()
		defer t.astrHostStrCacheLock.Unlock()
		res = t.astrHostStrCache[str]
		if res != nil {
			return
		}
	}
	res = ipaddr.NewHostNameParams(str, defaultHostOptions)
	if t.caching {
		t.astrHostStrCache[str] = res
	}
	return
}

func (t *allAddresses) createInetAtonHost(str string) (res *ipaddr.HostName) {
	if t.caching {
		t.ainetAtonStrIHostStrCacheLock.Lock()
		defer t.ainetAtonStrIHostStrCacheLock.Unlock()
		res = t.ainetAtonStrHostStrCache[str]
		if res != nil {
			return
		}
	}
	res = ipaddr.NewHostNameParams(str, defaultHostOptions)
	if t.caching {
		t.ainetAtonStrHostStrCache[str] = res
	}
	return
}

func (t *allAddresses) isLenient() bool {
	return true
}

var _, _, _ testAddresses = &addresses{}, &rangedAddresses{}, &allAddresses{}
