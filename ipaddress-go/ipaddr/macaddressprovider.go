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
	"sync"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrstrparam"
)

type macAddressProvider interface {
	getAddress() (*MACAddress, addrerr.IncompatibleAddressError)
}

type macAddressEmptyProvider struct{}

func (provider macAddressEmptyProvider) getAddress() (*MACAddress, addrerr.IncompatibleAddressError) {
	return nil, nil
}

var defaultMACAddressEmptyProvider = macAddressEmptyProvider{}

type macAddressAllProvider struct {
	validationOptions addrparam.MACAddressStringParams
	address           *MACAddress
	creationLock      sync.Mutex
}

func (provider *macAddressAllProvider) getAddress() (*MACAddress, addrerr.IncompatibleAddressError) {
	addr := provider.address
	if addr == nil {
		provider.creationLock.Lock()
		addr = provider.address
		if addr == nil {
			validationOptions := provider.validationOptions
			//creator := provider.validationOptions.GetNetwork().GetMACAddressCreator() xxxx ipaddress we used addrType to get network to get creator
			size := validationOptions.GetPreferredLen()
			creator := macType.getNetwork().getAddressCreator()
			var segCount int
			if size == addrparam.EUI64Len {
				segCount = ExtendedUniqueIdentifier64SegmentCount
			} else {
				segCount = MediaAccessControlSegmentCount
			}
			allRangeSegment := creator.createRangeSegment(0, MACMaxValuePerSegment)
			segments := make([]*AddressDivision, segCount)
			for i := range segments {
				segments[i] = allRangeSegment
			}
			section := creator.createSectionInternal(segments, true)
			addr = creator.createAddressInternal(section.ToSectionBase(), nil).ToMAC()
		}
		provider.creationLock.Unlock()
	}
	return addr, nil
}

var macAddressDefaultAllProvider = &macAddressAllProvider{validationOptions: defaultMACAddrParameters}

type wrappedMACAddressProvider struct {
	address *MACAddress
}

func (provider wrappedMACAddressProvider) getAddress() (*MACAddress, addrerr.IncompatibleAddressError) {
	return provider.address, nil
}

var (
	_, _, _ macAddressProvider = &macAddressEmptyProvider{},
		&macAddressAllProvider{},
		&wrappedMACAddressProvider{}
)
