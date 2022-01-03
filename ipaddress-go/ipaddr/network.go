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

package ipaddr

import (
	"net"
	"sync"
	"sync/atomic"
	"unsafe"
)

type addressNetwork interface {
	getAddressCreator() parsedAddressCreator
}

type IPAddressNetwork interface {
	GetLoopback() *IPAddress

	GetNetworkMask(prefixLength BitCount) *IPAddress

	GetPrefixedNetworkMask(prefixLength BitCount) *IPAddress

	GetHostMask(prefixLength BitCount) *IPAddress

	GetPrefixedHostMask(prefixLength BitCount) *IPAddress

	getIPAddressCreator() ipAddressCreator

	addressNetwork
}

type ipAddressNetwork struct {
	subnetsMasksWithPrefix, subnetMasks, hostMasksWithPrefix, hostMasks []*IPAddress
}

//
//
//
//
//
type IPv6AddressNetwork struct {
	ipAddressNetwork
	creator ipv6AddressCreator
}

func (network *IPv6AddressNetwork) getIPAddressCreator() ipAddressCreator {
	return &network.creator
}

func (network *IPv6AddressNetwork) getAddressCreator() parsedAddressCreator {
	return &network.creator
}

func (network *IPv6AddressNetwork) GetLoopback() *IPAddress {
	return ipv6loopback
}

func (network *IPv6AddressNetwork) GetNetworkMask(prefLen BitCount) *IPAddress {
	return getMask(IPv6, zeroIPv6Seg.ToDiv(), prefLen, network.subnetMasks, true, false)
}

func (network *IPv6AddressNetwork) GetPrefixedNetworkMask(prefLen BitCount) *IPAddress {
	return getMask(IPv6, zeroIPv6Seg.ToDiv(), prefLen, network.subnetsMasksWithPrefix, true, true)
}

func (network *IPv6AddressNetwork) GetHostMask(prefLen BitCount) *IPAddress {
	return getMask(IPv6, zeroIPv6Seg.ToDiv(), prefLen, network.hostMasks, false, false)
}

func (network *IPv6AddressNetwork) GetPrefixedHostMask(prefLen BitCount) *IPAddress {
	return getMask(IPv6, zeroIPv6Seg.ToDiv(), prefLen, network.hostMasksWithPrefix, false, true)
}

var _ IPAddressNetwork = &IPv6AddressNetwork{}

var IPv6Network = &IPv6AddressNetwork{
	ipAddressNetwork: ipAddressNetwork{
		make([]*IPAddress, IPv6BitCount+1),
		make([]*IPAddress, IPv6BitCount+1),
		make([]*IPAddress, IPv6BitCount+1),
		make([]*IPAddress, IPv6BitCount+1),
	},
}

//
//
//
//
//

type IPv4AddressNetwork struct {
	ipAddressNetwork
	creator ipv4AddressCreator
}

func (network *IPv4AddressNetwork) getIPAddressCreator() ipAddressCreator {
	return &network.creator
}

func (network *IPv4AddressNetwork) getAddressCreator() parsedAddressCreator {
	return &network.creator
}

func (network *IPv4AddressNetwork) GetLoopback() *IPAddress {
	return ipv4loopback
}

func (network *IPv4AddressNetwork) GetNetworkMask(prefLen BitCount) *IPAddress {
	return getMask(IPv4, zeroIPv4Seg.ToDiv(), prefLen, network.subnetMasks, true, false)
}

func (network *IPv4AddressNetwork) GetPrefixedNetworkMask(prefLen BitCount) *IPAddress {
	return getMask(IPv4, zeroIPv4Seg.ToDiv(), prefLen, network.subnetsMasksWithPrefix, true, true)
}

func (network *IPv4AddressNetwork) GetHostMask(prefLen BitCount) *IPAddress {
	return getMask(IPv4, zeroIPv4Seg.ToDiv(), prefLen, network.hostMasks, false, false)
}

func (network *IPv4AddressNetwork) GetPrefixedHostMask(prefLen BitCount) *IPAddress {
	return getMask(IPv4, zeroIPv4Seg.ToDiv(), prefLen, network.hostMasksWithPrefix, false, true)
}

var _ IPAddressNetwork = &IPv4AddressNetwork{}

var IPv4Network = &IPv4AddressNetwork{
	ipAddressNetwork: ipAddressNetwork{
		make([]*IPAddress, IPv4BitCount+1),
		make([]*IPAddress, IPv4BitCount+1),
		make([]*IPAddress, IPv4BitCount+1),
		make([]*IPAddress, IPv4BitCount+1),
	},
}

var maskMutex sync.Mutex

func getMask(version IPVersion, zeroSeg *AddressDivision, networkPrefixLength BitCount, cache []*IPAddress, network, withPrefixLength bool) *IPAddress {
	bits := networkPrefixLength
	addressBitLength := version.GetBitCount()
	if bits < 0 {
		bits = 0
	} else if bits > addressBitLength {
		bits = addressBitLength
	}
	cacheIndex := bits
	subnet := cache[cacheIndex]
	if subnet != nil {
		return subnet
	}

	maskMutex.Lock()
	subnet = cache[cacheIndex]
	if subnet != nil {
		maskMutex.Unlock()
		return subnet
	}
	//
	//
	//

	var onesSubnetIndex, zerosSubnetIndex int
	if network {
		onesSubnetIndex = int(addressBitLength)
		zerosSubnetIndex = 0
	} else {
		onesSubnetIndex = 0
		zerosSubnetIndex = int(addressBitLength)
	}
	onesSubnet := cache[onesSubnetIndex]
	zerosSubnet := cache[zerosSubnetIndex]
	segmentCount := version.GetSegmentCount()
	bitsPerSegment := version.GetBitsPerSegment()
	maxSegmentValue := version.GetMaxSegmentValue()
	if onesSubnet == nil {
		newSegments := createSegmentArray(segmentCount)

		if withPrefixLength {
			if network {
				segment := createAddressDivision(zeroSeg.deriveNewSeg(maxSegmentValue, nil))
				lastSegment := createAddressDivision(zeroSeg.deriveNewSeg(maxSegmentValue, cacheBitCount(bitsPerSegment) /* bitsPerSegment */))
				lastIndex := len(newSegments) - 1
				fillDivs(newSegments[:lastIndex], segment)
				newSegments[lastIndex] = lastSegment
				onesSubnet = createIPAddress(createSection(newSegments, cacheBitCount(addressBitLength), version.toType()), NoZone)
			} else {
				segment := createAddressDivision(zeroSeg.deriveNewSeg(maxSegmentValue, cacheBitCount(0)))
				fillDivs(newSegments, segment)
				onesSubnet = createIPAddress(createSection(newSegments, cacheBitCount(0), version.toType()), NoZone)
			}
		} else {
			segment := createAddressDivision(zeroSeg.deriveNewSeg(maxSegmentValue, nil))
			fillDivs(newSegments, segment)
			onesSubnet = createIPAddress(createSection(newSegments, nil, version.toType()), NoZone) /* address creation */
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[onesSubnetIndex]))
		atomic.StorePointer(dataLoc, unsafe.Pointer(onesSubnet))
	}
	if zerosSubnet == nil {
		newSegments := createSegmentArray(segmentCount)
		if withPrefixLength {
			prefLen := cacheBitCount(0)
			if network {
				segment := createAddressDivision(zeroSeg.deriveNewSeg(0, prefLen))
				fillDivs(newSegments, segment)
				zerosSubnet = createIPAddress(createSection(newSegments, prefLen, version.toType()), NoZone)
			} else {
				lastSegment := createAddressDivision(zeroSeg.deriveNewSeg(0, cacheBitCount(bitsPerSegment) /* bitsPerSegment */))
				lastIndex := len(newSegments) - 1
				fillDivs(newSegments[:lastIndex], zeroSeg)
				newSegments[lastIndex] = lastSegment
				zerosSubnet = createIPAddress(createSection(newSegments, cacheBitCount(addressBitLength), version.toType()), NoZone)
			}
		} else {
			segment := createAddressDivision(zeroSeg.deriveNewSeg(0, nil))
			fillDivs(newSegments, segment)
			zerosSubnet = createIPAddress(createSection(newSegments, nil, version.toType()), NoZone)
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[zerosSubnetIndex]))
		atomic.StorePointer(dataLoc, unsafe.Pointer(zerosSubnet))
	}
	prefix := bits
	onesSegment := onesSubnet.getDivision(0)
	zerosSegment := zerosSubnet.getDivision(0)
	newSegments := createSegmentArray(segmentCount)[:0]
	i := 0
	for ; bits > 0; i, bits = i+1, bits-bitsPerSegment {
		if bits <= bitsPerSegment {
			var segment *AddressDivision

			//first do a check whether we have already created a segment like the one we need
			offset := ((bits - 1) % bitsPerSegment) + 1
			for j, entry := 0, offset; j < segmentCount; j, entry = j+1, entry+bitsPerSegment {
				//for j := 0, entry = offset; j < segmentCount; j++, entry += bitsPerSegment {
				if entry != cacheIndex { //we already know that the entry at cacheIndex is null
					prev := cache[entry]
					if prev != nil {
						segment = prev.getDivision(j)
						break
					}
				}
			}

			//if none of the other addresses with a similar segment are created yet, we need a new segment.
			if segment == nil {
				if network {
					mask := maxSegmentValue & (maxSegmentValue << uint(bitsPerSegment-bits))
					if withPrefixLength {
						segment = createAddressDivision(zeroSeg.deriveNewSeg(mask, getDivisionPrefixLength(bitsPerSegment, bits)))
					} else {
						segment = createAddressDivision(zeroSeg.deriveNewSeg(mask, nil))
					}
				} else {
					mask := maxSegmentValue & ^(maxSegmentValue << uint(bitsPerSegment-bits))
					if withPrefixLength {
						segment = createAddressDivision(zeroSeg.deriveNewSeg(mask, getDivisionPrefixLength(bitsPerSegment, bits)))
					} else {
						segment = createAddressDivision(zeroSeg.deriveNewSeg(mask, nil))
					}
				}
			}
			newSegments = append(newSegments, segment)
		} else {
			if network {
				newSegments = append(newSegments, onesSegment)
			} else {
				newSegments = append(newSegments, zerosSegment)
			}
		}
	}
	for ; i < segmentCount; i++ {
		if network {
			newSegments = append(newSegments, zerosSegment)
		} else {
			newSegments = append(newSegments, onesSegment)
		}
	}
	var prefLen PrefixLen
	if withPrefixLength {
		prefLen = cacheBitCount(prefix)
	}
	subnet = createIPAddress(createSection(newSegments, prefLen, version.toType()), NoZone)
	dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&cache[cacheIndex]))
	atomic.StorePointer(dataLoc, unsafe.Pointer(subnet))

	maskMutex.Unlock()

	return subnet
}

type MACAddressNetwork struct {
	creator macAddressCreator
}

func (network *MACAddressNetwork) getAddressCreator() parsedAddressCreator {
	return &network.creator
}

var MACNetwork = &MACAddressNetwork{}

var _ addressNetwork = &MACAddressNetwork{}

var ipv4loopback = createIPv4Loopback().ToIP()
var ipv6loopback = createIPv6Loopback().ToIP()

func createIPv6Loopback() *IPv6Address {
	ipv6loopback, _ := NewIPv6AddressFromBytes(net.IPv6loopback)
	return ipv6loopback
}

func createIPv4Loopback() *IPv4Address {
	ipv4loopback, _ := NewIPv4AddressFromBytes([]byte{127, 0, 0, 1})
	return ipv4loopback
}
