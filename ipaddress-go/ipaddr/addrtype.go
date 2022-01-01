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

// addrType tracks which address division and address division groupings can be upscaled to higher-level types
type addrType string

const (
	zeroType        addrType = ""            // no segments
	ipv4Type        addrType = "IPv4"        // ipv4 segments
	ipv6Type        addrType = "IPv6"        // ipv6 segments
	ipv6v4MixedType addrType = "IPv6v4Mixed" // ipv6-v4 mixed segments
	macType         addrType = "MACSize"     // mac segments
)

func (a addrType) isNil() bool {
	return a == zeroType
}

func (a addrType) isIPv4() bool {
	return a == ipv4Type
}

func (a addrType) isIPv6() bool {
	return a == ipv6Type
}

func (a addrType) isIPv6v4Mixed() bool {
	return a == ipv6v4MixedType
}

func (a addrType) isIP() bool {
	return a.isIPv4() || a.isIPv6()
}

func (a addrType) isMAC() bool {
	return a == macType
}

func (a addrType) getIPNetwork() (network IPAddressNetwork) {
	if a.isIPv6() {
		network = IPv6Network
	} else if a.isIPv4() {
		network = IPv4Network
	}
	return
}

func (a addrType) getNetwork() (network addressNetwork) {
	if a.isIPv6() {
		network = IPv6Network
	} else if a.isIPv4() {
		network = IPv4Network
	} else if a.isMAC() {
		network = MACNetwork
	}
	return
}
