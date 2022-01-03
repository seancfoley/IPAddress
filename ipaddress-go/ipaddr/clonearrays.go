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

func cloneIPv4Sections(sect *IPv4AddressSection, orig []*IPv4AddressSection) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if sect != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if sect != nil {
		result[origCount] = WrapIPSection(sect.ToIP())
	}
	for i := range orig {
		result[i] = WrapIPSection(orig[i].ToIP()) // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
	}
	return result
}

func cloneIPv6Sections(sect *IPv6AddressSection, orig []*IPv6AddressSection) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if sect != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if sect != nil {
		result[origCount] = WrapIPSection(sect.ToIP())
	}
	for i := range orig {
		result[i] = WrapIPSection(orig[i].ToIP())
	}
	return result
}

func filterCloneIPAddrs(addr *IPAddress, orig []*IPAddress) []ExtendedIPSegmentSeries {
	if addr == nil {
		panic("no receiver")
	}
	origCount := len(orig)
	count := origCount + 1
	result := make([]ExtendedIPSegmentSeries, 0, count)
	result = append(result, WrapIPAddress(addr))
	version := addr.getIPVersion()
	for _, a := range orig {
		if version.Equal(a.GetIPVersion()) {
			result = append(result, WrapIPAddress(a))
		}
	}
	return result
}

func cloneIPv4Addrs(sect *IPv4Address, orig []*IPv4Address) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if sect != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if sect != nil {
		result[origCount] = WrapIPAddress(sect.ToIP())
	}
	for i := range orig {
		result[i] = WrapIPAddress(orig[i].ToIP())
	}
	return result
}

func cloneIPv6Addrs(sect *IPv6Address, orig []*IPv6Address) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if sect != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if sect != nil {
		result[origCount] = WrapIPAddress(sect.ToIP())
	}
	for i := range orig {
		result[i] = WrapIPAddress(orig[i].ToIP())
	}
	return result
}

func cloneToIPSections(orig []ExtendedIPSegmentSeries) []*IPAddressSection {
	result := make([]*IPAddressSection, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddressSection).IPAddressSection
	}
	return result
}

func cloneToIPv4Sections(orig []ExtendedIPSegmentSeries) []*IPv4AddressSection {
	result := make([]*IPv4AddressSection, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddressSection).IPAddressSection.ToIPv4()
	}
	return result
}

func cloneToIPv6Sections(orig []ExtendedIPSegmentSeries) []*IPv6AddressSection {
	result := make([]*IPv6AddressSection, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddressSection).IPAddressSection.ToIPv6()
	}
	return result
}

func cloneToIPAddrs(orig []ExtendedIPSegmentSeries) []*IPAddress {
	result := make([]*IPAddress, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddress).IPAddress
	}
	return result
}

func cloneToIPv4Addrs(orig []ExtendedIPSegmentSeries) []*IPv4Address {
	result := make([]*IPv4Address, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddress).IPAddress.ToIPv4()
	}
	return result
}

func cloneToIPv6Addrs(orig []ExtendedIPSegmentSeries) []*IPv6Address {
	result := make([]*IPv6Address, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddress).IPAddress.ToIPv6()
	}
	return result
}

func cloneToIPv4SeqRange(orig []*IPAddressSeqRange) []*IPv4AddressSeqRange {
	result := make([]*IPv4AddressSeqRange, len(orig))
	for i := range result {
		result[i] = orig[i].ToIPv4()
	}
	return result
}

func cloneToIPv6SeqRange(orig []*IPAddressSeqRange) []*IPv6AddressSeqRange {
	result := make([]*IPv6AddressSeqRange, len(orig))
	for i := range result {
		result[i] = orig[i].ToIPv6()
	}
	return result
}

func cloneIPv4AddrsToIPAddrs(orig []*IPv4Address) []*IPAddress {
	result := make([]*IPAddress, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIP()
	}
	return result
}

func cloneIPv6AddrsToIPAddrs(orig []*IPv6Address) []*IPAddress {
	result := make([]*IPAddress, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIP()
	}
	return result
}

func cloneIPAddrsToIPv4Addrs(orig []*IPAddress) []*IPv4Address {
	result := make([]*IPv4Address, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIPv4()
	}
	return result
}

func cloneIPAddrsToIPv6Addrs(orig []*IPAddress) []*IPv6Address {
	result := make([]*IPv6Address, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIPv6()
	}
	return result
}

func cloneIPSectsToIPv4Sects(orig []*IPAddressSection) []*IPv4AddressSection {
	result := make([]*IPv4AddressSection, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIPv4()
	}
	return result
}

func cloneIPSectsToIPv6Sects(orig []*IPAddressSection) []*IPv6AddressSection {
	result := make([]*IPv6AddressSection, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIPv6()
	}
	return result
}
