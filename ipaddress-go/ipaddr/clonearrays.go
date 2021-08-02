package ipaddr

func cloneIPv4Sections(sect *IPv4AddressSection, orig []*IPv4AddressSection) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if sect != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if sect != nil {
		result[origCount] = WrappedIPAddressSection{sect.ToIPAddressSection()}
	}
	for i := range orig {
		result[i] = WrappedIPAddressSection{orig[i].ToIPAddressSection()} // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
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
		result[origCount] = WrappedIPAddressSection{sect.ToIPAddressSection()}
	}
	for i := range orig {
		result[i] = WrappedIPAddressSection{orig[i].ToIPAddressSection()} // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
	}
	return result
}

func cloneIPAddrs(addr *IPAddress, orig []*IPAddress) []ExtendedIPSegmentSeries {
	origCount := len(orig)
	count := origCount
	if addr != nil {
		count++
	}
	result := make([]ExtendedIPSegmentSeries, count)
	if addr != nil {
		result[origCount] = WrappedIPAddress{addr}
	}
	for i := range orig {
		result[i] = WrappedIPAddress{orig[i]} // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
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
		result[origCount] = WrappedIPAddress{sect.ToIPAddress()}
	}
	for i := range orig {
		result[i] = WrappedIPAddress{orig[i].ToIPAddress()} // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
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
		result[origCount] = WrappedIPAddress{sect.ToIPAddress()}
	}
	for i := range orig {
		result[i] = WrappedIPAddress{orig[i].ToIPAddress()} // unlike Java, return types matter with interfaces - https://play.golang.org/p/HZR8FSp42a9 )
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
		result[i] = orig[i].(WrappedIPAddressSection).ToIPv4AddressSection()
	}
	return result
}

func cloneToIPv6Sections(orig []ExtendedIPSegmentSeries) []*IPv6AddressSection {
	result := make([]*IPv6AddressSection, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddressSection).ToIPv6AddressSection()
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
		result[i] = orig[i].(WrappedIPAddress).ToIPv4Address()
	}
	return result
}

func cloneToIPv6Addrs(orig []ExtendedIPSegmentSeries) []*IPv6Address {
	result := make([]*IPv6Address, len(orig))
	for i := range result {
		result[i] = orig[i].(WrappedIPAddress).ToIPv6Address()
	}
	return result
}

func cloneToIPv4SeqRange(orig []*IPAddressSeqRange) []*IPv4AddressSeqRange {
	result := make([]*IPv4AddressSeqRange, len(orig))
	for i := range result {
		result[i] = orig[i].ToIPv4SequentialRange()
	}
	return result
}

func cloneToIPv6SeqRange(orig []*IPAddressSeqRange) []*IPv6AddressSeqRange {
	result := make([]*IPv6AddressSeqRange, len(orig))
	for i := range result {
		result[i] = orig[i].ToIPv6SequentialRange()
	}
	return result
}

func cloneIPv4AddrsToIPAddrs(orig []*IPv4Address) []*IPAddress {
	result := make([]*IPAddress, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIPAddress()
	}
	return result
}

func cloneIPv6AddrsToIPAddrs(orig []*IPv6Address) []*IPAddress {
	result := make([]*IPAddress, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIPAddress()
	}
	return result
}

func cloneIPAddrsToIPv4Addrs(orig []*IPAddress) []*IPv4Address {
	result := make([]*IPv4Address, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIPv4Address()
	}
	return result
}

func cloneIPAddrsToIPv6Addrs(orig []*IPAddress) []*IPv6Address {
	result := make([]*IPv6Address, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIPv6Address()
	}
	return result
}

func cloneIPSectsToIPv4Sects(orig []*IPAddressSection) []*IPv4AddressSection {
	result := make([]*IPv4AddressSection, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIPv4AddressSection()
	}
	return result
}

func cloneIPSectsToIPv6Sects(orig []*IPAddressSection) []*IPv6AddressSection {
	result := make([]*IPv6AddressSection, len(orig))
	for i := range orig {
		result[i] = orig[i].ToIPv6AddressSection()
	}
	return result
}

func cloneIPv4SegsToDivs(orig []*IPv4AddressSegment) []*AddressDivision {
	result := make([]*AddressDivision, len(orig))
	for i := range result {
		result[i] = orig[i].ToAddressDivision()
	}
	return result
}

func cloneIPv6SegsToDivs(orig []*IPv6AddressSegment) []*AddressDivision {
	result := make([]*AddressDivision, len(orig))
	for i := range result {
		result[i] = orig[i].ToAddressDivision()
	}
	return result
}

func cloneMACSegsToDivs(orig []*MACAddressSegment) []*AddressDivision {
	result := make([]*AddressDivision, len(orig))
	for i := range result {
		result[i] = orig[i].ToAddressDivision()
	}
	return result
}