package ipaddr

type IPAddressSeqRange struct {
}

type ipAddressSeqRangeInternal struct {
	IPAddressSeqRange
}

type IPv4AddressSeqRange struct {
	ipAddressSeqRangeInternal
}

type IPv6AddressSeqRange struct {
	ipAddressSeqRangeInternal
}
