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
