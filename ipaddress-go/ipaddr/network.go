package ipaddr

type AddressNetwork interface {
	//GetAddressCreator() AddressCreator
}

//TODO I think I probably want to get rid of the address creators from networks (but they are still useful when passing into certain functions), I realize now they make little sense
//But I will still have caching.

// IPAddressNetwork represents the full collection of addresses for a given IP version.
// You can create your own network objects satisfying this interface, allowing you to create your own address types,
// or to provide your own IP address conversion between IPv4 and IPv6.
// When creating your own network, for IP addresses to be associated with it, you must:
// - create each address using the creator methods in the instance creator returned from GetIPAddressCreator(),
//	which will associate each address with said network when creating the address
// - return the network object from the IPAddressStringParameters implementation used for parsing an IPAddressString,
//	which will associate the parsed address with the network
// Addresses deprived from an existing address, using masking, iterating, or any other address manipulation,
// will be associated with the same network as the original address, by using the network's address creator instance.
// Addresses created by instantiation not through the network's creator instance will be associated with the default network.
type IPAddressNetwork interface {
	AddressNetwork

	//GetIPAddressCreator() IPAddressCreator

	GetLoopback() *IPAddress

	GetNetworkIPAddress(PrefixLen) *IPAddress

	GetNetworkMask(PrefixLen, bool) *IPAddress
}

//
//
//
//
//

type IPv6AddressNetwork struct {
	creator IPv6AddressCreator
}

func (network *IPv6AddressNetwork) GetIPv6AddressCreator() *IPv6AddressCreator {
	return &network.creator
}

//func (network *IPv6AddressNetwork) GetIPAddressCreator() IPAddressCreator {
//	return network.GetIPv6AddressCreator()
//}

//func (network *IPv6AddressNetwork) GetAddressCreator() AddressCreator {
//	return network.GetIPv6AddressCreator()
//}

func (network *IPv6AddressNetwork) GetLoopback() *IPAddress {
	//TODO use the creator
	return nil
}

func (network *IPv6AddressNetwork) GetNetworkIPAddress(prefLen PrefixLen) *IPAddress {
	return network.GetNetworkIPv6Address(prefLen).ToIPAddress()
}

func (network *IPv6AddressNetwork) GetNetworkMask(prefLen PrefixLen, withPrefixLength bool) *IPAddress {
	return network.GetNetworkIPv6Mask(prefLen, withPrefixLength).ToIPAddress()
}

func (network *IPv6AddressNetwork) GetNetworkIPv6Address(prefLen PrefixLen) *IPv6Address {
	//TODO
	return nil
}

func (network *IPv6AddressNetwork) GetNetworkIPv6Mask(prefLen PrefixLen, withPrefixLength bool) *IPv6Address {
	//TODO
	return nil
}

var _ IPAddressNetwork = &IPv6AddressNetwork{}

var DefaultIPv6Network IPv6AddressNetwork

//
//
//
//
//

type IPv4AddressNetwork struct {
	creator IPv4AddressCreator
}

func (network *IPv4AddressNetwork) GetIPv4AddressCreator() *IPv4AddressCreator {
	return &network.creator
}

//func (network *IPv4AddressNetwork) GetIPAddressCreator() IPAddressCreator {
//	return network.GetIPv4AddressCreator()
//}

//func (network *IPv4AddressNetwork) GetAddressCreator() AddressCreator {
//	return network.GetIPv4AddressCreator()
//}

func (network *IPv4AddressNetwork) GetLoopback() *IPAddress {
	//TODO
	return nil
}

func (network *IPv4AddressNetwork) GetNetworkIPAddress(prefLen PrefixLen) *IPAddress {
	return network.GetNetworkIPv4Address(prefLen).ToIPAddress()
}

func (network *IPv4AddressNetwork) GetNetworkMask(prefLen PrefixLen, withPrefixLength bool) *IPAddress {
	return network.GetNetworkIPv4Mask(prefLen, withPrefixLength).ToIPAddress()
}

func (network *IPv4AddressNetwork) GetNetworkIPv4Address(prefLen PrefixLen) *IPv4Address {
	//TODO get the ipv4 network address for a given prefix len, which is the all ones host (but for what address?)
	return nil
}

func (network *IPv4AddressNetwork) GetNetworkIPv4Mask(prefLen PrefixLen, withPrefixLength bool) *IPv4Address {
	//TODO
	return nil
}

var _ IPAddressNetwork = &IPv4AddressNetwork{}

var DefaultIPv4Network IPv4AddressNetwork

type MACAddressNetwork struct {
	creator MACAddressCreator
}

func (network *MACAddressNetwork) GetMACAddressCreator() *MACAddressCreator {
	return &network.creator
}

//
//func (network *MACAddressNetwork) GetAddressCreator() AddressCreator {
//	return network.GetMACAddressCreator()
//}

var _ AddressNetwork = &MACAddressNetwork{}

var DefaultMACNetwork MACAddressNetwork
