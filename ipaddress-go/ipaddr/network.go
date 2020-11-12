package ipaddr

type AddressNetwork interface {
	GetAddressCreator() AddressCreator
}

type AddressCreator interface {
	//TODO
}

type IPAddressNetwork interface {
	AddressNetwork

	GetIPAddressCreator() IPAddressCreator

	GetLoopback() *IPAddress
}

type IPAddressCreator interface {
	AddressCreator

	createAddressInternal(bytes []byte, zone string) *IPAddress
	//TODO
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

func (network *IPv6AddressNetwork) GetIPAddressCreator() IPAddressCreator {
	return network.GetIPv6AddressCreator()
}

func (network *IPv6AddressNetwork) GetAddressCreator() AddressCreator {
	return network.GetIPv6AddressCreator()
}

func (network *IPv6AddressNetwork) GetLoopback() *IPAddress {
	//TODO
	return nil
}

var _ IPAddressNetwork = &IPv6AddressNetwork{}

var DefaultIPv6Network IPv6AddressNetwork

type IPv6AddressCreator struct {
	//TODO
}

func (creator *IPv6AddressCreator) createAddressInternal(bytes []byte, zone string) *IPAddress {
	//TODO create address, call ToIPAddress
	return nil
}

//
//
//
//
//

type IPv4AddressNetwork struct {
	creator IPv4AddressCreator
	//TODO
}

func (network *IPv4AddressNetwork) GetIPv4AddressCreator() *IPv4AddressCreator {
	return &network.creator
}

func (network *IPv4AddressNetwork) GetIPAddressCreator() IPAddressCreator {
	return network.GetIPv4AddressCreator()
}

func (network *IPv4AddressNetwork) GetAddressCreator() AddressCreator {
	return network.GetIPv4AddressCreator()
}

func (network *IPv4AddressNetwork) GetLoopback() *IPAddress {
	//TODO
	return nil
}

var _ IPAddressNetwork = &IPv4AddressNetwork{}

var DefaultIPv4Network IPv4AddressNetwork

type IPv4AddressCreator struct {
	//TODO
}

func (creator *IPv4AddressCreator) createAddressInternal(bytes []byte, zone string) *IPAddress {
	//TODO create address, call ToIPAddress
	return nil
}

//
//
//
//
//

type MACAddressNetwork struct {
	creator MACAddressCreator
}

func (network *MACAddressNetwork) GetMACAddressCreator() *MACAddressCreator {
	return &network.creator
}

func (network *MACAddressNetwork) GetAddressCreator() AddressCreator {
	return network.GetMACAddressCreator()
}

var _ AddressNetwork = &MACAddressNetwork{}

var DefaultMACNetwork MACAddressNetwork

type MACAddressCreator struct {
	//TODO
}
