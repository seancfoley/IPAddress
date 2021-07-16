package ipaddr

import (
	"sync"
)

type macAddressProvider interface {
	getAddress() (*MACAddress, IncompatibleAddressError)
}

type macAddressEmptyProvider struct{}

func (provider macAddressEmptyProvider) getAddress() (*MACAddress, IncompatibleAddressError) {
	return nil, nil
}

var defaultMACAddressEmptyProvider = macAddressEmptyProvider{}

type macAddressAllProvider struct {
	validationOptions MACAddressStringParameters
	address           *MACAddress
	creationLock      sync.Mutex
}

func (provider *macAddressAllProvider) getAddress() (*MACAddress, IncompatibleAddressError) {
	addr := provider.address
	if addr == nil {
		provider.creationLock.Lock()
		addr = provider.address
		if addr == nil {
			validationOptions := provider.validationOptions
			//creator := provider.validationOptions.GetNetwork().GetMACAddressCreator() xxxx ipaddress we used addrType to get network to get creator
			size := validationOptions.AddressSize()
			creator := macType.getNetwork().getAddressCreator()
			var segCount int
			if size == EUI64 {
				segCount = ExtendedUniqueIdentifier64SegmentCount
			} else {
				segCount = MediaAccessControlSegmentCount
			}
			allRangeSegment := creator.createRangeSegment(0, MACMaxValuePerSegment)
			segments := make([]*AddressDivision, segCount)
			for i := range segments {
				segments[i] = allRangeSegment
			}
			section := creator.createSectionInternal(segments)
			addr = creator.createAddressInternal(section.ToAddressSection(), nil).ToMACAddress()
		}
		provider.creationLock.Unlock()
	}
	return addr, nil
}

var macAddressDefaultAllProvider = &macAddressAllProvider{validationOptions: defaultMACAddrParameters}

type wrappedMACAddressProvider struct {
	address *MACAddress
}

func (provider wrappedMACAddressProvider) getAddress() (*MACAddress, IncompatibleAddressError) {
	return provider.address, nil
}

var (
	_, _, _ macAddressProvider = &macAddressEmptyProvider{},
		&macAddressAllProvider{},
		&wrappedMACAddressProvider{}
)
