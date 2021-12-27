package ipaddr

import (
	"sync"

	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrerr"
	"github.com/seancfoley/ipaddress/ipaddress-go/ipaddr/addrformat"
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
	validationOptions addrformat.MACAddressStringParameters
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
			size := validationOptions.AddressSize()
			creator := macType.getNetwork().getAddressCreator()
			var segCount int
			if size == addrformat.EUI64Size {
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
