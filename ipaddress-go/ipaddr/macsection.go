package ipaddr

import (
	"unsafe"
)

//
//
//
//
//
//
//
type macAddressSectionInternal struct {
	addressSectionInternal
}

func (section *macAddressSectionInternal) GetSegment(index int) *MACAddressSegment {
	return section.GetDivision(index).ToMACAddressSegment()
}

//func (section *ipAddressSectionInternal) GetIPVersion() IPVersion (TODO need the MAC equivalent (ie EUI 64 or MAC 48, butcannot remember if there is a MAC equivalent)
//	if section.IsIPv4() {
//		return IPv4
//	}
//	return IPv6
//}

type MACAddressSection struct {
	macAddressSectionInternal
}

func (section *MACAddressSection) ToAddressSection() *AddressSection {
	return (*AddressSection)(unsafe.Pointer(section))
}

func (section *MACAddressSection) GetLower() *MACAddressSection {
	return section.ToAddressSection().GetLower().ToMACAddressSection()
}

func (section *MACAddressSection) GetUpper() *MACAddressSection {
	return section.ToAddressSection().GetUpper().ToMACAddressSection()
}

func (section *MACAddressSection) ToPrefixBlock() *MACAddressSection {
	//TODO ToPrefixBlock
	return nil
}
