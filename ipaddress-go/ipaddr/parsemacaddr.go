package ipaddr

type ParsedMACAddress struct { //TODO this needs to go somehwere else, what did I do with ParsedIPAddress?
	MACAddressParseData

	//TODO ParsedMACAddress

	originator HostIdentifierString
	//address *MACAddress //TODO
}

func (parseData *ParsedMACAddress) getMACAddressParseData() *MACAddressParseData {
	return &parseData.MACAddressParseData
}
