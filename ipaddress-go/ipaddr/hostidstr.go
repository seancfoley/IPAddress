package ipaddr

const SegmentValueDelimiter = ','

// HostIdentifierString represents a string that is used to identify a network host.
type HostIdentifierString interface {

	// provides a normalized String representation for the host identified by this HostIdentifierString instance
	ToNormalizedString() string

	//ToHostAddress() (*Address, error)

	//TODO either you add ToAddress and GetAddress with slightly different names or you make this for IPAddress only
	//I think the latter makes more sense, drop the MACAddressString
	// OR EVEN BETTER you do similar to ExtendedIPAddressSegmentSeries
	// You do wrapper classes for each of IPAddressString and MACAddressString, each of them has the set of methods listed here
	// and we use a return value that works for everybody
}

var (
	_ HostIdentifierString = &IPAddressString{}
	_ HostIdentifierString = &MACAddressString{}
)
