package ipaddr

// HostIdentifierString represents a string that is used to identify a network host.
type HostIdentifierString interface {

	//static final char SEGMENT_VALUE_DELIMITER = ',';

	// provides a normalized String representation for the host identified by this HostIdentifierString instance
	ToNormalizedString() string

	ToHostAddress() (*Address, error)
}

var (
	_ HostIdentifierString = &IPAddressString{}
	_ HostIdentifierString = &MACAddressString{}
)
