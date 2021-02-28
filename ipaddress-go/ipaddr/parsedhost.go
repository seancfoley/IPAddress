package ipaddr

import (
	"strings"
	//	"sync/atomic"
	//	"unsafe"
	"sync/atomic"
	"unsafe"
)

type EmbeddedAddress struct {
	isUNCIPv6Literal, isReverseDNS bool

	addressStringException AddressStringException

	addressProvider IPAddressProvider
}

var (
	// used by hosts
	//NO_EMBEDDED_ADDRESS *EmbeddedAddress                     = &EmbeddedAddress{}
	NO_QUALIFIER *ParsedHostIdentifierStringQualifier = &ParsedHostIdentifierStringQualifier{}
)

type hostStrings struct {
	normalizedLabels []string
	host             string
}

type parsedHostCache struct {
	*hostStrings
}

type ParsedHost struct {
	//normalizedLabels []string
	separatorIndices []int // can be nil
	normalizedFlags  []bool

	labelsQualifier ParsedHostIdentifierStringQualifier
	service         Service

	embeddedAddress EmbeddedAddress

	//host, originalStr string
	originalStr string

	*parsedHostCache
}

func (host *ParsedHost) getQualifier() *ParsedHostIdentifierStringQualifier {
	return &host.labelsQualifier
}

func (host *ParsedHost) isIPv6Address() bool {
	return host.hasEmbeddedAddress() && host.getAddressProvider().isProvidingIPv6()
}

func (host *ParsedHost) getPort() Port {
	return host.labelsQualifier.getPort()
}

func (host *ParsedHost) getService() Service {
	serv := host.service
	if serv == "" {
		serv = host.labelsQualifier.getService()
	}
	return serv
}

func (host *ParsedHost) getNetworkPrefixLength() PrefixLen {
	return host.labelsQualifier.getNetworkPrefixLength()
}

func (host *ParsedHost) getEquivalentPrefixLength() PrefixLen {
	return host.labelsQualifier.getEquivalentPrefixLength()
}

func (host *ParsedHost) getMask() *IPAddress {
	return host.labelsQualifier.getMaskLower()
}

func (host *ParsedHost) getAddressProvider() IPAddressProvider {
	return host.embeddedAddress.addressProvider
}

func (host *ParsedHost) hasEmbeddedAddress() bool {
	return host.embeddedAddress.addressProvider != nil
}

func (host *ParsedHost) isAddressString() bool {
	return host.getAddressProvider() != nil
}

func (host *ParsedHost) asAddress() (*IPAddress, IncompatibleAddressException) {
	if host.hasEmbeddedAddress() {
		return host.getAddressProvider().getProviderAddress()
	}
	return nil, nil
}

func (host *ParsedHost) mapString(addressProvider IPAddressProvider) string {
	if addressProvider.isProvidingAllAddresses() {
		return SegmentWildcardStr
		//} else if addressProvider.isProvidingPrefixOnly() {
		//return IPAddressNetwork.getPrefixString(addressProvider.getProviderNetworkPrefixLength())
	} else if addressProvider.isProvidingEmpty() {
		return ""
	}
	return host.originalStr
}

func (host *ParsedHost) asGenericAddressString() *IPAddressString {
	if host.hasEmbeddedAddress() {
		addressProvider := host.getAddressProvider()
		if addressProvider.isProvidingAllAddresses() {
			return NewIPAddressString(SegmentWildcardStr, addressProvider.getParameters())
			//} else if(addressProvider.isProvidingPrefixOnly()) {
			//	return new IPAddressString(IPAddressNetwork.getPrefixString(addressProvider.getProviderNetworkPrefixLength()), addressProvider.getParameters());
		} else if addressProvider.isProvidingEmpty() {
			return NewIPAddressString("", addressProvider.getParameters())
		} else {
			//try {
			addr, err := addressProvider.getProviderAddress()
			if err != nil {
				return NewIPAddressString(host.originalStr, addressProvider.getParameters())
			}
			return addr.ToAddressString()
			//} catch(IncompatibleAddressException e) {
			//return new IPAddressString(originalStr, addressProvider.getParameters());
			//}
		}
	}
	return nil
}

func (host *ParsedHost) getHost() string {
	return host.buildStrings().host
}

func (host *ParsedHost) buildStrings() *hostStrings {
	res := host.hostStrings
	if res == nil {
		var normalizedLabels []string
		var hostStr string
		if host.hasEmbeddedAddress() {
			addressProvider := host.getAddressProvider()
			addr, err := addressProvider.getProviderAddress()
			if err == nil {
				section := addr.GetSection()
				normalizedLabels = section.GetSegmentStrings()
				//port was stripped out
				//mask and prefix removed by toNormalizedWildcardString
				//getSection() removes zone
				hostStr = section.ToCanonicalWildcardString()
			} else {
				hostStr = host.mapString(addressProvider)
				if addressProvider.isProvidingEmpty() {
					normalizedLabels = []string{}
				} else {
					normalizedLabels = []string{hostStr}
				}
			}
		} else {
			normalizedLabels = make([]string, len(host.separatorIndices))
			normalizedFlags := host.normalizedFlags
			var first strings.Builder
			for i, lastSep := 0, -1; i < len(normalizedLabels); i++ {
				index := host.separatorIndices[i]
				if len(normalizedFlags) > 0 && !normalizedFlags[i] {
					var second strings.Builder
					second.Grow((index - lastSep) - 1)
					for j := lastSep + 1; j < index; j++ {
						c := host.originalStr[j]
						if c >= 'A' && c <= 'Z' {
							c = c + ('a' - 'A')
						}
						second.WriteByte(c)
					}
					normalizedLabels[i] = second.String()
				} else {
					normalizedLabels[i] = host.originalStr[lastSep+1 : index]
				}
				if i > 0 {
					first.WriteByte(LabelSeparator)
				}
				first.WriteString(normalizedLabels[i])
				lastSep = index
			}
			hostStr = first.String()
		}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&host.hostStrings))
		res = &hostStrings{
			normalizedLabels: normalizedLabels,
			host:             hostStr,
		}
		atomic.StorePointer(dataLoc, unsafe.Pointer(res))
	}
	return res
}

func (host *ParsedHost) getNormalizedLabels() []string {
	return host.buildStrings().normalizedLabels
}

/*
	public AddressStringException getAddressStringException() { // this is an exception when something looks like reverse dns string or ip literal string and it is off a bit
		return embeddedAddress.addressStringException;
	}
*/

func (host *ParsedHost) isUNCIPv6Literal() bool {
	return host.embeddedAddress.isUNCIPv6Literal
}

func (host *ParsedHost) isReverseDNS() bool {
	return host.embeddedAddress.isReverseDNS
}
