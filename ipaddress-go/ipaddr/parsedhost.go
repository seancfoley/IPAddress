package ipaddr

import (
	"strings"
	//	"sync/atomic"
	//	"unsafe"
	"sync/atomic"
	"unsafe"
)

type embeddedAddress struct {
	isUNCIPv6Literal, isReverseDNS bool

	addressStringError AddressStringError

	addressProvider IPAddressProvider
}

var (
	// used by hosts
	//NO_EMBEDDED_ADDRESS *embeddedAddress                     = &embeddedAddress{}
	noQualifier *parsedHostIdentifierStringQualifier = &parsedHostIdentifierStringQualifier{}
)

type hostStrings struct {
	normalizedLabels []string
	host             string
}

type parsedHostCache struct {
	*hostStrings
}

type parsedHost struct {
	separatorIndices []int // can be nil
	normalizedFlags  []bool

	labelsQualifier parsedHostIdentifierStringQualifier

	embeddedAddress embeddedAddress

	originalStr string

	*parsedHostCache
}

func (host *parsedHost) getQualifier() *parsedHostIdentifierStringQualifier {
	return &host.labelsQualifier
}

func (host *parsedHost) isIPv6Address() bool {
	return host.hasEmbeddedAddress() && host.getAddressProvider().isProvidingIPv6()
}

func (host *parsedHost) getPort() Port {
	return host.labelsQualifier.getPort()
}

func (host *parsedHost) getService() string {
	return host.labelsQualifier.getService()
}

func (host *parsedHost) getNetworkPrefixLength() PrefixLen {
	return host.labelsQualifier.getNetworkPrefixLength()
}

func (host *parsedHost) getEquivalentPrefixLength() PrefixLen {
	return host.labelsQualifier.getEquivalentPrefixLength()
}

func (host *parsedHost) getMask() *IPAddress {
	return host.labelsQualifier.getMaskLower()
}

func (host *parsedHost) getAddressProvider() IPAddressProvider {
	return host.embeddedAddress.addressProvider
}

func (host *parsedHost) hasEmbeddedAddress() bool {
	return host.embeddedAddress.addressProvider != nil
}

func (host *parsedHost) isAddressString() bool {
	return host.getAddressProvider() != nil
}

func (host *parsedHost) asAddress() (*IPAddress, IncompatibleAddressError) {
	if host.hasEmbeddedAddress() {
		return host.getAddressProvider().getProviderAddress()
	}
	return nil, nil
}

func (host *parsedHost) mapString(addressProvider IPAddressProvider) string {
	if addressProvider.isProvidingAllAddresses() {
		return SegmentWildcardStr
		//} else if addressProvider.isProvidingPrefixOnly() {
		//return IPAddressNetwork.getPrefixString(addressProvider.getProviderNetworkPrefixLength())
	} else if addressProvider.isProvidingEmpty() {
		return ""
	}
	return host.originalStr
}

func (host *parsedHost) asGenericAddressString() *IPAddressString {
	if host.hasEmbeddedAddress() {
		addressProvider := host.getAddressProvider()
		if addressProvider.isProvidingAllAddresses() {
			return NewIPAddressStringParams(SegmentWildcardStr, addressProvider.getParameters())
			//} else if(addressProvider.isProvidingPrefixOnly()) {
			//	return new IPAddressString(IPAddressNetwork.getPrefixString(addressProvider.getProviderNetworkPrefixLength()), addressProvider.getParameters());
		} else if addressProvider.isProvidingEmpty() {
			return NewIPAddressStringParams("", addressProvider.getParameters())
		} else {
			//try {
			addr, err := addressProvider.getProviderAddress()
			if err != nil {
				return NewIPAddressStringParams(host.originalStr, addressProvider.getParameters())
			}
			return addr.ToAddressString()
			//} catch(IncompatibleAddressError e) {
			//return new IPAddressString(originalStr, addressProvider.getParameters());
			//}
		}
	}
	return nil
}

func (host *parsedHost) getHost() string {
	return host.buildStrings().host
}

func (host *parsedHost) buildStrings() *hostStrings {
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

func (host *parsedHost) getNormalizedLabels() []string {
	return host.buildStrings().normalizedLabels
}

/*
	public AddressStringError getAddressStringException() { // this is an exception when something looks like reverse dns string or ip literal string and it is off a bit
		return embeddedAddress.addressStringError;
	}
*/

func (host *parsedHost) isUNCIPv6Literal() bool {
	return host.embeddedAddress.isUNCIPv6Literal
}

func (host *parsedHost) isReverseDNS() bool {
	return host.embeddedAddress.isReverseDNS
}
