package ipaddr

import (
	"net"
	//"strconv"
	"strings"
	"sync/atomic"
	"unsafe"
)

const (
	PortSeparator    = ':'
	LabelSeparator   = '.'
	IPv6StartBracket = '['
	IPv6EndBracket   = '['
)

// NewHostName constructs an HostName that will parse the given string according to the given parameters
func NewHostName(str string, params HostNameParameters) *HostName {
	var prms *hostNameParameters
	if params == nil {
		prms = defaultHostParameters
	} else {
		prms = getPrivateHostParams(params)
	}
	return &HostName{str: str, params: prms, hostCache: &hostCache{}}
}

func NewHostNameFromAddrPort(addr *IPAddress, port int) *HostName {
	hostStr := toNormalizedAddrPortString(addr, port) //TODO cache normalized string
	parsedHost := ParsedHost{
		originalStr:     hostStr,
		embeddedAddress: EmbeddedAddress{addressProvider: addr.getProvider()},
		labelsQualifier: ParsedHostIdentifierStringQualifier{port: cachePorts(port)},
	}
	return &HostName{
		str:       hostStr,
		params:    defaultHostParameters,
		hostCache: &hostCache{normalizedString: &hostStr, hostData: &hostData{parsedHost: &parsedHost}},
	}
}

func NewHostNameFromAddr(addr *IPAddress) *HostName {
	hostStr := addr.ToNormalizedString() //TODO cache normalized string
	parsedHost := ParsedHost{
		originalStr:     hostStr,
		embeddedAddress: EmbeddedAddress{addressProvider: addr.getProvider()},
	}
	return &HostName{
		str:       hostStr,
		params:    defaultHostParameters,
		hostCache: &hostCache{normalizedString: &hostStr, hostData: &hostData{parsedHost: &parsedHost}},
	}
}

//TODO other constructors

var defaultHostParameters = &hostNameParameters{}

var zeroHost = NewHostName("", defaultHostParameters)

type hostData struct {
	parsedHost        *ParsedHost
	validateException HostNameException
}

type resolveData struct {
	resolvedAddrs []*IPAddress
	err           error
}

type hostCache struct {
	*hostData
	*resolveData
	normalizedString *string
}

type HostName struct {
	str    string
	params *hostNameParameters
	*hostCache
}

func (host *HostName) init() *HostName {
	if host.params == nil {
		return zeroHost
	}
	return host
}

func (host *HostName) getParams() *hostNameParameters {
	return host.init().params
}

func (host *HostName) GetValidationOptions() HostNameParameters {
	return host.getParams()
}

// Validate validates that this string is a valid address, and if not, throws an exception with a descriptive message indicating why it is not.
func (host *HostName) Validate() HostNameException {
	host = host.init()
	data := host.hostData
	if data == nil {
		parsedHost, err := validator.validateHostName(host)
		data = &hostData{parsedHost, err}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&host.hostData))
		atomic.StorePointer(dataLoc, unsafe.Pointer(data))
	}
	return data.validateException
}

// TODO we do want the functions taking IPVersion as arg, they allow validation without address object creation
// the validation options can filter out one version already, although it's not obvious it can be done that way
// I decided to deprecate them in Java, but, maybe you want to change your mind?
// I am leaning towards deprecation, in part because the resolve works by delivering all address versions at once.
// So there is an asymmetry there.
// Another reason is that you can easily query for version without producing the address object.
// From that perspective, the versioned methods buy you nothing useful.
// This is a damn good reason to also remove these same functions from IPAddressString.

func (host *HostName) String() string {
	return host.str
}

func (host *HostName) IsAddressString() bool {
	host = host.init()
	return host.IsValid() && host.parsedHost.isAddressString()
}

func (host *HostName) IsAddress() bool {
	host = host.init()
	if host.IsAddressString() {
		addr, _ := host.parsedHost.asAddress()
		return addr != nil
	}
	return false
}

func (host *HostName) AsAddress() *IPAddress {
	if host.IsAddress() {
		addr, _ := host.parsedHost.asAddress()
		return addr
	}
	return nil
}

func (host *HostName) IsAllAddresses() bool {
	host = host.init()
	return host.IsValid() && host.parsedHost.getAddressProvider().isProvidingAllAddresses()
}

func (host *HostName) IsEmpty() bool {
	host = host.init()
	return host.IsValid() && host.parsedHost.getAddressProvider().isProvidingEmpty()
}

func (host *HostName) GetAddress() *IPAddress {
	addr, _ := host.ToAddress()
	return addr
}

func (host *HostName) ToAddresses() ([]*IPAddress, IPAddressException) {
	return host.toAddresses()
}

func (host *HostName) ToAddress() (addr *IPAddress, err IPAddressException) {
	addresses, err := host.toAddresses()
	if len(addresses) > 0 {
		addr = addresses[0]
	}
	return
}

//
// error can be AddressStringException or IncompatibleAddressException
func (host *HostName) toAddresses() (addrs []*IPAddress, err IPAddressException) {
	host = host.init()
	data := host.resolveData
	if data == nil {
		//note that validation handles empty address resolution
		err = host.Validate() //HostNameException
		if err != nil {
			return
		}
		// http://networkbit.ch/golang-dns-lookup/
		parsedHost := host.parsedHost
		if parsedHost.isAddressString() {
			addr, addrErr := parsedHost.asAddress() // IncompatibleAddressException
			addrs, err = []*IPAddress{addr}, addrErr
			//note there is no need to apply prefix or mask here, it would have been applied to the address already
		} else {
			strHost := parsedHost.getHost()
			validationOptions := host.getParams()
			if len(strHost) == 0 && !validationOptions.EmptyIsLoopback() {
				addrs = []*IPAddress{}
				//TODO if we make the zero string translate to zero address of a preferred version, need to change something here
			} else {
				var ips []net.IP
				ips, err = net.LookupIP(strHost)
				if err != nil {
					//Note we do not set resolveData, so we will attempt to resolve again
					return
				}
				count := len(ips)
				addrs = make([]*IPAddress, count)
				for j := 0; j < count; j++ {
					addr := ips[j]
					networkPrefixLength := parsedHost.getNetworkPrefixLength()
					byteLen := len(addr)
					if networkPrefixLength == nil {
						mask := parsedHost.getMask()
						if mask != nil {
							maskBytes := mask.GetBytes()
							if len(maskBytes) == byteLen {
								for i := 0; i < byteLen; i++ {
									addr[i] &= maskBytes[i]
								}
								networkPrefixLength = mask.GetBlockMaskPrefixLength(true)
							}
						}
					}
					if byteLen == IPv6ByteCount {
						ipv6Addr, addrErr := NewIPv6AddressFromPrefixedIP(addr, networkPrefixLength) // AddressValueException
						if addrErr != nil {
							return nil, addrErr
						}
						ipv6Addr.cache.fromHost = host
						addrs[j] = ipv6Addr.ToIPAddress()
					} else {
						if networkPrefixLength != nil && *networkPrefixLength > IPv4BitCount {
							networkPrefixLength = cacheBits(IPv4BitCount)
						}
						ipv4Addr, addrErr := NewIPv4AddressFromPrefixedIP(addr, networkPrefixLength) // AddressValueException
						if addrErr != nil {
							return nil, addrErr
						}
						ipv4Addr.cache.fromHost = host
						addrs[j] = ipv4Addr.ToIPAddress()
					}
				}
			}
		}
		data = &resolveData{addrs, err}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&host.resolveData))
		atomic.StorePointer(dataLoc, unsafe.Pointer(data))
	}
	return data.resolvedAddrs, nil
}

func (host *HostName) ToHostAddress() (*Address, IPAddressException) {
	host = host.init()
	addr, err := host.ToAddress()
	return addr.ToAddress(), err
}

func (host *HostName) IsValid() bool {
	return host.init().Validate() == nil
}

func (host *HostName) AsAddressString() *IPAddressString {
	host = host.init()
	if host.IsAddressString() {
		return host.parsedHost.asGenericAddressString()
	}
	return nil
}

func (host *HostName) GetPort() Port {
	host = host.init()
	if host.IsValid() {
		return host.parsedHost.getPort()
	}
	return nil
}

func (host *HostName) GetService() string {
	host = host.init()
	if host.IsValid() {
		return host.parsedHost.getService()
	}
	return ""
}

// ToNormalizedString provides a normalized string which is lowercase for host strings, and which is a normalized string for addresses.
func (host *HostName) ToNormalizedString() string {
	host = host.init()
	str := host.normalizedString
	if str == nil {
		newStr := host.toNormalizedString(false)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&host.normalizedString))
		str = &newStr
		atomic.StorePointer(dataLoc, unsafe.Pointer(str))
	}
	return *str
}

func (host *HostName) toNormalizedString(wildcard bool) string {
	if host.IsValid() {
		var builder strings.Builder
		if host.IsAddress() {
			toNormalizedHostString(host.AsAddress(), wildcard, &builder)
		} else if host.IsAddressString() {
			builder.WriteString(host.AsAddressString().ToNormalizedString())
		} else {
			builder.WriteString(host.parsedHost.getHost())
			/*
			 * If prefix or mask is supplied and there is an address, it is applied directly to the address provider, so
			 * we need only check for those things here
			 *
			 * Also note that ports and prefix/mask cannot appear at the same time, so this does not interfere with the port code below.
			 */
			networkPrefixLength := host.parsedHost.getEquivalentPrefixLength()
			if networkPrefixLength != nil {
				builder.WriteByte(PrefixLenSeparator)
				toUnsignedString(uint64(*networkPrefixLength), 10, &builder)
				//builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(networkPrefixLength);
			} else {
				mask := host.parsedHost.getMask()
				if mask != nil {
					builder.WriteByte(PrefixLenSeparator)
					builder.WriteString(mask.ToNormalizedString())
					//builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(mask.toNormalizedString())
				}
			}
		}
		port := host.parsedHost.getPort()
		if port != nil {
			toNormalizedPortString(*port, &builder)
		} else {
			service := host.parsedHost.getService()
			if service != "" {
				builder.WriteByte(PortSeparator)
				builder.WriteString(string(service))
				//builder.append(PORT_SEPARATOR).append(service)
			}
		}
		return builder.String()
	}
	return host.str
}

func toNormalizedPortString(port int, builder *strings.Builder) {
	builder.WriteByte(PortSeparator)
	toUnsignedString(uint64(port), 10, builder)
}

func toNormalizedHostString(addr *IPAddress, wildcard bool, builder *strings.Builder) {
	if addr.isIPv6() {
		if !wildcard && addr.IsPrefixed() { // prefix needs to be outside the brackets
			normalized := addr.ToNormalizedString()
			index := strings.IndexByte(normalized, PrefixLenSeparator)
			// translated := translateReserved(addr.ToIPv6Address(), normalized[: index]);
			builder.WriteByte(IPv6StartBracket)
			//builder.WriteString(translated)
			translateReserved(addr.ToIPv6Address(), normalized[:index], builder)
			builder.WriteByte(IPv6EndBracket)
			builder.WriteString(normalized[index:])
			//builder.append(IPV6_START_BRACKET).append(translated).append(IPV6_END_BRACKET).append(normalized.substring(index));
		} else {
			normalized := addr.ToNormalizedWildcardString()
			builder.WriteByte(IPv6StartBracket)
			translateReserved(addr.ToIPv6Address(), normalized, builder)
			builder.WriteByte(IPv6EndBracket)
			//translated := translateReserved(addr.ToIPv6Address(), normalized);
			//builder.append(IPV6_START_BRACKET).append(translated).append(IPV6_END_BRACKET);
		}
	} else {
		if wildcard {
			builder.WriteString(addr.ToNormalizedWildcardString())
		} else {
			builder.WriteString(addr.ToNormalizedString())
		}
		//builder.append(wildcard ? addr.toNormalizedWildcardString() : addr.toNormalizedString());
	}
}

func toNormalizedAddrPortString(addr *IPAddress, port int) string {
	builder := strings.Builder{}
	toNormalizedHostString(addr, false, &builder)
	toNormalizedPortString(port, &builder)
	return builder.String()
}

// Equals returns true if the given host name matches this one.
// For hosts to match, they must represent the same addresses or have the same host names.
// Hosts are not resolved when matching.  Also, hosts must have the same port and service.  They must have the same masks if they are host names.
// Even if two hosts are invalid, they match if they have the same invalid string.
func (host *HostName) Equals(other *HostName) bool {
	host = host.init()
	other = other.init()
	if host == other {
		return true
	}
	if host.IsValid() {
		if other.IsValid() {
			parsedHost := host.parsedHost
			otherParsedHost := other.parsedHost
			if parsedHost.isAddressString() {
				return otherParsedHost.isAddressString() &&
					parsedHost.asGenericAddressString().Equals(otherParsedHost.asGenericAddressString()) &&
					PortEquals(parsedHost.getPort(), otherParsedHost.getPort()) &&
					parsedHost.getService() == otherParsedHost.getService()
			}
			if otherParsedHost.isAddressString() {
				return false
			}
			thisHost := parsedHost.getHost()
			otherHost := otherParsedHost.getHost()
			if thisHost != otherHost {
				return false
			}
			return PrefixEquals(parsedHost.getEquivalentPrefixLength(), otherParsedHost.getEquivalentPrefixLength()) &&
				IPAddressEquals(parsedHost.getMask(), otherParsedHost.getMask()) &&
				PortEquals(parsedHost.getPort(), otherParsedHost.getPort()) &&
				parsedHost.getService() == otherParsedHost.getService()
		}
		return false
	}
	return !other.IsValid() && host.String() == other.String()
}

// GetNormalizedLabels returns an array of normalized strings for this host name instance.
//
// If this represents an IP address, the address segments are separated into the returned array.
// If this represents a host name string, the domain name segments are separated into the returned array,
// with the top-level domain name (right-most segment) as the last array element.
//
// The individual segment strings are normalized in the same way as {@link #toNormalizedString()}
//
// Ports, service name strings, prefix lengths, and masks are all omitted from the returned array.
func (host *HostName) GetNormalizedLabels() []string {
	host = host.init()
	if host.IsValid() {
		return host.parsedHost.getNormalizedLabels()
	} else {
		str := host.str
		if len(str) == 0 {
			return []string{}
		}
		return []string{str}
	}
}

// GetHost returns the host string normalized but without port, service, prefix or mask.
//
// If an address, returns the address string normalized, but without port, service, prefix, mask, or brackets for IPv6.
//
// To get a normalized string encompassing all details, use toNormalizedString()
//
// If not a valid host, returns the zero string
func (host *HostName) GetHost() string {
	host = host.init()
	if host.IsValid() {
		return host.parsedHost.getHost()
	}
	return ""
}

/*
TODO isUNCIPv6Literal and isReverseDNS

*/
///**
// * Returns whether this host name is an Uniform Naming Convention IPv6 literal host name.
// *
// * @return
// */
//public boolean isUNCIPv6Literal() {
//	return isValid() && parsedHost.isUNCIPv6Literal();
//}
//
///**
// * Returns whether this host name is a reverse DNS string host name.
// *
// * @return
// */
//public boolean isReverseDNS() {
//	return isValid() && parsedHost.isReverseDNS();
//}

/**
 * If a prefix length was supplied, either as part of an address or as part of a domain (in which case the prefix applies to any resolved address),
 * then returns that prefix length.  Otherwise, returns null.
 */
//public Integer getNetworkPrefixLength() {
//	if(isAddress()) {
//		return parsedHost.asAddress().getNetworkPrefixLength();
//	} else if(isAddressString()) {
//		return parsedHost.asGenericAddressString().getNetworkPrefixLength();
//	}
//	return isValid() ? parsedHost.getEquivalentPrefixLength() : null;
//}
//
///**
// * If a mask was provided with this host name, this returns the resulting mask value.
// *
// * @return
// */
//public IPAddress getMask() {
//	if(isValid()) {
//		if(parsedHost.isAddressString()) {
//			return parsedHost.getAddressProvider().getProviderMask();
//		}
//		return parsedHost.getMask();
//	}
//	return null;
//}

///**
// * Returns whether this represents, or resolves to,
// * a host or address representing the same host.
// *
// * @return whether this represents or resolves to the localhost host or a loopback address
// */
//public boolean resolvesToSelf() {
//	return isSelf() || (getAddress() != null && resolvedAddress.isLoopback());
//}
//
///**
// * Returns whether this represents a host or address representing the same host.
// * Also see {@link #isLocalHost()} and {@link #isLoopback()}
// *
// * @return whether this is the localhost host or a loopback address
// */
//public boolean isSelf() {
//	return isLocalHost() || isLoopback();
//}
//
///**
// * Returns whether this host is "localhost"
// * @return
// */
//public boolean isLocalHost() {
//	return isValid() && host.equalsIgnoreCase("localhost");
//}
//
///**
// * Returns whether this host has the loopback address, such as
// * [::1] (aka [0:0:0:0:0:0:0:1]) or 127.0.0.1
// *
// * Also see {@link #isSelf()}
// */
//public boolean isLoopback() {
//	return isAddress() && asAddress().isLoopback();
//}
//

// TODO java code has methods which provide InetSocketAddress, InetAddress, etc and/or take as constructor, so do the same for go types

// TODO compareTo

//
//private String toNormalizedWildcardString() {//used by hashCode
//	String result = normalizedWildcardString;
//	if(result == null) {
//		normalizedWildcardString = result = toNormalizedString(true);
//	}
//	return result;
//}
//
func translateReserved(addr *IPv6Address, str string, builder *strings.Builder) {
	//This is particularly targeted towards the zone
	if !addr.HasZone() {
		builder.WriteString(str)
		return
		//return str;
	}
	index := strings.IndexByte(str, IPv6ZoneSeparator)
	//var translated strings.Builder
	var translated *strings.Builder = builder
	//translated.Grow(((len(str) - index) * 3) + index)
	translated.WriteString(str[0:index])
	translated.WriteString("%25")
	for i := index + 1; i < len(str); i++ {
		c := str[i]
		if isReserved(c) {
			translated.WriteByte('%')
			toUnsignedString(uint64(c), 16, translated)
		} else {
			translated.WriteByte(c)
		}
	}
	//return translated.String()
}

func getPrivateHostParams(orig HostNameParameters) *hostNameParameters {
	if p, ok := orig.(*hostNameParameters); ok {
		return p
	}
	return ToHostNameParametersBuilder(orig).ToParams().(*hostNameParameters)
}
