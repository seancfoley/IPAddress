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

// NewHostName constructs an HostName that will parse the given string according to the default parameters
func NewHostName(str string) *HostName {
	return &HostName{str: str, params: defaultHostParameters, hostCache: &hostCache{}}
}

// NewHostNameParams constructs an HostName that will parse the given string according to the given parameters
func NewHostNameParams(str string, params HostNameParameters) *HostName {
	var prms *hostNameParameters
	if params == nil {
		prms = defaultHostParameters
	} else {
		prms = getPrivateHostParams(params)
	}
	return &HostName{str: str, params: prms, hostCache: &hostCache{}}
}

func NewHostNameFromAddrPort(addr *IPAddress, port int) *HostName {
	portVal := PortNum(port)
	hostStr := toNormalizedAddrPortString(addr, portVal)
	parsedHost := parsedHost{
		originalStr:     hostStr,
		embeddedAddress: embeddedAddress{addressProvider: addr.getProvider()},
		labelsQualifier: parsedHostIdentifierStringQualifier{port: cachePorts(portVal)},
	}
	return &HostName{
		str:       hostStr,
		params:    defaultHostParameters,
		hostCache: &hostCache{normalizedString: &hostStr, hostData: &hostData{parsedHost: &parsedHost}},
	}
}

func NewHostNameFromAddr(addr *IPAddress) *HostName {
	hostStr := addr.ToNormalizedString()
	return newHostNameFromAddr(hostStr, addr)
}

func newHostNameFromAddr(hostStr string, addr *IPAddress) *HostName { // same as HostName(String hostStr, ParsedHost parsed) {
	parsedHost := parsedHost{
		originalStr:     hostStr,
		embeddedAddress: embeddedAddress{addressProvider: addr.getProvider()},
	}
	return &HostName{
		str:       hostStr,
		params:    defaultHostParameters,
		hostCache: &hostCache{normalizedString: &hostStr, hostData: &hostData{parsedHost: &parsedHost}},
	}
}

func NewHostNameFromTCPAddr(addr *net.TCPAddr) (*HostName, AddressValueError) {
	return newHostNameFromSocketAddr(addr.IP, addr.Port, addr.Zone)
}

func NewHostNameFromUDPAddr(addr *net.UDPAddr) (*HostName, AddressValueError) {
	return newHostNameFromSocketAddr(addr.IP, addr.Port, addr.Zone)
}

func newHostNameFromSocketAddr(ip net.IP, port int, zone string) (hostName *HostName, err AddressValueError) {
	var ipAddr *IPAddress
	if zone == NoZone {
		ipAddr, err = addrFromIP(ip)
	} else {
		var addr6 *IPv6Address
		addr6, err = NewIPv6AddressFromIPAddr(&net.IPAddr{IP: ip, Zone: zone})
		ipAddr = addr6.ToIPAddress()
	}
	if err == nil {
		portVal := PortNum(port)
		hostStr := toNormalizedAddrPortString(ipAddr, portVal)
		parsedHost := parsedHost{
			originalStr:     hostStr,
			embeddedAddress: embeddedAddress{addressProvider: ipAddr.getProvider()},
			labelsQualifier: parsedHostIdentifierStringQualifier{port: cachePorts(portVal)},
		}
		hostName = &HostName{
			str:       hostStr,
			params:    defaultHostParameters,
			hostCache: &hostCache{normalizedString: &hostStr, hostData: &hostData{parsedHost: &parsedHost}},
		}
	}
	return
}

func NewHostNameFromIP(bytes net.IP) (hostName *HostName, err AddressValueError) {
	addr, err := addrFromIP(bytes)
	if err == nil {
		hostName = NewHostNameFromAddr(addr)
	}
	return
}

func NewHostNameFromPrefixedIP(bytes net.IP, prefixLen PrefixLen) (hostName *HostName, err AddressValueError) {
	addr, err := addrFromPrefixedIP(bytes, prefixLen)
	if err == nil {
		hostName = NewHostNameFromAddr(addr)
	}
	return
}

func NewHostNameFromIPAddr(addr *net.IPAddr) (hostName *HostName, err AddressValueError) {
	if addr.Zone == NoZone {
		return NewHostNameFromIP(addr.IP)
	}
	addr6, err := NewIPv6AddressFromIPAddr(addr)
	if err == nil {
		hostName = NewHostNameFromAddr(addr6.ToIPAddress())
	}
	return
}

func NewHostNameFromPrefixedIPAddr(addr *net.IPAddr, prefixLen PrefixLen) (hostName *HostName, err AddressValueError) {
	if addr.Zone == NoZone {
		return NewHostNameFromPrefixedIP(addr.IP, prefixLen)
	}
	addr6, err := NewIPv6AddressFromPrefixedIPAddr(addr, prefixLen)
	if err == nil {
		hostName = NewHostNameFromAddr(addr6.ToIPAddress())
	}
	return
}

var defaultHostParameters = &hostNameParameters{}

var zeroHost = NewHostName("")

type hostData struct {
	parsedHost    *parsedHost
	validateError HostNameError
}

type resolveData struct {
	resolvedAddrs []*IPAddress
	err           error
}

type hostCache struct {
	*hostData
	*resolveData
	normalizedString,
	normalizedWildcardString *string
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
func (host *HostName) Validate() HostNameError {
	host = host.init()
	data := host.hostData
	if data == nil {
		parsedHost, err := validator.validateHostName(host)
		data = &hostData{parsedHost, err}
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&host.hostData))
		atomic.StorePointer(dataLoc, unsafe.Pointer(data))
	}
	return data.validateError
}

func (host *HostName) String() string {
	return host.str
}

func (host *HostName) IsAddressString() bool {
	host = host.init()
	return host.IsValid() && host.parsedHost.isAddressString()
}

func (host *HostName) IsAddress() bool {
	if host.IsAddressString() {
		addr, _ := host.init().parsedHost.asAddress()
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

func (host *HostName) ToAddress() (addr *IPAddress, err AddressError) {
	addresses, err := host.ToAddresses()
	if len(addresses) > 0 {
		addr = addresses[0]
	}
	return
}

// error can be AddressStringError or IncompatibleAddressError
func (host *HostName) ToAddresses() (addrs []*IPAddress, err AddressError) {
	host = host.init()
	data := host.resolveData
	if data == nil {
		//note that validation handles empty address resolution
		err = host.Validate() //HostNameError
		if err != nil {
			return
		}
		// http://networkbit.ch/golang-dns-lookup/
		parsedHost := host.parsedHost
		if parsedHost.isAddressString() {
			addr, addrErr := parsedHost.asAddress() // IncompatibleAddressError
			addrs, err = []*IPAddress{addr}, addrErr
			//note there is no need to apply prefix or mask here, it would have been applied to the address already
		} else {
			strHost := parsedHost.getHost()
			validationOptions := host.getParams()
			if len(strHost) == 0 {
				emptyStringOpt := validationOptions.EmptyStrParsedAs()
				if emptyStringOpt != NoAddress {
					addrFunc, _ := emptyAddressCreator(
						validationOptions.EmptyStrParsedAs(),
						validationOptions.GetIPAddressParameters(),
						validationOptions.GetPreferredVersion(),
						NoZone)
					addr, _ := addrFunc()
					addrs = []*IPAddress{addr}
				} else {
					addrs = []*IPAddress{}
				}
			} else {
				var ips []net.IP
				ips, lookupErr := net.LookupIP(strHost)
				if lookupErr != nil {
					//Note we do not set resolveData, so we will attempt to resolve again
					err = &hostNameNestedError{nested: lookupErr,
						hostNameError: hostNameError{addressError{str: strHost, key: "ipaddress.host.error.host.resolve"}}}
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
						ipv6Addr, addrErr := NewIPv6AddressFromPrefixedIP(addr, networkPrefixLength) // AddressValueError
						if addrErr != nil {
							return nil, addrErr
						}
						ipv6Addr.cache.fromHost = host
						addrs[j] = ipv6Addr.ToIPAddress()
					} else {
						if networkPrefixLength != nil && *networkPrefixLength > IPv4BitCount {
							networkPrefixLength = cacheBitCount(IPv4BitCount)
						}
						ipv4Addr, addrErr := NewIPv4AddressFromPrefixedIP(addr, networkPrefixLength) // AddressValueError
						if addrErr != nil {
							return nil, addrErr
						}
						ipv4Addr.cache.fromHost = host
						addrs[j] = ipv4Addr.ToIPAddress()
					}
				}
				// sort by preferred version
				preferredVersion := validationOptions.GetPreferredVersion()
				boundaryCase := 8
				if count > boundaryCase {
					c := 0
					newAddrs := make([]*IPAddress, count)
					for _, val := range addrs {
						if val.getIPVersion() == preferredVersion {
							newAddrs[c] = val
							c++
						}
					}
					for i := 0; c < count; i++ {
						val := addrs[i]
						if val.getIPVersion() != preferredVersion {
							newAddrs[c] = val
							c++
						}
					}
					addrs = newAddrs
				} else {
					preferredIndex := 0
				top:
					for i := 0; i < count; i++ {
						notPreferred := addrs[i]
						if notPreferred.getIPVersion() != preferredVersion {
							var j int
							if preferredIndex == 0 {
								j = i + 1
							} else {
								j = preferredIndex
							}
							for ; j < len(addrs); j++ {
								preferred := addrs[j]
								if preferred.getIPVersion() == preferredVersion {
									addrs[i] = preferred
									// don't swap so the non-preferred order is preserved,
									// instead shift each upwards by one spot
									k := i + 1
									for ; k < j; k++ {
										addrs[k], notPreferred = notPreferred, addrs[k]
									}
									addrs[k] = notPreferred
									preferredIndex = j + 1
									continue top
								}
							}
							// no more preferred
							break
						}
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

func (host *HostName) ToHostAddress() (*Address, AddressError) {
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

// ToNormalizedString provides a normalized string which is lowercase for host strings, and which is a normalized string for addresses.
func (host *HostName) ToNormalizedWildcardString() string {
	host = host.init()
	str := host.normalizedWildcardString
	if str == nil {
		newStr := host.toNormalizedString(false)
		dataLoc := (*unsafe.Pointer)(unsafe.Pointer(&host.normalizedWildcardString))
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
			} else {
				mask := host.parsedHost.getMask()
				if mask != nil {
					builder.WriteByte(PrefixLenSeparator)
					builder.WriteString(mask.ToNormalizedString())
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
			}
		}
		return builder.String()
	}
	return host.str
}

func toNormalizedPortString(port PortNum, builder *strings.Builder) {
	builder.WriteByte(PortSeparator)
	toUnsignedString(uint64(port), 10, builder)
}

func toNormalizedHostString(addr *IPAddress, wildcard bool, builder *strings.Builder) {
	if addr.isIPv6() {
		if !wildcard && addr.IsPrefixed() { // prefix needs to be outside the brackets
			normalized := addr.ToNormalizedString()
			index := strings.IndexByte(normalized, PrefixLenSeparator)
			builder.WriteByte(IPv6StartBracket)
			translateReserved(addr.ToIPv6Address(), normalized[:index], builder)
			builder.WriteByte(IPv6EndBracket)
			builder.WriteString(normalized[index:])
		} else {
			normalized := addr.ToNormalizedWildcardString()
			builder.WriteByte(IPv6StartBracket)
			translateReserved(addr.ToIPv6Address(), normalized, builder)
			builder.WriteByte(IPv6EndBracket)
		}
	} else {
		if wildcard {
			builder.WriteString(addr.ToNormalizedWildcardString())
		} else {
			builder.WriteString(addr.ToNormalizedString())
		}
	}
}

func toNormalizedAddrPortString(addr *IPAddress, port PortNum) string {
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
TODO LATER isUNCIPv6Literal and isReverseDNS
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

// GetNetworkPrefixLength() returns the prefix length, if a prefix length was supplied,
// either as part of an address or as part of a domain (in which case the prefix applies to any resolved address),
// Otherwise, returns nil.
func (host *HostName) GetNetworkPrefixLength() PrefixLen {
	if host.IsAddress() {
		addr, err := host.parsedHost.asAddress()
		if err != nil {
			return addr.GetNetworkPrefixLength()
		}
	} else if host.IsAddressString() {
		return host.parsedHost.asGenericAddressString().GetNetworkPrefixLength()
	} else if host.IsValid() {
		return host.parsedHost.getEquivalentPrefixLength()
	}
	return nil
}

// GetMask returns the resulting mask value if a mask was provided with this host name.
func (host *HostName) GetMask() *IPAddress {
	if host.IsValid() {
		if host.parsedHost.isAddressString() {
			return host.parsedHost.getAddressProvider().getProviderMask()
		}
		return host.parsedHost.getMask()
	}
	return nil
}

// ResolvesToSelf returns whether this represents, or resolves to,
// a host or address representing the same host.
func (host *HostName) ResolvesToSelf() bool {
	if host.IsSelf() {
		return true
	} else if host.GetAddress() != nil {
		host.resolvedAddrs[0].IsLoopback()
	}
	return false
}

// IsSelf returns whether this represents a host or address representing the same host.
// Also see isLocalHost() and {@link #isLoopback()}
func (host *HostName) IsSelf() bool {
	return host.IsLocalHost() || host.IsLoopback()
}

// IsLocalHost returns whether this host is "localhost"
func (host *HostName) IsLocalHost() bool {
	return host.IsValid() && strings.EqualFold(host.str, "localhost")
}

// IsLoopback returns whether this host has the loopback address, such as
// [::1] (aka [0:0:0:0:0:0:0:1]) or 127.0.0.1
//
// Also see isSelf()
func (host *HostName) IsLoopback() bool {
	return host.IsAddress() && host.AsAddress().IsLoopback()
}

// ToTCPAddrService returns the TCPAddr if this HostName both resolves to an address and has an associated service or port
func (host *HostName) ToTCPAddrService(serviceMapper func(string) Port) *net.TCPAddr {
	if host.IsValid() {
		port := host.GetPort()
		if port == nil && serviceMapper != nil {
			service := host.GetService()
			if service != "" {
				port = serviceMapper(service)
			}
		}
		if port != nil {
			if addr := host.AsAddress(); addr != nil {
				return &net.TCPAddr{
					IP:   addr.GetIP(),
					Port: int(*port),
					Zone: string(addr.zone),
				}
			}
		}
	}
	return nil
}

// ToTCPAddr returns the TCPAddr if this HostName both resolves to an address and has an associated port
func (host *HostName) ToTCPAddr() *net.TCPAddr {
	return host.ToTCPAddrService(nil)
}

// ToUDPAddrService returns the UDPAddr if this HostName both resolves to an address and has an associated service or port
func (host *HostName) ToUDPAddrService(serviceMapper func(string) Port) *net.UDPAddr {
	tcpAddr := host.ToTCPAddrService(serviceMapper)
	if tcpAddr != nil {
		return &net.UDPAddr{
			IP:   tcpAddr.IP,
			Port: tcpAddr.Port,
			Zone: tcpAddr.Zone,
		}
	}
	return nil
}

// ToUDPAddr returns the UDPAddr if this HostName both resolves to an address and has an associated port
func (host *HostName) ToUDPAddr(serviceMapper func(string) Port) *net.UDPAddr {
	return host.ToUDPAddrService(serviceMapper)
}

func (host *HostName) ToIP() net.IP {
	if addr, err := host.ToAddress(); addr != nil && err == nil {
		return addr.GetIP()
	}
	return nil
}

func (host *HostName) ToIPAddr() *net.IPAddr {
	if addr, err := host.ToAddress(); addr != nil && err == nil {
		return &net.IPAddr{
			IP:   addr.GetIP(),
			Zone: string(addr.zone),
		}
	}
	return nil
}

func (host *HostName) compareTo(other *HostName) int {
	if host.IsValid() {
		if other.IsValid() {
			parsedHost := host.parsedHost
			otherParsedHost := other.parsedHost
			if parsedHost.isAddressString() {
				if otherParsedHost.isAddressString() {
					result := parsedHost.asGenericAddressString().CompareTo(otherParsedHost.asGenericAddressString())
					if result != 0 {
						return result
					}
					//fall through to compare ports
				} else {
					return -1
				}
			} else if otherParsedHost.isAddressString() {
				return 1
			} else {
				//both are non-address hosts
				normalizedLabels := parsedHost.getNormalizedLabels()
				otherNormalizedLabels := otherParsedHost.getNormalizedLabels()
				oneLen := len(normalizedLabels)
				twoLen := len(otherNormalizedLabels)
				var minLen int
				if oneLen < twoLen {
					minLen = oneLen
				} else {
					minLen = twoLen
				}
				for i := 1; i <= minLen; i++ {
					one := normalizedLabels[oneLen-i]
					two := otherNormalizedLabels[twoLen-i]
					result := strings.Compare(one, two)
					if result != 0 {
						return result
					}
				}
				if oneLen != twoLen {
					return oneLen - twoLen
				}

				//keep in mind that hosts can has masks/prefixes or ports, but not both
				networkPrefixLength := parsedHost.getEquivalentPrefixLength()
				otherPrefixLength := otherParsedHost.getEquivalentPrefixLength()
				if networkPrefixLength != nil {
					if otherPrefixLength != nil {
						if *networkPrefixLength != *otherPrefixLength {
							return int(*otherPrefixLength - *networkPrefixLength)
						}
						//fall through to compare ports
					} else {
						return 1
					}
				} else {
					if otherPrefixLength != nil {
						return -1
					}
					mask := parsedHost.getMask()
					otherMask := otherParsedHost.getMask()
					if mask != nil {
						if otherMask != nil {
							ret := mask.CompareTo(otherMask)
							if ret != 0 {
								return ret
							}
							//fall through to compare ports
						} else {
							return 1
						}
					} else {
						if otherMask != nil {
							return -1
						}
						//fall through to compare ports
					}
				} //end non-address host compare
			}

			//two equivalent address strings or two equivalent hosts, now check port and service names
			portOne := parsedHost.getPort()
			portTwo := otherParsedHost.getPort()
			if portOne != nil {
				if portTwo != nil {
					ret := *portOne - *portTwo
					if ret != 0 {
						return int(ret)
					}
				} else {
					return 1
				}
			} else if portTwo != nil {
				return -1
			}
			serviceOne := parsedHost.getService()
			serviceTwo := otherParsedHost.getService()
			if serviceOne != "" {
				if serviceTwo != "" {
					ret := strings.Compare(serviceOne, serviceTwo)
					if ret != 0 {
						return ret
					}
				} else {
					return 1
				}
			} else if serviceTwo != "" {
				return -1
			}
			return 0
		} else {
			return 1
		}
	} else if other.IsValid() {
		return -1
	}
	return strings.Compare(host.String(), other.String())
}

func translateReserved(addr *IPv6Address, str string, builder *strings.Builder) {
	//This is particularly targeted towards the zone
	if !addr.HasZone() {
		builder.WriteString(str)
		return
	}
	index := strings.IndexByte(str, IPv6ZoneSeparator)
	var translated *strings.Builder = builder
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
}

func getPrivateHostParams(orig HostNameParameters) *hostNameParameters {
	if p, ok := orig.(*hostNameParameters); ok {
		return p
	}
	return ToHostNameParametersBuilder(orig).ToParams().(*hostNameParameters)
}
