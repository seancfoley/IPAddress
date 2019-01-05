/*
 * Copyright 2016-2018 Sean C Foley
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *     or at
 *     https://github.com/seancfoley/IPAddress/blob/master/LICENSE
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package inet.ipaddr;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.validate.HostIdentifierStringValidator;
import inet.ipaddr.format.validate.ParsedHost;
import inet.ipaddr.format.validate.Validator;
import inet.ipaddr.ipv4.IPv4AddressNetwork.IPv4AddressCreator;
import inet.ipaddr.ipv6.IPv6Address;
import inet.ipaddr.ipv6.IPv6AddressNetwork.IPv6AddressCreator;

//TODO this class needs javadoc

/**
 * An internet host name.  Can be a fully qualified domain name, a simple host name, or an ip address string.
 * <p>
 * <h2>Supported formats</h2>
 * You can use all host or address formats supported by nmap and all address formats supported by {@link IPAddressString}.
 * All manners of domain names are supported. You can add a prefix length to denote the subnet of the resolved address.
 * <p>
 * Validation is done separately from DNS resolution to avoid unnecessary lookups.
 * <p>
 * See rfc 3513, 2181, 952, 1035, 1034, 1123, 5890 or the list of rfcs for IPAddress.  For IPv6 addresses in host, see rfc 2732 specifying [] notation
 * and 3986 and 4038 (combining IPv6 [] with prefix or zone) and SMTP rfc 2821 for alternative uses of [] for both IPv4 and IPv6
 * <p>
 * 
 * @custom.core
 * @author sfoley
 */
public class HostName implements HostIdentifierString, Comparable<HostName> {

	private static final long serialVersionUID = 4L;
	
	public static final char LABEL_SEPARATOR = '.';
	public static final char IPV6_START_BRACKET = '[', IPV6_END_BRACKET = ']';
	public static final char PORT_SEPARATOR = ':';
	
	/* Generally permissive, settings are the default constants in HostNameParameters */
	public static final HostNameParameters DEFAULT_VALIDATION_OPTIONS = new HostNameParameters.Builder().toParams();
	
	/* the original host in string format */
	private final String host;
	
	/* normalized strings representing the host */
	private transient String normalizedString, normalizedWildcardString;

	/* the host broken into its parsed components */
	private ParsedHost parsedHost;

	private HostNameException validationException;

	/* The address if this host represents an ip address, or the address obtained when this host is resolved. */
	IPAddress resolvedAddress;
	private boolean resolvedIsNull;
	
	/* validation options */
	private final HostNameParameters validationOptions;

	public HostName(IPAddress addr) {
		normalizedString = host = addr.toNormalizedString();
		parsedHost = new ParsedHost(host, addr.getProvider());
		validationOptions = null;
	}
	
	public HostName(InetAddress inetAddr) {
		this(inetAddr, IPAddressString.DEFAULT_VALIDATION_OPTIONS);
	}
	
	public HostName(InetAddress inetAddr, IPAddressStringParameters addressOptions) {
		this(inetAddr instanceof Inet4Address ?
				addressOptions.getIPv4Parameters().getNetwork().getAddressCreator().createAddress((Inet4Address) inetAddr) :
				addressOptions.getIPv6Parameters().getNetwork().getAddressCreator().createAddress((Inet6Address) inetAddr));
	}
	
	HostName(String hostStr, ParsedHost parsed) {
		host = hostStr;
		parsedHost = parsed;
		validationOptions = null;
	}
	
	public HostName(String host) {
		this(host, DEFAULT_VALIDATION_OPTIONS);
	}

	public HostName(String host, HostNameParameters options) {
		if(options == null) {
			throw new NullPointerException();
		}
		validationOptions = options;
		this.host = (host == null) ? "" : host.trim();
	}

	void cacheAddress(IPAddress addr) {
		if(parsedHost == null) {
			parsedHost = new ParsedHost(host, addr.getProvider());
			normalizedString = addr.toNormalizedString();
		} else if(normalizedString == null) {
			normalizedString = addr.toNormalizedString();
		}
	}

	public HostNameParameters getValidationOptions() {
		return validationOptions;
	}

	@Override
	public void validate() throws HostNameException {
		if(parsedHost != null) {
			return;
		}
		if(validationException != null) {
			throw validationException;
		}
		synchronized(this) {
			if(parsedHost != null) {
				return;
			}
			if(validationException != null) {
				throw validationException;
			}
			try {
				parsedHost = getValidator().validateHost(this);
			} catch(HostNameException e) {
				validationException = e;
				throw e;
			}
		}
	}
	
	protected HostIdentifierStringValidator getValidator() {
		return Validator.VALIDATOR;
	}

	public boolean isValid() {
		if(parsedHost != null) {
			return true;
		}
		if(validationException != null) {
			return false;
		}
		try {
			validate();
			return true;
		} catch(HostNameException e) {
			return false;
		}
	}
	
	public boolean resolvesToSelf() {
		return isSelf() || (getAddress() != null && resolvedAddress.isLoopback());
	}
	
	public boolean isSelf() {
		return isLocalHost() || isLoopback();
	}
	
	public boolean isLocalHost() {
		return isValid() && host.equalsIgnoreCase("localhost");
	}
	
	/*
	 * [::1] (aka [0:0:0:0:0:0:0:1]) or 127.0.0.1
	 */
	public boolean isLoopback() {
		return isAddress() && asAddress().isLoopback();
	}
	
	public InetAddress toInetAddress() throws HostNameException, UnknownHostException {
		validate();
		return toAddress().toInetAddress();
	}
	
	@Override
	public String toNormalizedString() {
		String result = normalizedString;
		if(result == null) {
			normalizedString = result = toNormalizedString(false);
		}
		return result;
	}
	
	private String toNormalizedWildcardString() {//used by hashCode
		String result = normalizedWildcardString;
		if(result == null) {
			normalizedWildcardString = result = toNormalizedString(true);
		}
		return result;
	}
	
	private static CharSequence translateReserved(IPv6Address addr, String str) {
		//This is particularly targeted towards the zone
		if(!addr.hasZone()) {
			return str;
		}
		int index = str.indexOf(IPv6Address.ZONE_SEPARATOR);
		StringBuilder translated = new StringBuilder(((str.length() - index) * 3) + index);
		translated.append(str, 0, index);
		translated.append("%25");
		for(int i = index + 1; i < str.length(); i++) {
			char c = str.charAt(i);
			if(Validator.isReserved(c)) {
				translated.append('%');
				IPAddressSegment.toUnsignedString(c, 16, translated);
			} else {
				translated.append(c);
			}
		}
		return translated;
	}
	
	private String toNormalizedString(boolean wildcard) {
		if(isValid()) {
			StringBuilder builder = new StringBuilder();
			if(isAddress()) {
				IPAddress addr = asAddress();
				if(addr.isIPv6()) {
					if(!wildcard && addr.isPrefixed()) {//prefix needs to be outside the brackets
						String normalized = addr.toNormalizedString();
						int index = normalized.indexOf(IPAddress.PREFIX_LEN_SEPARATOR);
						CharSequence translated = translateReserved(addr.toIPv6(), normalized.substring(0, index));
						builder.append(IPV6_START_BRACKET).append(translated).append(IPV6_END_BRACKET).append(normalized.substring(index));
					} else {
						String normalized = addr.toNormalizedWildcardString();
						CharSequence translated = translateReserved(addr.toIPv6(), normalized);
						builder.append(IPV6_START_BRACKET).append(translated).append(IPV6_END_BRACKET);
					}
				} else {
					builder.append(wildcard ? addr.toNormalizedWildcardString() : addr.toNormalizedString());
				}

			} else if(isAddressString()) {
				builder.append(asAddressString().toNormalizedString());
			} else {
				builder.append(parsedHost.getHost());
				/*
				 * If prefix or mask is supplied and there is an address, it is applied directly to the address provider, so 
				 * we need only check for those things here
				 * 
				 * Also note that ports and prefix/mask cannot appear at the same time, so this does not interfere with the port code below.
				 */
				Integer networkPrefixLength = parsedHost.getEquivalentPrefixLength();
				if(networkPrefixLength != null) {
					builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(networkPrefixLength);
				} else {
					IPAddress mask = parsedHost.getMask();
					if(mask != null) {
						builder.append(IPAddress.PREFIX_LEN_SEPARATOR).append(mask.toNormalizedString());
					}
				}
			}
			Integer port = parsedHost.getPort();
			if(port != null) {
				builder.append(PORT_SEPARATOR).append(port);
			} else {
				String service = parsedHost.getService();
				if(service != null) {
					builder.append(PORT_SEPARATOR).append(service);
				}
			}
			return builder.toString();
		}
		return host;
	}
	
	@Override
	public boolean equals(Object o) {
		return o instanceof HostName && matches((HostName) o);
	}

	@Override
	public int hashCode() {
		return toNormalizedWildcardString().hashCode();
	}
	
	public String[] getNormalizedLabels() {
		if(isValid()) {
			return parsedHost.getNormalizedLabels();
		}
		if(host.length() == 0) {
			return new String[0];
		}
		return new String[] {host};
	}
	
	/**
	 * Returns the host string normalized but without port, service, prefix or mask.
	 * 
	 * If an address, returns the address string normalized, but without port, service, prefix, mask, or brackets for IPv6.
	 * 
	 * To get a normalized string encompassing all details, use toNormalizedString()
	 * 
	 * If not a valid host, returns null
	 * 
	 * @return
	 */
	public String getHost() {
		if(isValid()) {
			return parsedHost.getHost();
		}
		return null;
	}
	
	public boolean matches(HostName host) {
		if(this == host) {
			return true;
		}
		if(isValid()) {
			if(host.isValid()) {
				if(isAddressString()) {
					return host.isAddressString()
							&& asAddressString().equals(host.asAddressString())
							&& Objects.equals(getPort(), host.getPort())
							&& Objects.equals(getService(), host.getService());
				}
				if(host.isAddressString()) {
					return false;
				}
				String thisHost = parsedHost.getHost();
				String otherHost = host.parsedHost.getHost();
				if(!thisHost.equals(otherHost)) {
					return false;
				}
				return Objects.equals(parsedHost.getEquivalentPrefixLength(), host.parsedHost.getEquivalentPrefixLength()) &&
						Objects.equals(parsedHost.getMask(), host.parsedHost.getMask()) &&
						Objects.equals(parsedHost.getPort(), host.parsedHost.getPort()) &&
						Objects.equals(parsedHost.getService(), host.parsedHost.getService());
			}
			return false;
		}
		return !host.isValid() && toString().equals(host.toString());
	}

	@Override
	public int compareTo(HostName other) {
		if(isValid()) {
			if(other.isValid()) {
				if(isAddressString()) {
					if(other.isAddressString()) {
						int result = asAddressString().compareTo(other.asAddressString());
						if(result != 0) {
							return result;
						}
						//fall through to compare ports
					} else {
						return -1;
					}
				} else if(other.isAddressString()) {
					return 1;
				} else {
					//both are non-address hosts
					String normalizedLabels[] = parsedHost.getNormalizedLabels();
					String otherNormalizedLabels[] = other.parsedHost.getNormalizedLabels();
					int oneLen = normalizedLabels.length;
					int twoLen = otherNormalizedLabels.length;
					for(int i = 1, minLen = Math.min(oneLen, twoLen); i <= minLen; i++) {
						String one = normalizedLabels[oneLen - i];
						String two = otherNormalizedLabels[twoLen - i];
						int result = one.compareTo(two);
						if(result != 0) {
							return result;
						}
					}
					if(oneLen != twoLen) {
						return oneLen - twoLen;
					}
					
					//keep in mind that hosts can has masks/prefixes or ports, but not both
					Integer networkPrefixLength = parsedHost.getEquivalentPrefixLength();
					Integer otherPrefixLength = other.parsedHost.getEquivalentPrefixLength();
					if(networkPrefixLength != null) {
						if(otherPrefixLength != null) {
							if(networkPrefixLength.intValue() != otherPrefixLength.intValue()) {
								return otherPrefixLength - networkPrefixLength;
							}
							//fall through to compare ports
						} else {
							return 1;
						}
					} else {
						if(otherPrefixLength != null) {
							return -1;
						}
						IPAddress mask = parsedHost.getMask();
						IPAddress otherMask = other.parsedHost.getMask();
						if(mask != null) {
							if(otherMask != null) {
								int ret = mask.compareTo(otherMask);
								if(ret != 0) {
									return ret;
								}
								//fall through to compare ports
							} else {
								return 1;
							}
						} else {
							if(otherMask != null) {
								return -1;
							}
							//fall through to compare ports
						}
					}//end non-address host compare
				}
				
				//two equivalent address strings or two equivalent hosts, now check port and service names
				Integer portOne = parsedHost.getPort();
				Integer portTwo = other.parsedHost.getPort();
				if(portOne != null) {
					if(portTwo != null) {
						int ret = portOne - portTwo;
						if(ret != 0) {
							return ret;
						}
					} else {
						return 1;
					}
				} else if(portTwo != null) {
					return -1;
				}
				String serviceOne = parsedHost.getService();
				String serviceTwo = other.parsedHost.getService();
				if(serviceOne != null) {
					if(serviceTwo != null) {
						int ret = serviceOne.compareTo(serviceTwo);
						if(ret != 0) {
							return ret;
						}
					} else {
						return 1;
					}
				} else if(serviceTwo != null) {
					return -1;
				}
				return 0;
			} else {
				return 1;
			}
		} else if(other.isValid()) {
			return -1;
		}
		return toString().compareTo(other.toString());
	}
	
	public boolean isAddress(IPVersion version) {
		return isValid() && parsedHost.isAddressString() && parsedHost.asAddress(version) != null;
	}
	
	public boolean isAddress() {
		return isAddressString() && parsedHost.asAddress() != null; 
	}
	
	public boolean isAddressString() {
		return isValid() && parsedHost.isAddressString();
	}
	
	/**
	 * @return whether the address represents the set all all valid IP addresses (as opposed to an empty string, a specific address, a prefix length, or an invalid format).
	 */
	public boolean isAllAddresses() {
		return isAddressString() && parsedHost.getAddressProvider().isProvidingAllAddresses();
	}

	/**
	 * @return whether the address represents a valid IP address network prefix (as opposed to an empty string, an address with or without a prefix, or an invalid format).
	 */
	public boolean isPrefixOnly() {
		return isAddressString() && parsedHost.getAddressProvider().isProvidingPrefixOnly();
	}

	/**
	 * Returns true if the address is empty (zero-length).
	 * @return
	 */
	public boolean isEmpty() {
		return isAddressString() && parsedHost.getAddressProvider().isProvidingEmpty();
	}

	/**
	 * If a port was supplied, returns the port, otherwise returns null
	 * 
	 * @return
	 */
	public Integer getPort() {
		return isValid() ? parsedHost.getPort() : null;
	}

	/**
	 * If a service name was supplied, returns the service name, otherwise returns null
	 * 
	 * @return
	 */
	public String getService() {
		return isValid() ? parsedHost.getService() : null;
	}

	/**
	 * Returns the exception thrown for invalid ipv6 literal or invalid reverse DNS hosts.
	 * 
	 * This method will return non-null when this host is valid, so no HostException is thrown,
	 * but a secondary address within the host is not valid.
	 *  
	 * @return
	 */
	public AddressStringException getAddressStringException() {
		if(isValid()) {
			return parsedHost.getAddressStringException();
		}
		return null;
	}
	
	public boolean isUNCIPv6Literal() {
		return isValid() && parsedHost.isUNCIPv6Literal();
	}
	
	public boolean isReverseDNS() {
		return isValid() && parsedHost.isReverseDNS();
	}
	
	/**
	 * If this represents an ip address or represents a valid IPAddressString, returns the corresponding address string.
	 * Otherwise, returns null.  Call toResolvedAddress or resolve to get the resolved address.
	 * @return
	 */
	public IPAddressString asAddressString() {
		if(isAddressString()) {
			return parsedHost.asGenericAddressString();//xxx;//this is for address string not convertible to address
		}
		return null;
	}
	
	/**
	 * If this represents an ip address, returns that address.
	 * Otherwise, returns null.  Call toResolvedAddress or resolve to get the resolved address, which is different.
	 * 
	 * In cases such as IPv6 literals and reverse DNS hosts, you can check the relevant methods isIpv6Literal or isReverseDNS,
	 * in which case this method should return the associated address.  If this method returns null then an exception occurred
	 * when producing the associated address, and that exception is available from getAddressStringException.
	 * 
	 * @return
	 */
	public IPAddress asAddress() {
		if(isAddress()) {
			return parsedHost.asAddress();
		}
		return null;
	}
	
	/**
	 * If this represents an ip address, returns that address.
	 * Otherwise, returns null.  Call {@link #toAddress()} or {@link #getAddress()} to get the resolved address.
	 * 
	 * @return
	 */
	public IPAddress asAddress(IPVersion version) {
		if(isAddress(version)) {
			return parsedHost.asAddress(version);
		}
		return null;
	}
	
	/**
	 * If a prefix length was supplied, either as part of an address or as part of a domain (in which case the prefix applies to any resolved address), 
	 * then returns that prefix length.  Otherwise, returns null.
	 */
	public Integer getNetworkPrefixLength() {
		if(isAddress()) {
			return parsedHost.asAddress().getNetworkPrefixLength();
		} else if(isAddressString()) {
			return parsedHost.asGenericAddressString().getNetworkPrefixLength();
		}
		return isValid() ? parsedHost.getNetworkPrefixLength() : null;
	}

	/**
	 * If this represents an ip address, returns that address.
	 * If this represents a host, returns the resolved ip address of that host.
	 * Otherwise, returns null, but only for strings that are considered valid address strings but cannot be converted to address objects.
	 * 
	 * This method will throw exceptions for invalid formats and failures to resolve the address.  The equivalent method {@link #getAddress()} will simply return null rather than throw those exceptions.
	 * 
	 * If you wish to get the represented address and avoid DNS resolution, use {@link #asAddress()} or {@link #asAddressString()}
	 * 
	 * @return
	 */
	@Override
	public IPAddress toAddress() throws UnknownHostException, HostNameException {
		IPAddress addr = resolvedAddress;
		if(addr == null && !resolvedIsNull) {
			//note that validation handles empty address resolution
			validate();
			synchronized(this) {
				addr = resolvedAddress;
				if(addr == null && !resolvedIsNull) {
					if(parsedHost.isAddressString()) {
						addr = parsedHost.asAddress();
						resolvedIsNull = (addr == null);
						//note there is no need to apply prefix or mask here, it would have been applied to the address already
					} else {
						String strHost = parsedHost.getHost();
						if(strHost.length() == 0 && !validationOptions.emptyIsLoopback) {
							addr = null;
							resolvedIsNull = true;
						} else {
							//Note we do not set resolvedIsNull, so we will attempt to resolve again if the previous attempt threw an exception
							InetAddress inetAddress = InetAddress.getByName(strHost);
							byte bytes[] = inetAddress.getAddress();
							Integer networkPrefixLength = parsedHost.getNetworkPrefixLength();
							if(networkPrefixLength == null) {
								IPAddress mask = parsedHost.getMask();
								if(mask != null) {
									byte maskBytes[] = mask.getBytes();
									if(maskBytes.length != bytes.length) {
										throw new HostNameException(host, "ipaddress.error.ipMismatch");
									}
									for(int i = 0; i < bytes.length; i++) {
										bytes[i] &= maskBytes[i];
									}
									networkPrefixLength = mask.getBlockMaskPrefixLength(true);
								}
							}
							IPAddressStringParameters addressParams = validationOptions.addressOptions;
							if(bytes.length == IPv6Address.BYTE_COUNT) {
								IPv6AddressCreator creator = addressParams.getIPv6Parameters().getNetwork().getAddressCreator();
								addr = creator.createAddressInternal(bytes, networkPrefixLength, null, this); /* address creation */
							} else {
								IPv4AddressCreator creator = addressParams.getIPv4Parameters().getNetwork().getAddressCreator();
								addr = creator.createAddressInternal(bytes, networkPrefixLength, this); /* address creation */
							}
						}
					}
					resolvedAddress = addr;
				}
			}
		}
		return addr;
	}

	/**
	 * If this represents an ip address, returns that address.
	 * If this represents a host, returns the resolved ip address of that host.
	 * Otherwise, returns null.
	 * 
	 * If you wish to get the represented address and avoid DNS resolution, use {@link #asAddress()} or {@link #asAddressString()}
	 * 
	 * @return
	 */
	@Override
	public IPAddress getAddress() {
		try {
			return toAddress();
		} catch(HostNameException | UnknownHostException e) {
			//call toResolvedAddress if you wish to see this exception
			//HostNameException objects are cached in validate and can be seen by calling validate
		}
		return null;
	}
	
	@Override
	public String toString() {
		return host;
	}
}
