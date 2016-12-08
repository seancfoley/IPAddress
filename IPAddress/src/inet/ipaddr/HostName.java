package inet.ipaddr;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.format.validate.AddressProvider;
import inet.ipaddr.format.validate.HostIdentifierStringValidator;
import inet.ipaddr.format.validate.ParsedHost;
import inet.ipaddr.format.validate.Validator;

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
 * and 4038 (combining IPv6 [] with prefix or zone) and SMTP rfc 2821 for alternative uses of [] for both IPv4 and IPv6
 * <p>
 * 
 * @custom.core
 * @author sfoley
 */
public class HostName implements HostIdentifierString, Comparable<HostName>, Serializable {

	private static final long serialVersionUID = 1L;
	
	public static final char LABEL_SEPARATOR = '.';
	public static final char IPV6_START_BRACKET = '[', IPV6_END_BRACKET = ']';
	
	/* Generally permissive, settings are the default constants in HostNameParameters */
	private static final HostNameParameters DEFAULT_BASIC_VALIDATION_OPTIONS = new HostNameParameters.Builder().toOptions();
	
	/* the original host in string format */
	private final String host;
	
	/* a normalized string representing the host, in practice the only normalization needed is lowercase */
	private transient String normalizedString;

	/* the host broken into its parsed components */
	private ParsedHost parsedHost;

	private HostNameException validationException;

	/* The address if this host represents an ip address, or the address obtained when this host is resolved. */
	IPAddress resolvedAddress;
	
	/* validation options */
	private final HostNameParameters validationOptions;

	public HostName(IPAddress addr) {
		normalizedString = host = addr.toNormalizedString();
		parsedHost = new ParsedHost(host, AddressProvider.getProviderFor(addr));
		validationOptions = null;
	}
	
	public HostName(InetAddress inetAddr) {
		this(IPAddress.from(inetAddr));
	}
	
	HostName(String host, ParsedHost parsed) {
		this.host = host;
		parsedHost = parsed;
		validationOptions = null;
	}
	
	public HostName(String host) {
		this(host, DEFAULT_BASIC_VALIDATION_OPTIONS);
	}
	
	public HostName(String host, HostNameParameters options) {
		if(options == null) {
			throw new NullPointerException();
		}
		this.validationOptions = options;
		this.host = (host == null) ? "" : host.trim();;
	}
	
	void cacheAddress(IPAddress addr) {
		if(parsedHost == null) {
			parsedHost = new ParsedHost(host, AddressProvider.getProviderFor(addr));
			normalizedString = addr.toNormalizedString();
		} else if(normalizedString == null) {
			normalizedString = addr.toNormalizedString();
		}
	}
	
	public HostNameParameters getValidationOptions() {
		return validationOptions;
	}

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
		return isSelf() || (resolve() != null && resolvedAddress.isLoopback());
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
		return toResolvedAddress().toInetAddress();
	}
	
	@Override
	public String toNormalizedString() {
		String result = normalizedString;
		if(result == null) {		
			try {
				validate();
				if(isAddressString()) {
					result = IPAddressString.toNormalizedString(parsedHost.addressProvider);
				} else {
					result = parsedHost.getHost();
				}
			} catch(HostNameException e) {
				//for invalid hosts, don't normalize, just return it as is
				result = host;
			}
			normalizedString = result;	
		}
		return result;
	}
	
	@Override
	public String toString() {
		return host;
	}
	
	@Override
	public boolean equals(Object o) {
		return o instanceof HostName && matches((HostName) o);
	}
	
	public boolean matches(HostName host) {
		if(this == host) {
			return true;
		}
		if(isAddressString()) {//address strings match
			return host.isValid() && parsedHost.addressProvider.equals(host.parsedHost.addressProvider);
		}
		return toNormalizedString().equals(host.toNormalizedString());
	}
	
	@Override
	public int hashCode() {
		if(isValid() && parsedHost.addressProvider != null) {
			IPAddress val = parsedHost.addressProvider.getAddress();
			if(val != null) {
				return val.hashCode();
			}
			return parsedHost.asGenericAddressString().hashCode();
		}
		return toNormalizedString().hashCode();
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
	
	@Override
	public int compareTo(HostName other) {
		if(isAddress()) {
			if(other.isAddress()) {
				return asAddress().compareTo(other.asAddress());
			} else {
				return -1;
			}
		} else {
			if(other.isAddress()) {
				return 1;
			} else {
				String normalizedLabels[] = parsedHost.getNormalizedLabels();
				if(normalizedLabels != null) {
					String otherNormalizedLabels[] = other.parsedHost.getNormalizedLabels();
					if(otherNormalizedLabels != null) {
						for(int i=1, max = Math.min(normalizedLabels.length, otherNormalizedLabels.length); i>=max; i--) {
							String one = normalizedLabels[normalizedLabels.length - i];
							String two = otherNormalizedLabels[otherNormalizedLabels.length - i];
							int result = one.compareTo(two);
							if(result != 0) {
								return result;
							}
						}
						return normalizedLabels.length - otherNormalizedLabels.length;
					}
				}
			}
		}
		return toNormalizedString().compareTo(other.toNormalizedString());
	}
	
	public boolean isAddress(IPVersion version) {
		return isValid() && parsedHost.addressProvider != null && parsedHost.addressProvider.getAddress(version) != null;
	}
	
	public boolean isAddress() {
		return isAddressString() && parsedHost.addressProvider.getAddress() != null;
	}
	
	public boolean isAddressString() {
		return isValid() && parsedHost.addressProvider != null;
	}
	
	/**
	 * @return whether the address represents the set all all valid IP addresses (as opposed to an empty string, a specific address, a prefix length, or an invalid format).
	 */
	public boolean isAllAddresses() {
		return isAddressString() && parsedHost.addressProvider.isAllAddresses();
	}
	
	/**
	 * @return whether the address represents a valid IP address network prefix (as opposed to an empty string, an address with or without a prefix, or an invalid format).
	 */
	public boolean isPrefixOnly() {
		return isAddressString() && parsedHost.addressProvider.isPrefixOnly();
	}
	
	/**
	 * Returns true if the address is empty (zero-length).
	 * @return
	 */
	public boolean isEmpty() {
		return isAddressString() && parsedHost.addressProvider.isEmpty();
	}
	
	/**
	 * If this represents an address that was not bracketed as a host, then it returns the bracketed address as a host.
	 * This is the standard for IPv6 in URLs.
	 * Otherwise, it returns the original string.
	 */
	public String toURLString() {
		if(isAddress()) {
			IPAddress addr = asAddress();
			if(addr.isPrefixed()) {//prefix needs to be outside the brackets
				int bits = addr.getNetworkPrefixLength();
				IPAddress addrNoPrefix = addr.toSubnet(addr.getNetwork().getNetworkMask(bits));//either we mask it or we grab the lowest value of the range to get rid of prefix
				return IPV6_START_BRACKET + addrNoPrefix.toNormalizedString() + IPV6_END_BRACKET + IPAddress.PREFIX_LEN_SEPARATOR + bits;
			} else {
				return IPV6_START_BRACKET + addr.toNormalizedString() + IPV6_END_BRACKET;
			}
		}
		return toNormalizedString();
	}
	
	/**
	 * If this represents an ip address or represents a valid IPAddressString, returns the corresponding address string.
	 * Otherwise, returns null.  Call toResolvedAddress or resolve to get the resolved address.
	 * @return
	 */
	public IPAddressString asAddressString() {
		if(isAddressString()) {
			IPAddress val = parsedHost.addressProvider.getAddress();
			if(val != null) {
				return val.toAddressString();
			}
			return parsedHost.asGenericAddressString();
		}
		return null;
	}
	
	/**
	 * If this represents an ip address, returns that address.
	 * Otherwise, returns null.  Call toResolvedAddress or resolve to get the resolved address, which is different.
	 * 
	 * @return
	 */
	public IPAddress asAddress() {
		if(isAddress()) {
			return parsedHost.addressProvider.getAddress();
		}
		return null;
	}
	
	/**
	 * If this represents an ip address, returns that address.
	 * Otherwise, returns null.  Call toResolvedAddress or resolve to get the resolved address, which is different.
	 * 
	 * @return
	 */
	public IPAddress asAddress(IPVersion version) {
		if(isAddress(version)) {
			return parsedHost.addressProvider.getAddress(version);
		}
		return null;
	}
	
	public IPAddress toResolvedAddress() throws UnknownHostException, HostNameException {
		IPAddress addr = resolvedAddress;
		if(addr == null) {
			//note that validation handles empty address resolution
			validate();
			synchronized(this) {
				addr = resolvedAddress;
				if(addr == null) {
					resolvedAddress = addr = parsedHost.resolveAddress(this, validationOptions);
				}
			}
		}
		return addr;
	}

	/**
	 * If this represents an ip address, returns that address.
	 * If this represents a host, returns the resolved ip address of that host.
	 * Otherwise, returns null.
	 * @return
	 */
	public IPAddress resolve() {
		try {
			return toResolvedAddress();
		} catch(HostNameException | UnknownHostException e) {
			//call toResolvedAddress if you wish to see this exception
		}
		return null;
	}
}
