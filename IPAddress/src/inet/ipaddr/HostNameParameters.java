package inet.ipaddr;

import java.io.Serializable;

/**
 * This class allows you to control the validation performed by the class {@link HostName}.
 * 
 * The {@link HostName} class uses a default permissive HostNameParameters object when you do not specify one.
 * 
 * If you wish to use parameters different from the default, then use this class.  All instances are immutable and must be constructed with the nested Builder class.
 * 
 * @author sfoley
 *
 */
public class HostNameParameters implements Cloneable, Comparable<HostNameParameters>, Serializable {
	
	private static final long serialVersionUID = 1L;

	public static final boolean DEFAULT_ALLOW_EMPTY = true;
	public static final boolean DEFAULT_EMPTY_IS_LOOPBACK = true; //Note that with InetAddress, empty strings are interpreted as the loopback address
	public static final boolean DEFAULT_ACCEPT_BRACKETED_IPV6 = true;
	public static final boolean DEFAULT_ACCEPT_BRACKETED_IPV4 = true;
	public static final boolean DEFAULT_NORMALIZE_TO_LOWER_CASE = true;
	public static final boolean DEFAULT_ALLOW_IP_ADDRESS = true;
	
	public final boolean allowEmpty;
	public final boolean emptyIsLoopback;
	public final boolean allowBracketedIPv4;
	public final boolean allowBracketedIPv6;
	public final boolean normalizeToLowercase;
	public final boolean allowIPAddress;
	public final IPAddressStringParameters addressOptions;
	
	public HostNameParameters(
			IPAddressStringParameters addressOptions,
			boolean allowEmpty,
			boolean emptyIsLoopback,
			boolean allowBracketedIPv6,
			boolean allowBracketedIPv4,
			boolean normalizeToLowercase,
			boolean allowIPAddress) {
		this.allowEmpty = allowEmpty;
		this.emptyIsLoopback = emptyIsLoopback;
		this.allowBracketedIPv6 = allowBracketedIPv6;
		this.allowBracketedIPv4 = allowBracketedIPv4;
		this.normalizeToLowercase = normalizeToLowercase;
		this.allowIPAddress = allowIPAddress;
		this.addressOptions = addressOptions;
	}
	
	public Builder toBuilder() {
		Builder builder = new Builder();
		builder.allowEmpty = allowEmpty;
		builder.emptyIsLoopback = emptyIsLoopback;
		builder.allowBracketedIPv4 = allowBracketedIPv4;
		builder.allowBracketedIPv6 = allowBracketedIPv6;
		builder.normalizeToLowercase = normalizeToLowercase;
		builder.allowIPAddress = allowIPAddress;
		builder.addressOptionsBuilder = toAddressOptionsBuilder();
		return builder;
	}
	
	public IPAddressStringParameters.Builder toAddressOptionsBuilder() {
		return addressOptions.toBuilder();
	}
	
	public static class Builder {
		private boolean allowEmpty = DEFAULT_ALLOW_EMPTY;
		private boolean emptyIsLoopback = DEFAULT_EMPTY_IS_LOOPBACK;
		private boolean allowBracketedIPv6 = DEFAULT_ACCEPT_BRACKETED_IPV6;
		private boolean allowBracketedIPv4 = DEFAULT_ACCEPT_BRACKETED_IPV4;
		private boolean normalizeToLowercase = DEFAULT_NORMALIZE_TO_LOWER_CASE;
		private boolean allowIPAddress = DEFAULT_ALLOW_IP_ADDRESS;
		
		private IPAddressStringParameters.Builder addressOptionsBuilder;
		private static final IPAddressStringParameters DEFAULT_ADDRESS_OPTIONS = new IPAddressStringParameters.Builder().toParams();
		
		public Builder() {}
		
		public Builder allowIPAddress(boolean allow) {
			allowIPAddress = allow;
			return this;
		}
		
		public Builder allowEmpty(boolean allow) {
			allowEmpty = allow;
			return this;
		}
		
		public Builder setEmptyAsLoopback(boolean bool) {
			emptyIsLoopback = bool;
			return this;
		}
		
		public Builder allowBracketedIPv6(boolean allow) {
			allowBracketedIPv6 = allow;
			return this;
		}
		
		public Builder allowBracketedIPv4(boolean allow) {
			allowBracketedIPv4 = allow;
			return this;
		}
		
		public Builder setNormalizeToLowercase(boolean bool) {
			normalizeToLowercase = bool;
			return this;
		}
		
		public IPAddressStringParameters.Builder getAddressOptionsBuilder() {
			if(addressOptionsBuilder == null) {
				addressOptionsBuilder = new IPAddressStringParameters.Builder();
			}
			addressOptionsBuilder.parent = this;
			return addressOptionsBuilder;
		}
		
		public HostNameParameters toOptions() {
			IPAddressStringParameters addressOpts;
			if(addressOptionsBuilder == null) {
				addressOpts = DEFAULT_ADDRESS_OPTIONS;
			} else {
				addressOpts = addressOptionsBuilder.toParams();
			}
			return new HostNameParameters(addressOpts, allowEmpty, emptyIsLoopback, allowIPAddress && allowBracketedIPv6, allowIPAddress && allowBracketedIPv4,  normalizeToLowercase, allowIPAddress);
		}
	}
	
	@Override
	public HostNameParameters clone() {
		try {
			return (HostNameParameters) super.clone();
		} catch (CloneNotSupportedException e) {}
		return null;
	}
	
	@Override
	public int compareTo(HostNameParameters o) {
		int result = Boolean.compare(allowEmpty, o.allowEmpty);
		if(result == 0) {
			result = Boolean.compare(allowBracketedIPv6, o.allowBracketedIPv6);
			if(result == 0) {
				result = Boolean.compare(allowBracketedIPv4, o.allowBracketedIPv4);
				if(result == 0) {
					result = Boolean.compare(normalizeToLowercase, o.normalizeToLowercase);
					if(result == 0) {
						result = Boolean.compare(allowIPAddress, o.allowIPAddress);
						if(result == 0) {
							result = addressOptions.compareTo(o.addressOptions);
						}
					}
				}
			}
		}
		return result;
	}
	
	@Override
	public boolean equals(Object o) {
		if(o instanceof HostNameParameters) {
			HostNameParameters other = (HostNameParameters) o;
			return allowEmpty == other.allowEmpty &&
					allowBracketedIPv6 == other.allowBracketedIPv6 &&
					allowBracketedIPv4 == other.allowBracketedIPv4 &&
					normalizeToLowercase == other.normalizeToLowercase &&
					allowIPAddress == other.allowIPAddress &&
					addressOptions.equals(other.addressOptions);
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		//uses up to the 5th bit in the last byte
		int hash = allowIPAddress ? addressOptions.hashCode() : 0;
		//now we use the last 3 bits
		if(allowEmpty) {
			hash |= 0x20000000;
		}
		if(normalizeToLowercase) {
			hash |= 0x40000000;
		}
		if(allowIPAddress) {
			if(allowBracketedIPv6 || allowBracketedIPv4) {
				hash |= 0x80000000;
			}
		}
		return hash;
	}
}