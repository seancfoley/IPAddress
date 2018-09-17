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
	
	private static final long serialVersionUID = 4L;

	public static final boolean DEFAULT_ALLOW_EMPTY = true;
	public static final boolean DEFAULT_EMPTY_IS_LOOPBACK = true; //Note that with InetAddress, empty strings are interpreted as the loopback address
	public static final boolean DEFAULT_ACCEPT_BRACKETED_IPV6 = true;
	public static final boolean DEFAULT_ACCEPT_BRACKETED_IPV4 = true;
	public static final boolean DEFAULT_NORMALIZE_TO_LOWER_CASE = true;
	public static final boolean DEFAULT_ALLOW_IP_ADDRESS = true;
	public static final boolean DEFAULT_ALLOW_PORT = true;
	public static final boolean DEFAULT_EXPECT_PORT = false; //in cases where an IP address port combination is ambiguous (eg fe80::6a05:caff:fe3:123), assume there is a port (note that square brackets [] can and should be used to resolve the ambiguity)
	public static final boolean DEFAULT_ALLOW_SERVICE = true;

	public final boolean allowEmpty;
	public final boolean emptyIsLoopback;
	public final boolean allowBracketedIPv4;
	public final boolean allowBracketedIPv6;
	public final boolean normalizeToLowercase;
	public final boolean allowIPAddress;
	public final boolean allowPort;
	public final boolean allowService;
	public final boolean expectPort;
	public final IPAddressStringParameters addressOptions;
	
	public HostNameParameters(
			IPAddressStringParameters addressOptions,
			boolean allowEmpty,
			boolean emptyIsLoopback,
			boolean allowBracketedIPv6,
			boolean allowBracketedIPv4,
			boolean normalizeToLowercase,
			boolean allowIPAddress,
			boolean allowPort,
			boolean expectPort,
			boolean allowService) {
		this.allowEmpty = allowEmpty;
		this.emptyIsLoopback = emptyIsLoopback;
		this.allowBracketedIPv6 = allowBracketedIPv6;
		this.allowBracketedIPv4 = allowBracketedIPv4;
		this.normalizeToLowercase = normalizeToLowercase;
		this.allowIPAddress = allowIPAddress;
		this.allowPort = allowPort;
		this.expectPort = expectPort;
		this.allowService = allowService;
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
		builder.allowPort = allowPort;
		builder.allowService = allowService;
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
		private boolean allowPort = DEFAULT_ALLOW_PORT;
		private boolean expectPort = DEFAULT_EXPECT_PORT;
		private boolean allowService = DEFAULT_ALLOW_SERVICE;
		
		private IPAddressStringParameters.Builder addressOptionsBuilder;

		public Builder() {}

		public Builder allowPort(boolean allow) {
			allowPort = allow;
			return this;
		}

		public Builder expectPort(boolean expect) {
			expectPort = expect;
			return this;
		}

		public Builder allowService(boolean allow) {
			allowService = allow;
			return this;
		}

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
		
		public HostNameParameters toParams() {
			IPAddressStringParameters addressOpts;
			if(addressOptionsBuilder == null) {
				addressOpts = IPAddressString.DEFAULT_VALIDATION_OPTIONS;
			} else {
				addressOpts = addressOptionsBuilder.toParams();
			}
			return new HostNameParameters(
					addressOpts,
					allowEmpty,
					emptyIsLoopback,
					allowIPAddress && allowBracketedIPv6,
					allowIPAddress && allowBracketedIPv4,
					normalizeToLowercase,
					allowIPAddress,
					allowPort,
					expectPort,
					allowService);
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
							result = Boolean.compare(allowPort, o.allowPort);
							if(result == 0) {
								result = Boolean.compare(expectPort, o.expectPort);
								if(result == 0) {
									result = Boolean.compare(allowService, o.allowService);
									if(result == 0) {
										result = addressOptions.compareTo(o.addressOptions);
									}
								}
							}
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
					allowPort == other.allowPort &&
					expectPort == other.expectPort &&
					allowService == other.allowService &&
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
//		if(normalizeToLowercase) {
//			hash |= 0x40000000;
//		}
		if(allowIPAddress) {
			if(allowBracketedIPv6 || allowBracketedIPv4) {
				hash |= 0x80000000;
			}
		}
		if(allowPort || allowService || expectPort) {
			hash |= 0x40000000;
		}
		return hash;
	}
}
