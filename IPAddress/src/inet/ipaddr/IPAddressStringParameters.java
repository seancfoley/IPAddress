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

import inet.ipaddr.IPAddress.IPVersion;
import inet.ipaddr.ipv4.IPv4AddressStringParameters;
import inet.ipaddr.ipv6.IPv6AddressStringParameters;

/**
 * This class allows you to control the validation performed by the class {@link IPAddressString}.
 * 
 * The {@link IPAddressString} class uses a default permissive IPAddressStringParameters instance when you do not specify one.
 * 
 * If you wish to use parameters different from the default, then use this class.  All instances are immutable and must be constructed with the nested Builder class.
 * 
 * @author sfoley
 *
 */
public class IPAddressStringParameters extends AddressStringParameters implements Comparable<IPAddressStringParameters> {
	
	private static final long serialVersionUID = 4L;

	//The defaults are permissive
	//One thing to note: since zones are allowed by default, the % character is interpreted as a zone, not as an SQL wildcard.
	//Also, since inet_aton style is allowed by default, leading zeros in ipv4 are interpreted as octal.
	//
	//If you wish to deviate from the default options,
	//you can simply pass in your own IPAddressStringParameters and HostNameParameters options to the respective constructors.
	//To standardize, you can subclass HostName and/or IPAddressString to use your own standard defaults in the constructors that take validation options.
	//Optionally, you can let everything parse successfully and then validate the resulting HostName/IPAddressString/IPAddress objects according to your taste.
	
	public static final boolean DEFAULT_ALLOW_PREFIX_ONLY = true;
	public static final boolean DEFAULT_EMPTY_IS_LOOPBACK = true; //Note that with InetAddress, empty strings are interpreted as the loopback address
	public static final boolean DEFAULT_ALLOW_PREFIX = true;
	public static final boolean DEFAULT_ALLOW_MASK = true;
	public static final boolean DEFAULT_ALLOW_IPV4 = true;
	public static final boolean DEFAULT_ALLOW_IPV6 = true;
	
	/**
	 * Allows addresses like /64 which are only prefix lenths.
	 * Such addresses are interpreted as the network mask for the given prefix length.
	 * @see #DEFAULT_ALLOW_PREFIX_ONLY
	 */
	public final boolean allowPrefixOnly;

	/**
	 * Whether the zero-length address is interpreted as the loopback.
	 * @see #allowEmpty
	 * @see #DEFAULT_EMPTY_IS_LOOPBACK
	 */
	public final boolean emptyIsLoopback;
	
	/**
	 * Allows addresses with prefix length like 1.2.0.0/16
	 * Such as an address is interpreted as a subnet.
	 * 1.2.0.0/16 is the subnet of addresses with network prefix 1.2
	 * 
	 * @see #DEFAULT_ALLOW_PREFIX
	 */
	public final boolean allowPrefix;
	
	/**
	 * Allows masks to follow valid addresses, such as 1.2.3.4/255.255.0.0 which has the mask 255.255.0.0<p>
	 * If the mask is the mask for a network prefix length, this is interpreted as the subnet for that network prefix length.
	 * Otherwise the address is simply masked by the mask.
	 * For instance, 1.2.3.4/255.0.255.0 is 1.0.3.0, while 1.2.3.4/255.255.0.0 is 1.2.0.0/16.
	 * 
	 * @see #allowPrefix
	 * @see #DEFAULT_ALLOW_MASK
	 * 
	 */
	public final boolean allowMask;

	public final boolean allowIPv6;
	public final boolean allowIPv4;
	
	
	private IPv6AddressStringParameters ipv6Options;
	private IPv4AddressStringParameters ipv4Options;
	
	public IPVersion inferVersion() {
		if(allowIPv6) {
			if(!allowIPv4) {
				return IPVersion.IPV6;
			}
		} else {
			if(allowIPv4) {
				return IPVersion.IPV4;
			}
		}
		return null;
	}
	
	public static class Builder extends AddressStringParameters.BuilderBase {
		private boolean emptyIsLoopback = DEFAULT_EMPTY_IS_LOOPBACK;
		private boolean allowPrefix = DEFAULT_ALLOW_PREFIX;
		private boolean allowMask = DEFAULT_ALLOW_MASK;
		private boolean allowPrefixOnly = DEFAULT_ALLOW_PREFIX_ONLY;
		private boolean allowIPv4 = DEFAULT_ALLOW_IPV4;
		private boolean allowIPv6 = DEFAULT_ALLOW_IPV6;
		//private boolean noIpv4Params, noIpv6Params;
		
		IPv4AddressStringParameters.Builder ipv4Builder;
		static private IPv4AddressStringParameters DEFAULT_IPV4_OPTS = new IPv4AddressStringParameters.Builder().toParams();
		IPv6AddressStringParameters.Builder ipv6Builder;
		static private IPv6AddressStringParameters DEFAULT_IPV6_OPTS = new IPv6AddressStringParameters.Builder().toParams();
		
		HostNameParameters.Builder parent;
		
		public Builder() {}
		
		public HostNameParameters.Builder getParentBuilder() {
			return parent;
		}
		
		/**
		 * @see IPAddressStringParameters#allowEmpty
		 * @param allow
		 * @return the builder
		 */
		@Override
		public Builder allowEmpty(boolean allow) {
			return (Builder) super.allowEmpty(allow);
		}
		
		@Override
		public Builder allowSingleSegment(boolean allow) {
			return (Builder) super.allowSingleSegment(allow);
		}
		
		public Builder setEmptyAsLoopback(boolean bool) {
			emptyIsLoopback = bool;
			return this;
		}
		
		public Builder allowPrefix(boolean allow) {
			allowPrefix = allow;
			return this;
		}
		
		public Builder allowMask(boolean allow) {
			allowMask = allow;
			return this;
		}
		
		public Builder allowPrefixOnly(boolean allow) {
			allowPrefixOnly = allow;
			return this;
		}
		
		@Override
		public Builder allowAll(boolean allow) {
			return (Builder) super.allowAll(allow);
		}
		
		public Builder allowIPv4(boolean allow) {
			allowIPv4 = allow;
			return this;
		}
		
		public Builder allowIPv6(boolean allow) {
			allowIPv6 = allow;
			return this;
		}
		
		public Builder allowWildcardedSeparator(boolean allow) {
			getIPv4AddressParametersBuilder().allowWildcardedSeparator(allow);
			getIPv6AddressParametersBuilder().allowWildcardedSeparator(allow);
			return this;
		}
		
		public Builder setRangeOptions(RangeParameters rangeOptions) {
			getIPv4AddressParametersBuilder().setRangeOptions(rangeOptions);
			getIPv6AddressParametersBuilder().setRangeOptions(rangeOptions);
			return this;
		}
		
		public Builder allow_inet_aton(boolean allow) {
			getIPv4AddressParametersBuilder().allow_inet_aton(allow);
			getIPv6AddressParametersBuilder().allow_mixed_inet_aton(allow);
			return this;
		}
		
		/**
		 * Replaces all existing IPv6 parameters with the ones in the supplied parameters instance.
		 */
		public void setIPv6AddressParameters(IPv6AddressStringParameters params) {
			ipv6Builder = params.toBuilder();
		}
		
		/**
		 * Get the sub-builder for setting IPv6 parameters.
		 * @return the IPv6 builder
		 */
		public IPv6AddressStringParameters.Builder getIPv6AddressParametersBuilder() {
			if(ipv6Builder == null) {
				ipv6Builder = new IPv6AddressStringParameters.Builder();
			}
			((IPAddressStringFormatParameters.BuilderBase) ipv6Builder).parent = this;
			return ipv6Builder;
		}
		
		/**
		 * Replaces all existing IPv4 parameters with the ones in the supplied parameters instance.
		 */
		public void setIPv4AddressParameters(IPv4AddressStringParameters params) {
			ipv4Builder = params.toBuilder();
		}
		
		/**
		 * Get the sub-builder for setting IPv4 parameters.
		 * @return the IPv4 builder
		 */
		public IPv4AddressStringParameters.Builder getIPv4AddressParametersBuilder() {
			if(ipv4Builder == null) {
				ipv4Builder = new IPv4AddressStringParameters.Builder();
			}
			((IPAddressStringFormatParameters.BuilderBase) ipv4Builder).parent = this;
			return ipv4Builder;
		}
		
		public IPAddressStringParameters toParams() {
			IPv4AddressStringParameters ipv4Opts;
			if(ipv4Builder == null) {
				ipv4Opts = DEFAULT_IPV4_OPTS;
			} else {
				ipv4Opts = ipv4Builder.toParams();
			}
			IPv6AddressStringParameters ipv6Opts;
			if(ipv6Builder == null) {
				ipv6Opts = DEFAULT_IPV6_OPTS;
			} else {
				ipv6Opts = ipv6Builder.toParams();
			}
			return new IPAddressStringParameters(allowEmpty, allowAll, allowSingleSegment, emptyIsLoopback, allowPrefix, allowMask, allowPrefixOnly, allowIPv4, allowIPv6, ipv4Opts, ipv6Opts);
		}
	}

	public abstract static class IPAddressStringFormatParameters extends AddressStringFormatParameters {

		private static final long serialVersionUID = 4L;
		
		public static final boolean DEFAULT_ALLOW_PREFIX_LENGTH_LEADING_ZEROS = true;
		public static final boolean DEFAULT_ALLOW_PREFIX_BEYOND_ADDRESS_SIZE = false;
		
		/**
		 * controls whether ipv4 can have prefix length bigger than 32 and whether ipv6 can have prefix length bigger than 128
		 * @see #DEFAULT_ALLOW_PREFIX_BEYOND_ADDRESS_SIZE
		 */
		public final boolean allowPrefixesBeyondAddressSize; 
		
		/**
		 * controls whether you allow addresses with prefixes that have leasing zeros like 1.0.0.0/08 or 1::/064
		 * 
		 * @see #DEFAULT_ALLOW_PREFIX_LENGTH_LEADING_ZEROS
		 */
		public final boolean allowPrefixLengthLeadingZeros;
		
		public IPAddressStringFormatParameters(
				boolean allowLeadingZeros,
				boolean allowPrefixLengthLeadingZeros,
				boolean allowUnlimitedLeadingZeros,
				RangeParameters rangeOptions,
				boolean allowWildcardedSeparator,
				boolean allowPrefixesBeyondAddressSize) {
			super(allowLeadingZeros, allowUnlimitedLeadingZeros, rangeOptions, allowWildcardedSeparator);
			this.allowPrefixLengthLeadingZeros = allowPrefixLengthLeadingZeros;
			this.allowPrefixesBeyondAddressSize = allowPrefixesBeyondAddressSize;
		}
		
		protected BuilderBase toBuilder(BuilderBase builder) {
			super.toBuilder(builder);
			builder.allowPrefixLengthLeadingZeros = allowPrefixLengthLeadingZeros;
			builder.allowPrefixesBeyondAddressSize = allowPrefixesBeyondAddressSize;
			return builder;
		}
		
		protected static class BuilderBase extends AddressStringFormatParameters.BuilderBase {
			protected boolean allowPrefixesBeyondAddressSize = DEFAULT_ALLOW_PREFIX_BEYOND_ADDRESS_SIZE;
			protected boolean allowPrefixLengthLeadingZeros = DEFAULT_ALLOW_PREFIX_LENGTH_LEADING_ZEROS;
			
			IPAddressStringParameters.Builder parent;
			
			public IPAddressStringParameters.Builder getParentBuilder() {
				return parent;
			}
			
			@Override
			public BuilderBase setRangeOptions(RangeParameters rangeOptions) {
				return (BuilderBase) super.setRangeOptions(rangeOptions);
			}
			
			public BuilderBase allowPrefixesBeyondAddressSize(boolean allow) {
				allowPrefixesBeyondAddressSize = allow;
				return this;
			}
			
			@Override
			public BuilderBase allowWildcardedSeparator(boolean allow) {
				return (BuilderBase) super.allowWildcardedSeparator(allow);
			}
			
			@Override
			public BuilderBase allowLeadingZeros(boolean allow) {
				return (BuilderBase) super.allowLeadingZeros(allow);
			}
			
			public BuilderBase allowPrefixLengthLeadingZeros(boolean allow) {
				allowPrefixLengthLeadingZeros = allow;
				return this;
			}
			
			@Override
			public BuilderBase allowUnlimitedLeadingZeros(boolean allow) {
				return (BuilderBase) super.allowUnlimitedLeadingZeros(allow);
			}
		}
		
		public abstract IPAddressNetwork<?, ?, ?, ?, ?> getNetwork();

		protected int compareTo(IPAddressStringFormatParameters o) {
			int result = super.compareTo(o);
			if(result == 0) {
				result = Boolean.compare(allowPrefixesBeyondAddressSize, o.allowPrefixesBeyondAddressSize);
				if(result == 0) {
					result = Boolean.compare(allowPrefixLengthLeadingZeros, o.allowPrefixLengthLeadingZeros);
				}
			}
			return result;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof IPAddressStringFormatParameters) {
				IPAddressStringFormatParameters other = (IPAddressStringFormatParameters) o;
				return super.equals(o) &&
						allowPrefixesBeyondAddressSize == other.allowPrefixesBeyondAddressSize
						&& allowPrefixLengthLeadingZeros == other.allowPrefixLengthLeadingZeros;
			}
			return false;
		}
		
		@Override
		public int hashCode() {
			int hash = super.hashCode();
			if(allowPrefixesBeyondAddressSize) {
				hash |= 0x8;//reuse the 4th bit
			}
			return hash;
		}
	}
	
	public Builder toBuilder() {
		return toBuilder(false);
	}
	
	public Builder toBuilder(boolean isMixed) {
		Builder builder = new Builder();
		super.toBuilder(builder);
		builder.allowPrefixOnly = allowPrefixOnly;
		builder.emptyIsLoopback = emptyIsLoopback;
		builder.allowPrefix = allowPrefix;
		builder.allowMask = allowMask;
		builder.allowIPv6 = allowIPv6;
		builder.allowIPv4 = allowIPv4;
		builder.ipv4Builder = ipv4Options.toBuilder();
		builder.ipv6Builder = ipv6Options.toBuilder(isMixed);
		builder.allowSingleSegment = allowSingleSegment;
		builder.allowEmpty = allowEmpty;
		builder.allowAll = allowAll;
		return builder;
	}

	public IPAddressStringParameters(
			boolean allowEmpty,
			boolean allowAll,
			boolean allowSingleSegment,
			boolean emptyIsLoopback,
			boolean allowPrefix,
			boolean allowMask,
			boolean allowPrefixOnly,
			boolean allowIPv4,
			boolean allowIPv6,
			IPv4AddressStringParameters ipv4Options,
			IPv6AddressStringParameters ipv6Options) {
		super(allowEmpty, allowAll, allowSingleSegment);
		this.allowPrefixOnly = allowPrefixOnly;
		this.emptyIsLoopback = emptyIsLoopback;
		this.allowPrefix = allowPrefix;
		this.allowMask = allowMask;
		this.allowIPv4 = allowIPv4;
		this.allowIPv6 = allowIPv6;
		this.ipv6Options = ipv6Options;
		this.ipv4Options = ipv4Options;
	}
	
	public IPv6AddressStringParameters getIPv6Parameters() {
		return ipv6Options;
	}
	
	public IPv4AddressStringParameters getIPv4Parameters() {
		return ipv4Options;
	}
	
	@Override
	public IPAddressStringParameters clone() {
		IPAddressStringParameters result = (IPAddressStringParameters) super.clone();
		result.ipv4Options = ipv4Options.clone();
		result.ipv6Options = ipv6Options.clone();
		return result;
	}

	@Override
	public int compareTo(IPAddressStringParameters o) {
		int result = super.compareTo(o);
		if(result == 0) {
			result = ipv4Options.compareTo(o.ipv4Options);
			if(result == 0) {
				result = ipv6Options.compareTo(o.ipv6Options);
				if(result == 0) {
					result = Boolean.compare(emptyIsLoopback, o.emptyIsLoopback);
					if(result == 0) {
						result = Boolean.compare(allowPrefix, o.allowPrefix);
						if(result == 0) {
							result = Boolean.compare(allowMask, o.allowMask);
							if(result == 0) {
								result = Boolean.compare(allowIPv6, o.allowIPv6);
								if(result == 0) {
									result = Boolean.compare(allowIPv4, o.allowIPv4);
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
		if(o instanceof IPAddressStringParameters) {
			IPAddressStringParameters other = (IPAddressStringParameters) o;
			return super.equals(o)
					&& ipv4Options.equals(other.ipv4Options) 
					&& ipv6Options.equals(other.ipv6Options) 
					&& emptyIsLoopback == other.emptyIsLoopback 
					&& allowPrefix == other.allowPrefix 
					&& allowMask == other.allowMask
					&& allowIPv6 == other.allowIPv6
					&& allowIPv4 == other.allowIPv4;
		}
		return false;
	}

	@Override
	public int hashCode() {
		//the ipv4 part uses just one byte and one additional bit
		int hash = ipv4Options.hashCode();
		
		//the ipv6 part uses 2 bytes plus two extra bit
		hash |= ipv6Options.hashCode() << 9;
		
		//so now we are up to 3 bytes and 3 additional bits, so we have 0x8000000 and onwards available
		if(emptyIsLoopback) {
			hash |= 0x8000000;
		}
		if(allowPrefix) {
			hash |= 0x10000000;
		}
		if(allowMask) {
			hash |= 0x20000000;
		}
		if(allowEmpty) {
			hash |= 0x40000000;
		}
		if(allowSingleSegment) {
			hash |= 0x80000000;
		}
		//no more bits available
//		if(allowAll) {
//			hash |= 0x100000000;
//		}
		return hash;
	}
}

