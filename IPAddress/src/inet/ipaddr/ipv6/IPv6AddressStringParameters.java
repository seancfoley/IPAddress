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

package inet.ipaddr.ipv6;

import java.util.Objects;

import inet.ipaddr.Address;
import inet.ipaddr.AddressStringParameters.RangeParameters;
import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IPAddressStringParameters.IPAddressStringFormatParameters;
import inet.ipaddr.ipv4.IPv4AddressStringParameters;

/**
 * The IPv6-specific parameters within a {@link IPAddressStringParameters} instance.
 * 
 * @author sfoley
 *
 */
public class IPv6AddressStringParameters extends IPAddressStringFormatParameters implements Comparable<IPv6AddressStringParameters> {
	
	private static final long serialVersionUID = 4L;

	public static final boolean DEFAULT_ALLOW_MIXED = true;
	public static final boolean DEFAULT_ALLOW_ZONE = true;
	public static final boolean DEFAULT_ALLOW_BASE85 = true;
	
	/**
	 * Allows IPv6 addresses with embedded ipv4 like a:b:c:d:e:f:1.2.3.4
	 * @see #DEFAULT_ALLOW_MIXED
	 */
	public final boolean allowMixed;
	
	/**
	 * Allows IPv6 zones with the '%' character, which generally denotes either scope identifiers or network interfaces.
	 * @see #DEFAULT_ALLOW_ZONE
	 */
	public final boolean allowZone;
	
	public final boolean allowBase85;
	
	/**
	 * The network that will be used to construct addresses - both parameters inside the network, and the network's address creator
	 */
	private final IPv6AddressNetwork network;
	
	/**
	 * if you allow mixed, this is the options used for the ipv4 section, 
	 * in which really only the ipv4 options apply and the ipv6 options are ignored except for the zone allowed setting
	 */
	private IPAddressStringParameters embeddedIPv4Options;
	
	public IPv6AddressStringParameters(
			boolean allowLeadingZeros,
			boolean allowCIDRPrefixLeadingZeros,
			boolean allowUnlmitedLeadingZeros,
			boolean allowMixed,
			IPAddressStringParameters mixedOptions,
			boolean allowZone,
			boolean allowBase85,
			RangeParameters rangeOptions,
			boolean allowWildcardedSeparator,
			boolean allowPrefixesBeyondAddressSize,
			IPv6AddressNetwork network) {
		super(allowLeadingZeros, allowCIDRPrefixLeadingZeros, allowUnlmitedLeadingZeros, rangeOptions, allowWildcardedSeparator, allowPrefixesBeyondAddressSize);
		this.allowMixed = allowMixed;
		this.allowZone = allowZone;
		this.allowBase85 = allowBase85;
		this.embeddedIPv4Options = mixedOptions;
		this.network = network;
	}
	
	public Builder toBuilder() {
		return toBuilder(false);
	}

	public Builder toBuilder(boolean isMixed) {
		Builder builder = new Builder();
		builder.allowMixed = allowMixed;
		builder.allowZone = allowZone;
		builder.allowBase85 = allowBase85;
		builder.network = network;
		if(!isMixed) {
			builder.embeddedIPv4OptionsBuilder = embeddedIPv4Options.toBuilder(true);
		}
		return (Builder) toBuilder(builder);
	}
	
	public static class Builder extends IPAddressStringFormatParameters.BuilderBase {
		private boolean allowMixed = DEFAULT_ALLOW_MIXED;
		private boolean allowZone = DEFAULT_ALLOW_ZONE;
		private boolean allowBase85 = DEFAULT_ALLOW_BASE85;
		private IPAddressStringParameters.Builder embeddedIPv4OptionsBuilder;
		private IPv6AddressNetwork network;
		
		//Note we need to have an ipv6 builder here to avoid using the default ipv6 options object which is also 
		//static and which are reference this static field, so we must avoid the circular dependency
		//But we don't need default ipv6 options anyway, we don't support ipv6 in the mixed section at all
		//and in fact it makes no sense that you might think there was ipv6 there anyway
		static private IPAddressStringParameters DEFAULT_MIXED_OPTS = new IPAddressStringParameters.Builder().
				allowEmpty(false).allowPrefix(false).allowMask(false).allowPrefixOnly(false).allowAll(false).
				getIPv6AddressParametersBuilder().allowMixed(false).getParentBuilder().toParams();
		
		public Builder() {}
		
		public Builder allowZone(boolean allow) {
			//we must decide whether to treat the % character as a zone when parsing the mixed part
			//if considered zone, then the zone character is actually part of the encompassing ipv6 address
			//otherwise, the zone character is an sql wildcard that is part of the mixed address
			//So whether we consider the % character a zone must match the same setting for the encompassing address
			getEmbeddedIPv4ParametersBuilder().getIPv6AddressParametersBuilder().allowZone = allow;
			allowZone = allow;
			return this;
		}
		
		/**
		 * Allow inet_aton formats in the mixed part of an IPv6 address
		 * @param allow
		 * @return the builder
		 */
		public Builder allow_mixed_inet_aton(boolean allow) {
			if(allow) {
				allowMixed(allow);
			}
			getEmbeddedIPv4ParametersBuilder().getIPv4AddressParametersBuilder().allow_inet_aton(allow);
			return this;
		}
		
		/**
		 * @see IPv6AddressStringParameters#allowMixed
		 * @param allow
		 * @return the builder
		 */
		public Builder allowMixed(boolean allow) {
			allowMixed = allow;
			return this;
		}
		
		/**
		 * Gets the builder for the parameters governing the IPv4 mixed part of an IPv6 address.
		 * @return
		 */
		public IPv4AddressStringParameters.Builder getEmbeddedIPv4AddressParametersBuilder() {
			return getEmbeddedIPv4ParametersBuilder().getIPv4AddressParametersBuilder();
		}
		
		/**
		 * Gets the builder for the parameters governing the mixed part of an IPv6 address.
		 * @return
		 */
		IPAddressStringParameters.Builder getEmbeddedIPv4ParametersBuilder() {
			//We need both ipv6 and ipv4options to parse the mixed part, although the mixed part is always ipv4.  
			//The only thing that matters in ipv6 is the zone, we must treat zones the same way as in the encompassing address.
			if(embeddedIPv4OptionsBuilder == null) {
				embeddedIPv4OptionsBuilder = new IPAddressStringParameters.Builder().
						allowEmpty(false).allowPrefix(false).allowMask(false).allowPrefixOnly(false).allowAll(false).allowIPv6(false);
				embeddedIPv4OptionsBuilder.getIPv6AddressParametersBuilder().allowZone = allowZone;
			}
			embeddedIPv4OptionsBuilder.getIPv4AddressParametersBuilder().setMixedParent(this);
			return embeddedIPv4OptionsBuilder;
		}
		
		/**
		 * @see IPv6AddressStringParameters#network
		 * @param network if null, the default network will be used
		 * @return the builder
		 */
		public Builder setNetwork(IPv6AddressNetwork network) {
			this.network = network;
			return this;
		}
		
		@Override
		public Builder allowWildcardedSeparator(boolean allow) {
			getEmbeddedIPv4AddressParametersBuilder().allowWildcardedSeparator(allow);
			super.allowWildcardedSeparator(allow);
			return this;
		}
		
		@Override
		public Builder allowLeadingZeros(boolean allow) {
			getEmbeddedIPv4AddressParametersBuilder().allowLeadingZeros(allow);
			super.allowLeadingZeros(allow);
			return this;
		}
		
		@Override
		public Builder allowUnlimitedLeadingZeros(boolean allow) {
			getEmbeddedIPv4AddressParametersBuilder().allowUnlimitedLeadingZeros(allow);
			super.allowUnlimitedLeadingZeros(allow);
			return this;
		}
		
		@Override
		public Builder setRangeOptions(RangeParameters rangeOptions) {
			getEmbeddedIPv4ParametersBuilder().getIPv4AddressParametersBuilder().setRangeOptions(rangeOptions);
			super.setRangeOptions(rangeOptions);
			return this;
		}

		@Override
		public Builder allowPrefixesBeyondAddressSize(boolean allow) {
			super.allowPrefixesBeyondAddressSize(allow);
			return this;
		}

		@Override
		public Builder allowPrefixLengthLeadingZeros(boolean allow) {
			super.allowPrefixLengthLeadingZeros(allow);
			return this;
		}
		
		
		public IPv6AddressStringParameters toParams() {
			IPAddressStringParameters mixedOptions;
			if(embeddedIPv4OptionsBuilder == null) {
				mixedOptions = DEFAULT_MIXED_OPTS;
			} else {
				mixedOptions = embeddedIPv4OptionsBuilder.toParams();
			}
			return new IPv6AddressStringParameters(
					allowLeadingZeros,
					allowPrefixLengthLeadingZeros,
					allowUnlimitedLeadingZeros,
					allowMixed,
					mixedOptions,
					allowZone,
					allowBase85,
					rangeOptions,
					allowWildcardedSeparator,
					allowPrefixesBeyondAddressSize,
					network);
		}
	}
	
	@Override
	public IPv6AddressNetwork getNetwork() {
		if(network == null) {
			return Address.defaultIpv6Network();
		}
		return network;
	}

	@Override
	public IPv6AddressStringParameters clone() {
		try {
			IPv6AddressStringParameters result = (IPv6AddressStringParameters) super.clone();
			result.embeddedIPv4Options = embeddedIPv4Options.clone();
			return result;
		} catch (CloneNotSupportedException e) {}
		return null;
	}
	
	public IPAddressStringParameters getMixedParameters() {
		return embeddedIPv4Options;
	}
	
	@Override
	public int compareTo(IPv6AddressStringParameters o) {
		int result = super.compareTo(o);
		if(result == 0) {
			//Of the mixed options neither the ipv6 options nor the general options are used and variable
			result = embeddedIPv4Options.getIPv4Parameters().compareTo(o.embeddedIPv4Options.getIPv4Parameters());
			if(result == 0) {
				result = Boolean.compare(allowMixed, o.allowMixed);
				if(result == 0) {
					result = Boolean.compare(allowZone, o.allowZone);
					if(result == 0) {
						result = Boolean.compare(allowBase85, o.allowBase85);
					}
				}
			}
		}
		return result;
	}
	
	@Override
	public boolean equals(Object o) {
		if(o instanceof IPv6AddressStringParameters) {
			if(super.equals(o)) {
				IPv6AddressStringParameters other = (IPv6AddressStringParameters) o;
				//Of the mixed options neither the ipv6 options nor the general options are used and variable
				return Objects.equals(embeddedIPv4Options.getIPv4Parameters(), other.embeddedIPv4Options.getIPv4Parameters())
					&& allowMixed == other.allowMixed
					&& allowZone == other.allowZone
					&& allowBase85 == other.allowBase85;
			}
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		int hash = super.hashCode();//super hash code uses 6 bits
		
		//we use the next 9 bits for the ipv4 part of mixedOptions
		//the ipv4 part is the only part of mixedOptions we use
		hash |= embeddedIPv4Options.getIPv4Parameters().hashCode() << 6;
		
		//so now we have used 15 bits, so we have 0x8000 and onwards available
		//now use the next two bits
		if(allowMixed) {
			hash |= 0x8000;
		}
		if(allowZone) {
			hash |= 0x10000;
		}
		if(allowBase85) {
			hash |= 0x20000;
		}
		return hash;
	}
}
