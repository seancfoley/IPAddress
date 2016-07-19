package inet.ipaddr.ipv6;

import java.util.Objects;

import inet.ipaddr.IPAddressStringParameters;
import inet.ipaddr.IPAddressStringParameters.IPVersionAddressStringParameters;
import inet.ipaddr.IPAddressStringParameters.RangeParameters;
import inet.ipaddr.ipv4.IPv4AddressStringParameters;

/**
 * The IPv6-specific parameters within a {@link IPAddressStringParameters} instance.
 * 
 * @author sfoley
 *
 */
public class IPv6AddressStringParameters extends IPVersionAddressStringParameters implements Comparable<IPv6AddressStringParameters> {
	
	private static final long serialVersionUID = 1L;

	public static final boolean DEFAULT_ALLOW_MIXED = true;
	public static final boolean DEFAULT_ALLOW_ZONE = true;
	
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
	
	/**
	 * if you allow mixed, this is the options used for the ipv4 section, 
	 * in which really only the ipv4 options apply and the ipv6 options are ignored except for the zone allowed setting
	 */
	private IPAddressStringParameters mixedOptions;
	
	public Builder toBuilder(boolean isMixed) {
		Builder builder = new Builder();
		builder.allowMixed = allowMixed;
		builder.allowZone = allowZone;
		if(!isMixed) {
			builder.mixedOptionsBuilder = mixedOptions.toBuilder(true);
		}
		return (Builder) toBuilder(builder);
	}
	
	public static class Builder extends IPVersionAddressStringParameters.BuilderBase {
		private boolean allowMixed = DEFAULT_ALLOW_MIXED;
		private boolean allowZone = DEFAULT_ALLOW_ZONE;
		private IPAddressStringParameters.Builder mixedOptionsBuilder;
		static private IPAddressStringParameters DEFAULT_MIXED_OPTS = new IPAddressStringParameters.Builder().
				allowEmpty(false).allowPrefix(false).allowMask(false).allowPrefixOnly(false).allowAll(false).toParams();
		
		public Builder() {}
		
		public Builder allowZone(boolean allow) {
			//we must decide whether to treat the % character as a zone when parsing the mixed part
			//if considered zone, then the zone character is actually part of the encompassing ipv6 address
			//otherwise, the zone character is an sql wildcard that is part of the mixed address
			//So whether we consider the % character a zone must match the same setting for the encompassing address
			getMixedAddressParametersBuilder().getIPv6AddressParametersBuilder().allowZone = allow;
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
			getMixedAddressParametersBuilder().getIPv4AddressParametersBuilder().allow_inet_aton(allow);
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
		public IPv4AddressStringParameters.Builder getMixedIPv4AddressParametersBuilder() {
			return getMixedAddressParametersBuilder().getIPv4AddressParametersBuilder();
		}
		
		/**
		 * Gets the builder for the parameters governing the mixed part of an IPv6 address.
		 * @return
		 */
		IPAddressStringParameters.Builder getMixedAddressParametersBuilder() {
			//We need both ipv6 and ipv4options to parse the mixed part, although the mixed part is always ipv4.  
			//The only thing that matters in ipv6 is the zone, we must treat zones the same way as in the encompassing address.
			if(mixedOptionsBuilder == null) {
				mixedOptionsBuilder = new IPAddressStringParameters.Builder().
						allowEmpty(false).allowPrefix(false).allowMask(false).allowPrefixOnly(false).allowAll(false);
				mixedOptionsBuilder.getIPv6AddressParametersBuilder().allowZone = allowZone;
			}
			setMixedParent(mixedOptionsBuilder, this);
			return mixedOptionsBuilder;
		}
		
		@Override
		public Builder allowWildcardedSeparator(boolean allow) {
			getMixedIPv4AddressParametersBuilder().allowWildcardedSeparator(allow);
			super.allowWildcardedSeparator(allow);
			return this;
		}
		
		@Override
		public Builder allowLeadingZeros(boolean allow) {
			getMixedIPv4AddressParametersBuilder().allowLeadingZeros(allow);
			super.allowLeadingZeros(allow);
			return this;
		}
		
		@Override
		public Builder allowUnlimitedLeadingZeros(boolean allow) {
			getMixedIPv4AddressParametersBuilder().allowUnlimitedLeadingZeros(allow);
			super.allowUnlimitedLeadingZeros(allow);
			return this;
		}
		
		@Override
		public Builder setRangeOptions(RangeParameters rangeOptions) {
			getMixedAddressParametersBuilder().getIPv4AddressParametersBuilder().setRangeOptions(rangeOptions);
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
			if(mixedOptionsBuilder == null) {
				mixedOptions = DEFAULT_MIXED_OPTS;
			} else {
				mixedOptions = mixedOptionsBuilder.toParams();
			}
			return new IPv6AddressStringParameters(
					allowLeadingZeros,
					allowPrefixLengthLeadingZeros,
					allowUnlimitedLeadingZeros,
					allowMixed,
					mixedOptions,
					allowZone,
					rangeOptions,
					allowWildcardedSeparator,
					allowPrefixesBeyondAddressSize);
		}
	}

	public IPv6AddressStringParameters(
			boolean allowLeadingZeros,
			boolean allowCIDRPrefixLeadingZeros,
			boolean allowUnlmitedLeadingZeros,
			boolean allowMixed,
			IPAddressStringParameters mixedOptions,
			boolean allowZone, 
			RangeParameters rangeOptions,
			boolean allowWildcardedSeparator,
			boolean allowPrefixesBeyondAddressSize) {
		super(allowLeadingZeros, allowCIDRPrefixLeadingZeros, allowUnlmitedLeadingZeros, rangeOptions, allowWildcardedSeparator, allowPrefixesBeyondAddressSize);
		this.allowMixed = allowMixed;
		this.allowZone = allowZone;
		this.mixedOptions = mixedOptions;
	}

	@Override
	public IPv6AddressStringParameters clone() {
		try {
			IPv6AddressStringParameters result = (IPv6AddressStringParameters) super.clone();
			result.mixedOptions = mixedOptions.clone();
			return result;
		} catch (CloneNotSupportedException e) {}
		return null;
	}
	
	public IPAddressStringParameters getMixedParameters() {
		return mixedOptions;
	}
	
	@Override
	public int compareTo(IPv6AddressStringParameters o) {
		int result = super.compareTo(o);
		if(result == 0) {
			//Of the mixed options neither the ipv6 options nor the general options are used and variable
			result = mixedOptions.getIPv4Parameters().compareTo(o.mixedOptions.getIPv4Parameters());
			if(result == 0) {
				result = Boolean.compare(allowMixed, o.allowMixed);
				if(result == 0) {
					result = Boolean.compare(allowZone, o.allowZone);
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
				return Objects.equals(mixedOptions.getIPv4Parameters(), other.mixedOptions.getIPv4Parameters())
					&& allowMixed == other.allowMixed
					&& allowZone == other.allowZone;
			}
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		int hash = super.hashCode();//super hash code uses 6 bits
		
		//we use the next 9 bits for the ipv4 part of mixedOptions
		//the ipv4 part is the only part of mixedOptions we use
		hash |= mixedOptions.getIPv4Parameters().hashCode() << 6;
		
		//so now we have used 15 bits, so we have 0x8000 and onwards available
		//now use the next two bits
		if(allowMixed) {
			hash |= 0x8000;
		}
		if(allowZone) {
			hash |= 0x10000;
		}
		return hash;
	}
}
