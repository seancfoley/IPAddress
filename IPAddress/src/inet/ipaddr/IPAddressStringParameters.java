package inet.ipaddr;

import java.io.Serializable;

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
public class IPAddressStringParameters implements Cloneable, Comparable<IPAddressStringParameters>, Serializable {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Controls special characters in addresses like '*', '-', '_'
	 * @see IPAddressStringParameters#DEFAULT_RANGE_OPTIONS
	 * @author sfoley
	 *
	 */
	public static class RangeParameters implements Comparable<RangeParameters>, Cloneable, Serializable {
		
		private static final long serialVersionUID = 1L;

		private final boolean wildcard, range, singleWildcard;
		
		public static RangeParameters NO_RANGE = new RangeParameters(false, false, false);
		public static RangeParameters WILDCARD_ONLY = new RangeParameters(true, false, true); /* use this to support addresses like 1.*.3.4 or 1::*:3 or 1.2_.3.4 or 1::a__:3  */
		public static RangeParameters WILDCARD_AND_RANGE = new RangeParameters(true, true, true);/* use this to support addresses supported by DEFAULT_WILDCARD_OPTIONS and also addresses like 1.2-3.3.4 or 1:0-ff:: */
		
		public RangeParameters(boolean wildcard, boolean range, boolean singleWildcard) {
			this.wildcard = wildcard;
			this.range = range;
			this.singleWildcard = singleWildcard;
		}
		
		/**
		 * 
		 * @return whether no wildcards or range characters allowed
		 */
		public boolean isNoRange() {
			return !(wildcard || range || singleWildcard);
		}
		
		/**
		 * 
		 * @return whether '*' is allowed to denote segments covering all possible segment values
		 */
		public boolean allowsWildcard() {
			return wildcard;
		}
		
		/**
		 * 
		 * @return whether '-' is allowed to denote a range from lower to higher, like 1-10
		 */
		public boolean allowsRangeSeparator() {
			return range;
		}
		
		/**
		 * 
		 * @return whether to allow a segment terminating with '_' characters, which represent any digit
		 */
		public boolean allowsSingleWildcard() {
			return singleWildcard;
		}
		
		@Override
		public RangeParameters clone() {
			try {
				return (RangeParameters) super.clone();
			} catch (CloneNotSupportedException e) {}
			return null;
		}
		
		@Override
		public int hashCode() {
			int result = 0;
			if(wildcard) {
				result = 1;
			}
			if(range) {
				result |= 2;
			}
			if(singleWildcard) {
				result |= 4;
			}
			return result;
		}
		
		@Override
		public boolean equals(Object o) {
			if(this == o) {
				return true;
			}
			if(o instanceof RangeParameters) {
				RangeParameters other = (RangeParameters) o;
				return wildcard == other.wildcard && range == other.range && singleWildcard == other.singleWildcard;
			}
			return false;
		}

		@Override
		public int compareTo(RangeParameters o) {
			int val = Boolean.compare(wildcard, o.wildcard);
			if(val == 0) {
				val = Boolean.compare(range, o.range);
				if(val == 0) {
					val = Boolean.compare(singleWildcard, o.singleWildcard);
				}
			}
			return val;
		}
	};
	
	//The defaults are permissive
	//One thing to note: since zones are allowed by default, the % character is interpreted as a zone, not as an SQL wildcard.
	//Also, since inet_aton style is allowed by default, leading zeros in ipv4 are interpreted as octal.
	//
	//If you wish to deviate from the default options,
	//you can simply pass in your own IPAddressStringParameters and HostNameParameters options to the respective constructors.
	//To standardize, you can subclass HostName and/or IPAddressString to use your own standard defaults in the constructors that take validation options.
	//Optionally, you can let everything parse successfully and then validate the resulting HostName/IPAddressString/IPAddress objects according to your tastes.
	public static final boolean DEFAULT_ALLOW_LEADING_ZEROS = true;
	public static final boolean DEFAULT_ALLOW_PREFIX_LENGTH_LEADING_ZEROS = true;
	public static final boolean DEFAULT_ALLOW_UNLIMITED_LEADING_ZEROS = true;
	public static final boolean DEFAULT_ALLOW_EMPTY = true;
	public static final boolean DEFAULT_EMPTY_IS_LOOPBACK = true; //Note that with InetAddress, empty strings are interpreted as the loopback address
	public static final boolean DEFAULT_ALLOW_PREFIX = true;
	public static final boolean DEFAULT_ALLOW_MASK = true;
	public static final boolean DEFAULT_ALLOW_PREFIX_ONLY = true;
	public static final boolean DEFAULT_ALLOW_ALL = true; //matches DEFAULT_RANGE_OPTIONS regarding the use of '*'
	public static final boolean DEFAULT_ALLOW_WILDCARDED_SEPARATOR = true;
	public static final boolean DEFAULT_ALLOW_PREFIX_BEYOND_ADDRESS_SIZE = false;
	public static final RangeParameters DEFAULT_RANGE_OPTIONS = RangeParameters.WILDCARD_AND_RANGE;
	
	/**
	 * Allows zero-length IPAddressStrings like ""
	 * @see #emptyIsLoopback
	 * @see #DEFAULT_ALLOW_EMPTY
	 */
	public final boolean allowEmpty;
	
	/**
	 * Allows addresses like /64 which are only prefix lenths.
	 * Such addresses are interpreted as the network mask for the given prefix length.
	 * @see #DEFAULT_ALLOW_PREFIX_ONLY
	 */
	public final boolean allowPrefixOnly;
	
	/**
	 * Allows the all-encompassing address *, which represents the network of all IPv4 and IPv6 addresses
	 * @see #DEFAULT_ALLOW_ALL
	 */
	public final boolean allowAll;
	
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
	
	private IPv6AddressStringParameters ipv6Options;
	private IPv4AddressStringParameters ipv4Options;
	
	public static class Builder {
		private boolean allowEmpty = DEFAULT_ALLOW_EMPTY; //allows IPAddressStrings like ""
		private boolean emptyIsLoopback = DEFAULT_EMPTY_IS_LOOPBACK;
		private boolean allowPrefix = DEFAULT_ALLOW_PREFIX;
		private boolean allowMask = DEFAULT_ALLOW_MASK;
		private boolean allowPrefixOnly = DEFAULT_ALLOW_PREFIX_ONLY;
		private boolean allowAll = DEFAULT_ALLOW_ALL;
		IPv4AddressStringParameters.Builder ipv4Builder;
		static private IPv4AddressStringParameters DEFAULT_IPV4_OPTS = new IPv4AddressStringParameters.Builder().toParams();
		IPv6AddressStringParameters.Builder ipv6Builder;
		static private IPv6AddressStringParameters DEFAULT_IPV6_OPTS = new IPv6AddressStringParameters.Builder().toParams();
		
		HostNameParameters.Builder parent;
		IPv6AddressStringParameters.Builder mixedParent;
		
		public Builder() {}
		
		public HostNameParameters.Builder getParentBuilder() {
			return parent;
		}
		
		/**
		 * @see IPAddressStringParameters#allowEmpty
		 * @param allow
		 * @return the builder
		 */
		public Builder allowEmpty(boolean allow) {
			allowEmpty = allow;
			return this;
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
		
		public Builder allowAll(boolean allow) {
			allowAll = allow;
			return this;
		}
		
		public Builder setRangeParameters(RangeParameters rangeOptions) {
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
		 * Get the sub-builder for setting IPv6 parameters.
		 * @return the IPv6 builder
		 */
		public IPv6AddressStringParameters.Builder getIPv6AddressParametersBuilder() {
			if(ipv6Builder == null) {
				ipv6Builder = new IPv6AddressStringParameters.Builder();
			}
			((IPVersionAddressStringParameters.BuilderBase) ipv6Builder).parent = this;
			return ipv6Builder;
		}
		
		/**
		 * Get the sub-builder for setting IPv4 parameters.
		 * @return the IPv4 builder
		 */
		public IPv4AddressStringParameters.Builder getIPv4AddressParametersBuilder() {
			if(ipv4Builder == null) {
				ipv4Builder = new IPv4AddressStringParameters.Builder();
			}
			((IPVersionAddressStringParameters.BuilderBase) ipv4Builder).parent = this;
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
			return new IPAddressStringParameters(allowEmpty, allowAll, emptyIsLoopback, allowPrefix, allowMask, allowPrefixOnly, ipv4Opts, ipv6Opts);
		}
	}

	public static class IPVersionAddressStringParameters implements Cloneable, Serializable {

		private static final long serialVersionUID = 1L;
		
		/**
		 * controls whether wildcards like '*', '_' or ranges with '-' are allowed
		 */
		public final RangeParameters rangeOptions;
		
		/**
		 * controls whether ipv4 can have prefix length bigger than 32 and whether ipv6 can have prefix length bigger than 128
		 * @see IPAddressStringParameters#DEFAULT_ALLOW_PREFIX_BEYOND_ADDRESS_SIZE
		 */
		public final boolean allowPrefixesBeyondAddressSize; 
		
		/**
		 * controls whether the wildcard '*' or '%' can replace the segment separators '.' and ':'.
		 * If so, then you can write addresses like *.* or *:*
		 * @see IPAddressStringParameters#DEFAULT_ALLOW_WILDCARDED_SEPARATOR
		 */
		public final boolean allowWildcardedSeparator; 
		
		/**
		 * whether you allow addresses with segments that have leasing zeros like 001.2.3.004 or 1:000a::
		 * For IPV4, this option overrides inet_aton octal.  
		 * 
		 * In other words, if this field is true, and if there are leading zeros then they are interpreted as decimal regardless of {@link IPv4AddressStringParameters#inet_aton_octal}. 
		 * 
		 * Otherwise, validation defers to {@link IPv4AddressStringParameters#inet_aton_octal}
		 * 
		 * @see IPAddressStringParameters#DEFAULT_ALLOW_LEADING_ZEROS
		 */
		public final boolean allowLeadingZeros; 
		
		/**
		 * if {@link #allowLeadingZeros} or the address is IPv4 and {@link IPv4AddressStringParameters#inet_aton_octal} is true, 
		 * this determines if you allow leading zeros that extend segments 
		 * beyond the usual segment length, which is 3 for IPv4 dotted-decimal and 4 for IPv6.  
		 * For example, this determines whether you allow 0001.0002.0003.0004
		 * 
		 * @see IPAddressStringParameters#DEFAULT_ALLOW_UNLIMITED_LEADING_ZEROS
		 */
		public final boolean allowUnlimitedLeadingZeros;
		
		/**
		 * controls whether you allow addresses with prefixes that have leasing zeros like 1.0.0.0/08 or 1::/064
		 * 
		 * @see IPAddressStringParameters#DEFAULT_ALLOW_PREFIX_LENGTH_LEADING_ZEROS
		 */
		public final boolean allowPrefixLengthLeadingZeros;
		
		public IPVersionAddressStringParameters(
				boolean allowLeadingZeros,
				boolean allowPrefixLengthLeadingZeros,
				boolean allowUnlimitedLeadingZeros,
				RangeParameters rangeOptions,
				boolean allowWildcardedSeparator,
				boolean allowPrefixesBeyondAddressSize) {
			this.rangeOptions = rangeOptions;
			if(rangeOptions == null) {
				throw new NullPointerException();
			}
			this.allowPrefixLengthLeadingZeros = allowPrefixLengthLeadingZeros;
			this.allowWildcardedSeparator = allowWildcardedSeparator;
			this.allowPrefixesBeyondAddressSize = allowPrefixesBeyondAddressSize;
			this.allowLeadingZeros = allowLeadingZeros;
			this.allowUnlimitedLeadingZeros = allowUnlimitedLeadingZeros;
		}
		
		protected BuilderBase toBuilder(BuilderBase builder) {
			builder.allowPrefixLengthLeadingZeros = allowPrefixLengthLeadingZeros;
			builder.allowUnlimitedLeadingZeros = allowUnlimitedLeadingZeros;
			builder.rangeOptions = rangeOptions;
			builder.allowPrefixesBeyondAddressSize = allowPrefixesBeyondAddressSize;
			builder.allowWildcardedSeparator = allowWildcardedSeparator;
			builder.allowLeadingZeros = allowLeadingZeros;
			return builder;
		}
		
		protected static class BuilderBase {
			
			protected RangeParameters rangeOptions = IPAddressStringParameters.DEFAULT_RANGE_OPTIONS;
			protected boolean allowPrefixesBeyondAddressSize = IPAddressStringParameters.DEFAULT_ALLOW_PREFIX_BEYOND_ADDRESS_SIZE;
			protected boolean allowWildcardedSeparator = IPAddressStringParameters.DEFAULT_ALLOW_WILDCARDED_SEPARATOR;
			protected boolean allowLeadingZeros = IPAddressStringParameters.DEFAULT_ALLOW_LEADING_ZEROS;
			protected boolean allowPrefixLengthLeadingZeros = IPAddressStringParameters.DEFAULT_ALLOW_PREFIX_LENGTH_LEADING_ZEROS;
			protected boolean allowUnlimitedLeadingZeros = IPAddressStringParameters.DEFAULT_ALLOW_UNLIMITED_LEADING_ZEROS;
			
			IPAddressStringParameters.Builder parent;
			
			protected static void setMixedParent(IPAddressStringParameters.Builder builder, IPv6AddressStringParameters.Builder parent) {
				builder.mixedParent = parent;
			}
			
			public IPAddressStringParameters.Builder getParentBuilder() {
				return parent;
			}
			
			public BuilderBase setRangeOptions(RangeParameters rangeOptions) {
				this.rangeOptions = rangeOptions;
				return this;
			}
			
			public BuilderBase allowPrefixesBeyondAddressSize(boolean allow) {
				allowPrefixesBeyondAddressSize = allow;
				return this;
			}
			
			public BuilderBase allowWildcardedSeparator(boolean allow) {
				allowWildcardedSeparator = allow;
				return this;
			}
			
			public BuilderBase allowLeadingZeros(boolean allow) {
				allowLeadingZeros = allow;
				if(!allow) {
					allowUnlimitedLeadingZeros = allow;
				}
				return this;
			}
			
			public BuilderBase allowPrefixLengthLeadingZeros(boolean allow) {
				allowPrefixLengthLeadingZeros = allow;
				return this;
			}
			
			public BuilderBase allowUnlimitedLeadingZeros(boolean allow) {
				allowUnlimitedLeadingZeros = allow;
				if(allow) {
					allowLeadingZeros = allow;
				}
				return this;
			}
		}

		protected int compareTo(IPVersionAddressStringParameters o) {
			int result = rangeOptions.compareTo(o.rangeOptions);
			if(result == 0) {
				result = Boolean.compare(allowPrefixesBeyondAddressSize, o.allowPrefixesBeyondAddressSize);
				if(result == 0) {
					result = Boolean.compare(allowWildcardedSeparator, o.allowWildcardedSeparator);
					if(result == 0) {
						result = Boolean.compare(allowLeadingZeros, o.allowLeadingZeros);
					}
				}
			}
			return result;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof IPVersionAddressStringParameters) {
				IPVersionAddressStringParameters other = (IPVersionAddressStringParameters) o;
				return rangeOptions.equals(other.rangeOptions) 
						&& allowPrefixesBeyondAddressSize == other.allowPrefixesBeyondAddressSize
						&& allowWildcardedSeparator == other.allowWildcardedSeparator
						&& allowLeadingZeros == other.allowLeadingZeros;
			}
			return false;
		}
		
		@Override
		public int hashCode() {
			int hash = rangeOptions.hashCode();//uses 3 bits
			if(allowPrefixesBeyondAddressSize) {
				hash |= 0x8;//4th bit
			}
			if(allowWildcardedSeparator) {
				hash |= 0x10;//5th bit
			}
			if(allowLeadingZeros) {
				hash |= 0x20;//6th bit
			}
			return hash;
		}
	}
	
	public Builder toBuilder() {
		return toBuilder(false);
	}
	
	public Builder toBuilder(boolean isMixed) {
		Builder builder = new Builder();
		builder.allowAll = allowAll;
		builder.allowPrefixOnly = allowPrefixOnly;
		builder.allowEmpty = allowEmpty;
		builder.emptyIsLoopback = emptyIsLoopback;
		builder.allowPrefix = allowPrefix;
		builder.allowMask = allowMask;
		builder.ipv4Builder = ipv4Options.toBuilder();
		builder.ipv6Builder = ipv6Options.toBuilder(isMixed);
		return builder;
	}

	public IPAddressStringParameters(
			boolean allowEmpty,
			boolean allowAll,
			boolean emptyIsLoopback,
			boolean allowPrefix,
			boolean allowMask,
			boolean allowPrefixOnly,
			IPv4AddressStringParameters ipv4Options,
			IPv6AddressStringParameters ipv6Options) {
		this.allowEmpty = allowEmpty;
		this.allowAll = allowAll;
		this.allowPrefixOnly = allowPrefixOnly;
		this.emptyIsLoopback = emptyIsLoopback;
		this.allowPrefix = allowPrefix;
		this.allowMask = allowMask;
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
		try {
			IPAddressStringParameters result = (IPAddressStringParameters) super.clone();
			result.ipv4Options = ipv4Options.clone();
			result.ipv6Options = ipv6Options.clone();
			return result;
		} catch (CloneNotSupportedException e) {}
		return null;
	}

	@Override
	public int compareTo(IPAddressStringParameters o) {
		int result = ipv4Options.compareTo(o.ipv4Options);
		if(result == 0) {
			result = ipv6Options.compareTo(o.ipv6Options);
			if(result == 0) {
				result = Boolean.compare(allowEmpty, o.allowEmpty);
				if(result == 0) {
					result = Boolean.compare(emptyIsLoopback, o.emptyIsLoopback);
					if(result == 0) {
						result = Boolean.compare(allowPrefix, o.allowPrefix);
						if(result == 0) {
							result = Boolean.compare(allowMask, o.allowMask);
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
			return ipv4Options.equals(other.ipv4Options) 
					&& ipv6Options.equals(other.ipv6Options) 
					&& allowEmpty == other.allowEmpty 
					&& emptyIsLoopback == other.emptyIsLoopback 
					&& allowPrefix == other.allowPrefix 
					&& allowMask == other.allowMask;
		}
		return false;
	}
	
	@Override
	public int hashCode() {
		//the ipv4 part uses just one byte and one additional bit
		int hash = ipv4Options.hashCode();
		
		//the ipv6 part uses 2 bytes plus one extra bit
		hash |= ipv6Options.hashCode() << 9;
		
		//so now we are up to 3 bytes and 2 additional bits, so we have 0x4000000 and onwards available
		if(allowEmpty) {
			hash |= 0x4000000;
		}
		if(emptyIsLoopback) {
			hash |= 0x8000000;
		}
		if(allowPrefix) {
			hash |= 0x10000000;
		}
		if(allowMask) {
			hash |= 0x20000000;
		}
		return hash;
	}
}

