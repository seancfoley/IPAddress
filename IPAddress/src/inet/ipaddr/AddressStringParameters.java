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
 * This class allows you to control the validation performed by the class {@link IPAddressString} or {@link MACAddressString}.
 * <p>
 * Those classes use a default permissive instance when you do not specify one.
 * <p>
 * All instances are immutable and must be constructed with the nested Builder class.
 * 
 * @author sfoley
 *
 */
public class AddressStringParameters implements Cloneable, Serializable {
	
	private static final long serialVersionUID = 4L;
	
	/**
	 * Controls special characters in addresses like '*', '-', '_'
	 * @see AddressStringFormatParameters#DEFAULT_RANGE_OPTIONS
	 * @author sfoley
	 *
	 */
	public static class RangeParameters implements Comparable<RangeParameters>, Cloneable, Serializable {
		
		private static final long serialVersionUID = 4L;

		private final boolean wildcard, range, singleWildcard;

		public static final RangeParameters NO_RANGE = new RangeParameters(false, false, false);
		public static final RangeParameters WILDCARD_ONLY = new RangeParameters(true, false, true); /* use this to support addresses like 1.*.3.4 or 1::*:3 or 1.2_.3.4 or 1::a__:3  */
		public static final RangeParameters WILDCARD_AND_RANGE = new RangeParameters(true, true, true);/* use this to support addresses supported by DEFAULT_WILDCARD_OPTIONS and also addresses like 1.2-3.3.4 or 1:0-ff:: */
		
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
		 * @return whether '-' (or the expected range separator for the address) is allowed to denote a range from lower to higher, like 1-10
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
	public static final boolean DEFAULT_ALLOW_EMPTY = true;
	public static final boolean DEFAULT_ALLOW_ALL = true; //matches DEFAULT_RANGE_OPTIONS regarding the use of '*'
	public static final boolean DEFAULT_ALLOW_SINGLE_SEGMENT = true;
	
	/**
	 * Allows zero-length IPAddressStrings like ""
	 * @see #DEFAULT_ALLOW_EMPTY
	 */
	public final boolean allowEmpty;
	
		
	/**
	 * Allows the all-encompassing address *, which represents the network of all IPv4 and IPv6 addresses
	 * @see #DEFAULT_ALLOW_ALL
	 */
	public final boolean allowAll;
	
	/**
	 * Allows an address to be specified as a single value, eg ffffffff, without the standard use of segments like 1.2.3.4 or 1:2:4:3:5:6:7:8
	 * 
	 * @see #DEFAULT_ALLOW_SINGLE_SEGMENT
	 */
	public final boolean allowSingleSegment;
	
	public static class BuilderBase {
		protected boolean allowEmpty = DEFAULT_ALLOW_EMPTY; //allows IPAddressStrings like ""
		protected boolean allowAll = DEFAULT_ALLOW_ALL;
		protected boolean allowSingleSegment = DEFAULT_ALLOW_SINGLE_SEGMENT;
		
		public BuilderBase() {}

		/**
		 * @see AddressStringParameters#allowEmpty
		 * @param allow
		 * @return the builder
		 */
		public BuilderBase allowEmpty(boolean allow) {
			allowEmpty = allow;
			return this;
		}
		
		/**
		 * @see AddressStringParameters#allowEmpty
		 * @param allow
		 * @return the builder
		 */
		public BuilderBase allowSingleSegment(boolean allow) {
			allowSingleSegment = allow;
			return this;
		}
		
		public BuilderBase allowAll(boolean allow) {
			allowAll = allow;
			return this;
		}
	}

	public static class AddressStringFormatParameters implements Cloneable, Serializable {

		private static final long serialVersionUID = 4L;
		
		public static final boolean DEFAULT_ALLOW_LEADING_ZEROS = true;
		public static final boolean DEFAULT_ALLOW_UNLIMITED_LEADING_ZEROS = true;
		public static final boolean DEFAULT_ALLOW_WILDCARDED_SEPARATOR = true;
		public static final RangeParameters DEFAULT_RANGE_OPTIONS = RangeParameters.WILDCARD_AND_RANGE;
		
		/**
		 * controls whether wildcards like '*', '_' or ranges with '-' are allowed
		 */
		public final RangeParameters rangeOptions;
		
		/**
		 * controls whether the wildcard '*' or '%' can replace the segment separators '.' and ':'.
		 * If so, then you can write addresses like *.* or *:*
		 * @see AddressStringFormatParameters#DEFAULT_ALLOW_WILDCARDED_SEPARATOR
		 */
		public final boolean allowWildcardedSeparator; 
		
		/**
		 * whether you allow addresses with segments that have leasing zeros like 001.2.3.004 or 1:000a::
		 * For IPV4, this option overrides inet_aton octal.  
		 * 
		 * In other words, if this field is true, and if there are leading zeros then they are interpreted as decimal regardless of {@link inet.ipaddr.ipv4.IPv4AddressStringParameters#inet_aton_octal}. 
		 * 
		 * Otherwise, validation defers to {@link inet.ipaddr.ipv4.IPv4AddressStringParameters#inet_aton_octal}
		 * 
		 * @see AddressStringFormatParameters#DEFAULT_ALLOW_LEADING_ZEROS
		 */
		public final boolean allowLeadingZeros; 
		
		/**
		 * if {@link #allowLeadingZeros} or the address is IPv4 and {@link inet.ipaddr.ipv4.IPv4AddressStringParameters#inet_aton_octal} is true, 
		 * this determines if you allow leading zeros that extend segments 
		 * beyond the usual segment length, which is 3 for IPv4 dotted-decimal and 4 for IPv6.  
		 * For example, this determines whether you allow 0001.0002.0003.0004
		 * 
		 * @see AddressStringFormatParameters#DEFAULT_ALLOW_UNLIMITED_LEADING_ZEROS
		 */
		public final boolean allowUnlimitedLeadingZeros;
		
		public AddressStringFormatParameters(
				boolean allowLeadingZeros,
				boolean allowUnlimitedLeadingZeros,
				RangeParameters rangeOptions,
				boolean allowWildcardedSeparator) {
			this.rangeOptions = rangeOptions;
			if(rangeOptions == null) {
				throw new NullPointerException();
			}
			this.allowWildcardedSeparator = allowWildcardedSeparator;
			this.allowLeadingZeros = allowLeadingZeros;
			this.allowUnlimitedLeadingZeros = allowUnlimitedLeadingZeros;
		}
		
		protected BuilderBase toBuilder(BuilderBase builder) {
			builder.allowUnlimitedLeadingZeros = allowUnlimitedLeadingZeros;
			builder.rangeOptions = rangeOptions;
			builder.allowWildcardedSeparator = allowWildcardedSeparator;
			builder.allowLeadingZeros = allowLeadingZeros;
			return builder;
		}
		
		protected static class BuilderBase {
			
			protected RangeParameters rangeOptions = DEFAULT_RANGE_OPTIONS;
			protected boolean allowWildcardedSeparator = DEFAULT_ALLOW_WILDCARDED_SEPARATOR;
			protected boolean allowLeadingZeros = DEFAULT_ALLOW_LEADING_ZEROS;
			protected boolean allowUnlimitedLeadingZeros = DEFAULT_ALLOW_UNLIMITED_LEADING_ZEROS;
			
			public BuilderBase setRangeOptions(RangeParameters rangeOptions) {
				this.rangeOptions = rangeOptions;
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
			
			public BuilderBase allowUnlimitedLeadingZeros(boolean allow) {
				allowUnlimitedLeadingZeros = allow;
				if(allow) {
					allowLeadingZeros = allow;
				}
				return this;
			}
		}

		protected int compareTo(AddressStringFormatParameters o) {
			int result = rangeOptions.compareTo(o.rangeOptions);
			if(result == 0) {
				result = Boolean.compare(allowWildcardedSeparator, o.allowWildcardedSeparator);
				if(result == 0) {
					result = Boolean.compare(allowLeadingZeros, o.allowLeadingZeros);
				}
			}
			return result;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof AddressStringFormatParameters) {
				AddressStringFormatParameters other = (AddressStringFormatParameters) o;
				return rangeOptions.equals(other.rangeOptions) 
						&& allowUnlimitedLeadingZeros == other.allowUnlimitedLeadingZeros
						&& allowWildcardedSeparator == other.allowWildcardedSeparator
						&& allowLeadingZeros == other.allowLeadingZeros;
			}
			return false;
		}
		
		@Override
		public int hashCode() {
			int hash = rangeOptions.hashCode();//uses 3 bits
			if(allowUnlimitedLeadingZeros) {
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
	
	public BuilderBase toBuilder(BuilderBase builder) {
		builder.allowAll = allowAll;
		builder.allowEmpty = allowEmpty;
		builder.allowSingleSegment = allowSingleSegment;
		return builder;
	}

	public AddressStringParameters(
			boolean allowEmpty,
			boolean allowAll,
			boolean allowSingleSegment) {
		this.allowEmpty = allowEmpty;
		this.allowAll = allowAll;
		this.allowSingleSegment = allowSingleSegment;
	}
	
	@Override
	public AddressStringParameters clone() {
		try {
			AddressStringParameters result = (AddressStringParameters) super.clone();
			return result;
		} catch (CloneNotSupportedException e) {}
		return null;
	}

	public int compareTo(AddressStringParameters o) {
		int result = Boolean.compare(allowAll, o.allowAll);
		if(result == 0) {
			result = Boolean.compare(allowEmpty, o.allowEmpty);
			if(result == 0) {
				result = Boolean.compare(allowSingleSegment, o.allowSingleSegment);
			}
		}
		return result;
	}
	
	@Override
	public boolean equals(Object o) {
		if(o instanceof AddressStringParameters) {
			AddressStringParameters other = (AddressStringParameters) o;
			return allowEmpty == other.allowEmpty && 
					allowAll == other.allowAll &&
					allowSingleSegment == other.allowSingleSegment;
		}
		return false;
	}
}

