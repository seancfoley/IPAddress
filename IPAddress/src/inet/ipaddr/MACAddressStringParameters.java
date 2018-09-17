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

import inet.ipaddr.mac.MACAddressNetwork;

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
public class MACAddressStringParameters extends AddressStringParameters implements Comparable<MACAddressStringParameters> {
	
	private static final long serialVersionUID = 4L;

	//The defaults are permissive
	public static final boolean DEFAULT_ALLOW_DASHED = true;
	public static final boolean DEFAULT_ALLOW_SINGLE_DASHED = true;
	public static final boolean DEFAULT_ALLOW_COLON_DELIMITED = true;
	public static final boolean DEFAULT_ALLOW_DOTTED = true;
	public static final boolean DEFAULT_ALLOW_SPACE_DELIMITED = true;
	
	public static enum AddressSize {
		MAC,
		EUI64,
		ANY;
	};
	
	/**
	 * Whether * is considered to be MAC 6 bytes, EUI-64 8 bytes, or either one
	 */
	public final AddressSize addressSize;
	
	
	/**
	 * Allows addresses like aa-bb-cc-dd-ee-ff
	 */
	public final boolean allowDashed;
	
	/**
	 * Allows addresses like aabbcc-ddeeff
	 */
	public final boolean allowSingleDashed;

	/**
	 * Allows addresses like aa:bb:cc:dd:ee:ff
	 */
	public final boolean allowColonDelimited;

	/**
	 * Allows addresses like aaa.bbb.ccc.ddd
	 */
	public final boolean allowDotted;

	/**
	 * Allows addresses like aa bb cc dd ee ff
	 */
	public final boolean allowSpaceDelimited;
	
	private final MACAddressNetwork network;

	private MACAddressStringFormatParameters formatOpts;
	
	public MACAddressStringParameters(
			boolean allowEmpty,
			boolean allowAll,
			AddressSize allAddresses,
			boolean allowSingleSegment,
			boolean allowDashed,
			boolean allowSingleDashed,
			boolean allowColonDelimited,
			boolean allowDotted,
			boolean allowSpaceDelimited,
			MACAddressStringFormatParameters formatOpts,
			MACAddressNetwork network) {
		super(allowEmpty, allowAll, allowSingleSegment);
		this.allowDashed = allowDashed;
		this.allowSingleDashed = allowSingleDashed;
		this.allowColonDelimited = allowColonDelimited;
		this.allowDotted = allowDotted;
		this.allowSpaceDelimited = allowSpaceDelimited;
		this.formatOpts = formatOpts;
		this.addressSize = allAddresses;
		this.network = network;
	}
	
	public static class Builder extends AddressStringParameters.BuilderBase {
		private boolean allowDashed = DEFAULT_ALLOW_DASHED;
		private boolean allowSingleDashed = DEFAULT_ALLOW_SINGLE_DASHED;
		private boolean allowColonDelimited = DEFAULT_ALLOW_COLON_DELIMITED;
		private boolean allowDotted = DEFAULT_ALLOW_DOTTED;
		private boolean allowSpaceDelimited = DEFAULT_ALLOW_SPACE_DELIMITED;
		private AddressSize allAddresses;
		private MACAddressNetwork network;

		MACAddressStringFormatParameters.Builder formatBuilder;
		static private MACAddressStringFormatParameters DEFAULT_FORMAT_OPTS = new MACAddressStringFormatParameters.Builder().toParams();
		
		public Builder() {}
		
		/**
		 * @see MACAddressStringParameters#allowEmpty
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

		public Builder allowDashed(boolean bool) {
			allowDashed = bool;
			return this;
		}
		
		public Builder allowColonDelimited(boolean allow) {
			allowColonDelimited = allow;
			return this;
		}
		
		public Builder allowDotted(boolean allow) {
			allowDotted = allow;
			return this;
		}
		
		public Builder allowSpaceDelimited(boolean allow) {
			allowSpaceDelimited = allow;
			return this;
		}
		
		@Override
		public Builder allowAll(boolean allow) {
			return (Builder) super.allowAll(allow);
		}
		
		public Builder setAllAddresses(AddressSize all) {
			allAddresses = all;
			return this;
		}
		
		/**
		 * @see MACAddressStringParameters#network
		 * @param network if null, the default network will be used
		 * @return the builder
		 */
		public Builder setNetwork(MACAddressNetwork network) {
			this.network = network;
			return this;
		}

		public Builder allowWildcardedSeparator(boolean allow) {
			getFormatBuilder().allowWildcardedSeparator(allow);
			return this;
		}
		
		public Builder setRangeOptions(RangeParameters rangeOptions) {
			getFormatBuilder().setRangeOptions(rangeOptions);
			return this;
		}
		/**
		 * Get the sub-builder for setting format parameters.
		 * @return the format builder
		 */
		public MACAddressStringFormatParameters.Builder getFormatBuilder() {
			if(formatBuilder == null) {
				formatBuilder = new MACAddressStringFormatParameters.Builder();
			}
			formatBuilder.parent = this;
			return formatBuilder;
		}
		
		public MACAddressStringParameters toParams() {
			MACAddressStringFormatParameters formatOpts;
			if(formatBuilder == null) {
				formatOpts = DEFAULT_FORMAT_OPTS;
			} else {
				formatOpts = formatBuilder.toParams();
			}
			return new MACAddressStringParameters(
					allowEmpty, allowAll, allAddresses, allowSingleSegment, allowDashed, allowSingleDashed, allowColonDelimited, allowDotted, allowSpaceDelimited, 
					formatOpts, network);
		}
	}

	public static class MACAddressStringFormatParameters extends AddressStringFormatParameters implements Comparable<MACAddressStringFormatParameters> {

		private static final long serialVersionUID = 4L;
		
		public static final boolean DEFAULT_ALLOW_SHORT_SEGMENTS = true;
		
		public final boolean allowShortSegments;
		
		public MACAddressStringFormatParameters(
				boolean allowShortSegments,
				boolean allowLeadingZeros,
				boolean allowUnlimitedLeadingZeros,
				RangeParameters rangeOptions,
				boolean allowWildcardedSeparator) {
			super(allowLeadingZeros, allowUnlimitedLeadingZeros, rangeOptions, allowWildcardedSeparator);
			this.allowShortSegments = allowShortSegments;
		}

		public Builder toBuilder() {
			Builder builder = new Builder();
			super.toBuilder(builder);
			builder.allowShortSegments = allowShortSegments;
			return builder;
		}
		
		public static class Builder extends AddressStringFormatParameters.BuilderBase {
			
			boolean allowShortSegments = DEFAULT_ALLOW_SHORT_SEGMENTS;
			
			MACAddressStringParameters.Builder parent;
			
			public MACAddressStringParameters.Builder getParentBuilder() {
				return parent;
			}
			
			public Builder allowShortSegments(boolean allow) {
				allowShortSegments = allow;
				return this;
			}
			
			@Override
			public Builder setRangeOptions(RangeParameters rangeOptions) {
				return (Builder) super.setRangeOptions(rangeOptions);
			}
			
			@Override
			public Builder allowWildcardedSeparator(boolean allow) {
				return (Builder) super.allowWildcardedSeparator(allow);
			}
			
			@Override
			public Builder allowLeadingZeros(boolean allow) {
				return (Builder) super.allowLeadingZeros(allow);
			}
			
			@Override
			public Builder allowUnlimitedLeadingZeros(boolean allow) {
				return (Builder) super.allowUnlimitedLeadingZeros(allow);
			}
			
			MACAddressStringFormatParameters toParams() {
				return new MACAddressStringFormatParameters(allowShortSegments, allowLeadingZeros, allowUnlimitedLeadingZeros, rangeOptions, allowWildcardedSeparator);
			}
		}

		@Override
		public int compareTo(MACAddressStringFormatParameters o) {
			int result = super.compareTo(o);
			if(result == 0) {
				result = Boolean.compare(allowShortSegments, o.allowShortSegments);
			}
			return result;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof MACAddressStringFormatParameters) {
				MACAddressStringFormatParameters other = (MACAddressStringFormatParameters) o;
				return super.equals(o) &&
						allowShortSegments == other.allowShortSegments;
			}
			return false;
		}
		
		@Override
		public int hashCode() {
			int hash = super.hashCode();
			if(allowShortSegments) {
				hash |= 0x40;
			}
			return hash;
		}
		
		@Override
		public MACAddressStringFormatParameters clone() {
			try {
				return (MACAddressStringFormatParameters) super.clone();
			} catch (CloneNotSupportedException e) {
				return null;
			}
		}
	}
	
	public Builder toBuilder() {
		Builder builder = new Builder();
		super.toBuilder(builder);
		builder.allowDashed = allowDashed;
		builder.allowSingleDashed = allowSingleDashed;
		builder.allowColonDelimited = allowColonDelimited;
		builder.allowDotted = allowDotted;
		builder.allowSpaceDelimited = allowSpaceDelimited;
		builder.formatBuilder = formatOpts.toBuilder();
		builder.allAddresses = addressSize;
		builder.network = network;
		return builder;
	}

	public MACAddressNetwork getNetwork() {
		if(network == null) {
			return Address.defaultMACNetwork();
		}
		return network;
	}

	public MACAddressStringFormatParameters getFormatParameters() {
		return formatOpts;
	}

	@Override
	public MACAddressStringParameters clone() {
		MACAddressStringParameters result = (MACAddressStringParameters) super.clone();
		result.formatOpts = formatOpts.clone();
		return result;
	}

	@Override
	public int compareTo(MACAddressStringParameters o) {
		int result = super.compareTo(o);
		if(result == 0) {
			result = formatOpts.compareTo(o.formatOpts);
			if(result == 0) {
				result = Boolean.compare(allowDashed, o.allowDashed);
				if(result == 0) {
					result = Boolean.compare(allowSingleDashed, o.allowSingleDashed);
					if(result == 0) {
						result = Boolean.compare(allowColonDelimited, o.allowColonDelimited);
						if(result == 0) {
							result = Boolean.compare(allowDotted, o.allowDotted);
							if(result == 0) {
								result = Boolean.compare(allowSpaceDelimited, o.allowSpaceDelimited);
								if(result == 0) {
									result = addressSize.ordinal() - o.addressSize.ordinal();
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
		if(o instanceof MACAddressStringParameters) {
			MACAddressStringParameters other = (MACAddressStringParameters) o;
			return super.equals(o) &&
					formatOpts.equals(other.formatOpts) &&
					allowDashed == other.allowDashed &&
					allowSingleDashed == other.allowSingleDashed &&
					allowColonDelimited == other.allowColonDelimited &&
					allowDotted == other.allowDotted &&
					allowSpaceDelimited == other.allowSpaceDelimited &&
					addressSize == other.addressSize;
		}
		return false;
	}

	@Override
	public int hashCode() {
		//the format options part uses 7 bits
		int hash = formatOpts.hashCode();
		if(allowAll) {
			hash |= 0x80;
		}
		if(allowDashed) {
			hash |= 0x100;
		}
		if(allowColonDelimited) {
			hash |= 0x200;
		}
		if(allowDotted) {
			hash |= 0x400;
		}
		if(allowSpaceDelimited) {
			hash |= 0x800;
		}
		if(allowSingleSegment) {
			hash |= 0x1000;
		}
		if(addressSize == AddressSize.MAC) {
			hash |= 0x2000;
		} else if(addressSize == AddressSize.EUI64) {
			hash |= 0x4000;
		}
		if(allowSingleDashed) {
			hash |= 0x8000;
		}
		if(allowEmpty) {
			hash |= 0x10000;
		}
		return hash;
	}
}
