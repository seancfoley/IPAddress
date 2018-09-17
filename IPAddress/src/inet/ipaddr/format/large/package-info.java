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


/**
 * Classes for constructing arbitrary divisions of unlimited length and the groupings of those divisions.
 * <p>
 * This is useful for arbitrary representations of IPv6 addresses, since  
 * IPv6 addresses have 128-bit length, exceeding the size of a 64-bit long.
 * <p>
 * BigInteger is used for representing division values.  For divisions under 64 bits,
 * which is the case for standard representations of IPv4 (8 bit segments), IPv6 (16 bit segments) and MAC (8 bit segments), 
 * you should use the classes in package inet.ipaddr.format.standard instead.
 *
 * @author sfoley
 */
package inet.ipaddr.format.large;
