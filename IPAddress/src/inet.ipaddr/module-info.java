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
 * @author seancfoley
 *
 */
open module inet.ipaddr {
	exports inet.ipaddr.format;
	exports inet.ipaddr.format.standard;
	exports inet.ipaddr.format.large;
	exports inet.ipaddr.format.string;
	exports inet.ipaddr.format.util;
	exports inet.ipaddr.format.util.sql;
	exports inet.ipaddr.format.validate;
	exports inet.ipaddr;
	exports inet.ipaddr.mac;
	exports inet.ipaddr.ipv4;
	exports inet.ipaddr.ipv6;

	requires java.base;
}
