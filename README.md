# IPAddress
Library for handling IP addresses and subnets, both IPv4 and IPv6

[View Project Page](https://seancfoley.github.io/IPAddress/)

[View Javadoc](https://seancfoley.github.io/IPAddress/IPAddress/apidocs/)

[In the Maven Central Repository](https://repo1.maven.org/maven2/com/github/seancfoley/ipaddress/)
- group id: com.github.seancfoley
- artifact id: [ipaddress](https://search.maven.org/search?q=ipaddress)
- versions: [2.0.2](https://search.maven.org/#artifactdetails%7Ccom.github.seancfoley%7Cipaddress%7C2.0.2%7Cjar), [3.0.0](https://search.maven.org/#artifactdetails%7Ccom.github.seancfoley%7Cipaddress%7C3.0.0%7Cjar), [4.2.0](https://search.maven.org/#artifactdetails%7Ccom.github.seancfoley%7Cipaddress%7C4.2.0%7Cjar)

Developed as an Eclipse project, the project files are checked in so it can be easily be imported into an Eclipse workspace.

Version | Notes
------- | -------------
[v1.0.0](https://github.com/seancfoley/IPAddress/releases/tag/v1.0.0) | Java 7 compatible
[v2.0.2](https://github.com/seancfoley/IPAddress/releases/tag/v2.0.2) | requires Java 8 or higher
[v3.0.0](https://github.com/seancfoley/IPAddress/releases/tag/v3.0.0) | requires Java 8 or higher, features MAC address support, EUI-48 and EUI-64 MAC integration with IPv6, new address framework, new IP string formats parsed and produced, and other additions
**[Latest Version v4.2.0](https://github.com/seancfoley/IPAddress/releases/tag/v4.2.0)** | requires Java 8 or higher.  Version 4 and up features new prefix length handling.  IPv4-network/IPv6-subnet-router-anycast/zero-host addresses are interpreted as the prefix block subnet, while other prefixed addresses are individual addresses. There exists the option to preserve the version 3 behaviour.  Version 4.2.0 has additional methods for managing prefix blocks.  Other enhancements listed on the [releases page](https://github.com/seancfoley/IPAddress/releases/tag/v4.2.0).

Planned future additions: ports to [**TypeScript**](https://www.typescriptlang.org/) / [**JavaScript**](https://www.npmjs.com/) and [**Go**](https://golang.org/).
