# IPAddress
Library for handling IP addresses, both IPv4 and IPv6

[View Project Page](https://seancfoley.github.io/IPAddress/)

[View Javadoc](https://seancfoley.github.io/IPAddress/IPAddress/apidocs/)

[In the Maven Central Repository](https://repo1.maven.org/maven2/com/github/seancfoley/ipaddress/)
- group id: com.github.seancfoley
- artifact id: [ipaddress](https://search.maven.org/#search%7Cga%7C1%7Cipaddress)
- versions: [2.0.2](https://search.maven.org/#artifactdetails%7Ccom.github.seancfoley%7Cipaddress%7C2.0.2%7Cjar), [3.0.0](https://search.maven.org/#artifactdetails%7Ccom.github.seancfoley%7Cipaddress%7C3.0.0%7Cjar), [4.1.0](https://search.maven.org/#artifactdetails%7Ccom.github.seancfoley%7Cipaddress%7C4.1.0%7Cjar)

Developed as an Eclipse project, the project files are checked in so it can be easily be imported into an Eclipse workspace.

Versions:

[v1.0.0](https://github.com/seancfoley/IPAddress/releases/tag/v1.0.0) is Java 7 compatible

[v2.0.2](https://github.com/seancfoley/IPAddress/releases/tag/v2.0.2) and later requires Java 8

[v3.0.0](https://github.com/seancfoley/IPAddress/releases/tag/v3.0.0) features MAC address support, EUI-48 and EUI-64 MAC integration with IPv6, new address framework, new IP string formats parsed and produced, and other additions

**[Latest Version v4.1.0](https://github.com/seancfoley/IPAddress/releases/tag/v4.1.0)** features new prefix length handling.  The default [prefix behaviour](https://seancfoley.github.io/IPAddress/#_Prefix_Length_Handling) has changed since version 3.  IPv4-network/IPv6-subnet router-anycast/zero-host addresses are interpreted as the prefix block subnet, while other prefixed addresses are individual addresses There exists the option to preserve the version 3 behaviour, treating all prefixed addresses as the prefix block subnet.  A third option can be used to interpret all prefixed addresses as individual addresses.

No further major releases planned at this time, while minor releases will continue.  Currently working on porting the library to **TypeScript** and **JavaScript**.
