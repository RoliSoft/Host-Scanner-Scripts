# Host Scanner Scripts

This repository hosts several miscellaneous utility scripts for the [Host Scanner](https://github.com/RoliSoft/Host-Scanner) application.

## `get.sh` and `convert.sh`

The first script downloads all the data files that are required for the various scripts to run. The second one runs the conversions.

When invoking the go scripts directly or via the converter script, the `--json` argument overrides the default behaviour of the `serializeEntries()` function within the scripts to dump the global `entries` list as an indented JSON to the specified output instead of the proprietary binary format. Similarly, the `--nogz` argument instructs the converter script not to gzip the output file after conversion.

This is useful for either debugging purposes or easy reuse of the data within 3rd-party applications. When reusing, please beware of the licenses under which these datasets are being distributed, as some do not allow commercial usage or restrict the licensing of the combined work.

## Format

The file format which the source data is converted to is a generic binary format, having the following header:

	┌ uint16      Package type
	├ uint16      Package version
	└[uint32      Number of entries]

The number of entries field is optional, however all files use it currently.

Strings are stored with a leading length indicator, and no trailing `NULL`:

	┌ uint16      String length
	└─ char       Characters

Integer types are encoded using little endian encoding.

## `cpe2hs.go`

Converts NIST's [Official Common Platform Enumeration (CPE) Dictionary](https://nvd.nist.gov/cpe.cfm) to the binary format in use by the application.

Entries other than applications (`a`) and operating systems (`o`) are filtered, since they are not observed by the main application at this time.

### Format

	┌ uint16      Package type [0x0100]
	├ uint16      Package version [0x0100]
	├ uint32      Number of entries
	└┬ string     CPE name
	 ├ uint8      Number of common tokens
	 ├─ string    Token
	 ├ uint32     Number of versions
	 └┬ string    CPE version
	  ├ string    Version token
	  ├ uint8     Number of version-specific tokens
	  └─ string   Token

## `cpealt2hs.go`

Since NIST's CVE database may use multiple CPE names to refer to the same application, the Debian Security team [compiled a list](https://wiki.debian.org/CPEtagPackagesDep) of CPE aliases for use in their [Security Tracker](https://security-tracker.debian.org/tracker/).

For example, nginx appears as both `cpe:/a:nginx:nginx` and `cpe:/a:igor_sysoev:nginx`, however there are more extreme cases, such as X11, which has 12 CPE names all referring to the same software package.

The alias database is licensed under [MIT License (Expat)](https://www.debian.org/legal/licenses/mit) by the Debian Security team.

### Format

	┌ uint16      Package type [0x0200]
	├ uint16      Package version [0x0100]
	├ uint32      Number of entries
	└┬ uint16     Number of aliases in entry
	 └─ string    CPE name

## `cve2hs.go`

Converts NIST's [National Vulnerability Database (NVD)](https://nvd.nist.gov/download.cfm) to an SQLite3 database to be queried by the application.

Entries not linked via CPE to at least one application or operating system are filtered, since they are of no use during automatic vulnerability discovery.

In order to run this script, you will need to first install the _go-sqlite3_ package with:

	go get github.com/mattn/go-sqlite3

Since this dependency is a _cgo_ package, you will need _gcc_ in your `%PATH%`. As Cygwin is not supported by Go, you specifically need the MinGW version on Windows.

### Tables

	vulns (id int, cve text, date int, descr text, severity float, access char(1))
	affected (vuln_id int, cpe text)

The `access` field represents the access vector, and can be:

- `l` for local: physical access or local presence is required to exploit.
- `a` for adjacent: attacker has to reside on the same local network.
- `n` for network: vulnerability is remotely exploitable over the Internet.

## `zudp2hs.go`

Converts ZMap's [UDP payloads](https://github.com/zmap/zmap/tree/master/examples/udp-probes) to the binary format in use by the application.

The payload list is licensed under [Apache License v2.0](https://www.apache.org/licenses/LICENSE-2.0) by the Regents of the University of Michigan.

### Format

	┌ uint16      Package type [0x0A00]
	├ uint16      Package version [0x0100]
	├ uint32      Number of entries
	└┬ string     Payload data
	 ├ uint16     Number of ports in entry
	 └─ uint16    Port number

## `nudp2hs.go`

Converts Nmap's [UDP payloads](https://nmap.org/book/nmap-payloads.html) to the binary format in use by the application.

The payload list is licensed under [GNU General Public License v2.0](https://www.gnu.org/licenses/gpl-2.0.html) by Insecure.Com LLC.

### Format

	┌ uint16      Package type [0x0A00]
	├ uint16      Package version [0x0100]
	├ uint32      Number of entries
	└┬ string     Payload data
	 ├ uint16     Number of ports in entry
	 └─ uint16    Port number

## `ncpe2hs.go`

Converts Nmap's [service probes](https://nmap.org/book/vscan-fileformat.html) to the binary format in use by the application.

The service probes list is licensed under [GNU General Public License v2.0](https://www.gnu.org/licenses/gpl-2.0.html) by Insecure.Com LLC.

### Format

	┌ uint16      Package type [0x0F00]
	├ uint16      Package version [0x0100]
	├ uint32      Number of entries
	└┬ string     Regular expression
	 ├ string     CPE name
	 ├ string     Product
	 └ string     Version

## `bsvr2hs.go`

Converts Burp Suite Software Version Check's [match rules](https://github.com/augustd/burp-suite-software-version-checks/blob/master/src/burp/match-rules.tab) to the binary format in use by the application.

The match rules list is licensed under [Creative Commons Attribution-NonCommercial-ShareAlike v3.0 Unported License](https://creativecommons.org/licenses/by-nc-sa/3.0/) by August Detlefsen.

### Format

	┌ uint16      Package type [0x0F00]
	├ uint16      Package version [0x0100]
	├ uint32      Number of entries
	└┬ string     Regular expression
	 ├ string     CPE name
	 ├ string     Product
	 └ string     Version