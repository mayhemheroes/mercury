# Mercury: network metadata capture and analysis
<img align="right" src="./mercury.png" width="200">

This package contains two programs for fingerprinting network traffic and capturing and analyzing packet metadata: **mercury**, a Linux application that leverages the modern Linux kernel's high-performance networking capabilities (AF_PACKET and TPACKETv3), which is described below, and [**pmercury**](python/README.md), a portable python application, which is described [here](python/README.md).  There is also a [User's Guide](https://github.com/cisco/mercury/wiki/Using-Mercury).  While mercury is used in some production applications, please consider it 'beta'.

## Overview

Mercury reads network packets, identifies metadata of interest, and writes out the metadata in JSON format.  Alternatively, mercury can write out the packets that contain the metadata in the PCAP file format.  Mercury can scale up to high data rates (40Gbps on server-class hardware); it uses zero-copy ring buffers to acquire packets, and packets are processed by independent worker threads.  The amount of memory consumed by the ring buffers, and the number of worker threads, are configurable; this makes it easy to scale up (but be wary of using too much memory).

Mercury produces fingerprint strings for TLS, DTLS, SSH, HTTP, TCP, and other protocols; these fingerprints are formed by carefully selecting and normalizing metadata extracted from packets.  Fingerprint strings are reported in the "fingerprint" object in the JSON output.  Optionally, mercury can perform process identification based on those fingerprints and the destination context; these results are reported in the "analysis" object.

## Version 2.5.13

* Added `--format` option that selects the fingerprint format(s).
* Added `tls/1` fingerprint format, in which extensions are sorted into increasing lexicographic order.  This compensates for TLS clients that randomize the order of extensions.
* Updated and amended this README.

## Version 2.5.12

* Fixes some bugs.
* Updated and amended this README.

## Version 2.5.11

* Run-time configurability for Genric Routing Encapsulation (GRE), Cisco Discovery Protocol (CDP), Link-Layer Discovery Protocol (LLDP), Address Resolution Protocol (ARP), Open Shortest Path First (OSPF), NetBIOS Datagram Service (NBDS), NetBIOS Streaming Service (NBSS), Stream Control Transmission Protocol (SCTP), and the Internet Control Message Protocol (ICMP).  These protocols are off by default; they must explicitly appear in the `--select` option to be selected.
* STUN and DNP3 introduce a new convention for reporting unknown type codes in JSON by including the hexadecimal value of the unknown code as a string, such as `"type":"UNKNOWN (0004)"`.  This convention allows for a smaller and simpler schema, since no additional fields are needed to report unknown values.
* Support for the [automatic generation of C++ classes that represent type codes](doc/autogen.md) from Comma Separated Value (CSV) files, in the [src/tables](src/tables) directory.  This facility is currently used by STUN and IKE.
* Experimental support for IKEv2.
* Fuzz tests now run in parallel, making that process considerably faster.  Additional fuzz tests were added.

## Version 2.5.10

* Fixes some bugs.
* Updated and amended this README.

## Version 2.5.9

* Support for detecting, parsing, and reporting STUN packets as JSON.  Fingerprinting for STUN is experimental.

## Version 2.5.8

* Added fuzz testing framework based on libfuzz.  This replaces AFL in the `make fuzz-test` target in `test/`.
* Support for on-demand TCP reassembly of TLS Client Hello packets and other metata.  This feature is configured with the --tcp-reassembly option.
* Support for detecting DNS over TCP packets and reporting that data in the JSON output.
* Support for detecting SMB v1 and v2 and reporting the fields of the negotiate request and response packets in the JSON output.
* Support of detecting IEC 60870-5-104 packets and reporting its fields in the JSON output.

## Version 2.5.7

* Support for detecting SSDP and reporting relevant fields in the JSON ouput.

## Version 2.5.6

* QUIC salt-guessing logic, to find the salt for unknown versions of that protocol.
* Support for parsing and reporting fields of NetBIOS Name Service (NBNS) packets.
* Support for parsing and reporting fields of Multicast DNS (mDNS) packets.

## Version 2.5.5

* Experimental: initial pcap-ng parsing code.
* Initial microbenchmarking code to analyze pcap throughput.
* Telemetry enhancements: performance optimizations and new fields such as the libmerc version and initialization time.
* Added changes to prioritize packet filter config over STATIC_CFG_SELECT.

## Version 2.5.4

* Experimental: initial Android support for standalone mercury and cython integration.
* New option for time-based output file rotation.
* Telemetry bugfixes to address inconsistent data across telemetry files post-rotation.

## Version 2.5.3

* Added support for reading and processing different LINKTYPEs; ETHERNET, RAW (IP), and PPP are currently supported.
* Added TLS and QUIC ALPN and user-agent reporting into libmerc.h API.
* Updated IANA values and added support for Facebook’s custom versions

## Version 2.5.2
* Improved QUIC fingerprinting.
* Added support for HTTP and QUIC process identification.
* Improved HTTP process identification by incorporating the User-Agent as additional context in the classifier.
* Separated the DTLS class from the TLS class, and moved it into its own [separate header file](src/libmerc/dtls.h).

## Version 2.5.1
* Extended the `stats` feature to report HTTP and QUIC metadata data, in addition to TLS data. Refactored the message queues to use tuples to serialise/deserialisze data features.
* IPv6 addresses are now reported in compressed format in the JSON output and `stats` output.
* Added  [libmerc_api.h](src/libmerc_api.h), a header-only C++ library that provides a clean interface into `libmerc.so`, and [libmerc_util](src/libmerc_util.cc), a test/example/driver program that dynamically loads a variant of that library.

## Version 2.5.0
* Replaced resource directory with resource archive.  A single compressed archive (or `.tar.gz`) file holds all of the resources that mercury needs in order to run its classifier.  The --resources command line option now specifies the path of the resources archive.  This change makes it easier to configure and distribute the set of resource files as an atomic set.  The archive format is a conventional Unix Standard tape archive format (as defined by POSIX in IEEE P1003.1-1988, and widely used through the GNU `tar` utility), compressed with GZIP (as defined by RFC1952, and widely used through `gzip` and `pigz`).
* Added the experimental `stats` feature, which computes and stores aggregate statistics regarding TLS fingerprints and destinations, and periodically writes those statistics out to a compressed JSON file.   The stats file output is independent from the normal session-oriented JSON output.  The number of stats entries can be limited in order to protect against memory exhaustion.  This feature is currently experimental, and is likely to evolve.  It uses these new command line options:

        --stats=f                             # write stats to file f
        --stats-time=T                        # write stats every T seconds
        --stats-limit=L                       # limit stats to L entries
* Added [SMTP](src/libmerc/smtp.h) parsing.
* Gathered together most of libmerc's global variables, to enable multiple libmerc instances to be used concurrently.   This makes it possible to update libmerc by loading a newer version of limberc.so. 
* Added the [libmerc_driver](src/libmerc_driver.cc) test program to test concurrent uses of libmerc.

## Version 2.4.0
* Added [batch_gcd](doc/batch-gcd.md), a program for efficiently finding the common factors of RSA public keys.
* Refactored TCP packet processing to use a C++17 `std::variant` for compile-time polymorphism, which enabled considerable code simplification.
* Added [mercury-json-validity-check.sh](test/mercury-json-validity-check.sh) to improve test coverage of mercury's different command line options.

## Version 2.3.6
* Organized all packet processing functions into [libmerc](src/libmerc), a separate library with makefile targets to support both shared objects and a static library.  An interface is defined in [libmerc.h](src/libmerc.h) (with [doxygen-based documentation](doc/mercury.pdf)), which provides a programmatic interface to TLS fingerprinting with destination context.
* Added the initial version of [tls_scanner](src/tls_scanner.cc), a tool for scanning HTTPS servers to obtain certificates, HTTP response headers, and redirect and src= links, and to test for domain fronting.
* Added [cert_analyze](src/cert_analyze.cc), a tool for analyzing X509/PKIX certificates.
* Added command completion for mercury, cert_analyze, and tls_scanner.

## Version 2.3.5
* Optimized the [Naive Bayes classifier for process and malware identification](doc/wnb.md).

## Version 2.3.4
* *Multiple* PCAP files can be piped in to the standard input, like `cat *.pcap | ./mercury`, which can simplify workflow and improve performance, especially when working with HDFS and NFS, by minimizing or eliminating the need to write intermediary files to disk.
* Added defensive coding (no changes in functionality).

## Version 2.3.3
* Improved QUIC processing.
* Added recognition of CONNECT, PUT, and HEAD methods for HTTP fingerprinting.
* Fixed a bug in the --analysis module caused when the fingerprint database contains a count field greater than 2^31.

## Version 2.3.2
* QUIC client fingerprints are now reported.
* PCAP files can be piped in to the standard input, like `cat dhcp.pcap | ./mercury --metadata`.  This feature makes it easier to work with some environments like HDFS.
* Added [documentation](doc/schema.md) for the JSON schema output by mercury.
* New **--nonselected-tcp-data** option writes out the TCP Data field for *non*-selected traffic, as a hex string in the JSON output.  This option provides a view into the TCP data that the --select option does not recognize. The --select filter affects the data written by this option; if you want to see the TCP Data field for all traffic, then '--select=none' on the command line.
* New **--nonselected-udp-data** option, similar to the one above, but for UDP traffic.
* There was a significant refactoring that eliminated much dead code, and flattened the packet-processing code (which is now in `pkt_proc.cc`, which is where you would probably expect to find it).
* Experimental suport for [on-demand TCP reassembly](doc/odtcpr.md).
* Improvements to DNS and DHCP processing and JSON output.
* Added documentation for the [safe parsing strategy](doc/safe-parsing.md) that mercury uses for parsing packets and certificates.

## Version 2.3.0
* New **--resources** command line option causes resource files (used in analysis) to be read from a directory other than the default.  This makes it easier to use a fingerprint prevalence database other than the system default one.
* New metadata output: SSH KEX INIT message and TCP initial sequence number (that is, the SEQ of the TCP SYN packet).
* The packet processing logic has been refactored to use a more systematic approach to packet parsing, which is documented in [doc/safe-parsing](https://github.com/cisco/mercury/blob/master/doc/safe-parsing.md).  The new code is considerably easier to read and extend; it is utilized by the JSON output path, though some functions from the old lower-level approach to packet parsing is still in place in the PCAP output path.

## Version 2.2.0
* New **--metadata** command line option causes JSON output to include a lot more metadata in its output: tls.client.version, tls.client.random, tls.client.session_id, tls.client.cipher_suites, tls.client.compression_methods, tls.client.server_name, tls.server.random, tls.server.certs, http.request.method, http.request.uri, http.request.protocol, http.request.host, and http.request.user_agent.
*  Accomodating the richer metadata required changes to the previous JSON schema.  The current schema is documented in [json-test.py](test/json-test.py).

## Version 2.1.0
* TLS certificates can optionally be output in detail as a JSON object, with the **--certs-json** command.
* Experimental: DNS responses can optionally be output in detail as a JSON object, with the **--dns-json** command.   The JSON schema used with this feature is likely to change.
* The --select (or -s) command now accepts an optional argument that specifies one or more protocols to select.  The argument --select=tls,dns causes mercury to process only TLS and DNS packets, for instance.
* Added support for VXLAN and MPLS
* Per-packet output is no longer supported

# Contents

* [Building and installing mercury](#building-and-installing-mercury)
   * [Installation](#installation)
   * [Compile-time options](#compile-time-options)
* [Running mercury](#running-mercury)
  * [Details](#details)
  * [System](#system)
  * [Examples](#examples)
* [Ethics](#ethics)
* [Credits](#credits)
* [Acknowledgements](#acknowledgments)


## Building and installing mercury

Mercury itself has minimal dependencies other than a g++ or llvm build environment, but to run the automated tests and ancillary programs in this package, you will need to install additional packages, as in the following Debian/Ubuntu example:
```
sudo apt install g++ jq git zlib1g-dev tcpreplay valgrind python3-pip libssl-dev clang
pip3 install jsonschema
```
To build mercury, in the root directory, run
```
./configure
make
```
to build the package (and check for the programs and python modules required to test it).  TPACKETv3 is present in Linux kernels newer than 3.2.

### Installation
In the root directory, edit mercury.cfg with the network interface you want to capture from, then run
```
./configure
make
sudo make install MERCURY_CFG=mercury.cfg
```
to install mercury and create and start a systemd service.  If you don't want the mercury systemd service to be installed, then instead run
```
sudo make install-nosystemd
```
The default file and directory locations are
   * __/usr/local/bin/mercury__ for the executable
   * __/usr/local/share/mercury__ for the resource files
   * __/usr/local/var/mercury__ for the output files
   * __/etc/mercury/mercury.cfg__ for the configuration file
   * __/etc/systemd/system/mercury.service__ for the systemd unit file

The output file directory is owned by the user **mercury**; this user is created by the 'make install' target, which must be run as root.  The installation prefix **/usr/local/** can be changed by running ./configure with the --prefix argument, for instance `--prefix=$HOME'.  If you want to install the program somewhere in your home directory, you probably don't want to create the user mercury; you should use the 'make install-nonroot' target, which does not create a user, does not install anything into /etc, and does not install a systemd unit.

The easiest way to run mercury in capture mode is using systemd; the OS automatically starts the mercury systemd unit after each boot, and halts it when the OS is shut down.  To check its status, run
```
systemctl status mercury
```
and the output should contain 'active (running)'.  To view the log (stderr) output from the mercury unit, run
```
sudo journalctl -u mercury
```

To uninstall mercury, run
```
sudo make uninstall
```
which will remove the mercury program, resources directory, user, group, and systemd related files.  The directory containing capture files will be retained, but its owner will be changed to root, to avoid unintentional data loss.  All captured data files are retained across successive installs and uninstalls, and must be manually deleted.

### Compile-time options
To create a debugging version of mercury, use the **make debug-mercury** target in the src/ subdirectory.  Be sure to run **make clean** first.

There are compile-time options that can tune mercury for your hardware.  Each of these options is set via a C/C++ preprocessor directive, which should be passed as an argument to "make" through the OPTFLAGS variable.   Frst run **make clean** to remove the previous build, then run **make "OPTFLAGS=<DIRECTIVE>"**.   This runs make, telling it to pass <DIRECTIVE> to the C/C++ compiler.  The available compile time options are:

   * -DDEBUG, which turns on debugging, and
   * -FBUFSIZE=16384, which sets the fwrite/fread buffer to 16,384 bytes (for instance).
If multiple compile time options are used, then they must be passed to make together in the OPTFLAGS string, e.g. "OPTFLAGS=-DDEBUG -DFBUFSIZE=16384".

## Running mercury
```
mercury: packet metadata capture and analysis
./src/mercury [INPUT] [OUTPUT] [OPTIONS]:
INPUT
   [-c or --capture] capture_interface   # capture packets from interface
   [-r or --read] read_file              # read packets from file
   no input option                       # read packets from standard input
OUTPUT
   [-f or --fingerprint] json_file_name  # write JSON fingerprints to file
   [-w or --write] pcap_file_name        # write packets to PCAP/MCAP file
   no output option                      # write JSON fingerprints to stdout
--capture OPTIONS
   [-b or --buffer] b                    # set RX_RING size to (b * PHYS_MEM)
   [-t or --threads] [num_threads | cpu] # set number of threads
   [-u or --user] u                      # set UID and GID to those of user u
   [-d or --directory] d                 # set working directory to d
GENERAL OPTIONS
   --config c                            # read configuration from file c
   [-a or --analysis]                    # analyze fingerprints
   --resources=f                         # use resource file f
   --stats=f                             # write stats to file f
   --stats-time=T                        # write stats every T seconds
   --stats-limit=L                       # limit stats to L entries
   [-s or --select] filter               # select traffic by filter (see --help)
   --nonselected-tcp-data                # tcp data for nonselected traffic
   --nonselected-udp-data                # udp data for nonselected traffic
   --tcp-reassembly                      # reassemble tcp data segments
   [-l or --limit] l                     # rotate output file after l records
   --output-time=T                       # rotate output file after T seconds
   --dns-json                            # output DNS as JSON, not base64
   --certs-json                          # output certs as JSON, not base64
   --metadata                            # output more protocol metadata in JSON
   [-v or --verbose]                     # additional information sent to stderr
   --license                             # write license information to stdout
   --version                             # write version information to stdout
   [-h or --help]                        # extended help, with examples

DETAILS
   "[-c or --capture] c" captures packets from interface c with Linux AF_PACKET
   using a separate ring buffer for each worker thread.  "[-t or --thread] t"
   sets the number of worker threads to t, if t is a positive integer; if t is
   "cpu", then the number of threads will be set to the number of available
   processors.  "[-b or --buffer] b" sets the total size of all ring buffers to
   (b * PHYS_MEM) where b is a decimal number between 0.0 and 1.0 and PHYS_MEM
   is the available memory; USE b < 0.1 EXCEPT WHEN THERE ARE GIGABYTES OF SPARE
   RAM to avoid OS failure due to memory starvation.

   "[-f or --fingerprint] f" writes a JSON record for each fingerprint observed,
   which incorporates the flow key and the time of observation, into the file f.
   With [-a or --analysis], fingerprints and destinations are analyzed and the
   results are included in the JSON output.

   "[-w or --write] w" writes packets to the file w, in PCAP format.  With the
   option [-s or --select], packets are filtered so that only ones with
   fingerprint metadata are written.

   "[r or --read] r" reads packets from the file r, in PCAP format.

   if neither -r nor -c is specified, then packets are read from standard input,
   in PCAP format.

   "[-s or --select] f" selects packets according to the metadata filter f, which
   is a comma-separated list of the following strings:
      dhcp              DHCP discover message
      dns               DNS messages
      dtls              DTLS clientHello, serverHello, and certificates
      http              HTTP request and response
      http.request      HTTP request
      http.response     HTTP response
      iec               IEC 60870-5-104
      mdns              multicast DNS
      nbns              NetBIOS Name Service
      quic              QUIC handshake
      ssh               SSH handshake and KEX
      smb               SMB v1 and v2
      stun              STUN messages
      ssdp              SSDP (UPnP)
      tcp               TCP headers
      tcp.message       TCP initial message
      tls               TLS clientHello, serverHello, and certificates
      tls.client_hello  TLS clientHello
      tls.server_hello  TLS serverHello
      tls.certificates  TLS serverCertificates
      wireguard         WG handshake initiation message
      all               all of the above
      <no option>       all of the above
      none              none of the above

   --nonselected-tcp-data writes the first TCP Data field in a flow with
   nonzero length, for *non*-selected traffic, into JSON.  This option provides
   a view into the TCP data that the --select option does not recognize. The
   --select filter affects the TCP data written by this option; use
   '--select=none' to obtain the TCP data for each flow.

   --nonselected-udp-data writes the first UDP Data field in a flow with
   nonzero length, for *non*-selected traffic, into JSON.  This option provides
   a view into the UDP data that the --select option does not recognize. The
   --select filter affects the UDP data written by this option; use
   '--select=none' to obtain the UDP data for each flow.

   --tcp-reassembly enables the tcp reassembly
   This option allows mercury to keep track of tcp segment state and 
   and reassemble these segments based on the application in tcp payload

   "[-u or --user] u" sets the UID and GID to those of user u, so that
   output file(s) are owned by this user.  If this option is not set, then
   the UID is set to SUDO_UID, so that privileges are dropped to those of
   the user that invoked sudo.  A system account with username mercury is
   created for use with a mercury daemon.

   "[-d or --directory] d" sets the working directory to d, so that all output
   files are written into that location.  When capturing at a high data rate, a
   high performance filesystem and disk should be used, and NFS partitions
   should be avoided.

   "--config c" reads configuration information from the file c.

   [-a or --analysis] performs analysis and reports results in the "analysis"
   object in the JSON records.   This option only works with the option
   [-f or --fingerprint].

   "[-l or --limit] l" rotates output files so that each file has at most
   l records or packets; filenames include a sequence number, date and time.

   --dns-json writes out DNS responses as a JSON object; otherwise,
   that data is output in base64 format, as a string with the key "base64".

   --certs-json writes out certificates as JSON objects; otherwise,
    that data is output in base64 format, as a string with the key "base64".

   --metadata writes out additional metadata into the protocol JSON objects.

   [-v or --verbose] writes additional information to the standard error,
   including the packet count, byte count, elapsed time and processing rate, as
   well as information about threads and files.

   --license and --version write their information to stdout, then halt.

   [-h or --help] writes this extended help message to stdout.

```

### SYSTEM
The directories used by the default install are as follows.  Run **mercury --help** to
see if the directories on your system differ.
```
   Resource files used in analysis: /usr/local/share/mercury
   Systemd service output:          /usr/local/var/mercury
   Systemd service configuration    /etc/mercury/mercury.cfg
```

### EXAMPLES
```
   mercury -c eth0 -w foo.pcap           # capture from eth0, write to foo.pcap
   mercury -c eth0 -w foo.pcap -t cpu    # as above, with one thread per CPU
   mercury -c eth0 -w foo.mcap -t cpu -s # as above, selecting packet metadata
   mercury -r foo.mcap -f foo.json       # read foo.mcap, write fingerprints
   mercury -r foo.mcap -f foo.json -a    # as above, with fingerprint analysis
   mercury -c eth0 -t cpu -f foo.json -a # capture and analyze fingerprints
```

## Ethics
Mercury is intended for defensive network monitoring, security research and forensics.  Researchers, administrators, penetration testers, and security operations teams can use these tools to protect networks, detect vulnerabilities, and benefit the broader community through improved awareness and defensive posture. As with any packet monitoring tool, Mercury could potentially be misused. **Do not run it on any network of which you are not the owner or the administrator**.

## Credits
Mercury and this package was developed by David McGrew, Brandon Enright, Blake Anderson, Lucas Messenger, Adam Weller, Andrew Chi, Shekhar Acharya, Anastasiia-Mariia Antonyk, Oleksandr Stepanov, Vigneshwari Viswanathan, and Apoorv Raj, with input from Brian Long, Bill Hudson, and others.  Pmercury was developed by Blake Anderson, with input from others.

## Acknowledgments

This package includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).

We make use of Mozilla's [Public Suffix List](https://publicsuffix.org/list/) which is subject to the terms of the [Mozilla Public License, v. 2.0](https://mozilla.org/MPL/2.0/).

This package directly incorporates some software made by other
developers, to make the package easier to build, deploy, and run.  We
are grateful to the copyright holders for making their excellent
software available under licensing terms that allow its
redistribution.
   * RapidJSON
      [https://github.com/cisco/mercury/src/rapidjson/license.txt](src/rapidjson/license.txt);
      this package is Copyright 2015 THL A29 Limited, a Tencent company,
      and Milo Yip.
   * lctrie [https://github.com/cisco/mercury/src/lctrie](src/lctrie);
      this package is copyright 2016-2017 Charles Stewart
      <chuckination_at_gmail_dot_com>
