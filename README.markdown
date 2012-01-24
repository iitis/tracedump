ABOUT
=====

tracedump - a single program sniffer

This program captures all TCP and UDP packets of a single program. It consists of three elements:

 1. ptrace monitor - tracks bind(), connect() and sendto() syscalls and extracts local port numbers
    that the traced application uses
 2. pcap sniffer - using information from 1. it listens on an AF_PACKET/SOCK_DGRAM socket, with an
    appropriate BPF filter attached
 3. garbage collector - instead of monitoring for close() syscalls, this thread reads
    /proc/net/{udp,tcp} files in order to detect the sockets that the application no longer uses

As the output, it generates a PCAP file with SLL-encapsulated IP packets - readable by eg.
Wireshark. It can be later used for detailed analysis of the networking operations made by a
particular application. For instance it might be useful for automatic systems of IP traffic
classification.

ISSUES
======

 * no Ctrl+C handling - on SIGINT some packets will be lost
 * the garbage collector is not yet implemented
 * the command line options facility is not yet implemented
 * packets past the first IP fragment will not be captured
 * sometimes the traced process segfaults
   * maybe more work on better ptrace transparency is required - especially on code injection?
 * cant start chromium-browser within tracedump, but attaching works (to appropriate pid)
