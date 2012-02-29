tracedump(8) -- a single application IP sniffer
===============================================

## SYNOPSIS

`tracedump` [<OPTIONS>...] <PID...>

`tracedump` [<OPTIONS>...] -- <COMMAND...>

## DESCRIPTION

`tracedump` is a single application IP packet sniffer, which captures all TCP and UDP packets of a
single Linux process. It consists of the following elements:

1. `ptrace monitor` - tracks bind(), connect() and sendto() syscalls and extracts local port numbers
   that the traced application uses
1. `pcap sniffer` - using information from the previous module, it listens on an AF\_PACKET socket,
   with an appropriate BPF filter attached
1. `garbage collector` - periodically reads /proc/net/{tcp,udp} files in order to detect the sockets
   that the application no longer uses

As the output, `tracedump` generates a PCAP file with SLL-encapsulated IP packets - readable by eg.
Wireshark. It can be later used for a detailed analysis of the networking operations made by a
particular application. For instance, it might be useful for IP traffic classification systems.

For more information on `tracedump`, see the paper referenced in [CITING TRACEDUMP][].

## OPTIONS

`tracedump` accepts options presented below:

  *  `-w`=<file>:
  output file name; by default "./dump.pcap"

  *  `-s`=<snaplen>:
  capture <snaplen> bytes of packet data; by default 0, which means all bytes

  * `--debug`=<num>:
  set debugging level

  * `--verbose`,`-V`:
  be verbose; alias for `--debug=5`

  * `--help`,`-h`:
  display short help screen and exit

  * `--version`,`-v`:
  display version and copying information

For program arguments, `tracedump` accepts either a list of process identifiers (PID numbers
separated with spaces), or a command to execute with execvp(3).

## LIMITATIONS

 * IP packets past the first fragment will not be captured
 * some applications (e.g. chromium-browser) cant be started from tracedump, but attaching to
   existing process by PID works

## BUGS

 * currently works on x86-32 Linux hosts only
 * maximum number of monitored ports is limited to less than 300 ports, due to limits on the
   BPF filter attached to the sniffing socket
 * there is a low probability of loosing TCP packets if the time distance between a particular
   bind() system call and a connect() or listen() call is greater than 10 seconds

## SEE ALSO

tcpdump(8), pcap(3pcap), [MuTriCs project](http://mutrics.iitis.pl/)

## AUTHOR AND COPYRIGHT

Author: Pawel Foremski <pjf@iitis.pl>, IITiS PAN

Copyright (C) 2011-2012 IITiS PAN <http://www.iitis.pl/> Gliwice, Poland

Licensed under the GNU General Public License version 3. Realized under grant nr 2011/01/N/ST6/07202
of the Polish National Science Centre.

## CITING TRACEDUMP

Please cite `tracedump` using the following publication:

>     Foremski P., "Tracedump: A Novel Single Application IP Packet Sniffer",
>     Theoretical and Applied Informatics, Vol. 24 No. 1/2012, Gliwice 2012


