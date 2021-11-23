# ebpf-edr
A proof-of-concept eBPF-based EDR for Linux

Seems to be working fine with the 20 basic rules implemented. Logs the alerts to stdout at the moment. 

# Build
Simple run `make` after cloning the repo. it should generate a portable statically-linked binary. Needs kernel 4.4+ to run


# Rules

current rules (almost all of them are borrowed from Elastic's public repo on SIEM rules)

 - Potential Protocol Tunneling via EarthWorm
 - Compression of Sensitive Files 
 - Potential OpenSSH Backdoor Logging Activity
 - Attempt to Disable IPTables or Firewall
 - Attempt to Disable Syslog Service
 - Tampering of Bash Command-Line History
 - Potential Disabling of SELinux
 - File Deletion via Shred
 - Removing a kernel module
 - System Log File Deletion
 - Interactive Terminal Spawned via Perl
 - Interactive Terminal Spawned via Python
 - Modification of Dynamic Linker Preload Shared Object

and some more.

