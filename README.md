# Huakiwi
Huwkiwi is an EDR powered by eBPF and Sigma. 

# Name

Huakiwi is named after [Leioproctus huakiwi](https://en.wikipedia.org/wiki/Leioproctus_huakiwi), a species of bee Endemic to New Zealand. 

<p align="center">
  <img width="460" height="300" src="static/bee-transparent.png">
</p>

credit: [hasherezade](https://github.com/hasherezade/drawings)

# Requirements
- kernel 4.4+ [go-ebf requirement](https://github.com/cilium/ebpf#requirements)
- LLVM/Clang


# Build
Simply run `make` after cloning the repo. it should generate a portable statically-linked binary. 

```sh
git clone https://github.com/bm9w/huakiwi
cd huakiwi
make
```


# Rules

current rules (almost all of them are borrowed from Elastic's public repo on SIEM rules)

 - Potential Protocol Tunneling via EarthWorm
 - Compression of Sensitive Files 
 - Potential OpenSSH Backdoor Logging Activity
 - Attempt to Disable IPTables or Firewall
 - Attempt to Disable Logging
 - Base16 or Base32 Encoding/Decoding Activity
 - Tampering of Bash Command-Line History
 - Potential Disabling of SELinux
 - File Deletion via Shred
 - Removing a kernel module
 - System Log File Deletion
 - Interactive Terminal Spawned via Perl
 - Interactive Terminal Spawned via Python
 - Modification of Dynamic Linker Preload Shared Object
 - Use of raw networking tools
 - Use of iodine DNS tunnel
 - Modification of Dynamic Linker Preload Shared Object

Contributions welcome! 
