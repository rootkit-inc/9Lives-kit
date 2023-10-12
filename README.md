# 9Lives-kit
- early WIP
This is a home project I did (It's a PoC) -for GOT poisoning (Panter), via LD_PRELOAD to inject code - which seems as most reasonable if you do not have root.
The second part is Raptor - which packs the Panter .so into a stub which is written without standard lib, Raptor-Stub relocates the .so during runtime then calls to (./includes/raptor/packer.h) ENTRY_POINT_NAME. (the stub is an .so as well!)
