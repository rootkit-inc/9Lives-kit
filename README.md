# 9Lives-kit (x86_64)
##### -early WIP
> This is a home project I did (It's a PoC) -for GOT poisoning (Panter), via LD_PRELOAD to inject code - which seems as most reasonable if you do not have root.

> The second part is Raptor - which packs the Panter .so into a stub which is written without standard lib, Raptor-Stub relocates the .so during runtime then passes the execution flow to (./includes/raptor/packer.h) ```ENTRY_POINT_NAME="__libc_start_main"```. (the stub is an shared object as well!)

##### To compile Panter
- (inside ./9Lives-kit/Panter) $ gcc ./src/lib.c ./src/layout_mapping.c ./src/process_elf.c -shared -fPIC -Wall -o panter.so  -D PANTER_SEPARATE
- if you want to use it with Raptor, then remove the "-D PANTER_SEPARATE"
- Run it as  LD_PRELOAD=./panter.so <eg. ps aux>

##### To compile Raptor
- (inside ./9Lives-kit/Raptor) $ gcc ../Panter/src/process_elf.c ./packer.c ./packer_helper.c  -o packer
- Run as ./packer <path to ./panter.so>
- If all went right, you will see ./9Lives-kit/Raptor/output/stub.so
- To Run the final .so - LD_PRELOAD=./output/stub.so <eg. ps aux>

#### This is just a PoC
