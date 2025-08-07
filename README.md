## Tegra_Ldr, a  POC for a Loader that:
* manually map a benign module (ex: chakra.dll) avoiding image load events (inspired by good old Bats3c's DarLoadLibrary). the .txt should be large enough for the trampoline shellcode
* stomp the maped dll (function stomping) with a small shellcode that is act as a trampoline (it can be places anywhere, better to pick a symbol closer to the .txt beginning to have enough space)
* execute the stomped function using Pool Party locally (code taken from: Paranoid Ninuja Bof:https://github.com/paranoidninja/BRC4-BOF-Artillery/tree/main/ThreadPoolInjection)

#### Lots of improvement can be added, this is only a PoC ^_-
* implement an unload login inside the stomped module for propper cleanup with "kinda" clean stack
* use more evasive ways for virtual alloc and virtual protect (again, this is a PoC ...do that yourself)
* implement other ways to execution like other pool party variants, undocumented ntdll callbacks (ex: tpAlloc) or fibers
* pick better stompable modules that would not get flagged by EDRs
* add some decoy API calls between the manual mapping steps ...as an attempt to break the anomoly detection :D

