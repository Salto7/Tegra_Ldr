K## POC for a Loader that:
* manually map a module (ex: chakra.dll) avoiding image load events (inspired by good old Bats3c's DarLoadLibrary)
* stomp the maped dll (function stomping) with a small shellcode that is act as a trampoline
* execute the stomped function using Pool Party locally

### Lots of improvement can be added, this is only a PoC ^_-
* implement an unload login inside the stomped module for propper cleanup with "kinda" clean stack
* use more evasive ways for virtual alloc and virtual protect (again, this is a PoC ...do that yourself)
* implement other ways to execution like other pool party variants, undocumented ntdll callbacks (ex: tpAlloc) or fibers
* pick better stompable modules that would not get flagged by EDRs

