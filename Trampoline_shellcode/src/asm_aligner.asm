[BITS 64]
DEFAULT REL 
extern Entry

section .text$A
    _Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  Entry
        mov   rsp, rsi
        pop   rsi
        ret
    ret
