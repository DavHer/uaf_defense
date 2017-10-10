.section .text
.global _start

_start:
 push {r3, lr}
 sub r3, r3, #143360
 cmp r3, #151552
 bls exit
 pop {r3}
 blx r3
 pop {pc}
exit:
 mov r7, #1
 svc     0x00000000
