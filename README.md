# A toy x86-64 virtualizing obfuscator

I plan on writing a blog or something about this soon going into more detail. Mostly used to familiarize myself with Rust and determine it's compatibility within this space (it's very good).

This super simple virtualizing obfuscator operates on "shellcode". You feed it fully assembled x86-64 instructions and it will disassemble them, translate them to a simple stack machine instruction set, and JIT assemble a vmenter and vmexit routine. You can then call the vmenter routine to run the virtualized shellcode.

Currently this project only supports virtualization of a very few select x86-64 instructions (namely the ones specifically required by the shellcode I chose to target), but adding support for more is easy. This could easily be used as the starting point for a more fully featured virtualizing obfuscation system.

The shellcode I chose was for the default godbolt function compiled by MSVC and GCC:

```cpp
// Type your code here, or load an example.
int square(int num) {
    return num * num;
}
```

MSVC:

```asm
mov     DWORD PTR [rsp+8], ecx
mov     eax, DWORD PTR num$[rsp]
imul    eax, DWORD PTR num$[rsp]
ret     0
```

GCC:


```asm
push    rbp
mov     rbp, rsp
mov     DWORD PTR [rbp-4], edi
mov     eax, DWORD PTR [rbp-4]
imul    eax, eax
pop     rbp
ret
```
