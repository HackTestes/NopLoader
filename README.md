# Nop Loader

## What is it?

- Command line tool for searching and editing other processes' code using [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) and [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) APIs. In other words, this utility will look for the right code in the right module and replace it with No Operation opcodes (0x90) or redirect the execution flow and inject previously assembled shellcode.

## Requirements

- WindowsOS >= 10
- Command line tool (Window terminal)

## Build

- Golang compiler (go1.19.4 windows/amd64)
- [Windows API golang package](https://pkg.go.dev/golang.org/x/sys/windows)

Command

```powershell
go run . <PROCESS_ID> <JSON> [OPTIONS]
```

## Important APIs and resources used

- [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)

- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

- [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)

- [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)

- [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)

- [VirtualFreeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex)

- [EnumProcessModulesEx](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodulesex)

- [Module Information](https://learn.microsoft.com/en-us/windows/win32/psapi/module-information)

- [Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)

- [Windows API golang package](https://pkg.go.dev/golang.org/x/sys/windows)

## Usage

You need to pass 2 basic parameters: process ID and a JSON-like file containing informations about instructions and actions that should be performed.


```powershell
NopLoader <PROCESS_ID> <JSON> [OPTIONS]
```
### OPTIONS
- -n : simulate write (good for testing before making changes)

---

## Implementation overview

The implementation is actually very simple:

1. It gets all the modules in a given process
1. Gets all the modules name (and base address) to compare it to the one given in the JSON file
1. Getting the module, it copies the module memory into its own memory for searches
1. Search for each instruction in the module copy and get its relative address
1. Perform a write to the absolute address in the target (module base + relative address) OR allocate executable mem and redirect to new code
1. Wait for user input to restore the original instructions AND deallocate new code segment if needed

### File format

It's a normal JSON file, but with comments (you're welcome)! One key benefit of comments is that you can disable features by simpling commenting that line.

- Fields explanation

    - *module_name*: name of the module that conatins the instructions (usually a .exe)
    - *instructions*[...]: array of instructions that should be replaced
        - *instruction*: the instruction that should be replaced in hex (0x...)
        - *matches_allowed*: the number of times a instruction sequence should be replaced (use 0 for testing)
        - *range*: allows to replace a part of the searched instructions, insted of changing all of it. The syntax use: "**index**:**size_bytes**", considering that 0 is the first index. Example: change the first 2 bytes -> "0:2"
        - *replace*: tells wether the code should be replaced by a new sequence, requiring redirecting the execution flow
        - *restore_original*: restore overwritten code in the new code segment (new code + overwritten code)
        - *new_code*: new code that will be injected in hex (should be pre-assembled in MASM for example)
        - *nop_padding*: number of nop to be added after redirection to align the instructions

[JSON example](https://github.com/HackTestes/NopLoader/blob/master/parameters.json)
```json
{
    "module_name": "Notepad.exe",

    // [instruction in hex, number of matches allowed]
    "intructions":
    [
        // A comment!
        {"instruction": "0x90", "matches_allowed": 1},

        {"instruction": "0x909090", "matches_allowed": 2}, //Instructions can have different lengths

        {"instruction": "0x909090", "matches_allowed": 2, "range": "0:1"},

        {"instruction": "0x909090", "matches_allowed": 1, "replace": true, "restore_original": true, "new_code": "0x909090909090", "nop_padding": 0},

        {"instruction": "0x9090", "matches_allowed": 16} // Nop sequence in the code
        //{"instruction": "0x9090", "matches_allowed": 16} do_not_replace me"

    ]
}

```

### Redirection code

Consult the [AsmInjectionTemplate](https://github.com/HackTestes/NopLoader/blob/master/AsmInjectionTemplate.asm) for the full code. All of this is hardcoded in the golang asmLoader file (Why? Because I am not implementing an assembler, or restoring information from a disassember).

You might be asking yourself "why this jmp"? 1. because it is very felxible, it can jump to any address in the 64bit range; 2. It is very simple to manipulate in the golang code, allowing me to change the JMP address dinamically (aka after I call *VirtualAllocEx*). The only downside is that it is very big and uses the stack to preserve the register's original value.

```asm
    ;INJECTION POINT
    push rax                    ;SAVING REGISTER VALUE
    mov rax, 0FF000000000000FFh ;ADDRESS - fixed size
    jmp rax
    pop rax                     ;RESTORE RAX AFTER JMP BACK

    ;REDIRECTED CODE
    pop rax                      ;RESTORE REGISTER AFTER JMP
    nop                          ;NEW CODE
    nop                          ;RESTORE PARTS OF ORIGINAL IF NEEDED
    push rax                     ;SAVING REGISTER VALUE
    mov rax, 0FF000000000000FFh  ;ADDRESS = INJECTION ADDRESS + 13 BYTES
    jmp rax                      ;JMP BACK
```

Note: the redirection code takes 14 bytes in total and was assembled with [MASM](https://learn.microsoft.com/pt-br/cpp/assembler/masm/masm-for-x64-ml64-exe?view=msvc-170) for 64bits

### Finding code

Now, how do we find code? You can use the [MemoryScanner](https://github.com/HackTestes/MemoryScanner) (another one of my projects) to find the address of a value and after getting it, you can setup a hadware breakpoint with your favorite debugger ([ba on Windbg](https://github.com/HackTestes/MemoryScanner)). This procedure will give you the instructions that read or write to a given address.

After all of this, you get the bytes related to the instructions you want to replace and put them in the JSON file (you can put more bytes to make it unique and use the range field).

If you want to to redirect the code, you have to pay attention to the size of the redirection code and add the necessay nop padding for the correct execution. And since you put the **correct** number of padding (at least I hope so), I can restore automatically the overwritten code!

---

## Key features

### Read process memory
- Makes heavy use of goroutines to speed up the search* (not for now)

### Write process memory
- Replace matched instructions with Nop opcodes (0x90) by reading a json-like file
- Redirect the execution flow and inject new code
- Restore code overwritten by redirection code
- Restore program's original instructions before exit

Note: the 0x90 opcode only works for desktop, ARM CPUs use another set of instructions

## Roadmap

* [ ] Add help option
* [ ] Use goroutines to improve performance
