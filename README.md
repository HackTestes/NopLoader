# Nop Loader

## What is it?

- Command line tool for searching and editing other processes' code using [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) and [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) APIs. Therefore, this utility will look for the right module and replace it with No Operation opcodes (0x90).

## Requirements

- WindowsOS >= 10
- Command line tool (Window terminal)

## Build

- Golang compiler (go1.19.4 windows/amd64)

## Important APIs and resources used

- [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)

- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

- [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)

- [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)

- [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)

- [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)*

- [EnumProcessModulesEx](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodulesex)

- [Module Information](https://learn.microsoft.com/en-us/windows/win32/psapi/module-information)

- [Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)

- [Windows API galang package](https://pkg.go.dev/golang.org/x/sys/windows)

## Usage

```
NopLoader <PROCESS_ID> <JSON_FILE>
```

## Implementation overview

Nothing for the moment

### File format

It's a normal json file, but with comments (you're welcome)! One key benefit of comments is that you can disable features by simpling commenting that line.

```json
{
    "module_name": "executable.exe",

    // A comment!
    "instructions": 
    [
        "0x9090", // Instructions can have different lengths
        "0x909090" // Decrement instruction (NAMING)
        //"0x90" Do not replace me!
    ]
}

```

## Key features

### Read process memory
- Makes heavy use of goroutines to speed up the search (not for now)

### Write process memory
- Replace matched instructions with Nop opcodes (0x90) by reading a json-like file
- Restore program's original instructions before exit

Note: the 0x90 opcode only works for desktop, ARM CPUs use another set of instructions

## Roadmap

* Fully working now!
    * [ ] Add options
