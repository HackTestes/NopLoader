package main

import (
    "encoding/json"
    "fmt"
    "regexp"
    "os"
    "reflect"
    "strconv"
    "strings"
    "bufio"
    hex "encoding/hex"
    windows "golang.org/x/sys/windows"
)

/*type Container struct {
    mutex sync.Mutex
    value_array []int
}*/

type ProcessWriteInfo struct {
    injection_indexes []int // This is NOT the absolute addresses
    range_start int
    range_size int
    allocated_process_mem uintptr
}

type Pair[T any, U any] struct {
    first  T
    second U
}

func NewPair[T, U any](first T, second U) *Pair[T, U]{

    pair := new(Pair[T, U]);
    pair.first = first;
    pair.second = second;

    return pair;
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func main() {

    kernel32DLL := windows.NewLazySystemDLL("kernel32.dll");

    VirtualAllocEx := kernel32DLL.NewProc("VirtualAllocEx");
    VirtualFreeEx := kernel32DLL.NewProc("VirtualFreeEx");

    // Read and parse arguments
    if len(os.Args) < 3 {
        fmt.Fprintln(os.Stderr, "Not enough arguments");
        return;
    }

    no_write_mode := false;
    if len(os.Args) == 4 && (os.Args[3] == "-n" || os.Args[3] == "--noWrite") {
        no_write_mode = true;
    }

    // Read configuration file
    jsonBytes, err := os.ReadFile(os.Args[2]);
    check(err);

    res := regexp.MustCompile("//(.*)\n").ReplaceAllString(string(jsonBytes), "\n");
    //fmt.Println(res);

    var json_config map[string]interface{};
    check(json.Unmarshal([]byte(res), &json_config));
    //fmt.Printf("json map: %v\n", json_config)

    // Attach to process
    process_id, err := strconv.ParseUint(os.Args[1], 10, 32);
    check(err);

    var process_handle, err_process = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE, false, uint32(process_id));
    check(err_process);

    fmt.Println("Process atached!");

    // Enumerate modules
    module_buffer := [2048]windows.Handle{};
    var bytes_needed uint32 = 0;

    check(windows.EnumProcessModulesEx(process_handle, &module_buffer[0], uint32(reflect.TypeOf(module_buffer).Size()), &bytes_needed, windows.LIST_MODULES_ALL));

    var target_module_start uintptr = 0;
    var target_module_size uint32 = 0;

    // Get module name (must match module_name)
    for i := range module_buffer {
        
        if module_buffer[i] != 0 {

            name_buffer := [2048]uint16{0};
            windows. GetModuleFileNameEx(process_handle, module_buffer[i], &name_buffer[0], uint32(reflect.TypeOf(name_buffer).Size()));

            module_name := windows.UTF16PtrToString(&name_buffer[0]);
            index := strings.LastIndex(module_name, "\\") + 1;


            if json_config["module_name"] == module_name[index:] {
                module_info := [1]windows.ModuleInfo{};

                check( windows.GetModuleInformation(process_handle, module_buffer[i], &module_info[0], uint32(reflect.TypeOf(module_info).Size())) );

                target_module_start = module_info[0].BaseOfDll;
                target_module_size = module_info[0].SizeOfImage;
            }
        }
        continue;
    }

    // Copy module memory into a buffer
    process_mem_copy := make([]byte, target_module_size, target_module_size);
    var number_of_bytes_read uintptr = 0;
    check(windows.ReadProcessMemory(process_handle, target_module_start, &process_mem_copy[0], uintptr(target_module_size), &number_of_bytes_read));


    restore_buffer := make([]ProcessWriteInfo, 0);

    fmt.Println(json_config["intructions"].([]interface{})[0].(map[string]interface{})["matches_allowed"] );

    // Search for the instructions (all the other fileds after module_name)
    for _, instruction_info := range json_config["intructions"].([]interface{}) {

        results := make([]int, 0, 1024);
        hex_instruc, err := hex.DecodeString(instruction_info.(map[string]interface{})["instruction"].(string)[2:]);
        check(err);

        //fmt.Println(instruc_index, instruction, hex_instruc);
        for process_mem_index := range process_mem_copy {

            match := true;

            for instruction_byte_index := range hex_instruc {

                if len(process_mem_copy) == (process_mem_index + instruction_byte_index )|| hex_instruc[instruction_byte_index] != process_mem_copy[process_mem_index + instruction_byte_index]{
                    match = false;
                    break;
                }
            }

            if match == true {
                results = append(results, process_mem_index)
            }
        }

        if len(results) == 0 {panic(0);}

        //fmt.Println(results);

        instruc_matches_allowed := int(instruction_info.(map[string]interface{})["matches_allowed"].(float64));
        replace_range, ok := instruction_info.(map[string]interface{})["range"].(string);
        range_start := 0;
        range_size := len(hex_instruc);
        if ok {
            range_start, _ = strconv.Atoi(strings.Split(replace_range, ":")[0]);
            range_size, _ = strconv.Atoi(strings.Split(replace_range, ":")[1]);
            if range_size > len(hex_instruc) {range_size = len(hex_instruc);}
        }

        replace_code, ok := instruction_info.(map[string]interface{})["replace"].(bool);
        restore_original := false;
        new_code := "";
        nop_padding := 0;
        if ok {
            restore_original = instruction_info.(map[string]interface{})["restore_original"].(bool);
            new_code = instruction_info.(map[string]interface{})["new_code"].(string);
            nop_padding = int(instruction_info.(map[string]interface{})["nop_padding"].(float64));
        } else {
            replace_code = false;
        }


        if len(results) > instruc_matches_allowed {

            fmt.Println("Too many matches: ", len(results));
            for _, result := range results {
                fmt.Printf( "%X ", uintptr(result)+target_module_start );
            }
            fmt.Println("");

        } else {

            // Replace the instruction for Nop (0x90)
            if replace_code == false {
                byte_buffer := AsmBuildNop(range_size);

                for i := range results {
                    base_address := target_module_start + uintptr(results[i]) + uintptr(range_start);
                    var number_of_bytes_written uintptr = 0;

                    fmt.Println("WriteProcessMemory: ", process_handle, base_address, byte_buffer, uintptr(range_size), number_of_bytes_written);
                    if no_write_mode == false {check(windows.WriteProcessMemory(process_handle, base_address, &byte_buffer[0], uintptr(range_size), &number_of_bytes_written));}
                }
                restore_buffer = append(restore_buffer, ProcessWriteInfo{injection_indexes: results, range_start: range_start, range_size: range_size, allocated_process_mem: 0});

            // Inject new code
            } else {

                allocated_mem_address, _, err:= VirtualAllocEx.Call(uintptr(process_handle), 0, 1024, windows.MEM_COMMIT, windows.PAGE_EXECUTE_READ);
                fmt.Println("Allocation: ", err, allocated_mem_address);
                full_redirection_code := AsmBuildRedirectionCode( AsmJmpToAbsoluteAddress(allocated_mem_address), AsmRestoreRegisterFromJmp(), nop_padding );
                new_codes_byte := AsmBuildNewCode(new_code);
                jmp_code_size := len(AsmJmpToAbsoluteAddress(0));

                // Only 1 result will be considered
                injection_index := uintptr(results[0]) + uintptr(range_start);
                injection_address := target_module_start + injection_index;
                overwritten_code := AsmRestoreOverwrittenCode(len(full_redirection_code), process_mem_copy, int(injection_index));
                var number_of_bytes_written uintptr = 0;

                full_injected_code := AsmBuildFullInjectedCode(injection_address, jmp_code_size, restore_original, new_codes_byte, overwritten_code);

                // Write redirection code
                fmt.Println("WriteProcessMemory(redirect): ", process_handle, injection_address, full_redirection_code, uintptr(len(full_redirection_code)), number_of_bytes_written);
                if no_write_mode == false {check(windows.WriteProcessMemory(process_handle, injection_address, &full_redirection_code[0], uintptr(len(full_redirection_code)), &number_of_bytes_written));}

                // Write injected code
                fmt.Println("WriteProcessMemory(inject): ", process_handle, allocated_mem_address, full_injected_code, uintptr(len(full_injected_code)), number_of_bytes_written);
                if no_write_mode == false {check(windows.WriteProcessMemory(process_handle, allocated_mem_address, &full_injected_code[0], uintptr(len(full_injected_code)), &number_of_bytes_written));}

                restore_buffer = append(restore_buffer, ProcessWriteInfo{injection_indexes: results[0:1], range_start: range_start, range_size: len(full_redirection_code), allocated_process_mem: allocated_mem_address});
            }
        }
    }


    // Restore original instructions (wait user to press ENTER)
    fmt.Print("\nPress 'ENTER' to restore process' original instructions...")
    bufio.NewReader(os.Stdin).ReadBytes('\n')

    for instruc_index := range restore_buffer {
        injection_range_start := restore_buffer[instruc_index].range_start;
        injection_range_size := restore_buffer[instruc_index].range_size;
        new_injected_code_mem := restore_buffer[instruc_index].allocated_process_mem;
        module_relative_addresses := restore_buffer[instruc_index].injection_indexes;

        for i := range module_relative_addresses {
            injection_start := module_relative_addresses[i]+injection_range_start;
            original_instruction := process_mem_copy[ injection_start:injection_start+injection_range_size ];
            base_address := target_module_start + uintptr(module_relative_addresses[i]) + uintptr(restore_buffer[instruc_index].range_start);
            var number_of_bytes_written uintptr = 0;

            fmt.Println("WriteProcessMemory: ", process_handle, base_address, original_instruction, uintptr(len(original_instruction)), number_of_bytes_written);
            if no_write_mode == false {check(windows.WriteProcessMemory(process_handle, base_address, &original_instruction[0], uintptr(len(original_instruction)), &number_of_bytes_written));}
        }

        if new_injected_code_mem != 0 {
            VirtualFreeEx.Call(uintptr(process_handle), new_injected_code_mem, 0, windows.MEM_RELEASE);
            fmt.Println(err);
            fmt.Println("Redirect deallocated");
        }
    }

    // Exit
    check(windows.CloseHandle(process_handle));
}