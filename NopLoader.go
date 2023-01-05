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

    // Read and parse arguments
    //fmt.Println(len(os.Args), os.Args);

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


    restore_buffer := make([]Pair[[]byte, []int], 0);

    fmt.Println(json_config["intructions"].([]interface{})[0].(map[string]interface{})["matches_allowed"] );

    // Search for the instructions (all the other fileds after module_name)
    for _, instruction_info := range json_config["intructions"].([]interface{}) {

        results := make([]int, 0, 1024);
        hex_instruc, err := hex.DecodeString(instruction_info.(map[string]interface{})["instruction"].(string)[2:]);
        instruc_matches_allowed := int(instruction_info.(map[string]interface{})["matches_allowed"].(float64));
        check(err);

        //fmt.Println(instruc_index, instruction, hex_instruc);
        for process_mem_index := range process_mem_copy {

            match := true;

            for instruction_byte_index := range hex_instruc {

                if hex_instruc[instruction_byte_index] != process_mem_copy[process_mem_index + instruction_byte_index]{
                    match = false;
                    break;
                }
            }

            if match == true {
                results = append(results, process_mem_index)
            }
        }

        //fmt.Println(results);

        // Replace the instruction for Nop (0x90)
        if len(results) > instruc_matches_allowed {
            fmt.Println("Too many matches: ", len(results));
            /*for _, result := range results {
                fmt.Printf( "%X ", uintptr(result)+target_module_start );
            }*/
        } else {
    
            byte_buffer := make([]byte, len(hex_instruc), len(hex_instruc))
            for i := range byte_buffer {
                byte_buffer[i] = 0x90;
            }

            for i := range results{
                base_address := target_module_start + uintptr(results[i]);
                var number_of_bytes_written uintptr = 0;

                fmt.Println("WriteProcessMemory: ", process_handle, base_address, byte_buffer, uintptr(len(hex_instruc)), number_of_bytes_written);
                check(windows.WriteProcessMemory(process_handle, base_address, &byte_buffer[0], uintptr(len(hex_instruc)), &number_of_bytes_written));
            }

            restore_buffer = append(restore_buffer, Pair[[]byte, []int]{first: hex_instruc, second: results});
        }
    }


    // Restore original instructions (wait user to press ENTER)
    fmt.Print("\nPress 'Enter' to restore process' original instructions...")
    bufio.NewReader(os.Stdin).ReadBytes('\n')

    for instruc_index := range restore_buffer {
        original_instruction := restore_buffer[instruc_index].first;
        module_relative_addresses := restore_buffer[instruc_index].second;

        for i := range module_relative_addresses {
            base_address := target_module_start + uintptr(module_relative_addresses[i]);
            var number_of_bytes_written uintptr = 0;

            fmt.Println("WriteProcessMemory: ", process_handle, base_address, original_instruction, uintptr(len(original_instruction)), number_of_bytes_written);
            check(windows.WriteProcessMemory(process_handle, base_address, &original_instruction[0], uintptr(len(original_instruction)), &number_of_bytes_written));
        }
    }

    // Exit
    check(windows.CloseHandle(process_handle));
}