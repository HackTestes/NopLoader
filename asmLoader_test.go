package main
import (
    "fmt"
    "testing"
	"reflect"
)

func Test_AsmRestoreRegisterFromJmp(t *testing.T) {
	if !reflect.DeepEqual([]byte{0x58}, AsmRestoreRegisterFromJmp()) {
		t.Error();
	}
}

func Test_AsmJmpToAbsoluteAddress(t *testing.T) {

	expect := []byte{0x50, 0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
	result := AsmJmpToAbsoluteAddress(1);

	if !reflect.DeepEqual(expect, result) {
		fmt.Print(expect, result);
		t.Error();
	}
}

// Not the best practice!
func Test_AsmJmpToAbsoluteAddress_02(t *testing.T) {

	expect := []byte{0x50, 0x48, 0xB8, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
	result := AsmJmpToAbsoluteAddress(1000);

	if !reflect.DeepEqual(expect, result) {
		fmt.Print(expect, result);
		t.Error();
	}
}


func Test_AsmBuildRedirectionCode(t *testing.T) {

	expect := []byte{0x50, 0x48, 0xB8, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0x58, 0x90}; // 1 nop padding
	result := AsmBuildRedirectionCode( AsmJmpToAbsoluteAddress(1000), AsmRestoreRegisterFromJmp(), 1 );

	if !reflect.DeepEqual(expect, result) {
		fmt.Print(expect, result);
		t.Error();
	}
}

func Test_AsmBuildNewCode(t *testing.T) {

	// Lets try to recreate the same redirection code
	expect := []byte{0x50, 0x48, 0xB8, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0x58, 0x90}; // 1 nop padding
	result := AsmBuildNewCode( "0x5048B8E803000000000000FFE05890" );

	if !reflect.DeepEqual(expect, result) {
		fmt.Print(expect, result);
		t.Error();
	}
}

func MakeFakeProcessMem(size_bytes uint64) {
	// Fake int3(0xCC) buffer
}

func Test_AsmRestoreOverwrittenCode(t *testing.T) {

	// Fake int3(0xCC) buffer
	fake_process_mem := AsmBuildBufferOfInstructions(100, 0xCC);
	fake_redirection_jmp_size := 10;
	fake_injection_index := 0; // Relative to the buffer

	// Lets try to recreate the same redirection code
	expect := fake_process_mem[0:10];
	result := AsmRestoreOverwrittenCode(fake_redirection_jmp_size, fake_process_mem, fake_injection_index);

	if !reflect.DeepEqual(expect, result) {
		fmt.Print(expect, result);
		t.Error();
	}
}

func Test_AsmBuildFullInjectedCode_Restore(t *testing.T) {

	// Fake int3(0xCC) buffer
	fake_process_mem := AsmBuildBufferOfInstructions(100, 0xCC);

	var fake_injection_address uintptr = 0; // Just pretend this is the absolute address 0
	full_redirection_jmp_size := len( AsmBuildRedirectionCode( AsmJmpToAbsoluteAddress(fake_injection_address), AsmRestoreRegisterFromJmp(), 0 ) );
	jmp_size := len( AsmJmpToAbsoluteAddress(0) );
	jmp_back := AsmJmpToAbsoluteAddress(fake_injection_address + uintptr(jmp_size));


	fake_injection_index := 0; // Relative to the buffer
	overwritten_code := AsmRestoreOverwrittenCode(full_redirection_jmp_size, fake_process_mem, fake_injection_index);
	new_code := AsmBuildNewCode( "0x48C7C00100000048FFC0" );
	restore_original := true;

	// Lets try to recreate the same redirection code
	expect := []byte{ 0x58, 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x48, 0xFF, 0xC0};
	expect = append(expect, AsmBuildBufferOfInstructions(full_redirection_jmp_size, 0xCC)[:]...);
	expect = append(expect, jmp_back[:]...);
	result := AsmBuildFullInjectedCode(fake_injection_address, jmp_size, restore_original, new_code, overwritten_code);

	if !reflect.DeepEqual(expect, result) {
		fmt.Print(expect, result);
		t.Error();
	}
}