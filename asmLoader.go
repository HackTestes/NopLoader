package main

import(
	binary "encoding/binary"
	hex "encoding/hex"
)

// This code should give the impression that you can simply add new asm code
// All hex code should be pre assembled (using MASM for example)
// Only rax register will be used
// Use the template for reference

func AsmBuildBufferOfInstructions(number_of_single_byte_instruc int, instruction byte) []byte {

	byte_buffer := make([]byte, number_of_single_byte_instruc, number_of_single_byte_instruc);
	for i := range byte_buffer {
		byte_buffer[i] = instruction;
	}

	return byte_buffer;
}

func AsmBuildNop(number_of_nops int) []byte {

	byte_buffer := make([]byte, number_of_nops, number_of_nops);
	for i := range byte_buffer {
		byte_buffer[i] = 0x90;
	}

	return byte_buffer;
}

func AsmRestoreRegisterFromJmp() []byte {
	return []byte{0x58};
}

func AsmJmpToAbsoluteAddress(address uintptr) []byte {

	address_bytes := make([]byte, 8);
	binary.LittleEndian.PutUint64(address_bytes, uint64(address));

	save_rax_stack := []byte{0x50};
	mov_address_to_rax := append([]byte{0x48, 0xB8}, address_bytes[:]...);
	jmp_to_address := []byte{0xFF, 0xE0};

	jmp_to_address_code := append(save_rax_stack, mov_address_to_rax[:]...);
	jmp_to_address_code = append(jmp_to_address_code, jmp_to_address[:]...);

	return jmp_to_address_code;
}

func AsmBuildRedirectionCode(jmp_code []byte, restore_register_code []byte, number_of_nop_padding int) []byte {

	redirection_code := []byte{};
	nop_padding := AsmBuildNop(number_of_nop_padding);

	redirection_code = append(redirection_code, jmp_code[:]...);
	redirection_code = append(redirection_code, restore_register_code[:]...);
	redirection_code = append(redirection_code, nop_padding[:]...);

	return redirection_code;
}



func AsmBuildNewCode(hex_code string) []byte {
	asm, err := hex.DecodeString(hex_code[2:]); // [2:] Removes the 0x
	check(err);
	return asm;
}

// Injection_index is relative to the process_memory buffer
func AsmRestoreOverwrittenCode(full_redirection_code_length int, process_memory []byte, injection_index int) []byte {
	return process_memory[injection_index:full_redirection_code_length];
}

// jmp redirection code ONLY (not the full redirection code), otherwise the rax register will never be restored after jmp back
func AsmBuildFullInjectedCode(injection_address uintptr, jmp_code_size int, restore_original bool, new_asm_code []byte, overwritten_code []byte) []byte {

	injected_code :=  []byte{};
	jmp_back := AsmJmpToAbsoluteAddress(injection_address + uintptr(jmp_code_size));

	if restore_original {
		injected_code = append( injected_code, AsmRestoreRegisterFromJmp()[:]... );
		injected_code = append( injected_code, new_asm_code[:]... );
		injected_code = append( injected_code, overwritten_code[:]... );
		injected_code = append( injected_code, jmp_back[:]... );

		return injected_code;

	} else {
		injected_code = append( injected_code, AsmRestoreRegisterFromJmp()[:]... );
		injected_code = append( injected_code, new_asm_code[:]... );
		injected_code = append( injected_code, jmp_back[:]... );

		return injected_code;
	}
}