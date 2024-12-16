package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	THREAD_GET_CONTEXT     = 0x0008
	THREAD_SET_CONTEXT     = 0x0010
	THREAD_SUSPEND_RESUME  = 0x0002
	THREAD_ALL_ACCESS      = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME
)

// IMAGE_DOS_HEADER represents the DOS header of a PE file
type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res1     [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32 // Offset to the PE header
}

// IMAGE_NT_HEADERS represents the NT headers of a PE file
type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

// IMAGE_FILE_HEADER represents the file header of a PE file
type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// IMAGE_OPTIONAL_HEADER represents the optional header of a PE file
type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

// IMAGE_DATA_DIRECTORY represents a data directory entry in a PE file
type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

// CONTEXT represents the thread context
type CONTEXT struct {
	P1Home, P2Home, P3Home, P4Home, P5Home, P6Home uint64
	ContextFlags                                   uint32
	MxCsr, SegCs, SegDs, SegEs, SegFs, SegGs, SegSs uint16
	EFlags                                         uint32
	Dr0, Dr1, Dr2, Dr3, Dr6, Dr7                  uint64
	Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi        uint64
	R8, R9, R10, R11, R12, R13, R14, R15          uint64
	Rip                                           uint64
}

var ntAllocateVirtualMemory = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtAllocateVirtualMemory")

func allocateMemory(handle windows.Handle, size uintptr) (uintptr, error) {
    var baseAddress uintptr
    status, _, _ := ntAllocateVirtualMemory.Call(
        uintptr(handle),
        uintptr(unsafe.Pointer(&baseAddress)),
        0,
        uintptr(unsafe.Pointer(&size)),
        MEM_COMMIT|MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if status != 0 {
        return 0, fmt.Errorf("failed to allocate memory: status 0x%x", status)
    }
    return baseAddress, nil
}

var ntWriteVirtualMemory = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtWriteVirtualMemory")

func writeMemory(handle windows.Handle, address uintptr, data []byte) error {
    var written uintptr
    status, _, _ := ntWriteVirtualMemory.Call(
        uintptr(handle),
        address,
        uintptr(unsafe.Pointer(&data[0])),
        uintptr(len(data)),
        uintptr(unsafe.Pointer(&written)),
    )
    if status != 0 {
        return fmt.Errorf("failed to write memory: status 0x%x", status)
    }
    return nil
}

var kernel32QueueUserAPC = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueueUserAPC")

func queueApc(thread windows.Handle, functionAddress uintptr, parameter uintptr) error {
	_, _, err := kernel32QueueUserAPC.Call(
		functionAddress,
		uintptr(thread),
		parameter,
	)
	if err != syscall.Errno(0) {
		return fmt.Errorf("failed to queue APC: %w", err)
	}
	return nil
}

var ntProtectVirtualMemory = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtProtectVirtualMemory")

func changeMemoryProtection(handle windows.Handle, address uintptr, size uintptr, newProtect uint32) error {
	var oldProtect uint32
	status, _, _ := ntProtectVirtualMemory.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&address)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if status != 0 {
		return fmt.Errorf("failed to change memory protection: status 0x%x", status)
	}
	return nil
}

func randomDelay(minMs, maxMs int) {
	delta := maxMs - minMs
	if delta <= 0 {
		time.Sleep(time.Duration(minMs) * time.Millisecond)
		return
	}
	time.Sleep(time.Duration(minMs+rand.Intn(delta)) * time.Millisecond)
}

func xorEncryptDecrypt(input, key string) string {
	output := make([]byte, len(input))
	keyLen := len(key)

	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[i%keyLen]
	}

	return string(output)
}

func encryptString(input, key string) string {
	return xorEncryptDecrypt(input, key)
}

func decryptString(encrypted string, key string) string {
	return xorEncryptDecrypt(encrypted, key)
}

// Compile-time encrypted strings
var encryptedProcessName = encryptString("cs2.exe", "secret_key")
var encryptedDllPath = encryptString("C:\\path\\to\\your.dll", "secret_key")

// Manually maps a DLL into a target process
func manualMap(processHandle windows.Handle, threadHandle windows.Handle, dllPath string) error {
	// Step 1: Read the DLL into memory
	dllData, err := os.ReadFile(dllPath)
	if err != nil {
		return fmt.Errorf("failed to read DLL: %w", err)
	}

	// Step 2: Parse the DLL headers
	dosHeader := IMAGE_DOS_HEADER{}
	if err := binary.Read(bytes.NewReader(dllData[:unsafe.Sizeof(dosHeader)]), binary.LittleEndian, &dosHeader); err != nil {
		return fmt.Errorf("failed to parse DOS header: %w", err)
	}
	if dosHeader.E_magic != 0x5A4D { // 'MZ'
		return fmt.Errorf("invalid DOS header magic")
	}

	ntHeaders := IMAGE_NT_HEADERS{}
	ntHeadersOffset := int(dosHeader.E_lfanew)
	if err := binary.Read(bytes.NewReader(dllData[ntHeadersOffset:]), binary.LittleEndian, &ntHeaders); err != nil {
		return fmt.Errorf("failed to parse NT headers: %w", err)
	}
	if ntHeaders.Signature != 0x4550 { // 'PE\0\0'
		return fmt.Errorf("invalid NT headers signature")
	}

	// Step 3: Allocate memory in the target process
	remoteBaseAddr, err := allocateMemory(processHandle, uintptr(ntHeaders.OptionalHeader.SizeOfImage))
	if err != nil {
		return fmt.Errorf("failed to allocate memory in target process: %w", err)
	}

	// Step 4: Copy the headers
	err = writeMemory(processHandle, remoteBaseAddr, dllData[:ntHeaders.OptionalHeader.SizeOfHeaders])
	if err != nil {
		return fmt.Errorf("failed to write headers to target process: %w", err)
	}

	// Step 4.1: Change memory protection to PAGE_EXECUTE_READ
	err = changeMemoryProtection(processHandle, remoteBaseAddr, uintptr(ntHeaders.OptionalHeader.SizeOfImage), windows.PAGE_EXECUTE_READ)
	if err != nil {
		return fmt.Errorf("failed to change memory protection: %w", err)
	}

	// Step 5: Calculate the entry point
	entryPoint := uintptr(ntHeaders.OptionalHeader.AddressOfEntryPoint) + remoteBaseAddr

	// Step 6: Queue the APC for the DLL's entry point
	if err := queueApc(threadHandle, entryPoint, 0); err != nil {
		return fmt.Errorf("failed to queue APC: %w", err)
	}

	// Step 7: Resume the thread to execute the APC
	if _, err := windows.ResumeThread(threadHandle); err != nil {
		return fmt.Errorf("failed to resume thread: %w", err)
	}

	// Step 8: Wait for execution and clean up
	time.Sleep(500 * time.Millisecond)

	// Overwrite the entry point memory with placeholder data (optional cleanup step)
	placeholder := make([]byte, ntHeaders.OptionalHeader.SizeOfHeaders)
	if err := writeMemory(processHandle, remoteBaseAddr, placeholder); err != nil {
		fmt.Printf("Failed to clean up memory: %s\n", err)
	}

	fmt.Println("DLL successfully mapped and APC cleaned!")
	return nil
}

func getProcessHandleByDuplicate(processID uint32) (windows.Handle, error) {
	currentProcessHandle := windows.CurrentProcess()

	var targetProcessHandle windows.Handle
	err := windows.DuplicateHandle(
		currentProcessHandle,
		currentProcessHandle,
		currentProcessHandle,
		&targetProcessHandle,
		0,                // Desired access (set to 0 to inherit permissions)
		false,            // Inherit handle
		windows.DUPLICATE_SAME_ACCESS, // Same access as current process
	)
	if err != nil {
		return 0, fmt.Errorf("failed to duplicate handle for process ID %d: %w", processID, err)
	}

	return targetProcessHandle, nil
}

// Helper function to get process ID by name
func getProcessIdByName(processName string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to create snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err := windows.Process32First(snapshot, &pe); err != nil {
		return 0, fmt.Errorf("failed to get first process: %w", err)
	}

	for {
		if windows.UTF16ToString(pe.ExeFile[:]) == processName {
			return pe.ProcessID, nil
		}
		if err := windows.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process not found: %s", processName)
}

func selectThread(processID uint32) (windows.Handle, error) {
	// Enumerate threads in the target process
	threadSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to create thread snapshot: %w", err)
	}
	defer windows.CloseHandle(threadSnapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	if err := windows.Thread32First(threadSnapshot, &te); err != nil {
		return 0, fmt.Errorf("failed to get first thread: %w", err)
	}

	for {
		// Check if the thread belongs to the target process
		if te.OwnerProcessID == processID {
			// Open the thread handle
			threadHandle, err := windows.OpenThread(THREAD_ALL_ACCESS, false, te.ThreadID)
			if err == nil {
				fmt.Printf("Selected thread ID: %d\n", te.ThreadID)
				return threadHandle, nil
			}
		}
		if err := windows.Thread32Next(threadSnapshot, &te); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("no suitable threads found")
}

func main() {
	// Step 1: Encrypt sensitive strings
	encryptionKey := "secret_key"
	encryptedProcessName := xorEncryptDecrypt("cs2.exe", encryptionKey)
	encryptedDllPath := xorEncryptDecrypt("C:\\path\\to\\your.dll", encryptionKey)

	// Step 2: Decrypt sensitive strings at runtime
	processName := xorEncryptDecrypt(encryptedProcessName, encryptionKey)
	dllPath := xorEncryptDecrypt(encryptedDllPath, encryptionKey)

	fmt.Printf("Decrypted Process Name: %s\n", processName)
	fmt.Printf("Decrypted DLL Path: %s\n", dllPath)

	// Step 3: Get the process ID
	processID, err := getProcessIdByName(processName)
	if err != nil {
		fmt.Printf("Failed to find process: %s\n", err)
		return
	}
	fmt.Printf("Found process ID: %d\n", processID)

	// Step 4: Open the target process
	// Obtain the target process handle using DuplicateHandle
	processHandle, err := getProcessHandleByDuplicate(processID)
	if err != nil {
		fmt.Printf("Failed to duplicate process handle: %s\n", err)
		return
	}
	defer windows.CloseHandle(processHandle)
	fmt.Println("Obtained target process handle via duplication.")

	// Step 5: Select a thread in the target process
	threadHandle, err := selectThread(processID)
	if err != nil {
		fmt.Printf("Failed to select thread: %s\n", err)
		return
	}
	defer windows.CloseHandle(threadHandle)
	fmt.Println("Selected target thread.")

	// Step 6: Manually map the DLL into the target process
	if err := manualMap(processHandle, threadHandle, dllPath); err != nil {
		fmt.Printf("DLL mapping failed: %s\n", err)
		return
	}

	fmt.Println("DLL injection completed successfully!")
}