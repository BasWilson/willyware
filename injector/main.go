//go:build windows
// +build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API constants and structures
const (
	PROCESS_ALL_ACCESS           = 0x1F0FFF
	MEM_COMMIT                   = 0x1000
	MEM_RESERVE                  = 0x2000
	PAGE_EXECUTE_READWRITE       = 0x40
	CONTEXT_FULL                 = 0x10007
	IMAGE_DIRECTORY_ENTRY_IMPORT = 1
	INFINITE                     = 0xFFFFFFFF
	DLL_PROCESS_ATTACH           = 1
)

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
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
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

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// CONTEXT structure for x64
type CONTEXT struct {
	P1Home       uint64
	P2Home       uint64
	P3Home       uint64
	P4Home       uint64
	P5Home       uint64
	P6Home       uint64
	ContextFlags uint32
	MxCsr        uint32
	SegCs        uint16
	SegDs        uint16
	SegEs        uint16
	SegFs        uint16
	SegGs        uint16
	SegSs        uint16
	EFlags       uint32
	Dr0          uint64
	Dr1          uint64
	Dr2          uint64
	Dr3          uint64
	Dr6          uint64
	Dr7          uint64
	Rax          uint64
	Rcx          uint64
	Rdx          uint64
	Rbx          uint64
	Rsp          uint64
	Rbp          uint64
	Rsi          uint64
	Rdi          uint64
	R8           uint64
	R9           uint64
	R10          uint64
	R11          uint64
	R12          uint64
	R13          uint64
	R14          uint64
	R15          uint64
	Rip          uint64
}

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")

	sleepAddr uintptr
)

func init() {
	// Get the address of Sleep from local kernel32.dll
	hKernel32, err := windows.LoadLibrary("kernel32.dll")
	if err != nil {
		fmt.Println("Failed to load kernel32:", err)
		os.Exit(1)
	}
	defer windows.FreeLibrary(hKernel32)

	sleepFunc, err := windows.GetProcAddress(hKernel32, "Sleep")
	if err != nil {
		fmt.Println("Failed to get address of Sleep:", err)
		os.Exit(1)
	}
	sleepAddr = sleepFunc
}

// Utility functions

func randomSleep() {
	ms := 50 + rand.Intn(450)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func getProcessIDByName(name string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	err = windows.Process32First(snapshot, &pe)
	for err == nil {
		pname := windows.UTF16PtrToString(&pe.ExeFile[0])
		if pname == name {
			return pe.ProcessID, nil
		}
		err = windows.Process32Next(snapshot, &pe)
	}
	return 0, fmt.Errorf("process not found")
}

func virtualAllocEx(hProcess windows.Handle, addr uintptr, size uint32, allocType uint32, protect uint32) (uintptr, error) {
	ret, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		addr,
		uintptr(size),
		uintptr(allocType),
		uintptr(protect),
	)
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func writeProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer []byte) error {
	var written uintptr
	r1, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		uintptr(unsafe.Pointer(&lpBuffer[0])),
		uintptr(len(lpBuffer)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func createSleepingThread(hProcess windows.Handle) (windows.Handle, error) {
	hThread, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0,
		0,
		sleepAddr,
		uintptr(INFINITE),
		0,
		0,
	)
	if hThread == 0 {
		return 0, fmt.Errorf("CreateRemoteThread failed: %v", err)
	}
	return windows.Handle(hThread), nil
}

// createRemoteThread is a helper to create a remote thread at a given start address (shellcode).
func createRemoteThread(hProcess windows.Handle, startAddr uintptr) (windows.Handle, error) {
	hThread, _, err := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0,
		0,
		startAddr,
		0,
		0,
		0,
	)
	if hThread == 0 {
		return 0, fmt.Errorf("CreateRemoteThread failed: %v", err)
	}
	return windows.Handle(hThread), nil
}

func main() {
	rand.Seed(time.Now().UnixNano())

	targetProc := "cs2.exe" // target process
	dllPath := "ww.dll"     // dll to inject

	// Get target process PID
	pid, err := getProcessIDByName(targetProc)
	if err != nil {
		fmt.Printf("Failed to find process: %v\n", err)
		return
	}
	fmt.Printf("[+] Found target PID: %d\n", pid)

	randomSleep()

	// Open process
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		fmt.Printf("Failed to open process: %v\n", err)
		return
	}
	defer windows.CloseHandle(hProcess)
	fmt.Println("[+] Opened target process handle")

	randomSleep()

	// Create a known-safe thread by calling Sleep(INFINITE) in the target
	// (This was used previously to hijack a thread; now we'll rely on calling DllMain directly.)
	// We'll still create it, but we won't hijack this one for calling DllMain.
	hThread, err := createSleepingThread(hProcess)
	if err != nil {
		fmt.Printf("Failed to create sleeping thread: %v\n", err)
		return
	}
	fmt.Printf("[+] Created remote sleeping thread: 0x%X\n", hThread)

	// Give the thread a moment to start and begin sleeping
	time.Sleep(500 * time.Millisecond)

	randomSleep()

	// Load DLL file in local memory
	dllData, err := os.ReadFile(dllPath)
	if err != nil {
		fmt.Printf("Failed to read DLL: %v\n", err)
		return
	}
	fmt.Println("[+] DLL read into memory")

	// Parse PE Headers
	dosHeader := IMAGE_DOS_HEADER{}
	err = binary.Read(bytes.NewReader(dllData), binary.LittleEndian, &dosHeader)
	if err != nil || dosHeader.E_magic != 0x5A4D { // 'MZ'
		fmt.Println("Invalid DOS header")
		return
	}

	ntHeaderOffset := dosHeader.E_lfanew
	ntHeaders := IMAGE_NT_HEADERS64{}
	err = binary.Read(bytes.NewReader(dllData[ntHeaderOffset:]), binary.LittleEndian, &ntHeaders)
	if err != nil {
		fmt.Println("Invalid NT header")
		return
	}
	if ntHeaders.Signature != 0x4550 { // 'PE'
		fmt.Println("Invalid NT signature")
		return
	}

	opt := ntHeaders.OptionalHeader
	imageSize := opt.SizeOfImage
	headersSize := opt.SizeOfHeaders

	// Allocate memory in remote process
	remoteBase, err := virtualAllocEx(hProcess, 0, imageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		fmt.Printf("Failed to allocate remote memory: %v\n", err)
		return
	}
	fmt.Printf("[+] Allocated remote memory at 0x%X\n", remoteBase)

	randomSleep()

	// Write PE headers
	err = writeProcessMemory(hProcess, remoteBase, dllData[:headersSize])
	if err != nil {
		fmt.Printf("Failed to write PE headers: %v\n", err)
		return
	}

	// Write sections
	sectionOffset := uint32(ntHeaderOffset) + uint32(unsafe.Sizeof(ntHeaders))
	for i := 0; i < int(ntHeaders.FileHeader.NumberOfSections); i++ {
		var sect IMAGE_SECTION_HEADER
		secReader := bytes.NewReader(dllData[sectionOffset:])
		binary.Read(secReader, binary.LittleEndian, &sect)

		if sect.SizeOfRawData > 0 {
			sectionData := dllData[sect.PointerToRawData : sect.PointerToRawData+sect.SizeOfRawData]
			err = writeProcessMemory(hProcess, remoteBase+uintptr(sect.VirtualAddress), sectionData)
			if err != nil {
				fmt.Printf("Failed to write section: %v\n", err)
				return
			}
		}
		sectionOffset += uint32(unsafe.Sizeof(sect))
	}
	fmt.Println("[+] PE sections written to remote process")

	randomSleep()

	// Omitting IAT and relocations fix for brevity

	entryPoint := remoteBase + uintptr(opt.AddressOfEntryPoint)
	fmt.Printf("[+] Entry point at 0x%X\n", entryPoint)

	randomSleep()

	// Now we will call DllMain(remoteBase, DLL_PROCESS_ATTACH, NULL) by creating shellcode:
	// x64 calling convention: RCX=hModule, RDX=ul_reason_for_call, R8=lpReserved
	// We'll write a small shellcode:
	//
	// mov rcx, remoteBase
	// mov rdx, 1
	// xor r8, r8
	// mov rax, entryPoint
	// call rax
	// ret
	//
	// We must embed remoteBase and entryPoint as immediate values. On x64, moving a 64-bit immediate into rcx requires a 10-byte instruction (Rex + opcode + modrm + imm64).
	// This is a simplistic example of shellcode (machine code bytes).

	shellcodeBuf := new(bytes.Buffer)

	// mov rcx, remoteBase (0x48 B9 imm64)
	shellcodeBuf.Write([]byte{0x48, 0xB9})
	binary.Write(shellcodeBuf, binary.LittleEndian, uint64(remoteBase))

	// mov rdx, 1 (0x48 BA 01 00 00 00 00 00 00 00)
	shellcodeBuf.Write([]byte{0x48, 0xBA})
	binary.Write(shellcodeBuf, binary.LittleEndian, uint64(1))

	// xor r8, r8 (49 31 C0)
	shellcodeBuf.Write([]byte{0x49, 0x31, 0xC0})

	// mov rax, entryPoint (48 B8 <entry>)
	shellcodeBuf.Write([]byte{0x48, 0xB8})
	binary.Write(shellcodeBuf, binary.LittleEndian, uint64(entryPoint))

	// call rax (FF D0)
	shellcodeBuf.Write([]byte{0xFF, 0xD0})

	// ret (C3)
	shellcodeBuf.Write([]byte{0xC3})

	shellcode := shellcodeBuf.Bytes()

	shellcodeAddr, err := virtualAllocEx(hProcess, 0, uint32(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		fmt.Printf("Failed to allocate memory for shellcode: %v\n", err)
		return
	}

	err = writeProcessMemory(hProcess, shellcodeAddr, shellcode)
	if err != nil {
		fmt.Printf("Failed to write shellcode: %v\n", err)
		return
	}

	// Execute shellcode with CreateRemoteThread
	hShellThread, err := createRemoteThread(hProcess, shellcodeAddr)
	if err != nil {
		fmt.Printf("Failed to create remote thread for DllMain call: %v\n", err)
		return
	}

	// Wait for the thread to finish
	windows.WaitForSingleObject(hShellThread, INFINITE)

	fmt.Println("[+] DllMain called with DLL_PROCESS_ATTACH. Injection complete.")
}
