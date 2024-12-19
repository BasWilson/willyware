package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows APIs
var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procOpenProcess        = kernel32.NewProc("OpenProcess")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procLoadLibraryA       = kernel32.NewProc("LoadLibraryA")
)

// Constants
const (
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_READ           = 0x0010
	MEM_COMMIT                = 0x1000
	MEM_RESERVE               = 0x2000
	PAGE_READWRITE            = 0x04
)

func injectDLL(processID uint32, dllPath string) error {
	// Open the target process
	processHandle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ),
		0,
		uintptr(processID),
	)
	if processHandle == 0 {
		return fmt.Errorf("failed to open process: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(processHandle))

	// Allocate memory in the target process for the DLL path
	remoteMemory, _, err := procVirtualAllocEx.Call(
		processHandle,
		0,
		uintptr(len(dllPath)+1),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if remoteMemory == 0 {
		return fmt.Errorf("failed to allocate memory: %w", err)
	}

	// Write the DLL path to the allocated memory
	dllPathBytes := append([]byte(dllPath), 0) // Null-terminated string
	ret, _, err := procWriteProcessMemory.Call(
		processHandle,
		remoteMemory,
		uintptr(unsafe.Pointer(&dllPathBytes[0])),
		uintptr(len(dllPathBytes)),
		0,
	)
	if ret == 0 {
		return fmt.Errorf("failed to write memory: %w", err)
	}

	// Get the address of LoadLibraryA
	loadLibraryAddr := procLoadLibraryA.Addr()
	if loadLibraryAddr == 0 {
		return fmt.Errorf("failed to get LoadLibraryA address")
	}

	// Create a remote thread to call LoadLibraryA with the DLL path
	threadHandle, _, err := procCreateRemoteThread.Call(
		processHandle,
		0,
		0,
		loadLibraryAddr,
		remoteMemory,
		0,
		0,
	)
	if threadHandle == 0 {
		return fmt.Errorf("failed to create remote thread: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(threadHandle))

	fmt.Println("DLL successfully injected!")
	return nil
}

func main() {
	processName := "cs2.exe" // Replace with your target process
	dllPath := "./ww.dll"    // Replace with the path to your DLL

	// Get the process ID
	processID, err := getProcessIdByName(processName)
	if err != nil {
		fmt.Printf("Failed to find process: %s\n", err)
		return
	}

	// Inject the DLL
	if err := injectDLL(processID, dllPath); err != nil {
		fmt.Printf("DLL injection failed: %s\n", err)
		return
	}

	fmt.Println("DLL injection completed successfully!")
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
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return 0, fmt.Errorf("failed to get next process: %w", err)
		}
	}

	return 0, fmt.Errorf("process not found: %s", processName)
}
