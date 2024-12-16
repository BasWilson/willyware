package main

import (
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"io/ioutil"
	"net/http"
	"syscall"
	"time"
	"unsafe"

	"github.com/fogleman/gg"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

// Screen dimensions (adjust to your resolution)
const (
	screenWidth  = 1920
	screenHeight = 1080
	entityMax    = 64
)

// Offset structure for dynamic fetching
type Offsets struct {
	ClientDLL map[string]uint32 `json:"client.dll"`
}

// Global variable for offsets
var offsets Offsets

// Fetch offsets from the given URL
func fetchOffsets(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch offsets: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch offsets: status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	err = json.Unmarshal(body, &offsets)
	if err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	fmt.Println("Offsets successfully loaded!")
	return nil
}

// Memory reading helper functions
func ReadMemory(handle windows.Handle, address uintptr, buffer unsafe.Pointer, size uint32) error {
	var bytesRead uintptr
	return windows.ReadProcessMemory(handle, address, (*byte)(buffer), uintptr(size), &bytesRead)
}

func ReadUint64(handle windows.Handle, address uintptr) (uint64, error) {
	var value uint64
	err := ReadMemory(handle, address, unsafe.Pointer(&value), uint32(unsafe.Sizeof(value)))
	return value, err
}

func ReadInt32(handle windows.Handle, address uintptr) (int32, error) {
	var value int32
	err := ReadMemory(handle, address, unsafe.Pointer(&value), uint32(unsafe.Sizeof(value)))
	return value, err
}

func WriteBool(handle windows.Handle, address uintptr, value bool) error {
	var val byte
	if value {
		val = 1
	}
	return windows.WriteProcessMemory(handle, address, (*byte)(unsafe.Pointer(&val)), 1, nil)
}

// Simulate a mouse click
func simulateMouseClick() {
	input := []win.MOUSE_INPUT{
		{
			Type: win.INPUT_MOUSE,
			Mi:   win.MOUSEINPUT{DwFlags: win.MOUSEEVENTF_LEFTDOWN},
		},
		{
			Type: win.INPUT_MOUSE,
			Mi:   win.MOUSEINPUT{DwFlags: win.MOUSEEVENTF_LEFTUP},
		},
	}
	win.SendInput(uint32(len(input)), unsafe.Pointer(&input[0]), int32(unsafe.Sizeof(input[0])))
}

// Create a transparent overlay window
func createOverlayWindow() win.HWND {
	className := windows.StringToUTF16Ptr("OverlayClass")
	windowName := windows.StringToUTF16Ptr("OverlayWindow")

	// Register the window class
	var wc win.WNDCLASSEX
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpszClassName = className
	wc.HInstance = win.GetModuleHandle(nil)
	wc.Style = win.CS_HREDRAW | win.CS_VREDRAW
	wc.LpfnWndProc = syscall.NewCallback(win.DefWindowProc)
	win.RegisterClassEx(&wc)

	// Create the window
	hwnd := win.CreateWindowEx(
		win.WS_EX_LAYERED|win.WS_EX_TRANSPARENT|win.WS_EX_TOPMOST,
		className,
		windowName,
		win.WS_POPUP,
		0, 0, screenWidth, screenHeight,
		0, 0, wc.HInstance, nil,
	)

	// Make the window transparent
	const LWA_ALPHA = 0x00000002
	user32 := windows.NewLazySystemDLL("user32.dll")
	setLayeredWindowAttributes := user32.NewProc("SetLayeredWindowAttributes")
	setLayeredWindowAttributes.Call(
		uintptr(hwnd),
		0,
		255,
		LWA_ALPHA,
	)
	win.ShowWindow(hwnd, win.SW_SHOWNORMAL)

	return hwnd
}

// Fetch entity data for overlay
func fetchEntityData(handle windows.Handle, clientBase uintptr) []struct {
	ID     int32
	Health int32
} {
	entities := []struct {
		ID     int32
		Health int32
	}{}

	for i := 0; i < entityMax; i++ {
		entityAddress := clientBase + uintptr(offsets.ClientDLL["dwEntityList"]) + uintptr(i*0x10)
		entity, err := ReadUint64(handle, entityAddress)
		if err != nil || entity == 0 {
			continue
		}

		health, err := ReadInt32(handle, uintptr(entity)+uintptr(offsets.ClientDLL["m_iHealth"]))
		if err != nil || health <= 0 {
			continue
		}

		id, err := ReadInt32(handle, uintptr(entity)+uintptr(offsets.ClientDLL["dwGameRules"]))
		if err != nil {
			continue
		}

		entities = append(entities, struct {
			ID     int32
			Health int32
		}{ID: id, Health: health})
	}

	return entities
}

// Render entity data on the overlay
func renderOverlay(hwnd win.HWND, entityData []struct {
	ID     int32
	Health int32
}) {
	// Create an offscreen image for rendering
	dc := gg.NewContext(screenWidth, screenHeight)
	dc.SetRGBA(0, 0, 0, 0) // Transparent background
	dc.Clear()

	// Render each entity's ID and health in a list
	dc.SetColor(color.White)
	yOffset := 50
	for _, entity := range entityData {
		if entity.Health > 0 {
			color := getColor(entity.Health)
			text := fmt.Sprintf("ID: %d, Health: %d", entity.ID, entity.Health)
			dc.SetColor(color)
			dc.DrawStringAnchored(text, 20, float64(yOffset), 0, 0.5)
			yOffset += 20
		}
	}

	// Cast the image to *image.NRGBA
	img := dc.Image().(*image.NRGBA)

	// Create a bitmap from the NRGBA image
	hBitmap := win.CreateBitmap(screenWidth, screenHeight, 1, 32, unsafe.Pointer(&img.Pix[0]))

	// Get the window device context
	hdc := win.GetDC(hwnd)
	defer win.ReleaseDC(hwnd, hdc)

	// Blit the image onto the overlay window
	memDC := win.CreateCompatibleDC(hdc)
	defer win.DeleteDC(memDC)

	oldBitmap := win.SelectObject(memDC, win.HGDIOBJ(hBitmap))
	defer win.SelectObject(memDC, oldBitmap)

	win.BitBlt(hdc, 0, 0, screenWidth, screenHeight, memDC, 0, 0, win.SRCCOPY)
	win.DeleteObject(win.HGDIOBJ(hBitmap))
}

func getColor(health int32) color.RGBA {
	if health < 50 {
		return color.RGBA{255, 0, 0, 255}
	} else if health < 75 {
		return color.RGBA{255, 255, 0, 255}
	}
	return color.RGBA{0, 255, 0, 255}
}

// TriggerBot functionality
func TriggerBot(handle windows.Handle, clientBase uintptr) {
	for {
		localPlayerAddress := clientBase + uintptr(offsets.ClientDLL["dwLocalPlayerPawn"])
		localPlayer, err := ReadUint64(handle, localPlayerAddress)
		if err != nil || localPlayer == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		crosshairID, err := ReadInt32(handle, uintptr(localPlayer)+uintptr(offsets.ClientDLL["dwViewAngles"]))
		if err != nil || crosshairID <= 0 || crosshairID > entityMax {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		entityAddress := clientBase + uintptr(offsets.ClientDLL["dwEntityList"]) + uintptr(crosshairID*0x10)
		entity, err := ReadUint64(handle, entityAddress)
		if err != nil || entity == 0 {
			continue
		}

		health, err := ReadInt32(handle, uintptr(entity)+uintptr(offsets.ClientDLL["m_iHealth"]))
		if err != nil || health <= 0 {
			continue
		}

		simulateMouseClick()
		time.Sleep(100 * time.Millisecond)
	}
}

func main() {
	offsetURL := "https://raw.githubusercontent.com/sezzyaep/CS2-OFFSETS/main/offsets.json"
	if err := fetchOffsets(offsetURL); err != nil {
		fmt.Printf("Error fetching offsets: %s\n", err)
		return
	}

	processName := "cs2.exe"
	processID, err := getProcessIdByName(processName)
	if err != nil {
		fmt.Printf("Failed to find process: %s\n", err)
		return
	}

	processHandle, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, processID)
	if err != nil {
		fmt.Printf("Failed to open process: %s\n", processName)
		return
	}
	defer windows.CloseHandle(processHandle)

	clientBase, err := getModuleBaseAddress(processHandle, "client.dll")
	if err != nil {
		fmt.Printf("Failed to get client.dll base address\n")
		return
	}

	hwnd := createOverlayWindow()

	go func() {
		for {
			entityData := fetchEntityData(processHandle, clientBase)
			renderOverlay(hwnd, entityData)
			time.Sleep(16 * time.Millisecond)
		}
	}()

	go TriggerBot(processHandle, clientBase)

	select {}
}

func getModuleBaseAddress(processHandle windows.Handle, moduleName string) (uintptr, error) {
	// Take a snapshot of all modules in the process
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(processHandle))
	if err != nil {
		return 0, fmt.Errorf("failed to create snapshot: %w", err)
	}
	defer windows.CloseHandle(hSnapshot)

	var moduleEntry windows.ModuleEntry32
	moduleEntry.Size = uint32(unsafe.Sizeof(moduleEntry))

	// Iterate through the modules to find the specified one
	if err := windows.Module32First(hSnapshot, &moduleEntry); err != nil {
		return 0, fmt.Errorf("failed to get first module: %w", err)
	}

	for {
		// Convert the module name to a Go string
		moduleNameFromEntry := windows.UTF16ToString(moduleEntry.Module[:])

		// Check if this is the module we're looking for
		if moduleNameFromEntry == moduleName {
			return uintptr(unsafe.Pointer(moduleEntry.ModBaseAddr)), nil
		}

		// Proceed to the next module
		if err := windows.Module32Next(hSnapshot, &moduleEntry); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("module %s not found", moduleName)
}

func getProcessIdByName(processName string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err := windows.Process32First(snapshot, &pe); err != nil {
		return 0, err
	}

	for {
		if windows.UTF16ToString(pe.ExeFile[:]) == processName {
			return pe.ProcessID, nil
		}
		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				return 0, fmt.Errorf("process not found: %s", processName)
			}
			return 0, err
		}
	}
}