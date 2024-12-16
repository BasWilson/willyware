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

const (
	screenWidth  = 1920
	screenHeight = 1080
)

// Core structures
type Memory struct {
	handle     windows.Handle
	clientBase uintptr
}

type Entity struct {
	ID     int32
	Health int32
	Team   int32
}

type Offsets struct {
	ClientDLL map[string]uint32 `json:"client.dll"`
}

var offsets Offsets

// Memory operations
func (m *Memory) Read(address uintptr, buffer unsafe.Pointer, size uint32) error {
	var bytesRead uintptr
	return windows.ReadProcessMemory(m.handle, address, (*byte)(buffer), uintptr(size), &bytesRead)
}

func (m *Memory) ReadInt32(address uintptr) (int32, error) {
	var value int32
	err := m.Read(address, unsafe.Pointer(&value), uint32(unsafe.Sizeof(value)))
	return value, err
}

func (m *Memory) ReadUint64(address uintptr) (uint64, error) {
	var value uint64
	err := m.Read(address, unsafe.Pointer(&value), uint32(unsafe.Sizeof(value)))
	return value, err
}

func (m *Memory) WriteBool(address uintptr, value bool) error {
	var val byte
	if value {
		val = 1
	}
	return windows.WriteProcessMemory(m.handle, address, (*byte)(unsafe.Pointer(&val)), 1, nil)
}

// Entity operations
func (m *Memory) GetLocalPlayer() (uint64, int32, error) {
	localPlayerAddr := m.clientBase + uintptr(offsets.ClientDLL["dwLocalPlayerPawn"])
	localPlayer, err := m.ReadUint64(localPlayerAddr)
	if err != nil {
		return 0, 0, err
	}

	team, err := m.ReadInt32(uintptr(localPlayer) + 0x3E3) // m_iTeamNum
	return localPlayer, team, err
}

func (m *Memory) GetEntities(localTeam int32) []Entity {
	entities := []Entity{}
	entityList := m.clientBase + uintptr(offsets.ClientDLL["dwEntityList"])
	entity, err := m.ReadUint64(entityList)
	if err != nil {
		return entities
	}

	for i := 0; i < 64; i++ {
		// Get list entity
		listEntityAddr := entity + uint64((8*(i&0x7FFF)>>9)+16)
		listEntity, err := m.ReadUint64(uintptr(listEntityAddr))
		if err != nil || listEntity == 0 {
			continue
		}

		// Get entity controller
		entityControllerAddr := listEntity + uint64(120*(i&0x1FF))
		entityController, err := m.ReadUint64(uintptr(entityControllerAddr))
		if err != nil || entityController == 0 {
			continue
		}

		// Get controller pawn
		entityControllerPawn, err := m.ReadUint64(uintptr(entityController) + 0x80C) // m_hPlayerPawn
		if err != nil || entityControllerPawn == 0 {
			continue
		}

		// Get list entity for pawn
		listEntityPawnAddr := entity + uint64(0x8*((entityControllerPawn&0x7FFF)>>9)+16)
		listEntityPawn, err := m.ReadUint64(uintptr(listEntityPawnAddr))
		if err != nil || listEntityPawn == 0 {
			continue
		}

		// Get entity pawn
		entityPawnAddr := listEntityPawn + uint64(120*(entityControllerPawn&0x1FF))
		entityPawn, err := m.ReadUint64(uintptr(entityPawnAddr))
		if err != nil || entityPawn == 0 {
			continue
		}

		health, team, err := m.getEntityInfo(entityPawn)
		if err != nil || health <= 0 || health > 100 || team == localTeam {
			continue
		}

		entities = append(entities, Entity{
			ID:     int32(i),
			Health: health,
			Team:   team,
		})
	}

	return entities
}

func (m *Memory) getEntityInfo(entityPawn uint64) (health int32, team int32, err error) {
	health, err = m.ReadInt32(uintptr(entityPawn) + 0x344) // m_iHealth
	if err != nil {
		return
	}
	team, err = m.ReadInt32(uintptr(entityPawn) + 0x3E3) // m_iTeamNum
	return
}

// Overlay operations
type Overlay struct {
	hwnd win.HWND
}

func NewOverlay() *Overlay {
	hwnd := createOverlayWindow()
	return &Overlay{hwnd: hwnd}
}

func (o *Overlay) Render(entities []Entity) {
	dc := gg.NewContext(screenWidth, screenHeight)
	dc.SetRGBA(0, 0, 0, 0)
	dc.Clear()

	// Draw background box
	padding := 10.0
	lineHeight := 20.0
	boxWidth := 200.0
	boxHeight := float64(len(entities))*lineHeight + 2*padding

	dc.SetRGBA(0, 0, 0, 0.5)
	dc.DrawRectangle(340, 440, boxWidth, boxHeight)
	dc.Fill()

	// Draw entity info
	yPos := 450.0
	for _, entity := range entities {
		color := getHealthColor(entity.Health)
		dc.SetColor(color)
		dc.DrawStringAnchored(
			fmt.Sprintf("ID: %d, Health: %d", entity.ID, entity.Health),
			350, yPos, 0, 0.5,
		)
		yPos += lineHeight
	}

	img := dc.Image().(*image.RGBA)
	updateWindowBitmap(o.hwnd, img)
}

func getHealthColor(health int32) color.RGBA {
	if health < 50 {
		return color.RGBA{255, 0, 0, 255}
	}
	if health < 75 {
		return color.RGBA{255, 255, 0, 255}
	}
	return color.RGBA{0, 255, 0, 255}
}

// Window creation and management
func createOverlayWindow() win.HWND {
	className := windows.StringToUTF16Ptr("OverlayClass")
	windowName := windows.StringToUTF16Ptr("OverlayWindow")

	wc := win.WNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(win.WNDCLASSEX{})),
		LpszClassName: className,
		HInstance:     win.GetModuleHandle(nil),
		Style:         win.CS_HREDRAW | win.CS_VREDRAW,
		LpfnWndProc:   syscall.NewCallback(wndProc),
	}
	win.RegisterClassEx(&wc)

	hwnd := win.CreateWindowEx(
		win.WS_EX_LAYERED|win.WS_EX_TRANSPARENT|win.WS_EX_TOPMOST,
		className,
		windowName,
		win.WS_POPUP,
		0, 0, screenWidth, screenHeight,
		0, 0, wc.HInstance, nil,
	)

	// Make window transparent
	user32 := windows.NewLazySystemDLL("user32.dll")
	setLayeredWindowAttributes := user32.NewProc("SetLayeredWindowAttributes")
	setLayeredWindowAttributes.Call(
		uintptr(hwnd),
		0,
		255,
		2, // LWA_ALPHA
	)

	// Extend frame into client area
	margins := struct{ Left, Right, Top, Bottom int32 }{-1, -1, -1, -1}
	dwmapi := windows.NewLazySystemDLL("dwmapi.dll")
	dwmExtendFrameIntoClientArea := dwmapi.NewProc("DwmExtendFrameIntoClientArea")
	dwmExtendFrameIntoClientArea.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&margins)))

	win.ShowWindow(hwnd, win.SW_SHOW)
	return hwnd
}

func wndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_DESTROY:
		win.PostQuitMessage(0)
		return 0
	}
	return win.DefWindowProc(hwnd, msg, wParam, lParam)
}

func updateWindowBitmap(hwnd win.HWND, img *image.RGBA) {
	hdc := win.GetDC(hwnd)
	if hdc == 0 {
		return
	}
	defer win.ReleaseDC(hwnd, hdc)

	memDC := win.CreateCompatibleDC(hdc)
	if memDC == 0 {
		return
	}
	defer win.DeleteDC(memDC)

	hBitmap := win.CreateBitmap(screenWidth, screenHeight, 1, 32, unsafe.Pointer(&img.Pix[0]))
	if hBitmap == 0 {
		return
	}
	defer win.DeleteObject(win.HGDIOBJ(hBitmap))

	oldBitmap := win.SelectObject(memDC, win.HGDIOBJ(hBitmap))
	win.BitBlt(hdc, 0, 0, screenWidth, screenHeight, memDC, 0, 0, win.SRCCOPY)
	win.SelectObject(memDC, oldBitmap)
}

// TriggerBot
func (m *Memory) RunTriggerBot() {
	for {
		if win.GetKeyState(win.VK_XBUTTON2)&-32768 == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		localPlayer, localTeam, err := m.GetLocalPlayer()
		if err != nil || localPlayer == 0 {
			continue
		}

		crosshairTarget, err := m.ReadInt32(uintptr(localPlayer) + 0x1458) // m_iIDEntIndex
		if err != nil || crosshairTarget <= 0 {
			continue
		}

		if m.isValidTarget(crosshairTarget, localTeam) {
			simulateMouseClick()
			time.Sleep(100 * time.Millisecond)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func (m *Memory) isValidTarget(targetID int32, localTeam int32) bool {
	entityList := m.clientBase + uintptr(offsets.ClientDLL["dwEntityList"])
	entity, err := m.ReadUint64(entityList)
	if err != nil {
		return false
	}

	// Get entity info using targetID
	listEntityAddr := entity + uint64(8*(targetID>>9)+16)
	listEntity, err := m.ReadUint64(uintptr(listEntityAddr))
	if err != nil {
		return false
	}

	entityAddr := listEntity + uint64(120*(targetID&0x1FF))
	targetEntity, err := m.ReadUint64(uintptr(entityAddr))
	if err != nil {
		return false
	}

	health, team, err := m.getEntityInfo(targetEntity)
	if err != nil || health <= 0 || health > 100 || team == localTeam {
		return false
	}

	return true
}

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

// Process and module handling
func initializeMemory() (*Memory, error) {
	processID, err := getProcessIdByName("cs2.exe")
	if err != nil {
		return nil, err
	}

	handle, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, processID)
	if err != nil {
		return nil, err
	}

	clientBase, err := getModuleBaseAddress(handle, "client.dll")
	if err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}

	return &Memory{
		handle:     handle,
		clientBase: clientBase,
	}, nil
}

// Add your existing helper functions (getProcessIdByName, getModuleBaseAddress, fetchOffsets)
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

func getModuleBaseAddress(processHandle windows.Handle, moduleName string) (uintptr, error) {
	processID, err := windows.GetProcessId(processHandle)
	if err != nil {
		return 0, err
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, processID)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))

	if err := windows.Module32First(snapshot, &me); err != nil {
		return 0, err
	}

	for {
		if windows.UTF16ToString(me.Module[:]) == moduleName {
			return uintptr(me.ModBaseAddr), nil
		}
		err = windows.Module32Next(snapshot, &me)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("module not found: %s", moduleName)
}

func fetchOffsets(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, &offsets)
}

func main() {
	if err := fetchOffsets("https://raw.githubusercontent.com/sezzyaep/CS2-OFFSETS/main/offsets.json"); err != nil {
		fmt.Printf("Error fetching offsets: %s\n", err)
		return
	}

	mem, err := initializeMemory()
	if err != nil {
		fmt.Printf("Error initializing memory: %s\n", err)
		return
	}

	overlay := NewOverlay()

	// Start main loop
	go func() {
		for {
			localPlayer, localTeam, _ := mem.GetLocalPlayer()
			if localPlayer != 0 {
				entities := mem.GetEntities(localTeam)
				overlay.Render(entities)
			}
			time.Sleep(16 * time.Millisecond)
		}
	}()

	// Start triggerbot
	go mem.RunTriggerBot()

	// Message loop
	var msg win.MSG
	for win.GetMessage(&msg, 0, 0, 0) != 0 {
		win.TranslateMessage(&msg)
		win.DispatchMessage(&msg)
	}
}
