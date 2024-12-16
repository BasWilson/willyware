package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/google/uuid"
)

func main() {
    http.HandleFunc("/", handleHome)
    http.HandleFunc("/download", handleDownload)

    log.Println("Server starting on :8080...")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFiles("templates/index.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    err = tmpl.Execute(w, nil)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
    // Create a temporary directory
    tempDir, err := os.MkdirTemp("", "cheat-build-*")
    if err != nil {
        log.Printf("Failed to create temp directory: %v", err)
        http.Error(w, "Failed to create temporary directory", http.StatusInternalServerError)
        return
    }
    defer os.RemoveAll(tempDir) // Clean up temp directory when done

    // Run the build script
    cmd := exec.Command("./build_random.sh", tempDir)
    cmd.Dir = "../ww" // Set working directory to where the script is
    output, err := cmd.CombinedOutput() // Capture both stdout and stderr
    if err != nil {
        log.Printf("Build script failed: %v\nOutput: %s", err, output)
        http.Error(w, "Failed to build executable", http.StatusInternalServerError)
        return
    }

    // The built file should be in the temp directory
    filePath := filepath.Join(tempDir, "cheat.exe")

    // Check if file exists
    if _, err := os.Stat(filePath); os.IsNotExist(err) {
        log.Printf("Built file not found at: %s", filePath)
        http.Error(w, "Built file not found", http.StatusInternalServerError)
        return
    }

    log.Printf("Serving file from: %s", filePath)

    randomUUID := uuid.New()

    // Set headers for file download
    w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.exe", randomUUID))
    w.Header().Set("Content-Type", "application/octet-stream")

    // Serve the file
    http.ServeFile(w, r, filePath)
}