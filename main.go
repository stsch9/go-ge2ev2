package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"

	"github.com/stsch9/ge2ev2/ge2ev2"
)

const usage = `Usage:
	ge2ev2 [-c config file] mkdr DATAROOM_PATH
	ge2ev2 [-c config file] upload FILE_PATH DATAROOM_PATH
	ge2ev2 [-c config file] ls DATAROOM_PATH
	ge2ev2 [-c config file] download FILE_PATH DESTINATION
	ge2ev2 [-c config file] chrec DATAROOM_PATH
	
Options:
	-c PATH		Use the config file at PATH. Default: config.toml`

func main() {
	configFlag := flag.String("c", "config.toml", "config file")

	flag.Parse()

	// If not enough args, return usage
	if len(flag.Args()) < 1 {
		fmt.Println(usage)
		os.Exit(0)
	}

	var config ge2ev2.Config
	config = readConfig(*configFlag)

	function := flag.Arg(0)

	switch function {
	case "help":
		fmt.Println(usage)
		os.Exit(0)
	case "mkdr":
		mkdrHandle(config)
	case "upload":
		uploadHandle(config)
	case "ls":
		lsHandle(config)
	case "download":
		downHandle(config)
	case "chrec":
		chrecHandle(config)
	default:
		fmt.Println("Run ge2ev2 help to show usage.")
		os.Exit(1)
	}
}

func mkdrHandle(config ge2ev2.Config) {
	if len(flag.Args()) != 2 {
		fmt.Println(usage)
		os.Exit(0)
	}

	dataroompath := flag.Arg(1)

	if ok, err := validateDR(config.Rcloneremote + ":" + dataroompath); err != nil {
		fmt.Println("Unexpected error: ", err)
		os.Exit(1)
	} else if ok {
		fmt.Println(dataroompath + " already exists")
		os.Exit(1)
	}

	cmd := exec.Command("rclone", "mkdir", config.Rcloneremote+"xsa:"+dataroompath+"/.meta")

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Prüfe, ob der Fehler ein ExitError ist
		if _, ok := err.(*exec.ExitError); ok {
			fmt.Println("Error: ", string(output))
			os.Exit(1)
		} else {
			fmt.Println("Unexpected error: ", err)
			os.Exit(1)
		}
	}

	ge2ev2.CreateDataroom(dataroompath, config)
}

func uploadHandle(config ge2ev2.Config) {
	if len(flag.Args()) != 3 {
		fmt.Println(usage)
		os.Exit(0)
	}

	file := flag.Arg(1)
	dataroompath := flag.Arg(2)

	if !validateFile(file) {
		fmt.Println("File " + file + " not found")
		os.Exit(1)
	}

	if ok, err := validateDR(config.Rcloneremote + ":" + dataroompath); err != nil {
		fmt.Println("Unexpected error: ", err)
		os.Exit(1)
	} else if !ok {
		fmt.Println("Dataroom " + dataroompath + " not found")
		os.Exit(1)
	}

	ge2ev2.UploadFile2(dataroompath, file, config)
}

func lsHandle(config ge2ev2.Config) {
	if len(flag.Args()) != 2 {
		fmt.Println(usage)
		os.Exit(0)
	}

	dataroompath := flag.Arg(1)

	if ok, err := validateDR(config.Rcloneremote + ":" + dataroompath); err != nil {
		fmt.Println("Unexpected error: ", err)
		os.Exit(1)
	} else if !ok {
		fmt.Println("Dataroom " + dataroompath + " not found")
		os.Exit(1)
	}

	ge2ev2.ShowFiles(dataroompath, config)
}

func downHandle(config ge2ev2.Config) {
	if len(flag.Args()) != 3 {
		fmt.Println(usage)
		os.Exit(0)
	}

	file := flag.Arg(1)
	filename := filepath.Base(file)
	dataroompath := filepath.Dir(file)
	dest := flag.Arg(2)
	dest2 := filepath.Clean(dest)

	if !validateFile(dest) {
		fmt.Println("Destination " + dest + " not found")
		os.Exit(1)
	}

	if dataroompath == "." {
		fmt.Println("Use a valid dataroom")
		os.Exit(1)
	}

	if ok, err := validateDR(config.Rcloneremote + ":" + dataroompath); err != nil {
		fmt.Println("Unexpected error: ", err)
		os.Exit(1)
	} else if !ok {
		fmt.Println("Dataroom " + dataroompath + " not found")
		os.Exit(1)
	}

	ge2ev2.DownloadFile2(dataroompath, filename, dest2, config)
}

func chrecHandle(config ge2ev2.Config) {
	if len(flag.Args()) != 2 {
		fmt.Println(usage)
		os.Exit(0)
	}

	dataroompath := flag.Arg(1)

	if ok, err := validateDR(config.Rcloneremote + ":" + dataroompath); err != nil {
		fmt.Println("Unexpected error: ", err)
		os.Exit(1)
	} else if !ok {
		fmt.Println("Dataroom " + dataroompath + " not found")
		os.Exit(1)
	}

	ge2ev2.ChangeRecipients(config, dataroompath)
}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}

	return true
}

func readConfig(configFile string) ge2ev2.Config {
	if !validateFile(configFile) {
		fmt.Println("Error: Config file " + configFile + "  not found")
		os.Exit(1)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("Error reading config file: %v", err)
		os.Exit(1)
	}

	// YAML-Daten in die Config-Struktur parsen
	var config ge2ev2.Config
	err = toml.Unmarshal(data, &config)
	if err != nil {
		fmt.Printf("Error reading config: %v", err)
		os.Exit(1)
	}

	if !validateFile(config.Agekeyfile) {
		fmt.Println("Error: Age key file " + config.Agekeyfile + "  not found.")
		os.Exit(1)
	}

	return config
}

func validateDR(dr string) (bool, error) {
	cmd := exec.Command("rclone", "ls", dr)

	err := cmd.Run()
	if err != nil {
		// Prüfe, ob der Fehler ein ExitError ist
		if _, ok := err.(*exec.ExitError); ok {
			// Exit Code abrufen
			//exitCode := exitErr.ExitCode()
			return false, nil
		} else {
			return false, err
		}
	} else {
		return true, nil
	}
}
