package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/hirochachacha/go-smb2"
)

func main() {

	targetIP := flag.String("target", "", "Target IP or hostname")
	targetFile := flag.String("file", "", "File with list of targets")

	flag.Parse()

	// Check that target arguments were provided correctly
	if *targetIP == "" && *targetFile == "" {
		fmt.Printf("[-] No target or file provided.\n\n")
		flag.Usage()
		os.Exit(0)
	} else if *targetIP != "" && *targetFile != "" {
		fmt.Printf("[-] Please only provide a target OR file, not both.\n\n")
		os.Exit(0)
	}

	// Retrieve argument data and pass to function for checking shares
	if *targetIP != "" {
		server := *targetIP

		checkServerShares(server)
	} else {
		file := *targetFile
		fmt.Printf("File name passed: %s\n", file)
	}

}

func checkServerShares(server string) {
	fmt.Printf("[*] Attempting to connect to %s...\n", server)

	// Connect to remote server
	conn, err := net.Dial("tcp", server+":445")
	if err != nil {
		fmt.Println("[-] Error connecting to server: " + server)
		panic(err)
	}
	defer conn.Close()

	fmt.Printf("[+] Successfully connected to %s!\n", server)

	// Create smb2 object with authentication information
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "shareuser",
			Password: "",
		},
	}

	// Connect to SMB service with provided authentication info
	s, err := d.Dial(conn)
	if err != nil {
		fmt.Println("[-] Error connecting to SMB service")
		panic(err)
	}
	defer s.Logoff()

	// List all shares available on remote server
	names, err := s.ListSharenames()
	if err != nil {
		fmt.Println("[-] Error listing shares")
		panic(err)
	}

	// Loop over found shares
	for _, name := range names {
		// Skip over default windows shares
		if name == "IPC$" || name == "PRINT$" {
			continue
		}

		fmt.Println("======== \\\\" + server + "\\" + name + " ========")

		// Temporarily mount each share
		fs, err := s.Mount("\\\\" + server + "\\" + name)
		if err != nil {
			panic(err)
		}
		defer fs.Umount()

		// Open a file object for the current directory
		dir, err := fs.Open(".")
		if err != nil {
			panic(err)
		}
		defer dir.Close()

		// Read all files located in the current directory
		fi, err := dir.Readdir(-1)
		if err != nil {
			panic(err)
		}

		// Loop over all files found in directory and print them out
		fmt.Printf("%-30s %10s\n", "File Name", "Size")
		fmt.Println("--------------------------------------------")
		for _, v := range fi {
			if v.IsDir() {
				fmt.Printf("%-20s (dir) %-10s\n", v.Name(), "")
			} else {
				fmt.Printf("%-30s %10d\n", v.Name(), v.Size())
			}

		}
	}
}
