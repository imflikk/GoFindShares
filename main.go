package main

import (
	"fmt"
	"net"

	"github.com/hirochachacha/go-smb2"
)

func main() {
	server := "192.168.50.142"

	// Connect to remote server
	conn, err := net.Dial("tcp", server+":445")
	if err != nil {
		fmt.Println("[-] Error connecting to server: " + server)
		panic(err)
	}
	defer conn.Close()

	// Create smb2 object with authentication information
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "Flikk",
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

		fmt.Println("----" + name + "----")

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
		for _, v := range fi {
			if v.IsDir() {
				fmt.Printf("%-20s (dir)\n", v.Name())
			} else {
				fmt.Printf("%-20s %d\n", v.Name(), v.Size())
			}

		}
	}

}
