package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/hirochachacha/go-smb2"
)

var keyword string

func main() {

	targetIP := flag.String("target", "", "Target IP or hostname")
	targetFile := flag.String("file", "", "File with list of targets")
	keywordArg := flag.String("keyword", "", "Keyword to search for in files")

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

	if *keywordArg != "" {
		keyword = *keywordArg
	} else {
		keyword = "password"
	}

	fmt.Printf("\n[*] Keyword to search for: %s\n\n", keyword)

	// Retrieve argument data and pass to function for checking shares
	if *targetIP != "" {
		server := *targetIP

		checkServerShares(server)
	} else {
		file := *targetFile
		readFile, err := os.Open(file)

		if err != nil {
			fmt.Println(err)
		}
		defer readFile.Close()

		fileScanner := bufio.NewScanner(readFile)

		fileScanner.Split(bufio.ScanLines)

		for fileScanner.Scan() {
			checkServerShares(fileScanner.Text())
		}

	}

}

func checkServerShares(server string) {
	fmt.Printf("\n[*] Attempting to connect to %s...\n", server)

	// Connect to remote server
	conn, err := net.Dial("tcp", server+":445")
	if err != nil {
		fmt.Println("[-] Error connecting to server: " + server)
		//panic(err)
		return
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
		fmt.Printf("[-] Error connecting to SMB service on %s\n", server)
		//panic(err)
		return
	}
	defer s.Logoff()

	// List all shares available on remote server
	names, err := s.ListSharenames()
	if err != nil {
		fmt.Printf("[-] Error listing shares on %s\n", server)
		//panic(err)
		return
	}

	// Loop over found shares
	for _, name := range names {
		// Skip over default windows shares
		if name == "IPC$" || name == "PRINT$" {
			continue
		}

		fullShareName := "\\\\" + server + "\\" + name

		fmt.Println("\n========" + fullShareName + " ========")

		// Walk the current share directory and recursively list all files
		// This seems to be easier than the commented section below, but keeping it just in case
		fmt.Printf("%-50s %10s %10s\n", "File Name", "Size", "Keyword found")
		fmt.Println(strings.Repeat("-", 80))
		err := filepath.Walk(fullShareName,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				keywordFound := false

				if !info.IsDir() {
					fileBuf, err := ioutil.ReadFile(path)
					if err != nil {
						panic(err)
					}
					bufAsString := string(fileBuf)
					//check whether s contains substring text
					keywordFound = strings.Contains(bufAsString, keyword)
				}

				fmt.Printf("%-50s %10d %10t\n", path, info.Size(), keywordFound)
				return nil
			})
		if err != nil {
			log.Println(err)
		}

		fmt.Println(strings.Repeat("-", 80))

		///////////
		// Keeping the below method just in case it's needed later
		///////////

		// Temporarily mount each share
		// fs, err := s.Mount("\\\\" + server + "\\" + name)
		// if err != nil {
		// 	panic(err)
		// }
		// defer fs.Umount()

		// // Open a file object for the current directory
		// dir, err := fs.Open(".")
		// if err != nil {
		// 	panic(err)
		// }
		// defer dir.Close()

		// // Read all files located in the current directory
		// fi, err := dir.Readdir(-1)
		// if err != nil {
		// 	panic(err)
		// }

		// // Loop over all files found in directory and print them out
		// fmt.Printf("%-30s %10s\n", "File Name", "Size")
		// fmt.Println("--------------------------------------------")
		// for _, v := range fi {
		// 	if v.IsDir() {
		// 		//dirsToCheck = append(dirsToCheck, v.Name())
		// 		fmt.Printf("%-20s (dir) %-10s\n", v.Name(), "")
		// 	} else {
		// 		fmt.Printf("%-30s %10d\n", v.Name(), v.Size())
		// 	}

		// }
	}
}
