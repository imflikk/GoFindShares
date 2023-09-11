package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/LeakIX/go-smb2"
	"github.com/LeakIX/ntlmssp"
)

var keyword string
var credsSet bool
var username string
var password string

func main() {

	targetIP := flag.String("target", "", "Target IP or hostname")
	targetFile := flag.String("file", "", "File with list of targets")
	keywordArg := flag.String("keyword", "", "Keyword to search for in files")
	usernameArg := flag.String("username", "", "Username to connect to SMB share with")
	passwordArg := flag.String("password", "", "Password to connect to SMB share with")

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

	// Check if credentials were provided.  If not use anonymous
	if *usernameArg == "" && *passwordArg == "" {
		credsSet = false
		fmt.Println("\n[*] No credentials provided, connecting as anonymous user.")
	} else {
		credsSet = true
		username = *usernameArg
		password = *passwordArg
		fmt.Printf("\n[*] Using credentials: %s:%s\n", username, password)
	}

	// Check if a keyword was provided, if not default to "password"
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

	fmt.Printf("[+] Successfully connected to %s\n", server)

	var ntlmsspClient *ntlmssp.Client
	var errClient error

	// Use provided credentials, otherwise connect as anonymous (non-existent username defaults to anonymous)
	if credsSet {
		ntlmsspClient, errClient = ntlmssp.NewClient(
			ntlmssp.SetCompatibilityLevel(3),
			ntlmssp.SetUserInfo(username, password),
			ntlmssp.SetDomain(""))
		if errClient != nil {
			fmt.Println("[-] Error creating NTLMSSP Client")
			//panic(err)
			return
		}
	} else {
		ntlmsspClient, errClient = ntlmssp.NewClient(
			ntlmssp.SetCompatibilityLevel(3),
			ntlmssp.SetUserInfo("thisdoesntexist", ""),
			ntlmssp.SetDomain(""))
		if errClient != nil {
			fmt.Println("[-] Error creating NTLMSSP Client")
			//panic(err)
			return
		}
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMSSPInitiator{
			NTLMSSPClient: ntlmsspClient,
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

	// Retrieve remote server info
	hostname, _ := ntlmsspClient.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvDNSComputerName)
	domain, _ := ntlmsspClient.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvNbDomainName)
	fmt.Printf("[*] Server info\n\tHostname: %s\n\tDomain: %s\n", utf16BytesToString(hostname), utf16BytesToString(domain))

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
		// Can be changed if you want to see any of these
		if name == "IPC$" || name == "PRINT$" || name == "ADMIN$" || name == "C$" {
			continue
		}

		fullShareName := "\\\\" + server + "\\" + name

		fmt.Println("\n========" + fullShareName + " ========")

		// Walk the current share directory and recursively list all files
		// This seems to be easier than the commented section below, but keeping it just in case
		fmt.Printf("%-80s %10s %20s\n", "File Name", "Size", "Keyword found")
		fmt.Println(strings.Repeat("-", 110))
		err := filepath.Walk(fullShareName,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				keywordFound := ""

				if !info.IsDir() {
					// Search for keyword if file is less than 5mb
					if info.Size() < 5000000 {
						fileBuf, err := os.ReadFile(path)
						if err != nil {
							panic(err)
						}
						bufAsString := string(fileBuf)
						//check whether s contains substring text
						foundWord := strings.Contains(bufAsString, keyword)
						if foundWord {
							keywordFound = "yes"
						}
					} else {
						keywordFound = "too large"
					}
				}

				fmt.Printf("%-80s %10d %20s\n", path, info.Size(), keywordFound)
				return nil
			})
		if err != nil {
			log.Println(err)
		}

		fmt.Println(strings.Repeat("-", 110))

	}
}

// Help from ChatGPT to convert a UTF-16 byte array to a string
func utf16BytesToString(utf16Bytes []byte) string {
	// Initialize an empty string to store the result
	var str string

	// Iterate over the byte array in pairs (assuming little-endian encoding)
	for i := 0; i < len(utf16Bytes); i += 2 {
		// Read the two bytes as a little-endian UTF-16 code unit
		codeUnit := binary.LittleEndian.Uint16(utf16Bytes[i : i+2])

		// Convert the UTF-16 code unit to a UTF-8 rune and append it to the string
		str += string(codeUnit)
	}

	return str
}
