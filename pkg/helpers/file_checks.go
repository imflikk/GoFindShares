package helpers

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	// Github imports
	"github.com/LeakIX/go-smb2"
	"github.com/LeakIX/ntlmssp"
)

func CheckServerShares(server string, credsSet bool, username string, password string, keyword string) {
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
	fmt.Printf("[*] Server info\n\tHostname: %s\n\tDomain: %s\n", Utf16BytesToString(hostname), Utf16BytesToString(domain))

	// List all shares available on remote server
	names, err := s.ListSharenames()
	if err != nil {
		fmt.Printf("[-] Error listing shares on %s\n", server)
		//panic(err)
		return
	}

	fmt.Printf("[*] Found shares:\n")
	for _, name := range names {
		fmt.Printf("\t" + name + "\n")
	}

	// Create string channel to keep output organized
	msg := make(chan string)
	finalMsg := ""

	// Create WaitGroup to use for concurrent calls to walkShareDirs
	var wg sync.WaitGroup
	wg.Add(len(names))

	// Loop over found shares
	for _, name := range names {
		go WalkShareDirs(name, server, keyword, s, &wg, msg)

		finalMsg += <-msg
	}

	wg.Wait()

	fmt.Println(finalMsg)

	fmt.Printf("")
}

func WalkShareDirs(name string, server string, keyword string, smbSession *smb2.Session, wg *sync.WaitGroup, ch chan string) {
	defer wg.Done()

	var finalData string

	// Skip over default windows shares
	// Can be changed if you want to see any of these
	if name == "IPC$" || name == "PRINT$" || name == "ADMIN$" || name == "C$" {
		ch <- ""
		return
	}

	fullShareName := "\\\\" + server + "\\" + name

	finalData += "\n========" + fullShareName + " ========\n"
	//fmt.Println("\n========" + fullShareName + " ========")

	finalData += fmt.Sprintf("%-80s %10s %20s\n", "File Name", "Size", "Keyword found")
	finalData += strings.Repeat("-", 110) + "\n"

	//fmt.Printf("%-80s %10s %20s\n", "File Name", "Size", "Keyword found")
	//fmt.Println(strings.Repeat("-", 110))

	// Mount the smb share so we can walk the directories and list files
	share, mountErr := smbSession.Mount(name)
	if mountErr != nil {
		log.Println("[-] Error mounting share "+name+": ", mountErr)
		ch <- ""
		return
	}
	defer share.Umount()

	//fmt.Printf("[*] Successfully mounted %s\n", fullShareName)

	// Open share so we can read files
	f, openErr := share.Open(".")
	if openErr != nil {
		log.Println("[-] Error opening share "+fullShareName+": ", openErr)
		ch <- ""
		return
	}
	defer f.Close()

	// Get list of files in share
	fileEntries, readErr := f.Readdir(0)
	if readErr != nil {
		log.Println("[-] Error reading share "+fullShareName+": ", readErr)
		ch <- ""
		return
	}

	for _, entry := range fileEntries {
		keywordFound := ""

		fileName := entry.Name()

		if !entry.IsDir() {
			// Search for keyword if file is less than 5mb
			if entry.Size() < 5000000 {
				fileBuf, err := share.ReadFile(fileName)
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

		finalData += fmt.Sprintf("%-80s %10d %20s\n", fileName, entry.Size(), keywordFound+" ("+keyword+")")
		//fmt.Printf("%-80s %10d %20s\n", fileName, entry.Size(), keywordFound)
	}

	finalData += strings.Repeat("-", 110) + "\n"
	//fmt.Println(strings.Repeat("-", 110))

	ch <- finalData

}
