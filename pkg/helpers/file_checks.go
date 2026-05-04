package helpers

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"

	// Github imports
	"github.com/LeakIX/go-smb2"
	"github.com/LeakIX/ntlmssp"
)

type SearchResult struct {
	FileLocation   string
	FileName       string
	FileSize       int64
	KeywordFound   string
	KeywordContext string
}

func CheckServerShares(server string, credsSet bool, username string, password string, keywords []string, results []SearchResult) ([]SearchResult, error) {

	// create channel to receive results from concurrent share checks
	resultsCh := make(chan SearchResult)
	done := make(chan struct{})

	// Create a goroutine to listen for results from share checks and append them to the results slice
	go func() {
		for r := range resultsCh {
			results = append(results, r)
		}
		close(done)
	}()

	fmt.Printf("\n[*] Attempting to connect to %s...\n", server)

	// Connect to remote server
	conn, err := net.Dial("tcp", server+":445")
	if err != nil {
		fmt.Println("[-] Error connecting to server: " + server)
		//panic(err)
		return results, err
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
			return results, errClient
		}
	} else {
		ntlmsspClient, errClient = ntlmssp.NewClient(
			ntlmssp.SetCompatibilityLevel(3),
			ntlmssp.SetUserInfo("thisdoesntexist", ""),
			ntlmssp.SetDomain(""))
		if errClient != nil {
			fmt.Println("[-] Error creating NTLMSSP Client")
			//panic(err)
			return results, errClient
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
		return results, err
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
		return results, err
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
		go WalkShareDirs(name, server, keywords, resultsCh, s, &wg, msg)

		finalMsg += <-msg
	}

	wg.Wait()

	fmt.Println(finalMsg)

	fmt.Printf("")

	return results, nil
}

func WalkShareDirs(name string, server string, keywords []string, resultsCh chan SearchResult, smbSession *smb2.Session, wg *sync.WaitGroup, ch chan string) {
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

	finalData += fmt.Sprintf("%-80s %10s %-20s %70s\n", "File Name", "Size", "Keyword found", "Context")
	finalData += strings.Repeat("-", 200) + "\n"

	//fmt.Printf("%-80s %10s %20s\n", "File Name", "Size", "Keyword found")
	//fmt.Println(strings.Repeat("-", 110))

	// Mount the smb share so we can walk the directories and list files
	share, mountErr := MountSmbShare(name, smbSession)
	if mountErr != nil {
		log.Println("[-] Error mounting share "+name+": ", mountErr)
		ch <- ""
		return
	}
	defer share.Umount()

	// Open share so we can read files
	openShare, openErr := OpenSmbShare(share, ".")
	if openErr != nil {
		log.Println("[-] Error opening share "+fullShareName+": ", openErr)
		ch <- ""
		return
	}
	defer openShare.Close()

	// Get list of files in share
	fileEntries, readErr := ReadFilesInDir(share, openShare)
	if readErr != nil {
		log.Println("[-] Error reading share "+fullShareName+": ", readErr)
		ch <- ""
		return
	}

	for _, entry := range fileEntries {
		//keywordFound := ""

		fileName := entry.Name()

		if entry.IsDir() {
			subDirPath := fileName + "\\"
			finalData += fmt.Sprintf("%-80s %10s %-20s %-70s\n", subDirPath, "<DIR>", "", "")
			//fmt.Printf("%-80s %10s %20s\n", subDirPath, "<DIR>", "")
			finalData += RecursiveDirCheck(fullShareName, share, subDirPath, keywords, resultsCh)
			continue
		} else {

			// This section only runs on files in the root of the share
			keywordFound, keywordContext, err := CheckFileForKeyword(fullShareName, share, "", entry, keywords, resultsCh, "")
			if err != nil {
				log.Println("[-] Error checking file "+entry.Name()+" for keyword: ", err)
				keywordFound = "error checking file"
			}

			finalData += fmt.Sprintf("%-80s %10d %-20s %-70s\n", fileName, entry.Size(), keywordFound, keywordContext)

			// send each results into the resultsCh to be saved later
			// if strings.Contains(keywordFound, "yes") {
			// 	resultsCh <- SearchResult{
			// 		FileLocation:   fullShareName + "\\" + fileName,
			// 		FileName:       name,
			// 		FileSize:       entry.Size(),
			// 		KeywordFound:   keyword,
			// 		KeywordContext: keywordContext,
			// 	}
			// }
		}

		//finalData += fmt.Sprintf("%-80s %10d %20s\n", fileName, entry.Size(), keywordFound+" ("+keyword+")")
		//fmt.Printf("%-80s %10d %20s\n", fileName, entry.Size(), keywordFound)
	}

	finalData += strings.Repeat("-", 200) + "\n"
	//fmt.Println(strings.Repeat("-", 110))

	ch <- finalData

}

func CheckFileForKeyword(fullShareName string, share *smb2.Share, dirPath string, fileEntry os.FileInfo, keywords []string, resultsCh chan SearchResult, keywordFound string) (string, string, error) {
	fullSharePath := dirPath + fileEntry.Name()

	keywordContext := ""

	for _, keyword := range keywords {

		// Search for keyword if file is less than 5mb
		if fileEntry.Size() < 5000000 {
			fileBuf, err := share.ReadFile(fullSharePath)
			if err != nil {
				panic(err)
			}
			bufAsString := string(fileBuf)
			//check whether s contains substring text
			//foundWord := strings.Contains(bufAsString, keyword)
			re := regexp.MustCompile("(?i)" + regexp.QuoteMeta(keyword))
			foundWord := re.MatchString(bufAsString)

			if foundWord {
				keywordFound = "yes"

				// Search content of file and return 30 characters before and after keyword if found
				//keywordIndex := strings.Index(bufAsString, keyword)
				keywordIndex := re.FindStringIndex(bufAsString)
				if keywordIndex == nil {
					continue
				}

				startIndex := keywordIndex[0] - 20
				endIndex := keywordIndex[0] + len(keyword) + 20

				if startIndex < 0 {
					startIndex = 0
				}
				if endIndex > len(bufAsString) {
					endIndex = len(bufAsString)
				}

				keywordContext = bufAsString[startIndex:endIndex]
				// Replace all line breaks in keyword context with literal \n for better formatting in output
				keywordContext = strings.ReplaceAll(keywordContext, "\r\n", "\\n")
				//fmt.Printf("[*] Keyword found in file: %s\n\tContext: ...%s...\n", fullSharePath, keywordContext)

				// save the results each time something is found
				if strings.Contains(keywordFound, "yes") {
					resultsCh <- SearchResult{
						FileLocation:   fullShareName + "\\" + fullSharePath,
						FileName:       fileEntry.Name(),
						FileSize:       fileEntry.Size(),
						KeywordFound:   keyword,
						KeywordContext: keywordContext,
					}
				}

			}
		} else {
			keywordFound = "too large"
		}
	}

	return keywordFound, keywordContext, nil
}

func RecursiveDirCheck(fullShareName string, share *smb2.Share, dirPath string, keywords []string, resultsCh chan SearchResult) (finalData string) {

	// recursively check directories until the content of a folder contains no directory
	//fmt.Printf("[*] Recursively checking directory: %s\n", dirPath)

	openDir, err := share.Open(dirPath)
	if err != nil {
		log.Println("[-] Error opening subdirectory "+dirPath+": ", err)
		return
	}
	defer openDir.Close()

	fileEntries, err := openDir.Readdir(0)
	if err != nil {
		log.Println("[-] Error reading subdirectory "+dirPath+": ", err)
		return
	}

	for _, entry := range fileEntries {
		if entry.IsDir() {
			fmt.Printf("[*] Found subdirectory: %s\n", entry.Name())
			subDirPath := dirPath + "\\" + entry.Name()
			finalData += RecursiveDirCheck(fullShareName, share, subDirPath, keywords, resultsCh)
			//finalData += fmt.Sprintf("%-80s %10s %20s\n", subDirPath+"\\", "<DIR>", "")
			//fmt.Printf("%-80s %10s %20s\n", subDirPath+"\\", "<DIR>", "")
			continue
		} else {

			//fmt.Printf("[*] Checking file: %s\n", entry.Name())
			keywordFound, keywordContext, err := CheckFileForKeyword(fullShareName, share, dirPath, entry, keywords, resultsCh, "")
			if err != nil {
				log.Println("[-] Error checking file "+entry.Name()+" for keyword: ", err)
				keywordFound = "error checking file"
			}

			finalData += fmt.Sprintf("%-80s %10d %-20s %-70s\n", dirPath+entry.Name(), entry.Size(), keywordFound, keywordContext)

			// send each results into the resultsCh to be saved later
			// if strings.Contains(keywordFound, "yes") {
			// 	resultsCh <- SearchResult{
			// 		FileLocation:   fullShareName + "\\" + dirPath + entry.Name(),
			// 		FileName:       entry.Name(),
			// 		FileSize:       entry.Size(),
			// 		KeywordFound:   keyword,
			// 		KeywordContext: keywordContext,
			// 	}
			// }

		}
	}

	return finalData
}

func MountSmbShare(name string, smbSession *smb2.Session) (*smb2.Share, error) {
	share, err := smbSession.Mount(name)
	if err != nil {
		return nil, err
	}

	return share, nil
}

func OpenSmbShare(share *smb2.Share, path string) (*smb2.File, error) {
	openShare, err := share.Open(path)
	if err != nil {
		return nil, err
	}

	return openShare, nil
}

func ReadFilesInDir(share *smb2.Share, openDir *smb2.File) ([]os.FileInfo, error) {
	fileEntries, err := openDir.Readdir(0)
	if err != nil {
		return nil, err
	}

	return fileEntries, nil
}
