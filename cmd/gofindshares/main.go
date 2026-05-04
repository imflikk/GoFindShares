package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	// Local imports
	"github.com/imflikk/GoFindShares/pkg/helpers"
)

func main() {

	var keywords []string
	var credsSet bool
	var username string
	var password string

	start := time.Now()

	// Custom usage message to make it easier to read
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage Info: %s\n", "GoFindShares.exe")

		flag.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(os.Stderr, "    -%v\n\t%v\n", f.Name, f.Usage) // f.Name, f.Value
		})

		fmt.Fprintf(os.Stderr, "\nExamples: \n\t%s\n", "GoFindShares.exe -target 10.0.0.1")
		fmt.Fprintf(os.Stderr, "\n\t%ss\n\n", "GoFindShares.exe -file C:\\Folder\\targets.txt -username test -password FakePass")
	}

	targetIP := flag.String("target", "", "Target IP or hostname")
	targetFile := flag.String("file", "", "File with list of targets")
	keywordsArg := flag.String("keywords", "", "(Optional) Keywords to search for in files (comma-separated)")
	usernameArg := flag.String("username", "", "(Optional) Username to connect to SMB share with")
	passwordArg := flag.String("password", "", "(Optional) Password to connect to SMB share with")

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
	if *keywordsArg != "" {
		// check for multiple keywords separated by commas
		keywords = strings.Split(*keywordsArg, ",")
		for i, k := range keywords {
			keywords[i] = strings.TrimSpace(k)
		}
		keywords = helpers.Deduplicate(keywords)
	} else {
		keywords = []string{"password"}
	}

	fmt.Printf("\n[*] Keywords to search for: %q\n\n", keywords)

	// create a slice to save results to be exported later
	var results []helpers.SearchResult

	// Retrieve argument data and pass to function for checking shares
	if *targetIP != "" {
		server := *targetIP

		err := error(nil)
		results, err = helpers.CheckServerShares(server, credsSet, username, password, keywords, results)
		if err != nil {
			fmt.Printf("[-] Error checking server shares on %s\n", server)
			//panic(err)
			os.Exit(0)
		}
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
			helpers.CheckServerShares(fileScanner.Text(), credsSet, username, password, keywords, results)
		}

	}

	// deduplicate results before exporting
	results = helpers.Deduplicate(results)

	fmt.Printf("\n[*] Search complete. Exporting %d results.\n", len(results))

	// pull results from the results slice and print them to the console
	// for _, result := range results {
	// 	fmt.Printf("File Location: %s\nFile Name: %s\nFile Size: %d bytes\nKeyword Found: %s\nKeyword Context: %s\n\n",
	// 		result.FileLocation, result.FileName, result.FileSize, result.KeywordFound, result.KeywordContext)
	// }

	// export results to a CSV file
	err := helpers.WriteResultsCSV("results.csv", results)
	if err != nil {
		fmt.Printf("[-] Error writing results to CSV: %s\n", err)
	} else {
		fmt.Printf("[+] Results successfully written to results.csv\n")
	}

	end := time.Now()

	elapsed := end.Sub(start)

	fmt.Printf("Elapsed time in seconds: %.2f\n", elapsed.Seconds())
	fmt.Printf("Elapsed time in milliseconds: %.2f\n", elapsed.Seconds()*1000)

}
