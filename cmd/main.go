package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	index     int
	validUrls int = 0
	urls      string
	mu        sync.Mutex
	wg        sync.WaitGroup
)

type result struct {
	url     string
	isValid bool
}

func check(url string, results chan<- result) {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     15 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	resp, err := client.Get(url + "/.git/HEAD")
	if err != nil {
		results <- result{url: url, isValid: false}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- result{url: url, isValid: false}
		return
	}

	if strings.Contains(string(body), "ref: refs/") {
		fmt.Println("Vulnerable: ", url)
		results <- result{url: url, isValid: true}
	} else {
		results <- result{url: url, isValid: false}
	}
}

func main() {
	fmt.Println("Erg0sum's Git Scanner")
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./scanner <file> <threads>")
		os.Exit(0)
	}

	list, err := os.OpenFile(os.Args[1], os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer list.Close()

	scanner := bufio.NewScanner(list)
	urlsQueue := make(chan string)
	results := make(chan result)

	var threads int
	threads, err = strconv.Atoi(os.Args[2])
	if err != nil {
		log.Println("Please enter a integer for your threads.")
		os.Exit(0)
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlsQueue {
				check(url, results)
			}
		}()
	}

	go func() {
		for scanner.Scan() {
			url := scanner.Text()
			urlsQueue <- url
		}
		close(urlsQueue)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.isValid {
			mu.Lock()
			urls += res.url + "\n"
			validUrls++
			mu.Unlock()
		}
		index++
	}

	if validUrls < 1 {
		fmt.Printf("Found %v valid git repos!\n", validUrls)
	} else {
		fmt.Printf("Found %v valid git repos! Enjoy XD\n", validUrls)
	}

	fmt.Printf("Finished scanning %v URLs\n", index)
	fmt.Println("Writing to file: validUrls.txt")

	f, err := os.OpenFile("./valids.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	mu.Lock()
	f.WriteString(urls)
	mu.Unlock()

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
