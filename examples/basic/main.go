package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	curlgo "github.com/blat-ai/curl-go"
)

func main() {
	target := "https://example.com"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	if err := run(target); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(target string) error {
	client, err := curlgo.NewClient(curlgo.Chrome)
	if err != nil {
		return err
	}
	defer client.Close()
	client.Timeout = 20 * time.Second
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	fmt.Fprintln(os.Stderr, response.Proto, response.Status)
	_, err = io.Copy(os.Stdout, response.Body)
	return err
}
