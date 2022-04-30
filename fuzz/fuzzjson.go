package fuzz

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/wahyuhadi/httpraw-fuzz/models"
	"github.com/wahyuhadi/httpraw-fuzz/parser"
	"github.com/wahyuhadi/jdam/pkg/jdam"
	"github.com/wahyuhadi/jdam/pkg/jdam/mutation"
)

var client = &http.Client{}

func Fuzz(req *parser.Request, raw string, opt *models.Opt) {
	var request *http.Request
	// var new *http.Request
	request, _ = http.NewRequest(req.Method, req.Url, strings.NewReader(raw))
	fmt.Println(request.URL.Query())
	transport := &http.Transport{}
	if opt.Proxy != "" {
		proxyString := opt.Proxy
		proxyURL, _ := url.Parse(proxyString)

		transport = &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

	}
	client = &http.Client{
		Transport: transport,
	}

	// custome content-length with body request
	request.Body = io.NopCloser(strings.NewReader(req.Data))
	for i, header := range req.Headers {
		if i == "Content-Length" {
			fmt.Println(header)
			continue
		}
		request.Header.Set(i, header)
	}
	request.ContentLength = int64(len(req.Data))

	subject := map[string]interface{}{}
	err := json.Unmarshal([]byte(req.Data), &subject)
	if err != nil {
		gologger.Error().Str("Error", "State").Str("Message", fmt.Sprintf("%v", err.Error())).Msg("Parsing Error")
		return
	}

	fuzzer := jdam.NewWithSeed(10, mutation.Mutators).MaxDepth(1000).NilChance(1)
	if request.Body != nil {
		// uniqMap := make(map[string]struct{})
		for i := 0; i < opt.Mutation; i++ {
			// Fuzz a random field with a random mutator.
			fuzzed := fuzzer.Fuzz(subject)
			// Encode the fuzzed object into JSON.
			fuzzedJSON, err := json.Marshal(fuzzed)
			if err != nil {
				panic(err)
			}

			request.Body = ioutil.NopCloser(strings.NewReader(string(fuzzedJSON)))
			conten, _ := strconv.ParseInt(string(fuzzedJSON), 10, 64)
			request.ContentLength = conten
			request.Close = true
			resp, err := client.Do(request)
			if err != nil {
				gologger.Error().Str("Error", "State").Str("Message", fmt.Sprintf("%v", err.Error())).Msg("Error request")
				continue
			}

			// for true {

			// }

			if resp.StatusCode != 200 {
				// Our payload has caused some sort of internal server error!
				// Write the payload to a file for further research.
				gologger.Error().Str("Error", "State").Str("HTTP status", fmt.Sprintf("%v", resp.StatusCode)).Msg("Error status code")
				bodyBytes, _ := ioutil.ReadAll(resp.Body)
				save := fmt.Sprintf("\n\n--------------------------Request--------------------------------\n\n%v\n--------------------------Responses--------------------------------\n\n\n%v\n", string(fuzzedJSON), string(bodyBytes))
				err := ioutil.WriteFile(fmt.Sprintf("crash/crash-%v-%v.json", resp.StatusCode, i), []byte(save), 0644)
				if err != nil {
					fmt.Println(err.Error())
				}
			}

			time.Sleep(100 * time.Millisecond)
			defer resp.Body.Close()
		}
	}
}

func copyMap(orig map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range orig {
		cp[k] = v
	}
	return cp
}

func makeFingerprint(s []byte) string {
	h := sha1.New()
	io.WriteString(h, string(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}
