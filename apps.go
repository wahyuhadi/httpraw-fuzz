package main

import (
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/url"

	"github.com/wahyuhadi/httpraw-fuzz/fuzz"

	"github.com/projectdiscovery/gologger"
	"github.com/wahyuhadi/httpraw-fuzz/models"
	"github.com/wahyuhadi/httpraw-fuzz/parser"
)

var file = flag.String("f", "", "http request file ")

// var treq = flag.Int("tr", 1000, "total  request  ")
var jsonb = flag.Bool("jsonb", true, "Is json body exist")
var igf = flag.String("igf", "id", "Is Ignor fields in json")
var proxy = flag.String("proxy", "", "Proxy burp to analize")
var urls = flag.String("url", "", "url")

const (
	fileNotFond = "http raw file not found"
)

func ParseOptions() (opts *models.Opt) {
	flag.Parse()
	return &models.Opt{
		File:         *file,
		Mutation:     1000,
		Jsonb:        *jsonb,
		IgnoreFields: *igf,
		Proxy:        *proxy,
		URL:          *urls,
	}
}

func CheckOptions(opts *models.Opt) (err error) {
	if opts.File == "" {
		return errors.New(fileNotFond)
	}

	if opts.URL == "" {
		return errors.New("url is empty")
	}
	return nil
}

func main() {
	opts := ParseOptions()
	err := CheckOptions(opts)
	if err != nil {
		gologger.Info().Str("state", "errored").Str("status", "error").Msg(err.Error())
		return
	}

	f, err := ioutil.ReadFile(opts.File)
	if err != nil {
		log.Fatal(err)
	}

	request, err := parser.ReadHTTPFromFile(string(f), opts.URL)
	if err != nil {
		gologger.Info().Str("status", "error").Msg(err.Error())
		return
	}

	u, e := url.Parse(opts.URL + request.Path)
	if e != nil {
		gologger.Info().Str("status", "error").Msg(e.Error())
		return
	}
	request.Url = opts.URL + request.Path
	request.Scheme = u.Scheme
	request.Port = "80"
	if u.Scheme == "https" {
		request.Port = "443"
	}
	request.Query = u.RawQuery
	fuzz.Fuzz(request, string(f), opts)
}
