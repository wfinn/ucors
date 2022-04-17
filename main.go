package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	tld "github.com/wfinn/go-tld"
)

var cookie string
var printonly bool
var onlyone bool
var attackerdomain string
var authheader string

func main() {
	goroutines := flag.Uint("r", 20, "go routines")
	flag.StringVar(&cookie, "c", "", "cookie e.g. session=abc123")
	flag.BoolVar(&printonly, "p", false, "only print the payloads")
	flag.BoolVar(&onlyone, "s", false, "stop scanning a url after a hit")
	flag.StringVar(&attackerdomain, "d", "evil.com", "attacker domain")
	flag.StringVar(&authheader, "a", "", "Authorization header value")
	flag.Parse()

	urls := make(chan string)

	// workers
	var wg sync.WaitGroup
	for i := 0; i < int(*goroutines); i++ {
		wg.Add(1)

		c := getClient()
		go func() {
			defer wg.Done()

			for u := range urls {
				testOrigins(c, u)
			}
		}()
	}

	sc := bufio.NewScanner(os.Stdin)

	// read urls from stdin
	for sc.Scan() {
		urls <- sc.Text()
	}
	close(urls)

	wg.Wait()

}

func getClient() *http.Client {
	tr := &http.Transport{
		MaxIdleConns:    30,
		IdleConnTimeout: time.Second,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * 10,
			KeepAlive: time.Second,
		}).DialContext,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       time.Second * 10,
	}
}

func testOrigins(c *http.Client, u string) {
	pp, err := getPermutations(u)

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}

	for _, p := range pp {
		if printonly {
			fmt.Println(p)
			continue
		}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return
		}
		req.Header.Set("Origin", p)
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		if authheader != "" {
			req.Header.Set("Authorization", authheader)
		}
		resp, err := c.Do(req)
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error requesting %s: %s\n", u, err)
			return
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == p {
			fmt.Printf("Url: %s Origin: %s ACAC: %s\n", u, p, acac)
			if onlyone {
				break
			}
		}
	}
}

func getPermutations(raw string) ([]string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return []string{}, err
	}

	origins := []string{
		"https://" + attackerdomain,
		"http://" + attackerdomain,
		"null",
	}

	patterns := []string{
		"https://%s." + attackerdomain,
		"https://%s" + attackerdomain,
		"https://xssonanysubdomain.%s",
	}

	for i, p := range patterns {
		patterns[i] = fmt.Sprintf(p, u.Hostname())
	}
	origins = append(origins, patterns...)

	origin := u.Scheme + "://" + u.Host

	if u, err := tld.Parse(raw); err == nil {
		// e.g. https://wwwXtarget.tld
		if u.Subdomain != "" {
			origins = append(origins, strings.Replace(origin, ".", "x", 1))
		} else {
			origins = append(origins, "https://"+"wwwx"+u.Hostname())
		}
		// e.g. https://target.wtf
		if re, err := regexp.Compile("\\." + u.TLD); err == nil {
			newTLD := ".wtf"
			if u.TLD == newTLD {
				newTLD = ".ooo"
			}
			origins = append(origins, re.ReplaceAllString(origin, newTLD))
		}
	}

	//most of these only work on Safari like with redirex
	subdomainchars := []string{",", "&", "'", "\"", ";", "!", "$", "^", "*", "(", ")", "+", "`", "~", "-", "_", "=", "|", "{", "}", "%", "%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08", "%0b", "%0c", "%0e", "%0f", "%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17", "%18", "%19", "%1a", "%1b", "%1c", "%1d", "%1e", "%1f", "%7f"}
	for _, char := range subdomainchars {
		// e.g. https://target.tld&.evil.com
		origins = append(origins, origin+char+"."+attackerdomain)
	}
	return origins, nil
}
