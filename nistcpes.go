package main

import (
	"os"
	"fmt"
	"time"
	"regexp"
	"strings"
	"io/ioutil"
	"encoding/xml"
)

var entries []CpeEntry

type CpeEntry struct {
	name, cpe, vendor, product, version  string
	fullreg, prodreg                    *regexp.Regexp
}

func ProcessEntry(name string, cpe string) {
	elems := strings.Split(cpe, ":")

	if elems[1] != "/a" {
		return
	}

	vendor  := strings.Replace(elems[2], "_", " ", -1)
	product := strings.Replace(elems[3], "_", " ", -1)
	version := strings.Replace(elems[4], "_", " ", -1)

	fullreg, _ := regexp.Compile(`\b` + strings.Replace(elems[2], "_", "[^a-z]*", -1) + "[^a-z]*" + strings.Replace(elems[3], "_", "[^a-z]*", -1) + `\b`)
	prodreg, _ := regexp.Compile(`\b` + strings.Replace(elems[3], "_", "[^a-z]*", -1) + `\b`)

	entry := CpeEntry {
		name:    name,
		cpe:     cpe,
		vendor:  vendor,
		product: product,
		version: version,
		fullreg: fullreg,
		prodreg: prodreg,
	}

	entries = append(entries, entry)
}

func main() {
	var query string

	if len(os.Args) > 1 {
		query = strings.ToLower(strings.Join(os.Args[1:], " "))
	} else {
		query = "apache http server"
	}

	var err error
	var fp *os.File

	if fp, err = os.Open("official-cpe-dictionary_v2.3.xml"); err != nil {
		fmt.Println(err)
		return
	}

	defer fp.Close()

	println("parsing")

	start := time.Now()

	txt, _ := ioutil.ReadAll(fp)

	var lst struct {
		CpeItems []struct {
			Title []struct {
				Name string `xml:",chardata"`
				Lang string `xml:"lang,attr"`
			} `xml:"title"`
			Value string `xml:"name,attr"`
		} `xml:"cpe-item"`
	}

	if err = xml.Unmarshal(txt, &lst); err != nil {
		fmt.Println(err)
		return
	}

	entries = make([]CpeEntry, 0)

	for _, cpe := range lst.CpeItems {
		if len(cpe.Title) == 1 {
			ProcessEntry(cpe.Title[0].Name, cpe.Value)
		} else {
			for _, item := range cpe.Title {
				if item.Lang == "en-US" {
					ProcessEntry(item.Name, cpe.Value)
				}
			}
		}
	}

	fmt.Println(len(entries))
	fmt.Println(time.Since(start))

	println("searching")

	start = time.Now()

	for _, entry := range entries {
		if entry.prodreg.MatchString(query) {
			println(entry.name)
		}
		if entry.fullreg.MatchString(query) {
			println(entry.name)
		}
	}

	fmt.Println(time.Since(start))
}