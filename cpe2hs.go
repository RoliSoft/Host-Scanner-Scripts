package main

import (
	"os"
	"bufio"
	"regexp"
	"strings"
	"net/url"
	"io/ioutil"
	"encoding/xml"
	"encoding/binary"
)

var entries map[string]*entry

type entry struct {
	CPE string
	Tokens []string
	Versions []*subentry
}

type subentry struct {
	Name, CPE string
}

// Reads the specified XML file and sends the entries for processing.
func parseInput(file string) error {
	var err error
	var fp  *os.File

	if fp, err = os.Open(file); err != nil {
		return err
	}

	defer fp.Close()

	txt, _ := ioutil.ReadAll(fp)

	var lst struct {
		Items []struct {
			Title []struct {
				Name string `xml:",chardata"`
				Lang string `xml:"lang,attr"`
			} `xml:"title"`
			Value string `xml:"name,attr"`
		} `xml:"cpe-item"`
	}

	if err = xml.Unmarshal(txt, &lst); err != nil {
		return err
	}

	entries = make(map[string]*entry)

	for _, cpe := range lst.Items {
		if len(cpe.Title) == 1 {
			processEntry(cpe.Title[0].Name, cpe.Value)
		} else {
			for _, item := range cpe.Title {
				if item.Lang == "en-US" {
					processEntry(item.Name, cpe.Value)
				}
			}
		}
	}

	// post-process entries array

	for _, entry := range entries {
		// add additional tokens from CPE

		re, _ := regexp.Compile(`([a-z][a-z0-9]+)`)
		mc := re.FindAllStringSubmatch(entry.CPE[7:], -1)

		if len(mc) > 0 {
			for _, match := range mc {
				found := false

				for _, token := range entry.Tokens {
					if token == match[1] {
						found = true
					}
				}

				if !found {
					entry.Tokens = append(entry.Tokens, match[1])
				}
			}
		}

		// remove tokens from the name of each version

		for _, subentry := range entry.Versions {
			for _, token := range entry.Tokens {
				subentry.Name = regexp.MustCompile(`(?:^|[^a-z])` + token + `(?:[^a-z]|$)`).ReplaceAllLiteralString(subentry.Name, " ")
			}

			subentry.Name = strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllLiteralString(subentry.Name, " "))
		}
	}

	return err
}

// Processes the specified CPE entry from the XML file and places
// it into the global variable `entries`.
func processEntry(name string, cpe string) {
	cpe, _ = url.QueryUnescape(cpe)
	elems := strings.Split(cpe, ":")

	if elems[1] != "/a" && elems[1] != "/o" {
		return
	}

	key := strings.Join(elems[1:4], ":")

	var ent *entry
	var ok  bool

	if ent, ok = entries[key]; !ok {
		ent = &entry {
			CPE:      strings.Join(elems[0:4], ":"),
			Versions: make([]*subentry, 0),
		}

		entries[key] = ent
	}

	ver := &subentry {
		CPE:  strings.Join(elems[4:], ":"),
		Name: strings.ToLower(name),
	}

	ent.Versions = append(ent.Versions, ver)

	re, _ := regexp.Compile(`([a-z][a-z0-9]+)`)
	mc := re.FindAllStringSubmatch(strings.ToLower(name), -1)

	if len(mc) > 0 {
		if len(ent.Tokens) == 0 {
			var tokens []string

			for _, token := range mc {
				tokens = append(tokens, token[1])
			}

			ent.Tokens = tokens
		} else {
			var tokens []string

			for _, token := range ent.Tokens {
				found := false

				for _, match := range mc {
					if token == match[1] {
						found = true
					}
				}

				if found {
					tokens = append(tokens, token)
				}
			}

			ent.Tokens = tokens
		}
	}
}

// Writes the globally loaded entries to the specified file.
func serializeEntries(file string) error {
	var err error
	var fp  *os.File

	if fp, err = os.Create(file); err != nil {
		return err
	}

	defer fp.Close()

	bw := bufio.NewWriter(fp)

	// package type: CPE dictionary
	binary.Write(bw, binary.LittleEndian, uint16(1))
	// package version
	binary.Write(bw, binary.LittleEndian, uint16(1))
	// number of entries
	binary.Write(bw, binary.LittleEndian, uint32(len(entries)))

	for _, entry := range entries {
		// CPE: [cpe:/]o:linux:linux_kernel
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.CPE) - 5))
		bw.WriteString(entry.CPE[5:])

		// number of tokens
		binary.Write(bw, binary.LittleEndian, uint8(len(entry.Tokens)))

		for _, token := range entry.Tokens {
			// token: Linux, Kernel
			binary.Write(bw, binary.LittleEndian, uint16(len(token)))
			bw.WriteString(token)
		}

		// number of versions
		binary.Write(bw, binary.LittleEndian, uint32(len(entry.Versions)))

		for _, subentry := range entry.Versions {
			// CPE: 3.10.0::~~~~arm64~
			binary.Write(bw, binary.LittleEndian, uint16(len(subentry.CPE)))
			bw.WriteString(subentry.CPE)

			// name: [Linux Kernel] 3.10.0 on ARM64 architecture
			binary.Write(bw, binary.LittleEndian, uint16(len(subentry.Name)))
			bw.WriteString(subentry.Name)
		}
	}

	binary.Write(bw, binary.LittleEndian, uint32(0))

	bw.Flush()

	return err
}

// Entry point of the application.
func main() {
	if len(os.Args) < 3 {
		println("usage: cpe2hs input output")
		os.Exit(-1)
	}

	var err error

	println("Parsing CPE dictionary...")

	if err = parseInput(os.Args[1]); err != nil {
		println(err)
		os.Exit(-1)
	}

	println("Writing parsed data...")

	if err = serializeEntries(os.Args[2]); err != nil {
		println(err)
		os.Exit(-1)
	}
}