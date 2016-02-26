package main

import (
	"os"
	"bufio"
	"regexp"
	"strings"
	"net/url"
	"io/ioutil"
	"encoding/xml"
	"encoding/json"
	"encoding/binary"
)

var entries map[string]*entry

type entry struct {
	CPE string
	Tokens []string
	Versions []*subentry
}

type subentry struct {
	CPE, Version string
	Name string `json:"-"`
	Tokens []string
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

		retm, _ := regexp.Compile(`([a-z][a-z0-9]+)`)
		mc := retm.FindAllStringSubmatch(entry.CPE[7:], -1)

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

			subentry.Name = regexp.MustCompile(strings.Replace(subentry.Version, ".", "\\.", -1)).ReplaceAllLiteralString(subentry.Name, " ")
			subentry.Name = strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllLiteralString(subentry.Name, " "))

			subentry.Tokens = strings.Split(subentry.Name, " ")

			if len(subentry.Tokens) == 1 && len(subentry.Tokens[0]) == 0 {
				subentry.Tokens = nil
			}
		}

		// replace tokens with the ones extracted from the CPE only

		entry.Tokens = make([]string, 0)

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

	revm, _ := regexp.Compile(`\d+\.(?:\d+\.)*\d+`)
	vmc := revm.FindAllStringSubmatch(strings.Join(elems[4:], ":"), -1)

	if len(vmc) == 0 || len(vmc[0]) == 0 {
		return
	}

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
		CPE:     strings.Join(elems[4:], ":"),
		Version: vmc[0][0],
		Name:    strings.ToLower(name),
	}

	ent.Versions = append(ent.Versions, ver)

	remt, _ := regexp.Compile(`([a-z][a-z0-9]+)`)
	mc := remt.FindAllStringSubmatch(strings.ToLower(name), -1)

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
func serializeEntries(file string, debug bool) error {
	var err error
	var fp  *os.File

	if fp, err = os.Create(file); err != nil {
		return err
	}

	defer fp.Close()

	bw := bufio.NewWriter(fp)

	if debug {
		var bs []byte
		bs, err = json.MarshalIndent(entries, "", "\t")

		bw.Write(bs)
		bw.Flush()

		return err
	}

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

			// version: 3.10.0
			binary.Write(bw, binary.LittleEndian, uint16(len(subentry.Version)))
			bw.WriteString(subentry.Version)

			// number of tokens
			binary.Write(bw, binary.LittleEndian, uint8(len(subentry.Tokens)))

			for _, token := range subentry.Tokens {
				// token: on, ARM64, architecture
				binary.Write(bw, binary.LittleEndian, uint16(len(token)))
				bw.WriteString(token)
			}
		}
	}

	binary.Write(bw, binary.LittleEndian, uint32(0))

	bw.Flush()

	return err
}

// Entry point of the application.
func main() {
	if len(os.Args) < 3 {
		println("usage: cpe2hs [--json] input output")
		os.Exit(-1)
	}

	var err error
	var dbg bool

	if os.Args[1] == "--json" {
		dbg = true
		os.Args = os.Args[1:]
	}

	println("Parsing CPE dictionary...")

	if err = parseInput(os.Args[1]); err != nil {
		println(err)
		os.Exit(-1)
	}

	println("Writing parsed data...")

	if err = serializeEntries(os.Args[2], dbg); err != nil {
		println(err)
		os.Exit(-1)
	}
}