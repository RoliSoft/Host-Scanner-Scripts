package main

import (
	"os"
	"bufio"
	"strings"
	"net/url"
	"io/ioutil"
	"encoding/xml"
	"encoding/binary"
)

var entries map[string]*entry

type entry struct {
	CPE string
	Versions []subentry
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

	key := strings.Join(elems[2:3], ":")

	var ent *entry
	var ok  bool

	if ent, ok = entries[key]; !ok {
		ent = &entry {
			CPE:      strings.Join(elems[0:3], ":"),
			Versions: make([]subentry, 0),
		}

		entries[key] = ent
	}

	ver := subentry {
		CPE:  strings.Join(elems[4:], ":"),
		Name: name,
	}

	ent.Versions = append(ent.Versions, ver)
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

		// number of versions
		binary.Write(bw, binary.LittleEndian, uint32(len(entry.Versions)))

		for _, subentry := range entry.Versions {
			// CPE: 3.10.0::~~~~arm64~
			binary.Write(bw, binary.LittleEndian, uint16(len(subentry.CPE)))
			bw.WriteString(subentry.CPE)

			// name: Linux Kernel 3.10.0 on ARM64 architecture
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