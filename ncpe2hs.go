package main

import (
	"os"
	"bufio"
	"regexp"
	"io/ioutil"
	"encoding/binary"
)

var entries []Entry

type Entry struct {
	Regex, CPE, Product, Version string
}

// Reads the specified file and sends the entries for processing.
func ParseInput(file string) error {
	var err error
	var fp *os.File

	if fp, err = os.Open(file); err != nil {
		return err
	}

	defer fp.Close()

	txt, _ := ioutil.ReadAll(fp)
	dat := string(txt)

	reme, _ := regexp.Compile(`(?m:^match.*m\|([^\|]+)\|[^\s]+(.+))`) // match entries
	resv, _ := regexp.Compile(`(?m:([pvihod]|cpe:)\/([^\/]+)\/)`) // match service info
	mc := reme.FindAllStringSubmatch(dat, -1)

	for _, m := range mc {
		entry := Entry {
			Regex: m[1],
		}

		ms := resv.FindAllStringSubmatch(m[2], -1)

		for _, s := range ms {
			switch s[1] {
			case "cpe:":
				entry.CPE = s[2]
			case "p":
				entry.Product = s[2]
			case "v":
				entry.Version = s[2]
			case "d":
				if len(entry.Product) == 0 {
					entry.Product = s[2]
				}
			}
		}

		entries = append(entries, entry)
	}

	return err
}

// Writes the globally loaded entries to the specified file.
func SerializeEntries(file string) error {
	var err error
	var fp *os.File

	if fp, err = os.Create(file); err != nil {
		return err
	}

	defer fp.Close()

	bw := bufio.NewWriter(fp)

	// package type: service regexes
	binary.Write(bw, binary.LittleEndian, uint16(15))
	// package version
	binary.Write(bw, binary.LittleEndian, uint16(1))
	// number of entries
	binary.Write(bw, binary.LittleEndian, uint32(len(entries)))

	for _, entry := range entries {
		// regex
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Regex)))
		bw.WriteString(entry.Regex)

		// cpe
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.CPE)))
		bw.WriteString(entry.CPE)

		// product
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Product)))
		bw.WriteString(entry.Product)

		// version
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Version)))
		bw.WriteString(entry.Version)
	}

	binary.Write(bw, binary.LittleEndian, uint32(0))

	bw.Flush()

	return err
}

// Entry point of the application.
func main() {
	if len(os.Args) < 3 {
		println("usage: ncpe2hs input output")
		os.Exit(-1)
	}

	var err error

	println("Parsing nmap service probes database...")

	if err = ParseInput(os.Args[1]); err != nil {
		println(err)
		os.Exit(-1)
	}

	println("Writing parsed data...")

	if err = SerializeEntries(os.Args[2]); err != nil {
		println(err)
		os.Exit(-1)
	}
}