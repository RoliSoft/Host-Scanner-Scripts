package main

import (
	"os"
	"bufio"
	"regexp"
	"io/ioutil"
	"encoding/json"
	"encoding/binary"
)

var entries []entry

type entry struct {
	Regex, CPE, Product, Version string
}

// Reads the specified file and sends the entries for processing.
func parseInput(file string) error {
	var err error
	var fp  *os.File

	if fp, err = os.Open(file); err != nil {
		return err
	}

	defer fp.Close()

	txt, _ := ioutil.ReadAll(fp)
	dat := string(txt)

	reme, _ := regexp.Compile(`(?m:^match\s+[^\s]+\s+m\|([^\|]+)\|(.*)$)`) // match entries with | ; go does
	rem2, _ := regexp.Compile(`(?m:^match\s+[^\s]+\s+m\=([^\=]+)\=(.*)$)`) // match entries with = ; not support
	rem3, _ := regexp.Compile(`(?m:^match\s+[^\s]+\s+m\%([^\%]+)\%(.*)$)`) // match entries with % ; backreferences
	resv, _ := regexp.Compile(`(?m:([pvihod]|cpe:)\/([^\/]+)\/)`) // match service info

	mc := reme.FindAllStringSubmatch(dat, -1)
	mc  = append(mc, rem2.FindAllStringSubmatch(dat, -1)...)
	mc  = append(mc, rem3.FindAllStringSubmatch(dat, -1)...)

	for _, m := range mc {
		entry := entry {
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
		println("usage: ncpe2hs [--json] input output")
		os.Exit(-1)
	}

	var err error
	var dbg bool

	if os.Args[1] == "--json" {
		dbg = true
		os.Args = os.Args[1:]
	}

	println("Parsing nmap service probes database...")

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