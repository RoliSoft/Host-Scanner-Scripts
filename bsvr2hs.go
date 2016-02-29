package main

import (
	"io"
	"os"
	"bufio"
	"encoding/csv"
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

	r := csv.NewReader(fp)
	r.Comma = '\t'
	r.LazyQuotes = true

	for {
		record, err := r.Read()

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		entry := entry {
			Regex: 	 record[0],
			Product: record[2],
			Version: "$" + record[1],
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
		println("usage: bsvr2hs [--json] input output")
		os.Exit(-1)
	}

	var err error
	var dbg bool

	if os.Args[1] == "--json" {
		dbg = true
		os.Args = os.Args[1:]
	}

	println("Parsing Burp match rules...")

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