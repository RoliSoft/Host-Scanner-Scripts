package main

import (
	"os"
	"bufio"
	"strings"
	"net/url"
	"encoding/binary"
)

var entries [][]string

// Reads the specified file and extracts the entries.
func parseInput(file string) error {
	var err   error
	var fp    *os.File
	var entry []string

	if fp, err = os.Open(file); err != nil {
		return err
	}

	defer fp.Close()

	entries = make([][]string, 0)

	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		ln := strings.TrimSpace(scanner.Text())

		if len(ln) == 0 {
			if len(entry) != 0 {
				entries = append(entries, entry)
				  entry = make([]string, 0)
			}
		} else if strings.HasPrefix(ln, "cpe:/a:") || strings.HasPrefix(ln, "cpe:/o:") {
			entry = append(entry, ln)
		}
	}

	err = scanner.Err()

	return err
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

	// package type: CPE aliases
	binary.Write(bw, binary.LittleEndian, uint16(2))
	// package version
	binary.Write(bw, binary.LittleEndian, uint16(1))
	// number of entries
	binary.Write(bw, binary.LittleEndian, uint32(len(entries)))

	for _, entry := range entries {
		// number of aliases in entry
		binary.Write(bw, binary.LittleEndian, uint16(len(entry)))

		for _, alias := range entry {
			alias, _ = url.QueryUnescape(alias)
			binary.Write(bw, binary.LittleEndian, uint16(len(alias) - 5))
			bw.WriteString(alias[5:])
		}
	}

	binary.Write(bw, binary.LittleEndian, uint32(0))

	bw.Flush()

	return err
}

// Entry point of the application.
func main() {
	if len(os.Args) < 3 {
		println("usage: cpealt2hs input output")
		os.Exit(-1)
	}

	var err error

	println("Parsing CPE aliases list...")

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