package main

import (
	"os"
	"bufio"
	"regexp"
	"strconv"
	"io/ioutil"
	"encoding/binary"
)

var entries []Entry

type Entry struct {
	Ports []int
	Data string
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

	resc, _ := regexp.Compile(`(?m:^\s*#.*$)`) // strip comments
	reme, _ := regexp.Compile(`(?m:udp\s+((?:\d+\,)*\d+)\s+((?:".+"\s*)*))`) // match udp entries from port to payload
	resp, _ := regexp.Compile(`(?m:\s*,\s*)`) // split enumerated ports by separator
	remp, _ := regexp.Compile(`(?m:"(.+)")`) // match data within the quotes optionally spread across multiple lines

	dat = resc.ReplaceAllString(dat, " ")
	mc := reme.FindAllStringSubmatch(dat, -1)

	for _, m := range mc {
		entry := Entry { }

		// extract port numbers

		for _, port := range resp.Split(m[1], -1) {
			if i, e := strconv.Atoi(port); e == nil {
				entry.Ports = append(entry.Ports, i)
			}
		}

		// extract payload

		for _, data := range remp.FindAllStringSubmatch(m[2], -1) {
			entry.Data += data[1]
		}

		if unquoted, e := strconv.Unquote("\"" + entry.Data + "\""); e == nil {
			entry.Data = unquoted
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

	// package type: UDP payloads
	binary.Write(bw, binary.LittleEndian, uint16(10))
	// package version
	binary.Write(bw, binary.LittleEndian, uint16(1))
	// number of entries
	binary.Write(bw, binary.LittleEndian, uint32(len(entries)))

	for _, entry := range entries {
		// payload data
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Data)))
		bw.WriteString(entry.Data)

		// number of ports in entry
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Ports)))

		for _, port := range entry.Ports {
			binary.Write(bw, binary.LittleEndian, uint16(port))
		}
	}

	binary.Write(bw, binary.LittleEndian, uint32(0))

	bw.Flush()

	return err
}

// Entry point of the application.
func main() {
	if len(os.Args) < 3 {
		println("usage: nudp2hs input output")
		os.Exit(-1)
	}

	var err error

	println("Parsing nmap payloads database...")

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