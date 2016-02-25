package main

import (
	"os"
	"path"
	"bufio"
	"regexp"
	"strconv"
	"io/ioutil"
	"encoding/json"
	"encoding/binary"
)

var entries []entry

type entry struct {
	Ports []int
	Data string
}

// Reads the specified files in the directory and sends the entries for processing.
func parseInput(dir string) error {
	var err error
	var fp  *os.File
	var ls  []os.FileInfo

	if ls, err = ioutil.ReadDir(dir); err != nil {
		return err
	}

	repn, _ := regexp.Compile(`_(\d+)(?:\.pkt|_)`) // match port number

	for _, f := range ls {
		if f.IsDir() || path.Ext(f.Name()) != ".pkt" {
			continue
		}

		entry := entry { }

		if mc := repn.FindAllStringSubmatch(f.Name(), -1); len(mc) > 0 {
			if i, e := strconv.Atoi(mc[0][1]); e == nil {
				entry.Ports = append(entry.Ports, i)
			}
		} else {
			continue
		}

		if fp, err = os.Open(path.Join(dir, f.Name())); err != nil {
			continue
		}

		txt, _ := ioutil.ReadAll(fp)
		dat := string(txt)

		fp.Close()

		entry.Data = dat

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
		println("usage: zudp2hs [--json] input output")
		os.Exit(-1)
	}

	var err error
	var dbg bool

	if os.Args[1] == "--json" {
		dbg = true
		os.Args = os.Args[1:]
	}

	println("Parsing zmap payloads database...")

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