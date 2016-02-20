package main

import (
	"os"
	"bufio"
	"strings"
	"io/ioutil"
	"encoding/xml"
	"encoding/binary"
)

var entries map[string]entry

type entry struct {
	Name, CPE, Vendor, Product, Version string
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

	entries = make(map[string]entry)

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
	elems := strings.Split(cpe, ":")

	if elems[1] != "/a" && elems[1] != "/o" {
		return
	}

	vendor  := strings.Replace(elems[2], "_", " ", -1)
	product := strings.Replace(elems[3], "_", " ", -1)

	key := vendor + " " + product

	if _, err := entries[key]; err {
		return
	}

	entry := entry {
		Name:    name,
		CPE:     elems[0] + ":" + elems[1] + ":" + elems[2] + ":" + elems[3],
		Vendor:  vendor,
		Product: product,
	}

	entries[key] = entry
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
		// number of fields in entry
		binary.Write(bw, binary.LittleEndian, uint8(4))

		// CPE: cpe:/a:igor_sysoev:nginx
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.CPE) - 5))
		bw.WriteString(entry.CPE[5:])

		// vendor: igor sysoev
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Vendor)))
		bw.WriteString(entry.Vendor)

		// product: nginx
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Product)))
		bw.WriteString(entry.Product)

		// name: Nginx 0.1.0
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Name)))
		bw.WriteString(entry.Name)
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