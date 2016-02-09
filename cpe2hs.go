package main

import (
	"os"
	"bufio"
	"strings"
	"io/ioutil"
	"encoding/xml"
	"encoding/binary"
)

var entries map[string]Entry

type Entry struct {
	name, cpe, vendor, product, version string
}

// Reads the specified XML file and sends the entries for processing.
func ParseInput(file string) error {
	var err error
	var fp *os.File

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

	entries = make(map[string]Entry)

	for _, cpe := range lst.Items {
		if len(cpe.Title) == 1 {
			ProcessEntry(cpe.Title[0].Name, cpe.Value)
		} else {
			for _, item := range cpe.Title {
				if item.Lang == "en-US" {
					ProcessEntry(item.Name, cpe.Value)
				}
			}
		}
	}

	return err
}

// Processes the specified CPE entry from the XML file and places
// it into the global variable `entries`.
func ProcessEntry(name string, cpe string) {
	elems := strings.Split(cpe, ":")

	if elems[1] != "/a" {
		return
	}

	vendor  := strings.Replace(elems[2], "_", " ", -1)
	product := strings.Replace(elems[3], "_", " ", -1)

	key := vendor + " " + product

	if _, err := entries[key]; err {
		return
	}

	entry := Entry{
		name:    name,
		cpe:     elems[0] + ":" + elems[1] + ":" + elems[2] + ":" + elems[3],
		vendor:  vendor,
		product: product,
	}

	entries[key] = entry
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
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.cpe)))
		bw.WriteString(entry.cpe)

		// vendor: igor sysoev
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.vendor)))
		bw.WriteString(entry.vendor)

		// product: nginx
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.product)))
		bw.WriteString(entry.product)

		// name: Nginx 0.1.0
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.name)))
		bw.WriteString(entry.name)
	}

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