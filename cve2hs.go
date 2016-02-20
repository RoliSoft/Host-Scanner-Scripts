package main

import (
	"os"
	"bufio"
	"math"
	"strings"
	"net/url"
	"io/ioutil"
	"encoding/xml"
	"encoding/binary"
)

var entries entry

type entry struct {
	Items []struct {
		Name 	string `xml:"cve-id"`
		Summary string `xml:"summary"`
		Weakness struct {
			Name string `xml:"id,attr"`
		} `xml:"cwe"`
		Classification struct {
			Severity 				float64 `xml:"score"`
			AccessVector 			string `xml:"access-vector"`
			AccessComplexity 		string `xml:"access-complexity"`
			Authentication 			string `xml:"authentication"`
			ConfidentialityImpact 	string `xml:"confidentiality-impact"`
			IntegrityImpact 		string `xml:"integrity-impact"`
			AvailablityImpact 		string `xml:"availability-impact"`
		} `xml:"cvss>base_metrics"`
		Software []string `xml:"vulnerable-software-list>product"`
	} `xml:"entry"`
}

// Reads the specified XML file and sends the entries for processing.
func parseInput(file string) error {
	var err error
	var fp *os.File

	if fp, err = os.Open(file); err != nil {
		return err
	}

	defer fp.Close()

	txt, _ := ioutil.ReadAll(fp)

	if err = xml.Unmarshal(txt, &entries); err != nil {
		return err
	}

	return err
}

// Writes the globally loaded entries to the specified file.
func serializeEntries(file string) error {
	var err error
	var fp *os.File

	if fp, err = os.Create(file); err != nil {
		return err
	}

	defer fp.Close()

	bw := bufio.NewWriter(fp)

	// package type: CVE database
	binary.Write(bw, binary.LittleEndian, uint16(5))
	// package version
	binary.Write(bw, binary.LittleEndian, uint16(1))
	// number of entries
	binary.Write(bw, binary.LittleEndian, uint32(len(entries.Items)))

	wr := 0
	for _, entry := range entries.Items {
		// get the number of vulnerable software
		vs := 0
		for _, cpe := range entry.Software {
			if strings.HasPrefix(cpe, "cpe:/a:") || strings.HasPrefix(cpe, "cpe:/o:") {
				vs++
			}
		}

		if vs == 0 {
			continue
		}

		wr++

		// number of fields in entry
		binary.Write(bw, binary.LittleEndian, uint8(3))

		// CVE: CVE-2015-4000
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Name) - 4))
		bw.WriteString(entry.Name[4:])

		// severity: 4.3
		binary.Write(bw, binary.LittleEndian, uint8(math.Floor(entry.Classification.Severity)))
		binary.Write(bw, binary.LittleEndian, uint8((entry.Classification.Severity - math.Floor(entry.Classification.Severity)) * 10))

		// vulnerable software
		binary.Write(bw, binary.LittleEndian, uint16(vs))

		for _, cpe := range entry.Software {
			if strings.HasPrefix(cpe, "cpe:/a:") || strings.HasPrefix(cpe, "cpe:/o:") {
				cpe, _ = url.QueryUnescape(cpe)
				binary.Write(bw, binary.LittleEndian, uint16(len(cpe) - 5))
				bw.WriteString(cpe[5:])
			}
		}
	}

	binary.Write(bw, binary.LittleEndian, uint32(0))

	// go back to the entry count
	bw.Flush()
	fp.Seek(4, 0)

	// write number of actual written entries
	binary.Write(bw, binary.LittleEndian, uint32(wr))
	bw.Flush()

	return err
}

// Entry point of the application.
func main() {
	if len(os.Args) < 3 {
		println("usage: cve2hs input output")
		os.Exit(-1)
	}

	var err error

	println("Parsing CVE database...")

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