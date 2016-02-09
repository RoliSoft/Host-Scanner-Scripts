package main

import (
	"os"
	"bufio"
	"io/ioutil"
	"encoding/xml"
	"encoding/binary"
	"strings"
	"math"
)

var entries Entry

type Entry struct {
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
func ParseInput(file string) error {
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
func SerializeEntries(file string) error {
	var err error
	var fp *os.File

	if fp, err = os.Create(file); err != nil {
		return err
	}

	defer fp.Close()

	bw := bufio.NewWriter(fp)

	// package type: CVE database
	binary.Write(bw, binary.LittleEndian, uint16(2))
	// package version
	binary.Write(bw, binary.LittleEndian, uint16(1))
	// number of entries
	binary.Write(bw, binary.LittleEndian, uint32(len(entries.Items)))

	for _, entry := range entries.Items {
		// number of fields in entry
		binary.Write(bw, binary.LittleEndian, uint8(3))

		// CVE: CVE-2015-4000
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Name) - 4))
		bw.WriteString(strings.TrimLeft(entry.Name, "CVE-"))
/*
		// CWE: CWE-310
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Weakness.Name) - 4))
		bw.WriteString(strings.TrimLeft(entry.Weakness.Name, "CWE-"))
*/
		// severity: 4.3
		binary.Write(bw, binary.LittleEndian, uint8(2))
		binary.Write(bw, binary.LittleEndian, uint8(math.Floor(entry.Classification.Severity)))
		binary.Write(bw, binary.LittleEndian, uint8((entry.Classification.Severity - math.Floor(entry.Classification.Severity)) * 10))

		// vulnerable software
		binary.Write(bw, binary.LittleEndian, uint16(len(entry.Software)))

		for _, cpe := range entry.Software {
			binary.Write(bw, binary.LittleEndian, uint16(len(cpe)))
			bw.WriteString(cpe)
		}
	}

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