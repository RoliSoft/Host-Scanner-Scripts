package main

import (
	"os"
	"fmt"
	"bufio"
	"strings"
	"net/url"
	"io/ioutil"
	"database/sql"
	"encoding/xml"
	"encoding/json"

	_ "github.com/mattn/go-sqlite3"
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
func serializeEntries(file string, debug bool) error {
	var err error

	if debug {
		var fp *os.File

		if fp, err = os.Create(file); err != nil {
			return err
		}

		defer fp.Close()

		bw := bufio.NewWriter(fp)

		var bs []byte
		bs, err = json.MarshalIndent(entries, "", "\t")

		bw.Write(bs)
		bw.Flush()

		return err
	}

	var db *sql.DB
	var tx *sql.Tx
	var stm1, stm2 *sql.Stmt

	if db, err = sql.Open("sqlite3", file); err != nil {
		return err
	}

	defer db.Close()

	db.Exec(`create table vulns (id int not null, cve text, descr text, severity real, access char(1), primary key(id))`)
	db.Exec(`create table affected (vuln_id int not null, cpe text, foreign key(vuln_id) references vulns(id))`)
	db.Exec(`create index cpe_vuln_idx on affected (cpe collate nocase)`)

	if tx, err = db.Begin(); err != nil {
		return err
	}

	defer tx.Commit()

	stm1, _ = tx.Prepare("insert into vulns values (?, ?, ?, ?, ?)")
	stm2, _ = tx.Prepare("insert into affected values (?, ?)")

	defer stm1.Close()
	defer stm2.Close()

	for id, entry := range entries.Items {
		vs := 0
		for _, cpe := range entry.Software {
			if strings.HasPrefix(cpe, "cpe:/a:") || strings.HasPrefix(cpe, "cpe:/o:") {
				vs++
				break
			}
		}

		if vs == 0 {
			continue
		}

		if _, err = stm1.Exec(id, entry.Name[4:], entry.Summary, entry.Classification.Severity, strings.ToLower(entry.Classification.AccessVector)[:1]); err != nil {
			fmt.Printf("%#v\n", err);
			continue
		}

		for _, cpe := range entry.Software {
			if strings.HasPrefix(cpe, "cpe:/a:") || strings.HasPrefix(cpe, "cpe:/o:") {
				cpe, _ = url.QueryUnescape(cpe)

				if _, err = stm2.Exec(id, cpe[5:]); err != nil {
					fmt.Printf("%#v\n", err);
					continue
				}
			}
		}
	}

	tx.Exec(`vacuum;`)

	return err
}

// Entry point of the application.
func main() {
	if len(os.Args) < 3 {
		println("usage: cve2hs [--json] input output")
		os.Exit(-1)
	}

	var err error
	var dbg bool

	if os.Args[1] == "--json" {
		dbg = true
		os.Args = os.Args[1:]
	}

	println("Parsing CVE database...")

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