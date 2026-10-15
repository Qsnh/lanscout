//go:build ignore

// gen_oui turns Wireshark's manuf file into oui.txt.gz, the vendor table
// the scanner embeds. Run it from this directory:
//
//	curl -LO https://www.wireshark.org/download/automated/data/manuf
//	go run gen_oui.go manuf
package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
)

// suffixes are the legal forms trimmed from vendor names, longest first.
var suffixes = regexp.MustCompile(`(?i)[\s,.]+(co\.?,?\s*ltd\.?|company\s+limited|corporation|incorporated|inc\.?|corp\.?|limited|ltd\.?|llc|gmbh(\s*&\s*co\.?\s*kg)?|s\.?a\.?|a/s|ag|b\.?v\.?|pty|s\.?r\.?l\.?|oy|ab|kg|plc|co\.?)\s*$`)

func clean(name string) string {
	name = strings.TrimSpace(name)
	for {
		trimmed := strings.TrimSpace(suffixes.ReplaceAllString(name, ""))
		if trimmed == name || trimmed == "" {
			break
		}
		name = trimmed
	}
	return strings.Trim(name, " ,.")
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: go run gen_oui.go manuf")
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 3 {
			continue
		}
		prefix := strings.TrimSpace(cols[0])
		bits := 24
		if i := strings.IndexByte(prefix, '/'); i >= 0 {
			fmt.Sscanf(prefix[i+1:], "%d", &bits)
			prefix = prefix[:i]
		}
		hex := strings.ToUpper(strings.ReplaceAll(prefix, ":", ""))
		hex = hex[:bits/4]
		name := clean(cols[2])
		if name == "" {
			name = strings.TrimSpace(cols[1])
		}
		lines = append(lines, fmt.Sprintf("%s\t%s", hex, name))
	}
	if err := sc.Err(); err != nil {
		log.Fatal(err)
	}
	sort.Strings(lines)

	out, err := os.Create("oui.txt.gz")
	if err != nil {
		log.Fatal(err)
	}
	zw, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
	for _, l := range lines {
		fmt.Fprintln(zw, l)
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := out.Close(); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d prefixes", len(lines))
}
