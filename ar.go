package main

import (
	"bufio"
	"debug/pe"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
)

const archiveHeaderMagic = "!<arch>\n"

func isArchive(pn string) (bool, error) {
	f, err := os.Open(pn)
	if err != nil {
		return false, err
	}
	defer f.Close()
	verb(3, "isArchive(%s) examining file", pn)
	var magbuf [len(archiveHeaderMagic)]byte
	if _, err := io.ReadFull(f, magbuf[:]); err != nil {
		return false, nil
	}
	if string(magbuf[:]) != archiveHeaderMagic {
		return false, nil
	}
	verb(3, "isArchive(%s) returns true", pn)
	return true, nil
}

func visitArchive(pn string) {
	ents, err := readArchiveEntries(pn)
	if err != nil {
		log.Fatalf("error reading %s: %v", pn, err)
	}
	f, err := os.Open(pn)
	if err != nil {
		log.Fatalf("error opening archive file %s: %v\n", pn, err)
	}
	defer f.Close()
	for k, ent := range ents {
		verb(1, "archive entry %d: name=%s offset=%d sizew=%d",
			k, ent.name, ent.offset, ent.size)
		fmt.Printf("\narchive element %s:\n", ent.name)
		sr := io.NewSectionReader(f, ent.offset, ent.size)
		f, err := pe.NewFile(sr)
		if err != nil {
			// silently skip
			continue
		}
		examine(f)
		f.Close()
	}
}

type archiveEntry struct {
	name   string
	offset int64
	size   int64
}

func readArchiveEntries(pn string) ([]archiveEntry, error) {
	args := []string{"tOv", pn}
	cmd := exec.Command("/usr/bin/ar", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	verb(2, "cmd started: ar %v", args)

	// 0          1      2   3  4   5     6     7        8
	// rw-r--r-- 0/0   1088 Dec 31 19:00 1969 _muldi3.o 0x386a

	//                           0     1      2      3     4     5     6      7      8
	are := regexp.MustCompile(`^\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+0x(\S+)\s*$`)
	rval := []archiveEntry{}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		verb(3, "line is %s", line)
		matched := are.FindStringSubmatch(line)
		if matched == nil {
			log.Fatalf("bad RE match for line: %s\n", line)
		}
		sstr := matched[1]
		nstr := matched[2]
		ostr := matched[3]
		sz, err := strconv.ParseInt(sstr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("reading archive: malformed size string %s", sstr)
		}
		of, err := strconv.ParseInt(ostr, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("reading archive: malformed offset string %s", sstr)
		}
		ent := archiveEntry{
			name:   nstr,
			offset: of,
			size:   sz,
		}
		rval = append(rval, ent)
	}
	return rval, nil
}
