package main

import (
	"debug/pe"
	"flag"
	"fmt"
	"log"
	"os"
	"pedump/peflags"
	"unsafe"
)

var verbflag = flag.Int("v", 0, "Verbose trace output level")
var relocsflag = flag.Bool("r", false, "Dump relocations")
var symsflag = flag.Bool("t", false, "Dump symbols")
var secheadersflag = flag.Bool("h", false, "Dump section headers")
var fileheadersflag = flag.Bool("f", false, "Dump file headers")
var contentsflag = flag.Bool("s", false, "Dump section contents")
var groupsflag = flag.Bool("g", false, "Dump info on COMDAT groups")
var whichflag = flag.String("j", "", "Restrict reloc/data dump to specific named section")

func verb(vlevel int, s string, a ...interface{}) {
	if *verbflag >= vlevel {
		fmt.Printf(s, a...)
		fmt.Printf("\n")
	}
}

func secCharacteristicsToString(val uint32) string {
	rv := " "
	c := peflags.ScnFlag(val)
	if c&peflags.IMAGE_SCN_MEM_READ != 0 {
		rv += "R"
	}
	if c&peflags.IMAGE_SCN_MEM_EXECUTE != 0 {
		rv += "X"
	}
	if c&peflags.IMAGE_SCN_MEM_WRITE != 0 {
		rv += "W"
	}
	if (c & peflags.IMAGE_SCN_TYPE_NOPAD) == 0 {
		rv += " nopad"
	}
	if c&peflags.IMAGE_SCN_CNT_CODE != 0 {
		rv += " code"
	}
	if c&peflags.IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
		rv += " idata"
	}
	if c&peflags.IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
		rv += " uidata"
	}
	if c&peflags.IMAGE_SCN_LNK_COMDAT != 0 {
		rv += " COMDAT"
	}
	if c&peflags.IMAGE_SCN_MEM_DISCARDABLE != 0 {
		rv += " disc"
	}
	return rv
}

func dumpSectionHeader(idx int, s *pe.Section) {
	fmt.Printf("%3d: VirtSize=0x%08x Vaddr=0x%08x Size=0x%08x Offset=0x%08x |%s | %s\n", idx, s.VirtualSize, s.VirtualAddress, s.Size, s.Offset, secCharacteristicsToString(s.Characteristics), s.Name)
}

func examine(f *pe.File) {
	if *fileheadersflag {
		fmt.Printf("COFF file header:\n%+v\n\n", f.FileHeader)
		fmt.Printf("COFF optional header:\n%+v\n", f.OptionalHeader)
	}
	if *secheadersflag {
		fmt.Printf("Sections:\n")
	}
	comdatSections := make(map[uint16]struct{})
	for i, s := range f.Sections {
		if s.Characteristics&uint32(peflags.IMAGE_SCN_LNK_COMDAT) != 0 {
			comdatSections[uint16(i)] = struct{}{}
		}
		if *secheadersflag {
			dumpSectionHeader(i, s)
		}
		if *contentsflag {
			if *whichflag == "" || *whichflag == s.Name {
				fmt.Printf("\ncontents of section %s (idx %d):\n", s.Name, i)
				b, err := s.Data()
				if err != nil {
					fmt.Fprintf(os.Stderr, "can't read .rdata: %v\n", err)
				} else {
					const chunk = 20
					for len(b) > 0 {
						e := chunk
						if e > len(b) {
							e = len(b)
						}
						fmt.Printf("%+0v\n", b[0:e])
						b = b[e:]
					}
				}
			}
		}
	}

	if *symsflag {
		for i, numaux := 0, 0; i < len(f.COFFSymbols); i += numaux + 1 {
			pesym := &f.COFFSymbols[i]
			numaux = int(pesym.NumberOfAuxSymbols)
			sname, err := pesym.FullName(f.StringTable)
			if err != nil {
				sname = fmt.Sprintf("<name unpack error: %v>", err)
			}
			cd := ""
			if _, ok := comdatSections[uint16(pesym.SectionNumber-1)]; ok {
				cd = " COMDAT"
			}
			sc := peflags.SymClass(pesym.StorageClass)
			fmt.Printf("%3d: Sec=%04d Val=0x%08x Typ=%2d StClass=%10s | %s%s\n",
				i, pesym.SectionNumber, pesym.Value, pesym.Type, sc.String(), sname, cd)
		}
	}

	// Second pass for group info
	if *groupsflag {
		fmt.Printf("Symbols:\n")
		for i, numaux := 0, 0; i < len(f.COFFSymbols); i += numaux + 1 {
			pesym := &f.COFFSymbols[i]
			numaux = int(pesym.NumberOfAuxSymbols)
			sname, err := pesym.FullName(f.StringTable)
			if err != nil {
				sname = fmt.Sprintf("<name unpack error: %v>", err)
			}
			if _, iscomdat := comdatSections[uint16(pesym.SectionNumber-1)]; !iscomdat {
				continue
			}
			if pesym.StorageClass != uint8(peflags.IMAGE_SYM_CLASS_STATIC) {
				continue
			}
			if numaux == 0 {
				fmt.Printf("malformed COMDAT at sym %d (sec=%d), no aux, continuing...\n", i, pesym.SectionNumber)
				continue
			}
			type AuxFormat5 struct {
				Size           uint32
				NumRelocs      uint16
				NumLineNumbers uint16
				Checksum       uint32
				SecNum         uint16
				Selection      uint8
				Padding        [3]uint8
			}

			// This is pretty gross, but I don't see a cleaner way to
			// handle this short of updating debug/pe.
			pesymn := &f.COFFSymbols[i+1]
			up := unsafe.Pointer(pesymn)
			aux := (*AuxFormat5)(up)
			sel := peflags.ComdatSelection(aux.Selection)
			fmt.Printf("\nGROUP at sym %d %s: Sec=%d Selection=%s\n",
				i, sname, aux.SecNum, sel.String())
		}
	}
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("pedump: ")
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatalf("please supply single filename as arg\n")
	}
	if !*relocsflag && !*secheadersflag && !*fileheadersflag && !*contentsflag && !*symsflag {
		log.Fatal("select one of -r/-h/-s/-t to dump something")
	}
	for _, arg := range flag.Args() {

		isarch, err := isArchive(arg)
		if err != nil {
			log.Fatal("opening %s: %v", arg, err)
		}
		if isarch {
			visitArchive(arg)
			continue
		}
		f, err := pe.Open(arg)
		if err != nil {
			log.Fatal(err)
		}
		examine(f)
		f.Close()
	}
}
