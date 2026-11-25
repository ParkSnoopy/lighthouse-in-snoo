//go:build ignore

// gen_platform_icons converts assets/icon/lighthouse-in-snoo.png using ImageMagick
// into all cross-platform icon formats required for Wayland, X11, Windows, and macOS:
//   - Embedded RGBA PNGs in internal/ui/assets/ (48, 128, 256, 512)
//   - Freedesktop hicolor PNG tree in assets/icon/hicolor/ (16..512)
//   - Windows multi-resolution ICO in assets/icon/lighthouse-in-snoo.ico (16..256)
//   - Windows COFF PE .syso resources in cmd/lighthouse-ui/icon_windows_{amd64,arm64}.syso
//   - macOS multi-resolution ICNS in assets/icon/lighthouse-in-snoo.icns (16..1024 + @2x)
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	sourcePNG = "assets/icon/lighthouse-in-snoo.png"
	appID     = "us.ireh.lighthouse"
)

func main() {
	if _, err := os.Stat(sourcePNG); err != nil {
		fatalf("missing source icon %s: %v", sourcePNG, err)
	}
	magickBin := findMagick()

	// 1. Generate high-quality Lanczos RGBA PNGs for every required dimension via ImageMagick.
	tmpDir, err := os.MkdirTemp("", "lighthouse-icons-*")
	if err != nil {
		fatalf("mkdtemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sizes := []int{16, 24, 32, 48, 64, 128, 256, 512, 1024}
	pngBySize := make(map[int][]byte, len(sizes))
	for _, sz := range sizes {
		dst := filepath.Join(tmpDir, fmt.Sprintf("icon-%d.png", sz))
		runMagick(magickBin,
			sourcePNG,
			"-filter", "Lanczos",
			"-resize", fmt.Sprintf("%dx%d", sz, sz),
			"-strip",
			"PNG32:"+dst,
		)
		data, readErr := os.ReadFile(dst)
		if readErr != nil {
			fatalf("read %s: %v", dst, readErr)
		}
		pngBySize[sz] = data
	}

	// 2. Write embedded runtime PNGs for internal/ui (X11/Windows/macOS runtime + Wayland XDG install).
	for _, item := range []struct {
		size int
		path string
	}{
		{48, "internal/ui/assets/icon-48.png"},
		{128, "internal/ui/assets/icon-128.png"},
		{256, "internal/ui/assets/icon-256.png"},
		{512, "internal/ui/assets/icon-512.png"},
	} {
		writeFile(item.path, pngBySize[item.size])
	}

	// 3. Write Freedesktop hicolor icon theme tree for Linux Wayland & X11 packaging.
	for _, sz := range []int{16, 32, 48, 64, 128, 256, 512} {
		p := filepath.Join("assets", "icon", "hicolor", fmt.Sprintf("%dx%d", sz, sz), "apps", appID+".png")
		writeFile(p, pngBySize[sz])
	}

	// 4. Generate Windows multi-resolution .ico (16, 24, 32, 48, 64, 128, 256) using ImageMagick.
	icoPath := filepath.Join("assets", "icon", "lighthouse-in-snoo.ico")
	runMagick(magickBin,
		sourcePNG,
		"-filter", "Lanczos",
		"-define", "icon:auto-resize=256,128,64,48,32,24,16",
		icoPath,
	)
	icoBytes, err := os.ReadFile(icoPath)
	if err != nil {
		fatalf("read %s: %v", icoPath, err)
	}

	// 5. Generate Windows COFF .syso PE icon resources (amd64 & arm64) from the ICO.
	// Go automatically links cmd/lighthouse-ui/icon_windows_<arch>.syso on GOOS=windows builds.
	for _, arch := range []struct {
		name      string
		machine   uint16
		relocType uint16
	}{
		{"amd64", 0x8664, 0x0003}, // IMAGE_FILE_MACHINE_AMD64 + IMAGE_REL_AMD64_ADDR32NB
		{"arm64", 0xAA64, 0x0002}, // IMAGE_FILE_MACHINE_ARM64 + IMAGE_REL_ARM64_ADDR32NB
	} {
		syso, buildErr := buildWindowsIconSYSO(icoBytes, arch.machine, arch.relocType)
		if buildErr != nil {
			fatalf("build %s syso: %v", arch.name, buildErr)
		}
		writeFile(filepath.Join("cmd", "lighthouse-ui", fmt.Sprintf("icon_windows_%s.syso", arch.name)), syso)
	}

	// 6. Generate macOS multi-resolution .icns (standard + @2x Retina PNG chunks).
	icnsBytes := buildMacOSICNS(pngBySize)
	writeFile(filepath.Join("assets", "icon", "lighthouse-in-snoo.icns"), icnsBytes)

	fmt.Println("Generated Wayland/X11 PNGs, Windows ICO + amd64/arm64 .syso, and macOS ICNS.")
}

func findMagick() string {
	for _, name := range []string{"magick", "convert"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	fatalf("ImageMagick ('magick' or 'convert') not found in PATH")
	return ""
}

func runMagick(bin string, args ...string) {
	cmd := exec.Command(bin, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		fatalf("%s %v failed: %v\n%s", bin, args, err, string(out))
	}
}

func writeFile(path string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

// buildMacOSICNS packs Apple modern PNG-based ICNS chunks (macOS 10.7+ through macOS 15+).
func buildMacOSICNS(pngBySize map[int][]byte) []byte {
	type chunk struct {
		osType string
		size   int
	}
	chunks := []chunk{
		{"icp4", 16},   // 16x16
		{"icp5", 32},   // 32x32
		{"icp6", 64},   // 64x64
		{"ic07", 128},  // 128x128
		{"ic08", 256},  // 256x256
		{"ic09", 512},  // 512x512
		{"ic10", 1024}, // 512x512@2x (1024x1024)
		{"ic11", 32},   // 16x16@2x
		{"ic12", 64},   // 32x32@2x
		{"ic13", 256},  // 128x128@2x
		{"ic14", 512},  // 256x256@2x
	}
	totalLen := uint32(8)
	for _, c := range chunks {
		totalLen += uint32(8 + len(pngBySize[c.size]))
	}
	buf := bytes.NewBuffer(make([]byte, 0, totalLen))
	buf.WriteString("icns")
	_ = binary.Write(buf, binary.BigEndian, totalLen)
	for _, c := range chunks {
		payload := pngBySize[c.size]
		buf.WriteString(c.osType)
		_ = binary.Write(buf, binary.BigEndian, uint32(8+len(payload)))
		buf.Write(payload)
	}
	return buf.Bytes()
}

type icoDirEntry struct {
	width       byte
	height      byte
	colorCount  byte
	reserved    byte
	planes      uint16
	bitCount    uint16
	bytesInRes  uint32
	imageOffset uint32
}

// buildWindowsIconSYSO builds a standard COFF .rsrc object file containing RT_ICON (type 3)
// and RT_GROUP_ICON (type 14, ID 1) resources from a Windows .ico payload.
func buildWindowsIconSYSO(ico []byte, machine, relocType uint16) ([]byte, error) {
	if len(ico) < 6 {
		return nil, fmt.Errorf("ico too short")
	}
	reserved := binary.LittleEndian.Uint16(ico[0:2])
	resType := binary.LittleEndian.Uint16(ico[2:4])
	count := int(binary.LittleEndian.Uint16(ico[4:6]))
	if reserved != 0 || resType != 1 || count == 0 || len(ico) < 6+count*16 {
		return nil, fmt.Errorf("invalid ico header (reserved=%d type=%d count=%d)", reserved, resType, count)
	}

	entries := make([]icoDirEntry, count)
	frames := make([][]byte, count)
	for i := 0; i < count; i++ {
		off := 6 + i*16
		e := icoDirEntry{
			width:       ico[off],
			height:      ico[off+1],
			colorCount:  ico[off+2],
			reserved:    ico[off+3],
			planes:      binary.LittleEndian.Uint16(ico[off+4 : off+6]),
			bitCount:    binary.LittleEndian.Uint16(ico[off+6 : off+8]),
			bytesInRes:  binary.LittleEndian.Uint32(ico[off+8 : off+12]),
			imageOffset: binary.LittleEndian.Uint32(ico[off+12 : off+16]),
		}
		if e.planes == 0 {
			e.planes = 1
		}
		if e.bitCount == 0 {
			e.bitCount = 32
		}
		end := uint64(e.imageOffset) + uint64(e.bytesInRes)
		if end > uint64(len(ico)) {
			return nil, fmt.Errorf("ico entry %d out of bounds", i)
		}
		entries[i] = e
		frames[i] = ico[e.imageOffset:end]
	}

	// Build RT_GROUP_ICON payload (6-byte header + N * 14-byte GRPICONDIRENTRY).
	grpBuf := bytes.NewBuffer(make([]byte, 0, 6+count*14))
	_ = binary.Write(grpBuf, binary.LittleEndian, uint16(0)) // Reserved
	_ = binary.Write(grpBuf, binary.LittleEndian, uint16(1)) // Type = Icon
	_ = binary.Write(grpBuf, binary.LittleEndian, uint16(count))
	for i, e := range entries {
		grpBuf.WriteByte(e.width)
		grpBuf.WriteByte(e.height)
		grpBuf.WriteByte(e.colorCount)
		grpBuf.WriteByte(0)
		_ = binary.Write(grpBuf, binary.LittleEndian, e.planes)
		_ = binary.Write(grpBuf, binary.LittleEndian, e.bitCount)
		_ = binary.Write(grpBuf, binary.LittleEndian, e.bytesInRes)
		_ = binary.Write(grpBuf, binary.LittleEndian, uint16(i+1)) // nID matches RT_ICON ID
	}
	grpData := grpBuf.Bytes()

	// Layout .rsrc section:
	//   Level 1 (Root): 2 entries -> Type 3 (RT_ICON), Type 14 (RT_GROUP_ICON)
	//   Level 2 (RT_ICON): count entries -> IDs 1..count
	//   Level 2 (RT_GROUP_ICON): 1 entry -> ID 1
	//   Level 3 (Languages): (count + 1) tables, each 1 entry -> Lang 0x0409 (en-US)
	//   Data Entries: (count + 1) IMAGE_RESOURCE_DATA_ENTRY structs (16 bytes each)
	//   Data Blobs: 4-byte aligned frame payloads + group payload
	const (
		dirHdrSize  = 16
		dirEntSize  = 8
		dataEntSize = 16
		subDirFlag  = uint32(0x80000000)
		rtIcon      = uint32(3)
		rtGroupIcon = uint32(14)
		langEnUS    = uint32(0x0409)
	)

	offRoot := uint32(0)
	offL2Icon := offRoot + dirHdrSize + 2*dirEntSize
	offL2Group := offL2Icon + dirHdrSize + uint32(count)*dirEntSize
	offL3Start := offL2Group + dirHdrSize + 1*dirEntSize
	l3TableSize := uint32(dirHdrSize + 1*dirEntSize)
	offDataEntStart := offL3Start + uint32(count+1)*l3TableSize
	offBlobsStart := offDataEntStart + uint32(count+1)*dataEntSize

	rsrc := &bytes.Buffer{}
	writeDirHeader := func(numID uint16) {
		_ = binary.Write(rsrc, binary.LittleEndian, uint32(0)) // Characteristics
		_ = binary.Write(rsrc, binary.LittleEndian, uint32(0)) // TimeDateStamp
		_ = binary.Write(rsrc, binary.LittleEndian, uint16(0)) // MajorVersion
		_ = binary.Write(rsrc, binary.LittleEndian, uint16(0)) // MinorVersion
		_ = binary.Write(rsrc, binary.LittleEndian, uint16(0)) // NumberOfNamedEntries
		_ = binary.Write(rsrc, binary.LittleEndian, numID)     // NumberOfIdEntries
	}
	writeDirEntry := func(id, offset uint32) {
		_ = binary.Write(rsrc, binary.LittleEndian, id)
		_ = binary.Write(rsrc, binary.LittleEndian, offset)
	}

	// Level 1: Root (IDs MUST be sorted ascending: 3 then 14).
	writeDirHeader(2)
	writeDirEntry(rtIcon, subDirFlag|offL2Icon)
	writeDirEntry(rtGroupIcon, subDirFlag|offL2Group)

	// Level 2: RT_ICON (IDs 1..count).
	writeDirHeader(uint16(count))
	for i := 0; i < count; i++ {
		writeDirEntry(uint32(i+1), subDirFlag|(offL3Start+uint32(i)*l3TableSize))
	}

	// Level 2: RT_GROUP_ICON (ID 1).
	writeDirHeader(1)
	writeDirEntry(1, subDirFlag|(offL3Start+uint32(count)*l3TableSize))

	// Level 3: Language tables (0..count-1 for icons, count for group icon).
	for i := 0; i < count+1; i++ {
		writeDirHeader(1)
		writeDirEntry(langEnUS, offDataEntStart+uint32(i)*dataEntSize)
	}

	// Compute blob offsets and write IMAGE_RESOURCE_DATA_ENTRY structs + relocation offsets.
	relocOffsets := make([]uint32, 0, count+1)
	blobCursor := offBlobsStart
	blobs := make([][]byte, 0, count+1)
	blobs = append(blobs, frames...)
	blobs = append(blobs, grpData)

	for i, blob := range blobs {
		dataEntryOff := offDataEntStart + uint32(i)*dataEntSize
		relocOffsets = append(relocOffsets, dataEntryOff)
		_ = binary.Write(rsrc, binary.LittleEndian, blobCursor)        // OffsetToData (relocated via ADDR32NB)
		_ = binary.Write(rsrc, binary.LittleEndian, uint32(len(blob))) // Size
		_ = binary.Write(rsrc, binary.LittleEndian, uint32(0))         // CodePage
		_ = binary.Write(rsrc, binary.LittleEndian, uint32(0))         // Reserved
		alignedLen := (uint32(len(blob)) + 3) &^ 3
		blobCursor += alignedLen
	}
	for _, blob := range blobs {
		rsrc.Write(blob)
		for rsrc.Len()%4 != 0 {
			rsrc.WriteByte(0)
		}
	}
	rsrcBytes := rsrc.Bytes()

	// Assemble COFF object:
	//   20-byte COFF File Header
	//   40-byte Section Header (".rsrc")
	//   rsrcBytes
	//   Relocations (10 bytes each, pointing to symbol 0 ".rsrc")
	//   Symbol Table (1 symbol, 18 bytes)
	//   String Table (4 bytes, value 4 = empty)
	const (
		coffHdrSize = 20
		secHdrSize  = 40
		relocSize   = 10
		symSize     = 18
	)
	ptrRawData := uint32(coffHdrSize + secHdrSize)
	ptrRelocs := ptrRawData + uint32(len(rsrcBytes))
	ptrSymTab := ptrRelocs + uint32(len(relocOffsets)*relocSize)

	out := &bytes.Buffer{}
	// COFF File Header
	_ = binary.Write(out, binary.LittleEndian, machine)
	_ = binary.Write(out, binary.LittleEndian, uint16(1)) // NumberOfSections
	_ = binary.Write(out, binary.LittleEndian, uint32(0)) // TimeDateStamp
	_ = binary.Write(out, binary.LittleEndian, ptrSymTab) // PointerToSymbolTable
	_ = binary.Write(out, binary.LittleEndian, uint32(1)) // NumberOfSymbols
	_ = binary.Write(out, binary.LittleEndian, uint16(0)) // SizeOfOptionalHeader
	_ = binary.Write(out, binary.LittleEndian, uint16(0)) // Characteristics

	// Section Header (".rsrc\0\0\0")
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0})
	_ = binary.Write(out, binary.LittleEndian, uint32(0))              // VirtualSize
	_ = binary.Write(out, binary.LittleEndian, uint32(0))              // VirtualAddress
	_ = binary.Write(out, binary.LittleEndian, uint32(len(rsrcBytes))) // SizeOfRawData
	_ = binary.Write(out, binary.LittleEndian, ptrRawData)             // PointerToRawData
	_ = binary.Write(out, binary.LittleEndian, ptrRelocs)              // PointerToRelocations
	_ = binary.Write(out, binary.LittleEndian, uint32(0))              // PointerToLinenumbers
	_ = binary.Write(out, binary.LittleEndian, uint16(len(relocOffsets)))
	_ = binary.Write(out, binary.LittleEndian, uint16(0))
	// IMAGE_SCN_CNT_INITIALIZED_DATA (0x40) | IMAGE_SCN_MEM_READ (0x40000000) | IMAGE_SCN_ALIGN_4BYTES (0x00300000)
	_ = binary.Write(out, binary.LittleEndian, uint32(0x40300040))

	// Section raw data
	out.Write(rsrcBytes)

	// Relocations
	for _, rOff := range relocOffsets {
		_ = binary.Write(out, binary.LittleEndian, rOff)      // VirtualAddress within .rsrc
		_ = binary.Write(out, binary.LittleEndian, uint32(0)) // SymbolTableIndex = 0 (".rsrc")
		_ = binary.Write(out, binary.LittleEndian, relocType)
	}

	// Symbol table: 1 section symbol ".rsrc"
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0})
	_ = binary.Write(out, binary.LittleEndian, uint32(0)) // Value
	_ = binary.Write(out, binary.LittleEndian, int16(1))  // SectionNumber (1-based)
	_ = binary.Write(out, binary.LittleEndian, uint16(0)) // Type
	out.WriteByte(3)                                      // StorageClass = IMAGE_SYM_CLASS_STATIC
	out.WriteByte(0)                                      // NumberOfAuxSymbols

	// String table (empty: 4-byte length = 4)
	_ = binary.Write(out, binary.LittleEndian, uint32(4))

	return out.Bytes(), nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen_platform_icons: "+format+"\n", args...)
	os.Exit(1)
}
