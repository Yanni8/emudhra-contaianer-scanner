package rpmdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// rpm's ndb package store (lib/backend/ndb/rpmpkg.c). All integers are
// little endian. The file starts with slot pages: a 32-byte header followed
// by 16-byte slots (magic, package index, block offset, block count). Blobs
// live after the slot pages at 16-byte block granularity, each preceded by
// a 16-byte header (magic, package index, generation, length).
const (
	ndbMagic          = "RpmP"
	ndbSlotMagic      = "Slot"
	ndbBlobMagic      = "BlbS"
	ndbVersion        = 0
	ndbHeaderSize     = 32
	ndbSlotSize       = 16
	ndbPageSize       = 4096
	ndbBlockSize      = 16
	ndbBlobHeaderSize = 16
	ndbMaxSlotPages   = 2048 // sanity bound: over half a million packages
)

// ndbSlot is one allocated slot.
type ndbSlot struct {
	index  uint32 // package index (header number)
	blkOff uint32 // first block of the blob
	blkCnt uint32 // blocks occupied by the blob
}

// parseNDB implements Parse for Packages.db.
func parseNDB(data []byte) ([]Package, error) {
	if len(data) < ndbHeaderSize || string(data[:4]) != ndbMagic {
		return nil, errors.New("not an rpm ndb database")
	}
	if v := binary.LittleEndian.Uint32(data[4:8]); v != ndbVersion {
		return nil, fmt.Errorf("%w: ndb version %d", ErrUnsupported, v)
	}
	slotPages := binary.LittleEndian.Uint32(data[12:16])
	if slotPages == 0 || slotPages > ndbMaxSlotPages {
		return nil, fmt.Errorf("implausible slot page count %d", slotPages)
	}
	slotEnd := int(slotPages) * ndbPageSize
	if len(data) < slotEnd {
		return nil, fmt.Errorf("truncated: %d slot pages need %d bytes, file has %d", slotPages, slotEnd, len(data))
	}
	var slots []ndbSlot
	for off := ndbHeaderSize; off < slotEnd; off += ndbSlotSize {
		s := data[off : off+ndbSlotSize]
		if string(s[:4]) != ndbSlotMagic {
			return nil, fmt.Errorf("bad slot magic at offset %d", off)
		}
		slot := ndbSlot{
			index:  binary.LittleEndian.Uint32(s[4:8]),
			blkOff: binary.LittleEndian.Uint32(s[8:12]),
			blkCnt: binary.LittleEndian.Uint32(s[12:16]),
		}
		if slot.index == 0 || slot.blkOff == 0 {
			continue // unused slot
		}
		slots = append(slots, slot)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].index < slots[j].index })

	pkgs := make([]Package, 0, len(slots))
	for _, s := range slots {
		start := uint64(s.blkOff) * ndbBlockSize
		end := start + uint64(s.blkCnt)*ndbBlockSize
		if s.blkCnt == 0 || start < uint64(slotEnd) || end > uint64(len(data)) {
			return nil, fmt.Errorf("package %d: blocks %d+%d lie outside the file", s.index, s.blkOff, s.blkCnt)
		}
		blk := data[start:end]
		if string(blk[:4]) != ndbBlobMagic {
			return nil, fmt.Errorf("package %d: bad blob magic at offset %d", s.index, start)
		}
		if idx := binary.LittleEndian.Uint32(blk[4:8]); idx != s.index {
			return nil, fmt.Errorf("package %d: blob at offset %d belongs to package %d", s.index, start, idx)
		}
		blobLen := binary.LittleEndian.Uint32(blk[12:16])
		if uint64(blobLen) > uint64(len(blk)-ndbBlobHeaderSize) {
			return nil, fmt.Errorf("package %d: blob length %d exceeds its %d blocks", s.index, blobLen, s.blkCnt)
		}
		p, err := ParseHeader(blk[ndbBlobHeaderSize : ndbBlobHeaderSize+int(blobLen)])
		if err != nil {
			return nil, fmt.Errorf("package %d: %w", s.index, err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}
