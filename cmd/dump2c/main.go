package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
)

type btfIterAttr struct {
	StartId   uint32
	NextId    uint32
	OpenFlags uint32
}

func findMember(needle string, st *btf.Struct) (btf.Member, bool) {
	for _, m := range st.Members {
		if m.Name == needle {
			return m, true
		}
	}
	return btf.Member{}, false
}

func findMapsSection(spec *btf.Spec) *btf.Datasec {
	iter := spec.Iterate()
	for iter.Next() {
		if dsec, ok := iter.Type.(*btf.Datasec); ok {
			if dsec.Name == ".maps" {
				return dsec
			}
		}
	}
	return nil
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: dump2c <map id> <name>")
	}

	mapId, _ := strconv.ParseInt(os.Args[1], 10, 32)
	typeName := os.Args[2]

	m, err := ebpf.NewMapFromID(ebpf.MapID(mapId))
	if err != nil {
		panic(err)
	}

	var attr btfIterAttr
	for {
		_, err := sys.BPF(sys.BPF_BTF_GET_NEXT_ID, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		if err != nil {
			break
		}
		attr.StartId = attr.NextId

		h, err := btf.NewHandleFromID(btf.ID(attr.NextId))
		if err == nil {
			spec := h.Spec()

			maps := findMapsSection(spec)
			if maps == nil {
				continue
			}

			for _, candidate := range maps.Vars {
				if v, ok := candidate.Type.(*btf.Var); ok {
					if strings.HasPrefix(v.Name, typeName) {
						s := v.Type.(*btf.Struct)

						// Try to find the key and value types. We ignore "untyped" maps
						// that only specify key_size/value_size
						keyMember, ok := findMember("key", s)
						if !ok {
							continue
						}
						keyType := keyMember.Type.(*btf.Pointer).Target
						keySize, _ := btf.Sizeof(keyType)

						valueMember, ok := findMember("value", s)
						if !ok {
							continue
						}
						valueType := valueMember.Type.(*btf.Pointer).Target
						valueSize, _ := btf.Sizeof(valueType)

						if int(m.KeySize()) != keySize || int(m.ValueSize()) != valueSize {
							fmt.Fprintf(os.Stderr, "Skipping candidate %q for %q, size mismatch %d/%d != %d/%d\n",
								v.Name, typeName, keySize, valueSize, m.KeySize(), m.ValueSize())
							continue
						}

						fmt.Fprintf(os.Stderr, "dumping map %q with map type %q, key %s, type %s\n", typeName, v.Name, keyType, valueType)
						dumpIt(m, keyType, valueType)
						return
					}
				}
			}
		} else {
			//fmt.Printf("NewHandle error: %s\n", err)
		}
	}
	panic("nothing found for " + typeName)

}

func typeName(typ btf.Type) string {
	switch typ := typ.(type) {
	case *btf.Struct:
		return "struct " + typ.Name
	case *btf.Union:
		return "union " + typ.Name
	case *btf.Typedef:
		return typ.Name
	default:
		panic(fmt.Sprintf("unhandled type %T", typ))
	}
}

func dumpIt(m *ebpf.Map, keyType btf.Type, valueType btf.Type) {
	var key, value []byte

	fmt.Printf("struct { %s key; %s value; } values[] = {\n", typeName(keyType), typeName(valueType))

	iter := m.Iterate()
	for iter.Next(&key, &value) {
		fmt.Printf("  {\n    .key = %s,\n", BtfBytesToCValue(keyType, key, 4))
		fmt.Printf("    .value = %s\n  },\n", BtfBytesToCValue(valueType, value, 4))
	}
	fmt.Println("};")

}

func BtfBytesToCValue(t btf.Type, val []byte, depth int) string {
	var sb strings.Builder
	btfBytesToCValue(&sb, t, val, depth)
	return sb.String()
}

func btfBytesToCValue(sb *strings.Builder, t btf.Type, val []byte, depth int) []byte {
	switch t := t.(type) {
	case *btf.Array:
		fmt.Fprint(sb, "{")
		for i := 0; i < int(t.Nelems); i++ {
			val = btfBytesToCValue(sb, t.Type, val, depth)
			if i+1 < int(t.Nelems) {
				fmt.Fprint(sb, ", ")
			}
		}
		fmt.Fprint(sb, "}")

	case *btf.Const:
		return btfBytesToCValue(sb, t.Type, val, 0)

	case *btf.Datasec:
		// Datasec isn't a C data type but a descriptor for a ELF section.
		return val

	case *btf.Enum:
		// TODO are enums always 32 bit?
		enumVal := int32(binary.LittleEndian.Uint32(val[:4]))
		for _, v := range t.Values {
			if v.Value == enumVal {
				fmt.Fprint(sb, v.Name)
				break
			}
		}
		return val[4:]

	case *btf.Float:
		switch t.Size {
		case 4:
			bits := binary.LittleEndian.Uint32(val[:4])
			fmt.Fprint(sb, math.Float32frombits(bits))
			return val[4:]
		case 8:
			bits := binary.LittleEndian.Uint64(val[:8])
			fmt.Fprint(sb, math.Float64frombits(bits))
			return val[8:]
		}

	case *btf.Func:
		// Can't print a function as value
		return val

	case *btf.FuncProto:
		// Can't print a func prototype on its own. print the btf.Func parent instread
		return val

	case *btf.Fwd:
		// Can't print a forward decleration as value
		return val

	case *btf.Int:
		//fmt.Fprintf(os.Stderr, "int, size: %d, len: %d\n", t.Size, len(val))
		if t.Encoding&btf.Bool > 0 {
			var boolVal bool
			for _, b := range val[:t.Size] {
				if b > 0 {
					boolVal = true
				}
			}

			fmt.Fprint(sb, boolVal)

		} else if t.Encoding&btf.Char > 0 {
			fmt.Fprint(sb, rune(val[0]))

		} else {
			var i uint64
			switch t.Size {
			case 1:
				i = uint64(val[0])
			case 2:
				i = uint64(binary.LittleEndian.Uint16(val[:2]))
			case 4:
				i = uint64(binary.LittleEndian.Uint32(val[:4]))
			case 8:
				i = uint64(binary.LittleEndian.Uint64(val[:8]))
			}

			if t.Encoding&btf.Signed == 0 {
				fmt.Fprint(sb, i)
			} else {
				fmt.Fprint(sb, int64(i))
			}
		}

		return val[t.Size:]

	case *btf.Pointer:
		return btfBytesToCValue(sb, t.Target, val, 0)

	case *btf.Restrict:
		return btfBytesToCValue(sb, t.Type, val, 0)

	case *btf.Struct:
		fmt.Fprint(sb, strings.Repeat(" ", depth), "{\n")
		//fmt.Fprint(sb, "struct ", t.Name, " {\n")

		var newVal []byte
		for _, m := range t.Members {
			if m.Name != "" {
				fmt.Fprint(sb, strings.Repeat(" ", depth+2))
				fmt.Fprint(sb, ".", m.Name, " = ")
			}

			off := m.Offset.Bytes()

			//fmt.Fprintf(os.Stderr, "field %s\n", m.Name)

			newVal = btfBytesToCValue(sb, m.Type, val[off:], depth)
			fmt.Fprint(sb, ",\n")
		}

		fmt.Fprint(sb, strings.Repeat(" ", depth), "}")
		return newVal

	case *btf.Typedef:
		return btfBytesToCValue(sb, t.Type, val, 0)

	case *btf.Union:
		first := true
		var newVal []byte
		for i, m := range t.Members {
			fmt.Fprint(sb, strings.Repeat(" ", depth+2))
			if !first {
				fmt.Fprint(sb, "// ")
			}

			if m.Name != "" {
				fmt.Fprint(sb, ".", m.Name, " = ")
			}

			off := m.Offset.Bytes()

			btfBytesToCValue(sb, m.Type, val[off:], depth+2)

			if i != len(t.Members)-1 {
				fmt.Fprint(sb, ",\n")
			}

			first = false
		}
		return newVal

	case *btf.Var:
		fmt.Fprint(sb, t.Name, " = ")
		return btfBytesToCValue(sb, t.Type, val, 0)

	case *btf.Void:
		fmt.Fprint(sb, "void")
		return val

	case *btf.Volatile:
		return btfBytesToCValue(sb, t.Type, val, 0)
	}

	return val
}
