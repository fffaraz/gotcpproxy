package proxy

import (
	"fmt"
	"strings"
)

func PrintByteArray(bytes []byte) {
	offset := 0
	base := 0
	index := 0
	for n := len(bytes); n > 0; offset, base = 0, base+16 {
		parts := []string{fmt.Sprintf("%08x:", base)}
		count := 16 - offset
		if count > n {
			count = n
		}
		ch := make([]byte, 17)
		ch[0] = ' '
		for i := 1; i <= offset; i++ {
			parts = append(parts, "  ")
			ch[i] = byte(' ')
		}
		for i := 0; i < count; i++ {
			c := bytes[index+i]
			parts = append(parts, fmt.Sprintf("%02x", c))
			if c < 32 || c >= 127 {
				c = byte('.')
			}
			ch[1+i+offset] = c
		}
		for i := offset + count; i < 16; i++ {
			parts = append(parts, "  ")
		}
		parts = append(parts, string(ch[:1+offset+count]))
		fmt.Println(strings.Join(parts, " "))
		index += count
		n -= count
	}
}
