package proxy

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
)

func CopyConn(name string, dst io.Writer, src io.Reader, stdoutMutex *sync.Mutex) {
	buf := make([]byte, 64*1024)
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
			stdoutMutex.Lock()
			fmt.Println()
			log.Printf("%s  bytes: %d\n", name, nr)
			PrintByteArray(buf[:nr])
			stdoutMutex.Unlock()
			nw, err := dst.Write(buf[:nr])
			if err != nil {
				printError(name+" dst.Write", err, stdoutMutex)
				break
			}
			if nw != nr {
				// short write
				break
			}
		}
		if err != nil {
			printError(name+" src.Read", err, stdoutMutex)
			break
		}
	}
}

func printError(name string, err error, stdoutMutex *sync.Mutex) {
	stdoutMutex.Lock()
	defer stdoutMutex.Unlock()
	fmt.Println()
	log.Printf("%s  error: %v\n", name, err)
}

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
