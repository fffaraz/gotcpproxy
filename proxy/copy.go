package proxy

import (
	"fmt"
	"io"
	"log"
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
				printError(name, io.ErrShortWrite, stdoutMutex)
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
