package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	duplicatesFlushThreshold = 10000
	duplicatesChanBuffer     = 50000
	duplicatesFilePrefix     = "/tmp/route_duplicates_"
)

type Stats struct {
	Success            int64
	AlreadyExist       int64
	NetworkUnreachable int64
	OperationNotPermit int64
	InvalidArgument    int64
	NoRouteToHost      int64
	UnknownError       int64

	dupChan        chan string
	writerDone     chan struct{}
	duplicatesFile *os.File
	filename       string
	closeOnce      sync.Once
}

func NewStats() *Stats {
	filename := fmt.Sprintf("%s%s.log", duplicatesFilePrefix, time.Now().Format("2006-01-02_15-04-05"))
	s := &Stats{
		dupChan:    make(chan string, duplicatesChanBuffer),
		writerDone: make(chan struct{}),
		filename:   filename,
	}
	go s.duplicatesWriter()
	return s
}

func (s *Stats) duplicatesWriter() {
	buffer := make([]string, 0, duplicatesFlushThreshold)

	flush := func() {
		if len(buffer) == 0 {
			return
		}

		if s.duplicatesFile == nil {
			file, err := os.Create(s.filename)
			if err != nil {
				log.Printf("Error creating duplicates file: %v\n", err)
				buffer = buffer[:0]
				return
			}
			s.duplicatesFile = file
		}

		writer := bufio.NewWriter(s.duplicatesFile)
		for _, dup := range buffer {
			if _, err := writer.WriteString(dup); err != nil {
				log.Printf("Error writing duplicate: %v", err)
			}
			if err := writer.WriteByte('\n'); err != nil {
				log.Printf("Error writing newline: %v", err)
			}
		}
		if err := writer.Flush(); err != nil {
			log.Printf("Error flushing duplicates file: %v", err)
		}
		buffer = buffer[:0]
	}

	for route := range s.dupChan {
		buffer = append(buffer, route)
		if len(buffer) >= duplicatesFlushThreshold {
			flush()
		}
	}

	flush()

	if s.duplicatesFile != nil {
		if err := s.duplicatesFile.Close(); err != nil {
			log.Printf("Error closing duplicates file: %v", err)
		}
		log.Printf("Duplicates written to: %s", s.filename)
	}

	close(s.writerDone)
}

func (s *Stats) AddSuccess() {
	atomic.AddInt64(&s.Success, 1)
}

func (s *Stats) AddAlreadyExist(route string) {
	atomic.AddInt64(&s.AlreadyExist, 1)
	s.dupChan <- route
}

func (s *Stats) AddError(errType string) {
	switch errType {
	case "network_unreachable":
		atomic.AddInt64(&s.NetworkUnreachable, 1)
	case "operation_not_permitted":
		atomic.AddInt64(&s.OperationNotPermit, 1)
	case "invalid_argument":
		atomic.AddInt64(&s.InvalidArgument, 1)
	case "no_route_to_host":
		atomic.AddInt64(&s.NoRouteToHost, 1)
	case "unknown":
		atomic.AddInt64(&s.UnknownError, 1)
	}
}

func (s *Stats) PrintStats() {
	success := atomic.LoadInt64(&s.Success)
	alreadyExist := atomic.LoadInt64(&s.AlreadyExist)
	networkUnreachable := atomic.LoadInt64(&s.NetworkUnreachable)
	operationNotPermit := atomic.LoadInt64(&s.OperationNotPermit)
	invalidArgument := atomic.LoadInt64(&s.InvalidArgument)
	noRouteToHost := atomic.LoadInt64(&s.NoRouteToHost)
	unknownError := atomic.LoadInt64(&s.UnknownError)

	var sb strings.Builder
	sb.WriteString("\n========== Statistics ==========\n")
	fmt.Fprintf(&sb, "Successfully added: %d\n", success)
	fmt.Fprintf(&sb, "Already existed (skipped): %d\n", alreadyExist)

	if networkUnreachable > 0 {
		fmt.Fprintf(&sb, "Network unreachable: %d\n", networkUnreachable)
	}
	if operationNotPermit > 0 {
		fmt.Fprintf(&sb, "Operation not permitted: %d\n", operationNotPermit)
	}
	if invalidArgument > 0 {
		fmt.Fprintf(&sb, "Invalid argument: %d\n", invalidArgument)
	}
	if noRouteToHost > 0 {
		fmt.Fprintf(&sb, "No route to host: %d\n", noRouteToHost)
	}
	if unknownError > 0 {
		fmt.Fprintf(&sb, "Unknown errors: %d\n", unknownError)
	}

	totalErrors := alreadyExist + networkUnreachable + operationNotPermit + invalidArgument + noRouteToHost + unknownError
	fmt.Fprintf(&sb, "Total processed: %d\n", success+totalErrors)
	sb.WriteString("================================")

	log.Print(sb.String())
}

func (s *Stats) Close() {
	s.closeOnce.Do(func() {
		close(s.dupChan)
		<-s.writerDone
	})
}

func classifyError(err error) string {
	errStr := err.Error()

	if strings.Contains(errStr, "file exists") {
		return "file_exists"
	}
	if strings.Contains(errStr, "network is unreachable") {
		return "network_unreachable"
	}
	if strings.Contains(errStr, "no such device") {
		return "no_such_device"
	}
	if strings.Contains(errStr, "operation not permitted") {
		return "operation_not_permitted"
	}
	if strings.Contains(errStr, "invalid argument") {
		return "invalid_argument"
	}
	if strings.Contains(errStr, "no route to host") {
		return "no_route_to_host"
	}

	return "unknown"
}
