package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var timeout int64

// Store the result of a portscan
type scanRes struct {
	port int
	open int // 1 means open
}

func scanPort(host string, ports chan int, results chan scanRes) {
	for p := range ports {
		addr := fmt.Sprintf("%s:%d", host, p)
		dialer := net.Dialer{
			Timeout: time.Millisecond * time.Duration(timeout),
		}
		conn, err := dialer.Dial("tcp", addr)
		result := scanRes{port: p}
		if err == nil { // We have a succesful connection
			conn.Close()
			result.open = 1
		}
		results <- result // blocks worker until result is retrieved
	}
}

func scanHost(host string, ports []int, amountWorkers int) {
	start := time.Now()
	portsChan := make(chan int, 0)
	resultsChan := make(chan scanRes, 0)

	if len(ports) < amountWorkers {
		fmt.Println("Requested workers higher than ports. Capping workers")
		amountWorkers = len(ports)
	}

	fmt.Printf("[%s] Starting %d workers\n", host, amountWorkers)
	for i := 0; i < amountWorkers; i++ {
		go scanPort(host, portsChan, resultsChan)
	}

	// Feed the ports to the workers async
	go func() {
		for _, p := range ports {
			portsChan <- p
		}
	}()

	var result scanRes
	var amount_closed_ports int
	for i := 0; i < len(ports); i++ {
		result = <-resultsChan // blocks on getting each result
		if result.open == 1 {
			fmt.Printf("[%s] %d open\n", host, result.port)
		} else {
			amount_closed_ports++
		}
	}
	fmt.Printf("[%s] found %d closed ports\n", host, amount_closed_ports)

	duration := time.Since(start)
	fmt.Printf("[%s] Scan duration: %s\n", host, duration)
	close(portsChan)
	close(resultsChan)
}

func main() {
	var hosts string
	var portspec string
	var amountWorkers int

	flag.StringVar(&hosts, "hosts", "scanme.nmap.org", "provide one or more targets comma separated")
	flag.StringVar(&portspec, "ports", "1-100", "provide the ports to scan comma separated")
	flag.IntVar(&amountWorkers, "workers", 50, "Provide the amount of concurrent workers")
	flag.Int64Var(&timeout, "timeout", 5000, "Timeout in milliseconds")

	flag.Parse()

	var ports []int

	for _, p := range strings.Split(portspec, ",") {
		if strings.Index(p, "-") == -1 {
			portInt, err := strconv.Atoi(p)
			if err != nil {
				fmt.Printf("Failed to parse ports argument %q\n", err)
				return
			}
			ports = append(ports, portInt)
		} else {
			lowerUpper := strings.Split(p, "-")
			lowerPort, err := strconv.Atoi(lowerUpper[0])
			if err != nil {
				fmt.Printf("Failed to parse ports argument %q\n", err)
				return
			}
			upperPort, err := strconv.Atoi(lowerUpper[1])
			if err != nil {
				fmt.Printf("Failed to parse ports argument %q\n", err)
				return
			}
			for i := lowerPort; i < upperPort; i++ {
				ports = append(ports, i)
			}
		}
	}

	for _, host := range strings.Split(hosts, ",") {
		scanHost(host, ports, amountWorkers)
	}
}
