package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acidvegas/golcg"
	"github.com/miekg/dns"
	"github.com/rivo/tview"
)

const defaultResolversURL = "https://raw.githubusercontent.com/trickest/resolvers/refs/heads/main/resolvers.txt"

type Config struct {
	concurrency   int
	timeout       time.Duration
	retries       int
	dnsServers    []string
	serverIndex   int
	debug         bool
	outputFile    *os.File
	mu            sync.Mutex
	lastDNSUpdate time.Time
	updateMu      sync.Mutex
	loop          bool
}

type Stats struct {
	processed     uint64
	total         uint64
	lastProcessed uint64
	lastCheckTime time.Time
	startTime     time.Time
	success       uint64
	failed        uint64
	cnames        uint64
	speedHistory  []float64
	mu            sync.Mutex
}

func (s *Stats) increment() {
	atomic.AddUint64(&s.processed, 1)
}

func (s *Stats) incrementSuccess() {
	atomic.AddUint64(&s.success, 1)
}

func (s *Stats) incrementFailed() {
	atomic.AddUint64(&s.failed, 1)
}

func (s *Stats) incrementCNAME() {
	atomic.AddUint64(&s.cnames, 1)
}

func (c *Config) getNextServer() string {
	if err := c.updateDNSServers(); err != nil {
		fmt.Printf("Failed to update DNS servers: %v\n", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.dnsServers) == 0 {
		return ""
	}

	server := c.dnsServers[c.serverIndex]
	c.serverIndex = (c.serverIndex + 1) % len(c.dnsServers)
	return server
}

func fetchDefaultResolvers() ([]string, error) {
	resp, err := http.Get(defaultResolversURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch default resolvers: %v", err)
	}
	defer resp.Body.Close()

	var resolvers []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		resolver := strings.TrimSpace(scanner.Text())
		if resolver != "" {
			resolvers = append(resolvers, resolver)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading default resolvers: %v", err)
	}

	return resolvers, nil
}

func loadDNSServers(dnsFile string) ([]string, error) {
	if dnsFile == "" {
		resolvers, err := fetchDefaultResolvers()
		if err != nil {
			return nil, err
		}
		if len(resolvers) == 0 {
			return nil, fmt.Errorf("no default resolvers found")
		}
		return resolvers, nil
	}

	file, err := os.Open(dnsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open DNS servers file: %v", err)
	}
	defer file.Close()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		server := strings.TrimSpace(scanner.Text())
		if server != "" {
			servers = append(servers, server)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading DNS servers file: %v", err)
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("no DNS servers found in file")
	}

	return servers, nil
}

type DNSResponse struct {
	Names      []string
	Server     string
	RecordType string // "PTR" or "CNAME"
	Target     string // For CNAME records, stores the target
	TTL        uint32 // Add TTL field
}

func lookupWithRetry(ip string, cfg *Config) (DNSResponse, error) {
	var lastErr error

	for i := 0; i < cfg.retries; i++ {
		server := cfg.getNextServer()
		if server == "" {
			return DNSResponse{}, fmt.Errorf("no DNS servers available")
		}

		// Create DNS message
		m := new(dns.Msg)
		arpa, err := dns.ReverseAddr(ip)
		if err != nil {
			return DNSResponse{}, err
		}
		m.SetQuestion(arpa, dns.TypePTR)
		m.RecursionDesired = true

		// Create DNS client
		c := new(dns.Client)
		c.Timeout = cfg.timeout

		// Make the query
		r, _, err := c.Exchange(m, server)
		if err != nil {
			lastErr = err
			continue
		}

		if r.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS query failed with code: %d", r.Rcode)
			continue
		}

		logServer := server
		if idx := strings.Index(server, ":"); idx != -1 {
			logServer = server[:idx]
		}

		// Process the response
		if len(r.Answer) > 0 {
			var names []string
			var ttl uint32
			var isCNAME bool
			var target string

			for _, ans := range r.Answer {
				switch rr := ans.(type) {
				case *dns.PTR:
					names = append(names, rr.Ptr)
					ttl = rr.Hdr.Ttl
				case *dns.CNAME:
					isCNAME = true
					names = append(names, rr.Hdr.Name)
					target = rr.Target
					ttl = rr.Hdr.Ttl
				}
			}

			if len(names) > 0 {
				if isCNAME {
					return DNSResponse{
						Names:      names,
						Server:     logServer,
						RecordType: "CNAME",
						Target:     strings.TrimSuffix(target, "."),
						TTL:        ttl,
					}, nil
				}
				return DNSResponse{
					Names:      names,
					Server:     logServer,
					RecordType: "PTR",
					TTL:        ttl,
				}, nil
			}
		}

		lastErr = fmt.Errorf("no PTR records found")
	}

	return DNSResponse{}, lastErr
}

func reverse(ss []string) []string {
	reversed := make([]string, len(ss))
	for i, s := range ss {
		reversed[len(ss)-1-i] = s
	}
	return reversed
}

func colorizeIPInPtr(ptr, ip string) string {
	specialHosts := []string{"localhost", "undefined.hostname.localhost", "unknown"}
	for _, host := range specialHosts {
		if strings.EqualFold(ptr, host) {
			return "[gray]" + ptr
		}
	}

	octets := strings.Split(ip, ".")

	patterns := []string{
		strings.ReplaceAll(ip, ".", "\\."),
		strings.Join(reverse(strings.Split(ip, ".")), "\\."),
		strings.ReplaceAll(ip, ".", "-"),
		strings.Join(reverse(strings.Split(ip, ".")), "-"),
	}

	zeroPadded := make([]string, 4)
	for i, octet := range octets {
		zeroPadded[i] = fmt.Sprintf("%03d", parseInt(octet))
	}
	patterns = append(patterns,
		strings.Join(zeroPadded, "-"),
		strings.Join(reverse(zeroPadded), "-"),
	)

	pattern := strings.Join(patterns, "|")
	re := regexp.MustCompile("(" + pattern + ")")

	matches := re.FindAllStringIndex(ptr, -1)
	if matches == nil {
		return "[white]" + ptr
	}

	var result strings.Builder
	lastEnd := 0

	for _, match := range matches {
		if match[0] > lastEnd {
			result.WriteString("[white]")
			result.WriteString(ptr[lastEnd:match[0]])
		}
		result.WriteString("[aqua]")
		result.WriteString(ptr[match[0]:match[1]])
		lastEnd = match[1]
	}

	if lastEnd < len(ptr) {
		result.WriteString("[white]")
		result.WriteString(ptr[lastEnd:])
	}

	finalResult := result.String()

	if strings.HasSuffix(finalResult, ".in-addr.arpa") {
		finalResult = finalResult[:len(finalResult)-13] + ".[blue]in-addr.arpa"
	}
	if strings.HasSuffix(finalResult, ".gov") {
		finalResult = finalResult[:len(finalResult)-4] + ".[red]gov"
	}
	if strings.HasSuffix(finalResult, ".mil") {
		finalResult = finalResult[:len(finalResult)-4] + ".[red]mil"
	}

	return finalResult
}

func parseInt(s string) int {
	num := 0
	fmt.Sscanf(s, "%d", &num)
	return num
}

const maxBufferLines = 1000

func worker(jobs <-chan string, wg *sync.WaitGroup, cfg *Config, stats *Stats, textView *tview.TextView, app *tview.Application) {
	defer wg.Done()
	for ip := range jobs {
		timestamp := time.Now()
		var response DNSResponse
		var err error

		if len(cfg.dnsServers) > 0 {
			response, err = lookupWithRetry(ip, cfg)
		} else {
			names, err := net.LookupAddr(ip)
			if err == nil {
				response = DNSResponse{Names: names, RecordType: "PTR"}
			}
		}

		stats.increment()

		if err != nil {
			stats.incrementFailed()
			if cfg.debug {
				timestamp := time.Now().Format("2006-01-02 15:04:05")
				errMsg := err.Error()
				if idx := strings.LastIndex(errMsg, ": "); idx != -1 {
					errMsg = errMsg[idx+2:]
				}
				debugLine := fmt.Sprintf("[gray]%s[-] [purple]%15s[-] [gray]│[-] [red]%s[-]\n",
					timestamp,
					ip,
					errMsg)
				app.QueueUpdateDraw(func() {
					fmt.Fprint(textView, debugLine)
					textView.ScrollToEnd()
				})
			}
			continue
		}

		if len(response.Names) == 0 {
			stats.incrementFailed()
			if cfg.debug {
				timestamp := time.Now().Format("2006-01-02 15:04:05")
				debugLine := fmt.Sprintf("[gray]%s[-] [purple]%15s[-] [gray]│[-] [red]No PTR record[-]\n",
					timestamp,
					ip)
				app.QueueUpdateDraw(func() {
					fmt.Fprint(textView, debugLine)
					textView.ScrollToEnd()
				})
			}
			continue
		}

		stats.incrementSuccess()

		ptr := ""
		for _, name := range response.Names {
			if cleaned := strings.TrimSpace(strings.TrimSuffix(name, ".")); cleaned != "" {
				ptr = cleaned
				break
			}
		}

		if ptr == "" {
			continue
		}

		writeNDJSON(cfg, timestamp, ip, response.Server, ptr, response.RecordType, response.Target, response.TTL)

		timeStr := time.Now().Format("2006-01-02 15:04:05")
		recordTypeColor := "[blue] PTR [-]"
		if response.RecordType == "CNAME" {
			stats.incrementCNAME()
			recordTypeColor = "[fuchsia]CNAME[-]"
			ptr = fmt.Sprintf("%s -> %s", ptr, response.Target)
		}

		var line string
		if len(cfg.dnsServers) > 0 {
			line = fmt.Sprintf("[gray]%s [gray]│[-] [purple]%15s[-] [gray]│[-] [aqua]%-15s[-] [gray]│[-] %-5s [gray]│[-] %s [gray]│[-] %s\n",
				timeStr,
				ip,
				response.Server,
				recordTypeColor,
				colorizeTTL(response.TTL),
				colorizeIPInPtr(ptr, ip))
		} else {
			line = fmt.Sprintf("[gray]%s [gray]│[-] [purple]%15s[-] [gray]│[-] %-5s [gray]│[-] %s [gray]│[-] %s\n",
				timeStr,
				ip,
				recordTypeColor,
				colorizeTTL(response.TTL),
				colorizeIPInPtr(ptr, ip))
		}

		app.QueueUpdateDraw(func() {
			fmt.Fprint(textView, line)
			content := textView.GetText(false)
			lines := strings.Split(content, "\n")
			if len(lines) > maxBufferLines {
				newContent := strings.Join(lines[len(lines)-maxBufferLines:], "\n")
				textView.Clear()
				fmt.Fprint(textView, newContent)
			}
			textView.ScrollToEnd()
		})
	}
}

func parseShardArg(shard string) (int, int, error) {
	if shard == "" {
		return 1, 1, nil
	}

	parts := strings.Split(shard, "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid shard format (expected n/total)")
	}

	shardNum, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid shard number: %v", err)
	}

	totalShards, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid total shards: %v", err)
	}

	if shardNum < 1 || shardNum > totalShards {
		return 0, 0, fmt.Errorf("shard number must be between 1 and total shards")
	}

	return shardNum, totalShards, nil
}

func (c *Config) updateDNSServers() error {
	c.updateMu.Lock()
	defer c.updateMu.Unlock()

	if time.Since(c.lastDNSUpdate) < 24*time.Hour {
		return nil
	}

	resolvers, err := fetchDefaultResolvers()
	if err != nil {
		return err
	}

	if len(resolvers) == 0 {
		return fmt.Errorf("no resolvers found in update")
	}

	for i, server := range resolvers {
		if !strings.Contains(server, ":") {
			resolvers[i] = server + ":53"
		}
	}

	c.mu.Lock()
	c.dnsServers = resolvers
	c.serverIndex = 0
	c.lastDNSUpdate = time.Now()
	c.mu.Unlock()

	return nil
}

func main() {
	concurrency := flag.Int("c", 100, "Concurrency level")
	timeout := flag.Duration("t", 2*time.Second, "Timeout for DNS queries")
	retries := flag.Int("r", 2, "Number of retries for failed lookups")
	dnsFile := flag.String("dns", "", "File containing DNS servers (one per line)")
	debug := flag.Bool("debug", false, "Show unsuccessful lookups")
	outputPath := flag.String("o", "", "Path to NDJSON output file")
	seed := flag.Int64("s", 0, "Seed for IP generation (0 for random)")
	shard := flag.String("shard", "", "Shard specification (e.g., 1/4 for first shard of 4)")
	loop := flag.Bool("l", false, "Loop continuously after completion")
	flag.Parse()

	shardNum, totalShards, err := parseShardArg(*shard)
	if err != nil {
		fmt.Printf("Error parsing shard argument: %v\n", err)
		return
	}

	if *seed == 0 {
		*seed = time.Now().UnixNano()
	}

	servers, err := loadDNSServers(*dnsFile)
	if err != nil {
		fmt.Printf("Error loading DNS servers: %v\n", err)
		return
	}

	for i, server := range servers {
		if !strings.Contains(server, ":") {
			servers[i] = server + ":53"
		}
	}

	cfg := &Config{
		concurrency:   *concurrency,
		timeout:       *timeout,
		retries:       *retries,
		debug:         *debug,
		dnsServers:    servers,
		lastDNSUpdate: time.Now(),
		loop:          *loop,
	}

	if *outputPath != "" {
		f, err := os.OpenFile(*outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Printf("Error opening output file: %v\n", err)
			return
		}
		cfg.outputFile = f
		defer f.Close()
	}

	app := tview.NewApplication()

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() {
			app.Draw()
		})
	textView.SetBorder(true).SetTitle(" PTR Records ")

	progress := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	progress.SetBorder(true).SetTitle(" Progress ")

	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(textView, 0, 1, false).
		AddItem(progress, 4, 0, false)

	stats := &Stats{
		total:         1 << 32,
		lastCheckTime: time.Now(),
		startTime:     time.Now(),
	}

	go func() {
		const movingAverageWindow = 5
		stats.speedHistory = make([]float64, 0, movingAverageWindow)
		stats.lastCheckTime = time.Now()

		for {
			processed := atomic.LoadUint64(&stats.processed)
			success := atomic.LoadUint64(&stats.success)
			failed := atomic.LoadUint64(&stats.failed)

			now := time.Now()
			duration := now.Sub(stats.lastCheckTime).Seconds()

			if duration >= 1.0 {
				stats.mu.Lock()
				speed := float64(processed-stats.lastProcessed) / duration
				stats.speedHistory = append(stats.speedHistory, speed)
				if len(stats.speedHistory) > movingAverageWindow {
					stats.speedHistory = stats.speedHistory[1:]
				}

				var avgSpeed float64
				for _, s := range stats.speedHistory {
					avgSpeed += s
				}
				avgSpeed /= float64(len(stats.speedHistory))

				stats.lastProcessed = processed
				stats.lastCheckTime = now
				stats.mu.Unlock()

				percent := float64(processed) / float64(stats.total) * 100

				app.QueueUpdateDraw(func() {
					var width int
					_, _, width, _ = progress.GetInnerRect()
					if width <= 0 {
						return
					}

					// First line: stats
					statsLine := fmt.Sprintf(" [aqua]Elapsed:[:-] [white]%s [gray]│[-] [aqua]Count:[:-] [white]%s [gray]│[-] [aqua]Progress:[:-] [darkgray]%.2f%%[-] [gray]│[-] [aqua]Rate:[:-] %s [gray]│[-] [aqua]CNAMEs:[:-] [yellow]%s[-][darkgray] (%.1f%%)[-] [gray]│[-] [aqua]Successful:[:-] [green]✓ %s[-][darkgray] (%.1f%%)[-] [gray]│[-] [aqua]Failed:[:-] [red]✗ %s[-][darkgray] (%.1f%%)[-]\n",
						formatDuration(time.Since(stats.startTime)),
						formatNumber(processed),
						percent,
						colorizeSpeed(avgSpeed),
						formatNumber(atomic.LoadUint64(&stats.cnames)),
						float64(atomic.LoadUint64(&stats.cnames))/float64(processed)*100,
						formatNumber(success),
						float64(success)/float64(processed)*100,
						formatNumber(failed),
						float64(failed)/float64(processed)*100)

					// Second line: progress bar
					barWidth := width - 3 // -3 for the [] and space
					if barWidth < 1 {
						progress.Clear()
						fmt.Fprint(progress, statsLine)
						return
					}

					filled := int(float64(barWidth) * (percent / 100))
					if filled > barWidth {
						filled = barWidth
					}

					barLine := fmt.Sprintf(" [%s%s]",
						strings.Repeat("█", filled),
						strings.Repeat("░", barWidth-filled))

					// Combine both lines with explicit newline
					progress.Clear()
					fmt.Fprintf(progress, "%s%s", statsLine, barLine)
				})
			}

			time.Sleep(100 * time.Millisecond)
		}
	}()

	jobs := make(chan string, cfg.concurrency)

	go func() {
		for {
			stream, err := golcg.IPStream("0.0.0.0/0", shardNum, totalShards, int(*seed), nil)
			if err != nil {
				fmt.Printf("Error creating IP stream: %v\n", err)
				return
			}

			for ip := range stream {
				jobs <- ip
			}

			if !cfg.loop {
				break
			}
		}
		close(jobs)
	}()

	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go worker(jobs, &wg, cfg, stats, textView, app)
	}

	go func() {
		wg.Wait()
		app.Stop()
	}()

	if err := app.SetRoot(flex, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}

func formatNumber(n uint64) string {
	s := fmt.Sprint(n)
	parts := make([]string, 0)
	for i := len(s); i > 0; i -= 3 {
		start := i - 3
		if start < 0 {
			start = 0
		}
		parts = append([]string{s[start:i]}, parts...)
	}
	return strings.Join(parts, ",")
}

func colorizeSpeed(speed float64) string {
	switch {
	case speed >= 500:
		return fmt.Sprintf("[green]%5.0f/s[-]", speed)
	case speed >= 350:
		return fmt.Sprintf("[yellow]%5.0f/s[-]", speed)
	case speed >= 200:
		return fmt.Sprintf("[orange]%5.0f/s[-]", speed)
	case speed >= 100:
		return fmt.Sprintf("[red]%5.0f/s[-]", speed)
	default:
		return fmt.Sprintf("[gray]%5.0f/s[-]", speed)
	}
}

func visibleLength(s string) int {
	noColors := regexp.MustCompile(`\[[a-zA-Z:-]*\]`).ReplaceAllString(s, "")
	return len(noColors)
}

func writeNDJSON(cfg *Config, timestamp time.Time, ip, server, ptr, recordType, target string, ttl uint32) {
	if cfg.outputFile == nil {
		return
	}

	record := struct {
		Timestamp  string `json:"timestamp"`
		IPAddr     string `json:"ip_addr"`
		DNSServer  string `json:"dns_server"`
		PTRRecord  string `json:"ptr_record"`
		RecordType string `json:"record_type"`
		Target     string `json:"target,omitempty"`
		TTL        uint32 `json:"ttl"`
	}{
		Timestamp:  timestamp.Format(time.RFC3339),
		IPAddr:     ip,
		DNSServer:  server,
		PTRRecord:  ptr,
		RecordType: recordType,
		Target:     target,
		TTL:        ttl,
	}

	if data, err := json.Marshal(record); err == nil {
		cfg.mu.Lock()
		cfg.outputFile.Write(data)
		cfg.outputFile.Write([]byte("\n"))
		cfg.mu.Unlock()
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)

	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour

	hours := d / time.Hour
	d -= hours * time.Hour

	minutes := d / time.Minute
	d -= minutes * time.Minute

	seconds := d / time.Second

	var result string

	if days > 0 {
		if hours > 0 && minutes > 0 {
			result = fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
		} else if hours > 0 {
			result = fmt.Sprintf("%dd %dh", days, hours)
		} else {
			result = fmt.Sprintf("%dd", days)
		}
	} else if hours > 0 {
		if minutes > 0 {
			result = fmt.Sprintf("%dh %dm", hours, minutes)
		} else {
			result = fmt.Sprintf("%dh", hours)
		}
	} else if minutes > 0 {
		if seconds > 0 {
			result = fmt.Sprintf("%dm %ds", minutes, seconds)
		} else {
			result = fmt.Sprintf("%dm", minutes)
		}
	} else {
		result = fmt.Sprintf("%ds", seconds)
	}

	return result
}

func colorizeTTL(ttl uint32) string {
	switch {
	case ttl >= 86400: // 1 day or more
		return fmt.Sprintf("[#00FF00::b]%-6d[-]", ttl) // Bright green with bold
	case ttl >= 3600: // 1 hour or more
		return fmt.Sprintf("[yellow]%-6d[-]", ttl)
	case ttl >= 300: // 5 minutes or more
		return fmt.Sprintf("[orange]%-6d[-]", ttl)
	case ttl >= 60: // 1 minute or more
		return fmt.Sprintf("[red]%-6d[-]", ttl)
	default: // Less than 60 seconds
		return fmt.Sprintf("[gray]%-6d[-]", ttl)
	}
}
