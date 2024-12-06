package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acidvegas/golcg"
	"github.com/rivo/tview"
)

type Config struct {
	concurrency int
	timeout     time.Duration
	retries     int
	dnsServers  []string
	serverIndex int
	debug       bool
	outputFile  *os.File
	mu          sync.Mutex
}

type Stats struct {
	processed     uint64
	total         uint64
	lastProcessed uint64
	lastCheckTime time.Time
	success       uint64
	failed        uint64
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

func (c *Config) getNextServer() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.dnsServers) == 0 {
		return ""
	}

	server := c.dnsServers[c.serverIndex]
	c.serverIndex = (c.serverIndex + 1) % len(c.dnsServers)
	return server
}

func loadDNSServers(filename string) ([]string, error) {
	if filename == "" {
		return nil, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		server := strings.TrimSpace(scanner.Text())
		if server != "" && !strings.HasPrefix(server, "#") {
			if !strings.Contains(server, ":") {
				server += ":53"
			}
			servers = append(servers, server)
		}
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("no valid DNS servers found in file")
	}

	return servers, scanner.Err()
}

func lookupWithRetry(ip string, cfg *Config) ([]string, string, error) {
	server := cfg.getNextServer()
	if server == "" {
		return nil, "", fmt.Errorf("no DNS servers available")
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: cfg.timeout,
			}
			return d.DialContext(ctx, "udp", server)
		},
	}

	for i := 0; i < cfg.retries; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
		names, err := r.LookupAddr(ctx, ip)
		cancel()

		if err == nil {
			return names, server, nil
		}

		if i < cfg.retries-1 {
			server = cfg.getNextServer()
			if server == "" {
				return nil, "", fmt.Errorf("no more DNS servers available")
			}
			r = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: cfg.timeout,
					}
					return d.DialContext(ctx, "udp", server)
				},
			}
		}
	}
	return nil, "", fmt.Errorf("lookup failed after %d retries", cfg.retries)
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
		return "[green]" + ptr
	}

	var result strings.Builder
	lastEnd := 0

	for _, match := range matches {
		if match[0] > lastEnd {
			result.WriteString("[green]")
			result.WriteString(ptr[lastEnd:match[0]])
		}
		result.WriteString("[aqua]")
		result.WriteString(ptr[match[0]:match[1]])
		lastEnd = match[1]
	}

	if lastEnd < len(ptr) {
		result.WriteString("[green]")
		result.WriteString(ptr[lastEnd:])
	}

	finalResult := result.String()
	finalResult = strings.ReplaceAll(finalResult, ".in-addr.arpa", ".[blue]in-addr.arpa")
	finalResult = strings.ReplaceAll(finalResult, ".gov", ".[red]gov")
	finalResult = strings.ReplaceAll(finalResult, ".mil", ".[red]mil")

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
		var names []string
		var server string
		var err error
		timestamp := time.Now()

		if len(cfg.dnsServers) > 0 {
			names, server, err = lookupWithRetry(ip, cfg)
			if idx := strings.Index(server, ":"); idx != -1 {
				server = server[:idx]
			}
		} else {
			names, err = net.LookupAddr(ip)
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

		if len(names) == 0 {
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
		for _, name := range names {
			if cleaned := strings.TrimSpace(strings.TrimSuffix(name, ".")); cleaned != "" {
				ptr = cleaned
				break
			}
		}

		if ptr == "" {
			continue
		}

		writeNDJSON(cfg, timestamp, ip, server, ptr)

		timeStr := time.Now().Format("2006-01-02 15:04:05")

		var line string
		if len(cfg.dnsServers) > 0 {
			line = fmt.Sprintf("[gray]%s[-] [purple]%15s[-] [gray]│[-] [yellow]%15s[-] [gray]│[-] %s\n",
				timeStr,
				ip,
				server,
				colorizeIPInPtr(ptr, ip))
		} else {
			line = fmt.Sprintf("[gray]%s[-] [purple]%15s[-] [gray]│[-] %s\n",
				timeStr,
				ip,
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

func main() {
	concurrency := flag.Int("c", 100, "Concurrency level")
	timeout := flag.Duration("t", 2*time.Second, "Timeout for DNS queries")
	retries := flag.Int("r", 2, "Number of retries for failed lookups")
	dnsFile := flag.String("dns", "", "File containing DNS servers (one per line)")
	debug := flag.Bool("debug", false, "Show unsuccessful lookups")
	outputPath := flag.String("o", "", "Path to NDJSON output file")
	seed := flag.Int64("s", 0, "Seed for IP generation (0 for random)")
	shard := flag.String("shard", "", "Shard specification (e.g., 1/4 for first shard of 4)")
	flag.Parse()

	shardNum, totalShards, err := parseShardArg(*shard)
	if err != nil {
		fmt.Printf("Error parsing shard argument: %v\n", err)
		return
	}

	if *seed == 0 {
		*seed = time.Now().UnixNano()
	}

	cfg := &Config{
		concurrency: *concurrency,
		timeout:     *timeout,
		retries:     *retries,
		debug:       *debug,
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

	if *dnsFile != "" {
		servers, err := loadDNSServers(*dnsFile)
		if err != nil {
			fmt.Printf("Error loading DNS servers: %v\n", err)
			return
		}
		cfg.dnsServers = servers
		fmt.Printf("Loaded %d DNS servers\n", len(servers))
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
		AddItem(progress, 3, 0, false)

	stats := &Stats{
		total:         1 << 32,
		lastCheckTime: time.Now(),
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
					if width == 0 {
						return
					}

					statsText := fmt.Sprintf(" [aqua]Count:[:-] [white]%s [gray]│[-] [aqua]Progress:[:-] [darkgray]%7.2f%%[-] [gray]│[-] [aqua]Rate:[:-] %s [gray]│[-] [aqua]Successful:[:-] [green]✓%s [-][darkgray](%5.1f%%)[-] [gray]│[-] [aqua]Failed:[:-] [red]✗%s [-][darkgray](%5.1f%%)[-] ",
						formatNumber(processed),
						percent,
						colorizeSpeed(avgSpeed),
						formatNumber(success),
						float64(success)/float64(processed)*100,
						formatNumber(failed),
						float64(failed)/float64(processed)*100)

					barWidth := width - visibleLength(statsText) - 2
					filled := int(float64(barWidth) * (percent / 100))
					if filled > barWidth {
						filled = barWidth
					}

					bar := strings.Builder{}
					bar.WriteString(statsText)
					bar.WriteString("[")
					bar.WriteString(strings.Repeat("█", filled))
					bar.WriteString(strings.Repeat("░", barWidth-filled))
					bar.WriteString("]")

					progress.Clear()
					fmt.Fprint(progress, bar.String())
				})
			}

			time.Sleep(100 * time.Millisecond)
		}
	}()

	stream, err := golcg.IPStream("0.0.0.0/0", shardNum, totalShards, int(*seed), nil)
	if err != nil {
		fmt.Printf("Error creating IP stream: %v\n", err)
		return
	}

	jobs := make(chan string, cfg.concurrency)

	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go worker(jobs, &wg, cfg, stats, textView, app)
	}

	go func() {
		for ip := range stream {
			jobs <- ip
		}
		close(jobs)
	}()

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
	formatted := strings.Join(parts, ",")

	totalWidth := len(fmt.Sprint(1<<32)) + 3
	for len(formatted) < totalWidth {
		formatted = " " + formatted
	}

	return formatted
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

func writeNDJSON(cfg *Config, timestamp time.Time, ip, server, ptr string) {
	if cfg.outputFile == nil {
		return
	}

	record := struct {
		Timestamp string `json:"timestamp"`
		IPAddr    string `json:"ip_addr"`
		DNSServer string `json:"dns_server"`
		PTRRecord string `json:"ptr_record"`
	}{
		Timestamp: timestamp.Format(time.RFC3339),
		IPAddr:    ip,
		DNSServer: server,
		PTRRecord: ptr,
	}

	if data, err := json.Marshal(record); err == nil {
		cfg.mu.Lock()
		cfg.outputFile.Write(data)
		cfg.outputFile.Write([]byte("\n"))
		cfg.mu.Unlock()
	}
}
