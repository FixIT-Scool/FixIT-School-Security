package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	mathrand "math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Strutture dati per la raccolta di entropy

type EntropyData struct {
	Timestamp          time.Time              `json:"timestamp"`
	SystemInfo         SystemInformation      `json:"system_info"`
	NetworkInfo        NetworkInformation     `json:"network_info"`
	ProcessInfo        ProcessInformation     `json:"process_info"`
	HardwareInfo       HardwareInformation    `json:"hardware_info"`
	EnvironmentInfo    EnvironmentInformation `json:"environment_info"`
	RandomSources      RandomSourcesData      `json:"random_sources"`
	TimingVariations   TimingData             `json:"timing_variations"`
	FileSystemInfo     FileSystemData         `json:"filesystem_info"`
	MemoryInfo         MemoryData             `json:"memory_info"`
	CombinedEntropyHash string                `json:"combined_entropy_hash"`
}

type SystemInformation struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Hostname     string `json:"hostname"`
	NumCPU       int    `json:"num_cpu"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	GOVersion    string `json:"go_version"`
	ProcessID    int    `json:"process_id"`
	ParentPID    int    `json:"parent_pid"`
	Username     string `json:"username"`
}

type NetworkInformation struct {
	Interfaces     []NetworkInterface `json:"interfaces"`
	LocalAddresses []string          `json:"local_addresses"`
	MACAddresses   []string          `json:"mac_addresses"`
	ConnectionHash string            `json:"connection_hash"`
}

type NetworkInterface struct {
	Name         string   `json:"name"`
	HardwareAddr string   `json:"hardware_addr"`
	IPAddresses  []string `json:"ip_addresses"`
	Flags        string   `json:"flags"`
	MTU          int      `json:"mtu"`
}

type ProcessInformation struct {
	CurrentPID    int      `json:"current_pid"`
	ParentPID     int      `json:"parent_pid"`
	ProcessList   []string `json:"process_list"`
	Goroutines    int      `json:"goroutines"`
	WorkingDir    string   `json:"working_dir"`
	ExecutablePath string  `json:"executable_path"`
}

type HardwareInformation struct {
	CPUInfo        CPUInfo  `json:"cpu_info"`
	MemoryStats    MemStats `json:"memory_stats"`
	DiskInfo       []DiskInfo `json:"disk_info"`
	RandomHWHash   string   `json:"random_hw_hash"`
}

type CPUInfo struct {
	NumCPU      int     `json:"num_cpu"`
	NumCores    int     `json:"num_cores"`
	ThreadCount int     `json:"thread_count"`
	UsageHash   string  `json:"usage_hash"`
}

type MemStats struct {
	Alloc         uint64 `json:"alloc"`
	TotalAlloc    uint64 `json:"total_alloc"`
	Sys           uint64 `json:"sys"`
	NumGC         uint32 `json:"num_gc"`
	HeapAlloc     uint64 `json:"heap_alloc"`
	HeapSys       uint64 `json:"heap_sys"`
	HeapInuse     uint64 `json:"heap_inuse"`
}

type DiskInfo struct {
	Path        string `json:"path"`
	SizeHash    string `json:"size_hash"`
	AccessTime  string `json:"access_time"`
}

type EnvironmentInformation struct {
	Variables    map[string]string `json:"variables"`
	Path         string           `json:"path"`
	TempDir      string           `json:"temp_dir"`
	HomeDir      string           `json:"home_dir"`
	EnvHash      string           `json:"env_hash"`
}

type RandomSourcesData struct {
	CryptoRandom    string `json:"crypto_random"`
	MathRandom      string `json:"math_random"`
	TimeBasedRandom string `json:"time_based_random"`
	MixedRandom     string `json:"mixed_random"`
	UUIDLike        string `json:"uuid_like"`
}

type TimingData struct {
	SystemTime        time.Time     `json:"system_time"`
	MonotonicTime     int64         `json:"monotonic_time"`
	NanosecondTime    int64         `json:"nanosecond_time"`
	ExecutionTimings  []int64       `json:"execution_timings"`
	JitterMeasurements []float64    `json:"jitter_measurements"`
	TimingHash        string        `json:"timing_hash"`
}

type FileSystemData struct {
	TempFiles       []string `json:"temp_files"`
	FileCount       int      `json:"file_count"`
	DirectoryTree   []string `json:"directory_tree"`
	FileSystemHash  string   `json:"filesystem_hash"`
}

type MemoryData struct {
	AllocatedMemory   uint64 `json:"allocated_memory"`
	FreeMemory        uint64 `json:"free_memory"`
	MemoryPattern     string `json:"memory_pattern"`
	GarbageCollections uint32 `json:"gc_count"`
}

// EntropyCollector principale

type EntropyCollector struct {
	data          *EntropyData
	mu            sync.Mutex
	logger        *log.Logger
	collectionTime time.Duration
	sources       []func() error
}

func NewEntropyCollector() *EntropyCollector {
	ec := &EntropyCollector{
		data:   &EntropyData{},
		logger: log.New(os.Stdout, "[ENTROPY] ", log.LstdFlags),
	}

	ec.sources = []func() error{
		ec.collectSystemInfo,
		ec.collectNetworkInfo,
		ec.collectProcessInfo,
		ec.collectHardwareInfo,
		ec.collectEnvironmentInfo,
		ec.collectRandomSources,
		ec.collectTimingVariations,
		ec.collectFileSystemInfo,
		ec.collectMemoryInfo,
	}

	return ec
}

// Raccolta informazioni di sistema

func (ec *EntropyCollector) collectSystemInfo() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}

	ec.data.SystemInfo = SystemInformation{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		Hostname:     hostname,
		NumCPU:       runtime.NumCPU(),
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		GOVersion:    runtime.Version(),
		ProcessID:    os.Getpid(),
		ParentPID:    os.Getppid(),
		Username:     username,
	}

	ec.logger.Printf("Sistema: %s/%s, Hostname: %s, CPU: %d",
		runtime.GOOS, runtime.GOARCH, hostname, runtime.NumCPU())

	return nil
}

// Raccolta informazioni di rete

func (ec *EntropyCollector) collectNetworkInfo() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("errore lettura interfacce: %w", err)
	}

	netInfo := NetworkInformation{
		Interfaces:     make([]NetworkInterface, 0),
		LocalAddresses: make([]string, 0),
		MACAddresses:   make([]string, 0),
	}

	var hashData strings.Builder

	for _, iface := range interfaces {
		netIface := NetworkInterface{
			Name:         iface.Name,
			HardwareAddr: iface.HardwareAddr.String(),
			IPAddresses:  make([]string, 0),
			Flags:        iface.Flags.String(),
			MTU:          iface.MTU,
		}

		if iface.HardwareAddr.String() != "" {
			netInfo.MACAddresses = append(netInfo.MACAddresses, iface.HardwareAddr.String())
			hashData.WriteString(iface.HardwareAddr.String())
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				addrStr := addr.String()
				netIface.IPAddresses = append(netIface.IPAddresses, addrStr)
				netInfo.LocalAddresses = append(netInfo.LocalAddresses, addrStr)
				hashData.WriteString(addrStr)
			}
		}

		netInfo.Interfaces = append(netInfo.Interfaces, netIface)
	}

	hash := sha512.Sum512([]byte(hashData.String()))
	netInfo.ConnectionHash = hex.EncodeToString(hash[:])

	ec.data.NetworkInfo = netInfo

	ec.logger.Printf("Rete: %d interfacce, %d indirizzi MAC",
		len(netInfo.Interfaces), len(netInfo.MACAddresses))

	return nil
}

// Raccolta informazioni sui processi

func (ec *EntropyCollector) collectProcessInfo() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	workDir, err := os.Getwd()
	if err != nil {
		workDir = "unknown"
	}

	execPath, err := os.Executable()
	if err != nil {
		execPath = "unknown"
	}

	processList := make([]string, 0)

	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		cmd := exec.Command("ps", "aux")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for i, line := range lines {
				if i < 50 && line != "" {
					processList = append(processList, line)
				}
			}
		}
	} else if runtime.GOOS == "windows" {
		cmd := exec.Command("tasklist")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for i, line := range lines {
				if i < 50 && line != "" {
					processList = append(processList, line)
				}
			}
		}
	}

	ec.data.ProcessInfo = ProcessInformation{
		CurrentPID:    os.Getpid(),
		ParentPID:     os.Getppid(),
		ProcessList:   processList,
		Goroutines:    runtime.NumGoroutine(),
		WorkingDir:    workDir,
		ExecutablePath: execPath,
	}

	ec.logger.Printf("Processi: PID=%d, Goroutines=%d, Processi elencati=%d",
		os.Getpid(), runtime.NumGoroutine(), len(processList))

	return nil
}

// Raccolta informazioni hardware

func (ec *EntropyCollector) collectHardwareInfo() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	cpuInfo := CPUInfo{
		NumCPU:      runtime.NumCPU(),
		NumCores:    runtime.NumCPU(),
		ThreadCount: runtime.GOMAXPROCS(0),
	}

	cpuHashData := fmt.Sprintf("%d-%d-%d-%d",
		cpuInfo.NumCPU, cpuInfo.NumCores, time.Now().UnixNano(), memStats.Alloc)
	cpuHash := sha512.Sum512([]byte(cpuHashData))
	cpuInfo.UsageHash = hex.EncodeToString(cpuHash[:32])

	diskInfo := make([]DiskInfo, 0)

	tempDir := os.TempDir()
	if info, err := os.Stat(tempDir); err == nil {
		sizeHash := sha512.Sum512([]byte(fmt.Sprintf("%d-%s", info.Size(), info.ModTime())))
		diskInfo = append(diskInfo, DiskInfo{
			Path:       tempDir,
			SizeHash:   hex.EncodeToString(sizeHash[:16]),
			AccessTime: info.ModTime().Format(time.RFC3339Nano),
		})
	}

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		if info, err := os.Stat(homeDir); err == nil {
			sizeHash := sha512.Sum512([]byte(fmt.Sprintf("%d-%s", info.Size(), info.ModTime())))
			diskInfo = append(diskInfo, DiskInfo{
				Path:       homeDir,
				SizeHash:   hex.EncodeToString(sizeHash[:16]),
				AccessTime: info.ModTime().Format(time.RFC3339Nano),
			})
		}
	}

	hwHashData := fmt.Sprintf("%s-%d-%d-%d",
		cpuInfo.UsageHash, memStats.TotalAlloc, memStats.Sys, time.Now().UnixNano())
	hwHash := sha512.Sum512([]byte(hwHashData))

	ec.data.HardwareInfo = HardwareInformation{
		CPUInfo: cpuInfo,
		MemoryStats: MemStats{
			Alloc:      memStats.Alloc,
			TotalAlloc: memStats.TotalAlloc,
			Sys:        memStats.Sys,
			NumGC:      memStats.NumGC,
			HeapAlloc:  memStats.HeapAlloc,
			HeapSys:    memStats.HeapSys,
			HeapInuse:  memStats.HeapInuse,
		},
		DiskInfo:     diskInfo,
		RandomHWHash: hex.EncodeToString(hwHash[:]),
	}

	ec.logger.Printf("Hardware: CPU=%d, Memoria Alloc=%d MB, GC=%d",
		cpuInfo.NumCPU, memStats.Alloc/(1024*1024), memStats.NumGC)

	return nil
}

// Raccolta variabili d'ambiente

func (ec *EntropyCollector) collectEnvironmentInfo() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	envVars := make(map[string]string)
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) == 2 {
			envVars[pair[0]] = pair[1]
		}
	}

	tempDir := os.TempDir()
	homeDir, _ := os.UserHomeDir()

	var envHashData strings.Builder
	for key, value := range envVars {
		envHashData.WriteString(key)
		envHashData.WriteString(value)
	}
	envHashData.WriteString(fmt.Sprintf("%d", time.Now().UnixNano()))

	envHash := sha512.Sum512([]byte(envHashData.String()))

	ec.data.EnvironmentInfo = EnvironmentInformation{
		Variables: envVars,
		Path:      os.Getenv("PATH"),
		TempDir:   tempDir,
		HomeDir:   homeDir,
		EnvHash:   hex.EncodeToString(envHash[:]),
	}

	ec.logger.Printf("Ambiente: %d variabili, TempDir=%s",
		len(envVars), tempDir)

	return nil
}

// Generazione sorgenti casuali

func (ec *EntropyCollector) collectRandomSources() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	cryptoBytes := make([]byte, 32)
	if _, err := rand.Read(cryptoBytes); err != nil {
		return err
	}

	mathrand.Seed(time.Now().UnixNano())
	mathBytes := make([]byte, 32)
	for i := range mathBytes {
		mathBytes[i] = byte(mathrand.Intn(256))
	}

	timeBytes := []byte(fmt.Sprintf("%d-%d-%d",
		time.Now().Unix(),
		time.Now().UnixNano(),
		time.Now().UnixMicro()))
	timeHash := sha512.Sum512(timeBytes)

	mixed := make([]byte, 32)
	for i := range mixed {
		mixed[i] = cryptoBytes[i] ^ mathBytes[i] ^ timeHash[i]
	}

	uuidBytes := make([]byte, 16)
	rand.Read(uuidBytes)
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		uuidBytes[0:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:16])

	ec.data.RandomSources = RandomSourcesData{
		CryptoRandom:    hex.EncodeToString(cryptoBytes),
		MathRandom:      hex.EncodeToString(mathBytes),
		TimeBasedRandom: hex.EncodeToString(timeHash[:32]),
		MixedRandom:     hex.EncodeToString(mixed),
		UUIDLike:        uuid,
	}

	ec.logger.Println("Random: Generati 5 tipi di dati casuali")

	return nil
}

// Raccolta variazioni temporali

func (ec *EntropyCollector) collectTimingVariations() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	now := time.Now()
	timings := make([]int64, 0, 100)
	jitter := make([]float64, 0, 100)

	for i := 0; i < 100; i++ {
		start := time.Now()
		time.Sleep(time.Microsecond)
		elapsed := time.Since(start).Nanoseconds()
		timings = append(timings, elapsed)

		if i > 0 {
			diff := math.Abs(float64(elapsed - timings[i-1]))
			jitter = append(jitter, diff)
		}
	}

	timingHashData := fmt.Sprintf("%d-%d-%v",
		now.Unix(), now.UnixNano(), timings)
	timingHash := sha512.Sum512([]byte(timingHashData))

	ec.data.TimingVariations = TimingData{
		SystemTime:        now,
		MonotonicTime:     now.Unix(),
		NanosecondTime:    now.UnixNano(),
		ExecutionTimings:  timings,
		JitterMeasurements: jitter,
		TimingHash:        hex.EncodeToString(timingHash[:]),
	}

	ec.logger.Printf("Timing: %d misurazioni, jitter medio=%.2fns",
		len(timings), calculateAverage(jitter))

	return nil
}

// Raccolta informazioni filesystem

func (ec *EntropyCollector) collectFileSystemInfo() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	tempDir := os.TempDir()
	tempFiles := make([]string, 0)

	files, err := ioutil.ReadDir(tempDir)
	if err == nil {
		for i, file := range files {
			if i < 20 {
				tempFiles = append(tempFiles, file.Name())
			}
		}
	}

	dirTree := make([]string, 0)
	workDir, _ := os.Getwd()
	filepath.Walk(workDir, func(path string, info os.FileInfo, err error) error {
		if len(dirTree) < 50 && err == nil {
			dirTree = append(dirTree, path)
		}
		return nil
	})

	fsHashData := strings.Join(append(tempFiles, dirTree...), "|")
	fsHashData += fmt.Sprintf("%d", time.Now().UnixNano())
	fsHash := sha512.Sum512([]byte(fsHashData))

	ec.data.FileSystemInfo = FileSystemData{
		TempFiles:      tempFiles,
		FileCount:      len(tempFiles),
		DirectoryTree:  dirTree,
		FileSystemHash: hex.EncodeToString(fsHash[:]),
	}

	ec.logger.Printf("FileSystem: %d file temp, %d directory analizzate",
		len(tempFiles), len(dirTree))

	return nil
}

// Raccolta informazioni memoria

func (ec *EntropyCollector) collectMemoryInfo() error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	pattern := make([]byte, 1024)
	rand.Read(pattern)
	patternHash := sha512.Sum512(pattern)

	ec.data.MemoryInfo = MemoryData{
		AllocatedMemory:   memStats.Alloc,
		FreeMemory:        memStats.Sys - memStats.Alloc,
		MemoryPattern:     hex.EncodeToString(patternHash[:32]),
		GarbageCollections: memStats.NumGC,
	}

	ec.logger.Printf("Memoria: Alloc=%d MB, Free=%d MB, GC=%d",
		memStats.Alloc/(1024*1024),
		(memStats.Sys-memStats.Alloc)/(1024*1024),
		memStats.NumGC)

	return nil
}

// Raccolta completa di tutti i dati

func (ec *EntropyCollector) CollectAll() (*EntropyData, error) {
	ec.logger.Println("Inizio raccolta entropy completa...")

	startTime := time.Now()

	ec.data.Timestamp = time.Now()

	var wg sync.WaitGroup
	errorsChan := make(chan error, len(ec.sources))

	for _, source := range ec.sources {
		wg.Add(1)
		go func(fn func() error) {
			defer wg.Done()
			if err := fn(); err != nil {
				errorsChan <- err
			}
		}(source)
	}

	wg.Wait()
	close(errorsChan)

	for err := range errorsChan {
		ec.logger.Printf("Errore durante raccolta: %v", err)
	}

	ec.data.CombinedEntropyHash = ec.generateCombinedHash()

	ec.collectionTime = time.Since(startTime)
	ec.logger.Printf("Raccolta completata in %v", ec.collectionTime)
	ec.logger.Printf("Hash entropy combinato: %s...", ec.data.CombinedEntropyHash[:32])

	return ec.data, nil
}

// Genera hash combinato di tutti i dati

func (ec *EntropyCollector) generateCombinedHash() string {
	var hashData strings.Builder

	hashData.WriteString(ec.data.SystemInfo.Hostname)
	hashData.WriteString(fmt.Sprintf("%d", ec.data.SystemInfo.ProcessID))
	hashData.WriteString(ec.data.NetworkInfo.ConnectionHash)
	hashData.WriteString(fmt.Sprintf("%d", ec.data.ProcessInfo.Goroutines))
	hashData.WriteString(ec.data.HardwareInfo.RandomHWHash)
	hashData.WriteString(ec.data.EnvironmentInfo.EnvHash)
	hashData.WriteString(ec.data.RandomSources.CryptoRandom)
	hashData.WriteString(ec.data.RandomSources.MixedRandom)
	hashData.WriteString(ec.data.TimingVariations.TimingHash)
	hashData.WriteString(ec.data.FileSystemInfo.FileSystemHash)
	hashData.WriteString(ec.data.MemoryInfo.MemoryPattern)
	hashData.WriteString(fmt.Sprintf("%d", time.Now().UnixNano()))

	hash := sha512.Sum512([]byte(hashData.String()))
	return hex.EncodeToString(hash[:])
}

// Export dei dati in JSON

func (ec *EntropyCollector) ExportJSON() (string, error) {
	jsonData, err := json.MarshalIndent(ec.data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("errore export JSON: %w", err)
	}
	return string(jsonData), nil
}

// Salva su file

func (ec *EntropyCollector) SaveToFile(filename string) error {
	jsonData, err := ec.ExportJSON()
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filename, []byte(jsonData), 0644); err != nil {
		return fmt.Errorf("errore scrittura file: %w", err)
	}

	ec.logger.Printf("Dati salvati su: %s", filename)
	return nil
}

// Genera seed per il crypto system

func (ec *EntropyCollector) GenerateSeed() (string, error) {
	if ec.data.CombinedEntropyHash == "" {
		return "", fmt.Errorf("nessun dato di entropy raccolto")
	}

	seedData := fmt.Sprintf("%s-%s-%s-%d",
		ec.data.CombinedEntropyHash,
		ec.data.RandomSources.CryptoRandom,
		ec.data.RandomSources.UUIDLike,
		time.Now().UnixNano())

	hash := sha512.Sum512([]byte(seedData))

	return hex.EncodeToString(hash[:]), nil
}

// Utility functions

func calculateAverage(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// Continuous collection mode

func (ec *EntropyCollector) StartContinuousCollection(interval time.Duration, callback func(*EntropyData)) {
	ec.logger.Printf("Avvio raccolta continua ogni %v", interval)

	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			data, err := ec.CollectAll()
			if err != nil {
				ec.logger.Printf("Errore raccolta continua: %v", err)
				continue
			}
			if callback != nil {
				callback(data)
			}
		}
	}()
}

