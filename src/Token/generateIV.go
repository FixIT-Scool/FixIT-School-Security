package Encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Strutture dati per il sistema di ticketing

type TicketMarker struct {
	ID                string    `json:"id"`
	Signature         string    `json:"signature"`
	Timestamp         time.Time `json:"timestamp"`
	EntropyFingerprint string   `json:"entropy_fingerprint"`
	Version           string    `json:"version"`
	SchoolID          string    `json:"school_id"`
	TicketType        string    `json:"ticket_type"`
	ValidationHash    string    `json:"validation_hash"`
}

type MarkerGenerator struct {
	masterPassword    []byte
	salt              []byte
	derivedKey        []byte
	hmacKey           []byte
	encryptionKey     []byte
	keyDerivationAlgo string
	iterations        int
	version           string
}

type SignatureComponents struct {
	Timestamp      string
	RandomComponent string
	EntropyHash    string
	Counter        uint64
	MacAddress     string
	ProcessID      int
}

type ValidationRecord struct {
	MarkerID       string
	CreationTime   time.Time
	ValidUntil     time.Time
	IssuedBy       string
	VerificationCode string
	Metadata       map[string]interface{}
}

// Costanti di configurazione

const (
	VERSION                = "1.0.0"
	SALT_SIZE             = 32
	KEY_SIZE              = 64
	HMAC_KEY_SIZE         = 32
	ENCRYPTION_KEY_SIZE   = 32
	RANDOM_COMPONENT_SIZE = 32
	PBKDF2_ITERATIONS     = 100000
	SCRYPT_N              = 32768
	SCRYPT_R              = 8
	SCRYPT_P              = 1
	ARGON2_TIME           = 3
	ARGON2_MEMORY         = 64 * 1024
	ARGON2_THREADS        = 4
	MARKER_PREFIX         = "SCHOOL-TICKET"
	MARKER_SEPARATOR      = "-"
)

// Funzioni di utilità crittografica

func generateSecureRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("errore generazione bytes casuali: %w", err)
	}
	return bytes, nil
}

func generateSecureSalt() ([]byte, error) {
	return generateSecureRandomBytes(SALT_SIZE)
}

func generateSecureRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}
	return string(result), nil
}

func hashWithSHA256(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func hashWithSHA512(data []byte) []byte {
	hasher := sha512.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func computeHMAC(data []byte, key []byte, hashFunc func() hash.Hash) []byte {
	mac := hmac.New(hashFunc, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func computeHMACSHA256(data []byte, key []byte) []byte {
	return computeHMAC(data, key, sha256.New)
}

func computeHMACSHA512(data []byte, key []byte) []byte {
	return computeHMAC(data, key, sha512.New)
}

// Funzioni di derivazione chiave

func deriveKeyPBKDF2(password []byte, salt []byte, iterations int, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha512.New)
}

func deriveKeyScrypt(password []byte, salt []byte, keyLen int) ([]byte, error) {
	key, err := scrypt.Key(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, keyLen)
	if err != nil {
		return nil, fmt.Errorf("errore scrypt: %w", err)
	}
	return key, nil
}

func deriveKeyArgon2(password []byte, salt []byte, keyLen int) []byte {
	return argon2.IDKey(password, salt, ARGON2_TIME, ARGON2_MEMORY, ARGON2_THREADS, uint32(keyLen))
}

// Funzioni di crittografia AES

func encryptAESGCM(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decryptAESGCM(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext troppo corto")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Costruttore MarkerGenerator

func NewMarkerGenerator(encryptedPassword string) (*MarkerGenerator, error) {
	salt, err := generateSecureSalt()
	if err != nil {
		return nil, fmt.Errorf("errore generazione salt: %w", err)
	}

	mg := &MarkerGenerator{
		masterPassword:    []byte(encryptedPassword),
		salt:              salt,
		keyDerivationAlgo: "argon2id",
		iterations:        PBKDF2_ITERATIONS,
		version:           VERSION,
	}

	if err := mg.deriveAllKeys(); err != nil {
		return nil, fmt.Errorf("errore derivazione chiavi: %w", err)
	}

	return mg, nil
}

func (mg *MarkerGenerator) deriveAllKeys() error {
	mg.derivedKey = deriveKeyArgon2(mg.masterPassword, mg.salt, KEY_SIZE)

	hmacSalt, err := generateSecureSalt()
	if err != nil {
		return err
	}
	mg.hmacKey = deriveKeyPBKDF2(mg.derivedKey, hmacSalt, mg.iterations, HMAC_KEY_SIZE)

	encSalt, err := generateSecureSalt()
	if err != nil {
		return err
	}
	mg.encryptionKey = deriveKeyPBKDF2(mg.derivedKey, encSalt, mg.iterations, ENCRYPTION_KEY_SIZE)

	return nil
}

// Generazione componenti firma

func (mg *MarkerGenerator) generateTimestampComponent() string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("%016x", timestamp)
}

func (mg *MarkerGenerator) generateRandomComponent() (string, error) {
	bytes, err := generateSecureRandomBytes(RANDOM_COMPONENT_SIZE)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (mg *MarkerGenerator) generateCounterComponent(counter uint64) string {
	return fmt.Sprintf("%016x", counter)
}

func (mg *MarkerGenerator) createEntropyHash(entropyData string) string {
	combined := append([]byte(entropyData), mg.salt...)
	hash := hashWithSHA512(combined)
	return hex.EncodeToString(hash)
}

func (mg *MarkerGenerator) generateProcessComponent() string {
	pid := os.Getpid()
	return fmt.Sprintf("%08x", pid)
}

func (mg *MarkerGenerator) generateUniqueIdentifier() (string, error) {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		return "", err
	}

	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

// Generazione ID marker principale

func (mg *MarkerGenerator) GenerateMarkerID(entropyData string, ticketType string, schoolID string) (*TicketMarker, error) {
	components := &SignatureComponents{
		Timestamp:      mg.generateTimestampComponent(),
		EntropyHash:    mg.createEntropyHash(entropyData),
		ProcessID:      os.Getpid(),
	}

	randComp, err := mg.generateRandomComponent()
	if err != nil {
		return nil, err
	}
	components.RandomComponent = randComp

	uuid, err := mg.generateUniqueIdentifier()
	if err != nil {
		return nil, err
	}

	markerID := fmt.Sprintf("%s%s%s%s%s%s%s",
		MARKER_PREFIX,
		MARKER_SEPARATOR,
		components.Timestamp,
		MARKER_SEPARATOR,
		randComp[:16],
		MARKER_SEPARATOR,
		uuid)

	signature, err := mg.signMarkerID(markerID, components, entropyData)
	if err != nil {
		return nil, err
	}

	validationHash := mg.createValidationHash(markerID, signature, schoolID)

	marker := &TicketMarker{
		ID:                markerID,
		Signature:         signature,
		Timestamp:         time.Now(),
		EntropyFingerprint: components.EntropyHash[:32],
		Version:           VERSION,
		SchoolID:          schoolID,
		TicketType:        ticketType,
		ValidationHash:    validationHash,
	}

	return marker, nil
}

func (mg *MarkerGenerator) signMarkerID(markerID string, components *SignatureComponents, entropyData string) (string, error) {
	dataToSign := fmt.Sprintf("%s|%s|%s|%s|%d|%s",
		markerID,
		components.Timestamp,
		components.RandomComponent,
		components.EntropyHash,
		components.ProcessID,
		entropyData)

	signature := computeHMACSHA512([]byte(dataToSign), mg.hmacKey)

	encryptedSig, err := encryptAESGCM(signature, mg.encryptionKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedSig), nil
}

func (mg *MarkerGenerator) createValidationHash(markerID, signature, schoolID string) string {
	combined := fmt.Sprintf("%s|%s|%s|%s", markerID, signature, schoolID, mg.version)
	hash := hashWithSHA256([]byte(combined))
	return hex.EncodeToString(hash)
}

// Funzioni di verifica

func (mg *MarkerGenerator) VerifyMarker(marker *TicketMarker) (bool, error) {
	if marker.Version != VERSION {
		return false, fmt.Errorf("versione non compatibile")
	}

	if time.Since(marker.Timestamp) > 24*time.Hour {
		return false, fmt.Errorf("marker scaduto")
	}

	expectedValidationHash := mg.createValidationHash(marker.ID, marker.Signature, marker.SchoolID)
	if marker.ValidationHash != expectedValidationHash {
		return false, fmt.Errorf("validation hash non corrisponde")
	}

	return true, nil
}

func (mg *MarkerGenerator) DecryptAndVerifySignature(encodedSignature string) ([]byte, error) {
	encryptedSig, err := base64.StdEncoding.DecodeString(encodedSignature)
	if err != nil {
		return nil, err
	}

	decryptedSig, err := decryptAESGCM(encryptedSig, mg.encryptionKey)
	if err != nil {
		return nil, err
	}

	return decryptedSig, nil
}

// Sistema di validazione e registrazione

type TicketRegistry struct {
	markers map[string]*ValidationRecord
	log     *log.Logger
}

func NewTicketRegistry() *TicketRegistry {
	return &TicketRegistry{
		markers: make(map[string]*ValidationRecord),
		log:     log.New(os.Stdout, "[TICKET-REGISTRY] ", log.LstdFlags),
	}
}

func (tr *TicketRegistry) RegisterMarker(marker *TicketMarker, validDuration time.Duration) error {
	if _, exists := tr.markers[marker.ID]; exists {
		return fmt.Errorf("marker già registrato")
	}

	verificationCode, err := generateSecureRandomString(32)
	if err != nil {
		return err
	}

	record := &ValidationRecord{
		MarkerID:       marker.ID,
		CreationTime:   marker.Timestamp,
		ValidUntil:     time.Now().Add(validDuration),
		IssuedBy:       marker.SchoolID,
		VerificationCode: verificationCode,
		Metadata: map[string]interface{}{
			"ticket_type":         marker.TicketType,
			"entropy_fingerprint": marker.EntropyFingerprint,
			"version":            marker.Version,
		},
	}

	tr.markers[marker.ID] = record
	tr.log.Printf("Marker registrato: %s", marker.ID)

	return nil
}

func (tr *TicketRegistry) ValidateMarker(markerID string) (bool, *ValidationRecord, error) {
	record, exists := tr.markers[markerID]
	if !exists {
		return false, nil, fmt.Errorf("marker non trovato")
	}

	if time.Now().After(record.ValidUntil) {
		return false, record, fmt.Errorf("marker scaduto")
	}

	return true, record, nil
}

func (tr *TicketRegistry) RevokeMarker(markerID string, reason string) error {
	record, exists := tr.markers[markerID]
	if !exists {
		return fmt.Errorf("marker non trovato")
	}

	record.ValidUntil = time.Now()
	record.Metadata["revoked"] = true
	record.Metadata["revoke_reason"] = reason

	tr.log.Printf("Marker revocato: %s - Motivo: %s", markerID, reason)

	return nil
}

// Funzioni di export/import

func (mg *MarkerGenerator) ExportMarkerToJSON(marker *TicketMarker) (string, error) {
	jsonData, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func (mg *MarkerGenerator) ImportMarkerFromJSON(jsonStr string) (*TicketMarker, error) {
	var marker TicketMarker
	if err := json.Unmarshal([]byte(jsonStr), &marker); err != nil {
		return nil, err
	}
	return &marker, nil
}

func (tr *TicketRegistry) ExportRegistry() (string, error) {
	data := make(map[string]interface{})
	data["markers"] = tr.markers
	data["export_time"] = time.Now()
	data["total_markers"] = len(tr.markers)

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// Funzioni di utilità avanzate

func (mg *MarkerGenerator) GenerateBatchMarkers(count int, entropyData string, ticketType string, schoolID string) ([]*TicketMarker, error) {
	markers := make([]*TicketMarker, 0, count)

	for i := 0; i < count; i++ {
		marker, err := mg.GenerateMarkerID(entropyData, ticketType, schoolID)
		if err != nil {
			return nil, fmt.Errorf("errore generazione marker %d: %w", i, err)
		}
		markers = append(markers, marker)

		time.Sleep(time.Microsecond)
	}

	return markers, nil
}

func (mg *MarkerGenerator) CreateSignedTicketData(marker *TicketMarker, ticketData map[string]interface{}) (string, error) {
	ticketData["marker_id"] = marker.ID
	ticketData["signature"] = marker.Signature
	ticketData["timestamp"] = marker.Timestamp

	jsonData, err := json.Marshal(ticketData)
	if err != nil {
		return "", err
	}

	signature := computeHMACSHA256(jsonData, mg.hmacKey)

	signedData := map[string]interface{}{
		"data":      base64.StdEncoding.EncodeToString(jsonData),
		"signature": hex.EncodeToString(signature),
		"algorithm": "HMAC-SHA256",
	}

	result, err := json.MarshalIndent(signedData, "", "  ")
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func (mg *MarkerGenerator) VerifySignedTicketData(signedDataJSON string) (map[string]interface{}, bool, error) {
	var signedData map[string]interface{}
	if err := json.Unmarshal([]byte(signedDataJSON), &signedData); err != nil {
		return nil, false, err
	}

	encodedData, ok := signedData["data"].(string)
	if !ok {
		return nil, false, fmt.Errorf("data non valido")
	}

	encodedSig, ok := signedData["signature"].(string)
	if !ok {
		return nil, false, fmt.Errorf("signature non valida")
	}

	jsonData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, false, err
	}

	providedSig, err := hex.DecodeString(encodedSig)
	if err != nil {
		return nil, false, err
	}

	expectedSig := computeHMACSHA256(jsonData, mg.hmacKey)

	if !hmac.Equal(providedSig, expectedSig) {
		return nil, false, nil
	}

	var ticketData map[string]interface{}
	if err := json.Unmarshal(jsonData, &ticketData); err != nil {
		return nil, false, err
	}

	return ticketData, true, nil
}

// Funzione main di esempio

func main() {
	fmt.Println("=== Sistema di Generazione Marker Univoci per Ticket Scolastici ===")
	fmt.Println()

	// Simulazione: in un'applicazione reale, questa password verrebbe
	// dall'entropy collector e dal crypto system
	encryptedPassword := "SIMULATED_ENCRYPTED_SEED_FROM_ENTROPY_SYSTEM_" + time.Now().Format("20060102150405")

	generator, err := NewMarkerGenerator(encryptedPassword)
	if err != nil {
		log.Fatalf("Errore inizializzazione generator: %v", err)
	}

	registry := NewTicketRegistry()

	// Simulazione dati entropy (in realtà vengono dal collector)
	simulatedEntropyData := fmt.Sprintf("entropy_%d_%s", time.Now().Unix(), generateSimulatedEntropy())

	fmt.Println("Generazione marker di test...")
	marker, err := generator.GenerateMarkerID(
		simulatedEntropyData,
		"PROBLEMA_TECNICO",
		"SCHOOL_001",
	)
	if err != nil {
		log.Fatalf("Errore generazione marker: %v", err)
	}

	fmt.Printf("\n✓ Marker generato con successo!\n")
	fmt.Printf("  ID: %s\n", marker.ID)
	fmt.Printf("  Timestamp: %s\n", marker.Timestamp.Format(time.RFC3339))
	fmt.Printf("  Tipo: %s\n", marker.TicketType)
	fmt.Printf("  School ID: %s\n", marker.SchoolID)
	fmt.Printf("  Validation Hash: %s...\n", marker.ValidationHash[:32])

	// Registrazione marker
	if err := registry.RegisterMarker(marker, 24*time.Hour); err != nil {
		log.Fatalf("Errore registrazione: %v", err)
	}
	fmt.Println("\n✓ Marker registrato nel registry")

	// Verifica marker
	valid, err := generator.VerifyMarker(marker)
	if err != nil {
		log.Printf("Errore verifica: %v", err)
	} else if valid {
		fmt.Println("✓ Marker verificato correttamente")
	}

	// Validazione nel registry
	isValid, record, err := registry.ValidateMarker(marker.ID)
	if err != nil {
		log.Printf("Errore validazione registry: %v", err)
	} else if isValid {
		fmt.Printf("✓ Marker valido fino a: %s\n", record.ValidUntil.Format(time.RFC3339))
		fmt.Printf("  Verification Code: %s\n", record.VerificationCode)
	}

	// Creazione ticket firmato
	ticketData := map[string]interface{}{
		"title":       "Problema connessione WiFi",
		"description": "La rete WiFi del laboratorio non funziona",
		"priority":    "ALTA",
		"room":        "LAB-INFORMATICA-1",
		"reporter":    "studente@scuola.it",
	}

	signedTicket, err := generator.CreateSignedTicketData(marker, ticketData)
	if err != nil {
		log.Fatalf("Errore creazione ticket firmato: %v", err)
	}

	fmt.Println("\n✓ Ticket firmato creato")
	fmt.Println("\nContenuto ticket firmato:")
	fmt.Println(signedTicket)

	// Verifica ticket firmato
	verifiedData, isAuthentic, err := generator.VerifySignedTicketData(signedTicket)
	if err != nil {
		log.Printf("Errore verifica ticket: %v", err)
	} else if isAuthentic {
		fmt.Println("\n✓ Firma del ticket verificata correttamente")
		fmt.Printf("  Titolo ticket: %v\n", verifiedData["title"])
		fmt.Printf("  Priorità: %v\n", verifiedData["priority"])
	}

	// Export JSON
	jsonMarker, err := generator.ExportMarkerToJSON(marker)
	if err != nil {
		log.Printf("Errore export JSON: %v", err)
	} else {
		fmt.Println("\n✓ Export JSON marker:")
		lines := strings.Split(jsonMarker, "\n")
		for i, line := range lines {
			if i < 10 {
				fmt.Println("  " + line)
			}
		}
		if len(lines) > 10 {
			fmt.Println("  ...")
		}
	}

	fmt.Println("\n=== Test completati con successo ===")
}

func generateSimulatedEntropy() string {
	bytes, _ := generateSecureRandomBytes(16)
	return hex.EncodeToString(bytes)
}