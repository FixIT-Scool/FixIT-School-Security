package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Strutture dati per il sistema crittografico

type EncryptedSeed struct {
	CipherText      string    `json:"cipher_text"`
	Algorithm       string    `json:"algorithm"`
	KeyDerivation   string    `json:"key_derivation"`
	IV              string    `json:"iv"`
	Salt            string    `json:"salt"`
	HMAC            string    `json:"hmac"`
	Timestamp       time.Time `json:"timestamp"`
	Version         string    `json:"version"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type CryptoKeys struct {
	MasterKey       []byte
	EncryptionKey   []byte
	HMACKey         []byte
	DerivedKey      []byte
	Salt            []byte
	KeyDerivationAlgo string
	Iterations      int
}

type CryptoEncryptor struct {
	keys           *CryptoKeys
	logger         *log.Logger
	rsaPrivateKey  *rsa.PrivateKey
	rsaPublicKey   *rsa.PublicKey
	ecdsaPrivateKey *ecdsa.PrivateKey
	ecdsaPublicKey  *ecdsa.PublicKey
	version        string
}

type EncryptionMetadata struct {
	OriginalLength int       `json:"original_length"`
	EncryptionTime time.Time `json:"encryption_time"`
	KeyFingerprint string    `json:"key_fingerprint"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
	ChecksumSHA512 string    `json:"checksum_sha512"`
}

type MultiLayerEncryption struct {
	Layer1          EncryptedSeed `json:"layer1"`
	Layer2          EncryptedSeed `json:"layer2"`
	Layer3          EncryptedSeed `json:"layer3"`
	CombinedHMAC    string       `json:"combined_hmac"`
	EncryptionChain string       `json:"encryption_chain"`
}

// Costanti crittografiche

const (
	CRYPTO_VERSION         = "2.0.0"
	AES_KEY_SIZE          = 32
	HMAC_KEY_SIZE         = 64
	SALT_SIZE             = 32
	RSA_KEY_SIZE          = 4096
	PBKDF2_ITERATIONS     = 200000
	SCRYPT_N              = 65536
	SCRYPT_R              = 8
	SCRYPT_P              = 1
	ARGON2_TIME           = 4
	ARGON2_MEMORY         = 128 * 1024
	ARGON2_THREADS        = 8
	BCRYPT_COST           = 14
)

// Funzioni di utilità crittografica base

func generateCryptoRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, fmt.Errorf("errore generazione random: %w", err)
	}
	return bytes, nil
}

func generateCryptoSalt() ([]byte, error) {
	return generateCryptoRandomBytes(SALT_SIZE)
}

func hashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func hashSHA512(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

func computeHMACWithAlgo(data []byte, key []byte, hashFunc func() hash.Hash) []byte {
	h := hmac.New(hashFunc, key)
	h.Write(data)
	return h.Sum(nil)
}

func verifyHMAC(data []byte, key []byte, signature []byte, hashFunc func() hash.Hash) bool {
	expectedMAC := computeHMACWithAlgo(data, key, hashFunc)
	return hmac.Equal(signature, expectedMAC)
}

// Derivazione chiavi con algoritmi multipli

func deriveKeyWithPBKDF2(password []byte, salt []byte, iterations int, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha512.New)
}

func deriveKeyWithScrypt(password []byte, salt []byte, keyLen int) ([]byte, error) {
	return scrypt.Key(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, keyLen)
}

func deriveKeyWithArgon2(password []byte, salt []byte, keyLen int) []byte {
	return argon2.IDKey(password, salt, ARGON2_TIME, ARGON2_MEMORY, ARGON2_THREADS, uint32(keyLen))
}

func deriveKeyWithBcrypt(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, BCRYPT_COST)
}

// Costruttore CryptoEncryptor

func NewCryptoEncryptor(masterPassword string) (*CryptoEncryptor, error) {
	ce := &CryptoEncryptor{
		logger:  log.New(os.Stdout, "[CRYPTO] ", log.LstdFlags),
		version: CRYPTO_VERSION,
	}

	if err := ce.initializeKeys(masterPassword); err != nil {
		return nil, fmt.Errorf("errore inizializzazione chiavi: %w", err)
	}

	if err := ce.generateRSAKeys(); err != nil {
		return nil, fmt.Errorf("errore generazione RSA: %w", err)
	}

	if err := ce.generateECDSAKeys(); err != nil {
		return nil, fmt.Errorf("errore generazione ECDSA: %w", err)
	}

	ce.logger.Println("CryptoEncryptor inizializzato con successo")

	return ce, nil
}

func (ce *CryptoEncryptor) initializeKeys(masterPassword string) error {
	salt, err := generateCryptoSalt()
	if err != nil {
		return err
	}

	masterKey := deriveKeyWithArgon2([]byte(masterPassword), salt, 64)

	encryptionSalt, err := generateCryptoSalt()
	if err != nil {
		return err
	}
	encryptionKey := deriveKeyWithPBKDF2(masterKey, encryptionSalt, PBKDF2_ITERATIONS, AES_KEY_SIZE)

	hmacSalt, err := generateCryptoSalt()
	if err != nil {
		return err
	}
	hmacKey := deriveKeyWithPBKDF2(masterKey, hmacSalt, PBKDF2_ITERATIONS, HMAC_KEY_SIZE)

	derivedKey := deriveKeyWithArgon2(masterKey, salt, 64)

	ce.keys = &CryptoKeys{
		MasterKey:       masterKey,
		EncryptionKey:   encryptionKey,
		HMACKey:         hmacKey,
		DerivedKey:      derivedKey,
		Salt:            salt,
		KeyDerivationAlgo: "argon2id",
		Iterations:      PBKDF2_ITERATIONS,
	}

	return nil
}

// Generazione chiavi asimmetriche

func (ce *CryptoEncryptor) generateRSAKeys() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSA_KEY_SIZE)
	if err != nil {
		return fmt.Errorf("errore generazione RSA: %w", err)
	}

	ce.rsaPrivateKey = privateKey
	ce.rsaPublicKey = &privateKey.PublicKey

	ce.logger.Printf("Chiavi RSA-%d generate", RSA_KEY_SIZE)

	return nil
}

func (ce *CryptoEncryptor) generateECDSAKeys() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return fmt.Errorf("errore generazione ECDSA: %w", err)
	}

	ce.ecdsaPrivateKey = privateKey
	ce.ecdsaPublicKey = &privateKey.PublicKey

	ce.logger.Println("Chiavi ECDSA P-521 generate")

	return nil
}

// Crittografia AES-GCM

func (ce *CryptoEncryptor) encryptAESGCM(plaintext []byte, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

func (ce *CryptoEncryptor) decryptAESGCM(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Crittografia ChaCha20-Poly1305

func (ce *CryptoEncryptor) encryptChaCha20(plaintext []byte, key []byte) ([]byte, []byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		derivedKey := hashSHA256(key)
		key = derivedKey
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

func (ce *CryptoEncryptor) decryptChaCha20(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		derivedKey := hashSHA256(key)
		key = derivedKey
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Crittografia RSA-OAEP

func (ce *CryptoEncryptor) encryptRSA(plaintext []byte) ([]byte, error) {
	if ce.rsaPublicKey == nil {
		return nil, errors.New("chiave pubblica RSA non inizializzata")
	}

	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, ce.rsaPublicKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("errore encryption RSA: %w", err)
	}

	return ciphertext, nil
}

func (ce *CryptoEncryptor) decryptRSA(ciphertext []byte) ([]byte, error) {
	if ce.rsaPrivateKey == nil {
		return nil, errors.New("chiave privata RSA non inizializzata")
	}

	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, ce.rsaPrivateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("errore decryption RSA: %w", err)
	}

	return plaintext, nil
}

// Firma digitale ECDSA

func (ce *CryptoEncryptor) signECDSA(data []byte) (string, error) {
	if ce.ecdsaPrivateKey == nil {
		return "", errors.New("chiave privata ECDSA non inizializzata")
	}

	hash := sha512.Sum512(data)

	r, s, err := ecdsa.Sign(rand.Reader, ce.ecdsaPrivateKey, hash[:])
	if err != nil {
		return "", err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (ce *CryptoEncryptor) verifyECDSA(data []byte, signatureStr string) (bool, error) {
	if ce.ecdsaPublicKey == nil {
		return false, errors.New("chiave pubblica ECDSA non inizializzata")
	}

	signature, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return false, err
	}

	hash := sha512.Sum512(data)

	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	valid := ecdsa.Verify(ce.ecdsaPublicKey, hash[:], r, s)
	return valid, nil
}

// Crittografia principale del seed

func (ce *CryptoEncryptor) EncryptSeed(seed string) (*EncryptedSeed, error) {
	ce.logger.Printf("Inizio encryption seed (lunghezza: %d bytes)", len(seed))

	ciphertext, iv, err := ce.encryptAESGCM([]byte(seed), ce.keys.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("errore AES encryption: %w", err)
	}

	hmacValue := computeHMACWithAlgo(ciphertext, ce.keys.HMACKey, sha512.New)

	metadata := EncryptionMetadata{
		OriginalLength: len(seed),
		EncryptionTime: time.Now(),
		KeyFingerprint: hex.EncodeToString(hashSHA256(ce.keys.EncryptionKey)),
		ChecksumSHA256: hex.EncodeToString(hashSHA256([]byte(seed))),
		ChecksumSHA512: hex.EncodeToString(hashSHA512([]byte(seed))),
	}

	metadataMap := map[string]interface{}{
		"original_length": metadata.OriginalLength,
		"encryption_time": metadata.EncryptionTime,
		"key_fingerprint": metadata.KeyFingerprint,
		"checksum_sha256": metadata.ChecksumSHA256,
		"checksum_sha512": metadata.ChecksumSHA512,
	}

	encrypted := &EncryptedSeed{
		CipherText:    base64.StdEncoding.EncodeToString(ciphertext),
		Algorithm:     "AES-256-GCM",
		KeyDerivation: ce.keys.KeyDerivationAlgo,
		IV:            base64.StdEncoding.EncodeToString(iv),
		Salt:          base64.StdEncoding.EncodeToString(ce.keys.Salt),
		HMAC:          base64.StdEncoding.EncodeToString(hmacValue),
		Timestamp:     time.Now(),
		Version:       ce.version,
		Metadata:      metadataMap,
	}

	ce.logger.Println("Seed encrypted con successo")

	return encrypted, nil
}

func (ce *CryptoEncryptor) DecryptSeed(encrypted *EncryptedSeed) (string, error) {
	ce.logger.Println("Inizio decryption seed")

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.CipherText)
	if err != nil {
		return "", fmt.Errorf("errore decode ciphertext: %w", err)
	}

	iv, err := base64.StdEncoding.DecodeString(encrypted.IV)
	if err != nil {
		return "", fmt.Errorf("errore decode IV: %w", err)
	}

	hmacValue, err := base64.StdEncoding.DecodeString(encrypted.HMAC)
	if err != nil {
		return "", fmt.Errorf("errore decode HMAC: %w", err)
	}

	if !verifyHMAC(ciphertext, ce.keys.HMACKey, hmacValue, sha512.New) {
		return "", errors.New("HMAC verification failed")
	}

	plaintext, err := ce.decryptAESGCM(ciphertext, ce.keys.EncryptionKey, iv)
	if err != nil {
		return "", fmt.Errorf("errore AES decryption: %w", err)
	}

	ce.logger.Println("Seed decrypted con successo")

	return string(plaintext), nil
}

// Crittografia multi-layer

func (ce *CryptoEncryptor) EncryptMultiLayer(seed string) (*MultiLayerEncryption, error) {
	ce.logger.Println("Inizio encryption multi-layer")

	layer1, err := ce.EncryptSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("errore layer 1: %w", err)
	}

	layer1JSON, _ := json.Marshal(layer1)

	tempKey2, _ := generateCryptoRandomBytes(AES_KEY_SIZE)
	ciphertext2, iv2, err := ce.encryptChaCha20(layer1JSON, tempKey2)
	if err != nil {
		return nil, fmt.Errorf("errore layer 2: %w", err)
	}

	hmac2 := computeHMACWithAlgo(ciphertext2, ce.keys.HMACKey, sha512.New)

	layer2 := &EncryptedSeed{
		CipherText:    base64.StdEncoding.EncodeToString(ciphertext2),
		Algorithm:     "ChaCha20-Poly1305",
		KeyDerivation: "Random-Generated",
		IV:            base64.StdEncoding.EncodeToString(iv2),
		Salt:          base64.StdEncoding.EncodeToString(tempKey2),
		HMAC:          base64.StdEncoding.EncodeToString(hmac2),
		Timestamp:     time.Now(),
		Version:       ce.version,
		Metadata:      map[string]interface{}{"layer": 2},
	}

	layer2JSON, _ := json.Marshal(layer2)

	ciphertext3, iv3, err := ce.encryptAESGCM(layer2JSON, ce.keys.DerivedKey[:AES_KEY_SIZE])
	if err != nil {
		return nil, fmt.Errorf("errore layer 3: %w", err)
	}

	hmac3 := computeHMACWithAlgo(ciphertext3, ce.keys.HMACKey, sha256.New)

	layer3 := &EncryptedSeed{
		CipherText:    base64.StdEncoding.EncodeToString(ciphertext3),
		Algorithm:     "AES-256-GCM-Final",
		KeyDerivation: "Derived-Master-Key",
		IV:            base64.StdEncoding.EncodeToString(iv3),
		Salt:          base64.StdEncoding.EncodeToString(ce.keys.Salt),
		HMAC:          base64.StdEncoding.EncodeToString(hmac3),
		Timestamp:     time.Now(),
		Version:       ce.version,
		Metadata:      map[string]interface{}{"layer": 3, "final": true},
	}

	combinedData := fmt.Sprintf("%s|%s|%s", layer1.HMAC, layer2.HMAC, layer3.HMAC)
	combinedHMAC := computeHMACWithAlgo([]byte(combinedData), ce.keys.HMACKey, sha512.New)

	encryptionChain := fmt.Sprintf("Layer1[%s]->Layer2[%s]->Layer3[%s]",
		layer1.Algorithm, layer2.Algorithm, layer3.Algorithm)

	multiLayer := &MultiLayerEncryption{
		Layer1:          *layer1,
		Layer2:          *layer2,
		Layer3:          *layer3,
		CombinedHMAC:    base64.StdEncoding.EncodeToString(combinedHMAC),
		EncryptionChain: encryptionChain,
	}

	ce.logger.Println("Encryption multi-layer completata")

	return multiLayer, nil
}

// Export/Import

func (ce *CryptoEncryptor) ExportEncryptedSeedJSON(encrypted *EncryptedSeed) (string, error) {
	jsonData, err := json.MarshalIndent(encrypted, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func (ce *CryptoEncryptor) ImportEncryptedSeedJSON(jsonStr string) (*EncryptedSeed, error) {
	var encrypted EncryptedSeed
	if err := json.Unmarshal([]byte(jsonStr), &encrypted); err != nil {
		return nil, err
	}
	return &encrypted, nil
}

func (ce *CryptoEncryptor) SaveEncryptedSeed(encrypted *EncryptedSeed, filename string) error {
	jsonData, err := ce.ExportEncryptedSeedJSON(encrypted)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(filename, []byte(jsonData), 0600); err != nil {
		return fmt.Errorf("errore scrittura file: %w", err)
	}

	ce.logger.Printf("Seed encrypted salvato: %s", filename)

	return nil
}

// Export chiavi PEM

func (ce *CryptoEncryptor) ExportRSAPrivateKeyPEM() (string, error) {
	if ce.rsaPrivateKey == nil {
		return "", errors.New("chiave RSA privata non disponibile")
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(ce.rsaPrivateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}

func (ce *CryptoEncryptor) ExportRSAPublicKeyPEM() (string, error) {
	if ce.rsaPublicKey == nil {
		return "", errors.New("chiave RSA pubblica non disponibile")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(ce.rsaPublicKey)
	if err != nil {
		return "", err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

// Generazione password per il marker generator

func (ce *CryptoEncryptor) GenerateMarkerPassword(encryptedSeed *EncryptedSeed) (string, error) {
	ce.logger.Println("Generazione password per marker generator")

	passwordData := fmt.Sprintf("%s:%s:%s:%s:%d",
		encryptedSeed.CipherText,
		encryptedSeed.HMAC,
		encryptedSeed.Salt,
		encryptedSeed.Version,
		time.Now().UnixNano())

	hash := hashSHA512([]byte(passwordData))

	signature, err := ce.signECDSA(hash)
	if err != nil {
		return "", err
	}

	finalPassword := fmt.Sprintf("ENCRYPTED_SEED_%s_%s",
		hex.EncodeToString(hash),
		strings.ReplaceAll(signature, "=", ""))

	ce.logger.Printf("Password generata (lunghezza: %d)", len(finalPassword))

	return finalPassword, nil
}

