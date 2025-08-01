package ge2ev2

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	immudb "github.com/codenotary/immudb/pkg/client"
)

type FileKeys struct {
	Version    int                  `json:"Version"`
	Keys       map[string][2]string `json:"Keys"`
	Recipients []string             `json:"Recipients"`
}

type Config struct {
	Immudbserver     string
	Immmudbport      int
	Immudbuser       string
	Immudbpassword   string
	Rcloneremote     string
	Agerecipientfile string
	Agekeyfile       string
}

const filekeysize = 32

func CreateDataroom(dataroompath string, config Config) {

	// read recipients file
	recfile, err := os.Open(config.Agerecipientfile)
	if err != nil {
		panic(err)
	}
	defer recfile.Close()

	var recipients []string

	scanner := bufio.NewScanner(recfile)
	for scanner.Scan() {
		recipients = append(recipients, scanner.Text())
	}

	if err = scanner.Err(); err != nil {
		panic(err)
	}

	// Create FileKey File
	k := make(map[string][2]string)
	fk := FileKeys{1, k, recipients}
	jsonFileKey, err := json.Marshal(fk)
	if err != nil {
		panic(err)
	}

	// create sha256 sum
	hash := sha256.Sum256(jsonFileKey)

	// Konvertiere []byte in io.Reader
	reader := bytes.NewReader(jsonFileKey)

	// encrypt Filekeys; old without rclone
	// err = EncryptAge(recipients, dataroompath+"/.meta/Filekeys", reader)
	// if err != nil {
	// 	panic(err)
	// }

	err = RcloneUpload(recipients, reader, config.Rcloneremote, dataroompath+"/.meta/Filekeys")
	if err != nil {
		panic(err)
	}

	// write immudb
	err = WriteImmmudb(dataroompath, hash[:], config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		// rollback/delete FileKeys
		fmt.Println("INFO: Due to an immudb error the Filekeys file is deleted again")

		err2 := os.Remove(dataroompath + "/.meta/Filekeys")
		if err2 != nil {
			fmt.Println("Error deleting the file: ", err2)
		}

		fmt.Println("Error: writing to immudb: ", err)
		os.Exit(1)
	}

	// Option 1: create hash of recipients file and store it in immudb !!!
	// immudb ist vertrauenswürdig nur berechtigte User haben Zugriff, (ssl cert authentication)
	// einen user für hash of recipient file (es gibt verscheidene rollen read/write, read, usw.)
	// eine user für hash of filekeys file
	//
	// Option 1a: Store filekeys and recipients in one file. Manipulation fällt schneller auf, da nicht mehr einfach nur die recipients manipuliert werden können.
	// Option 1aa: Use vrf and store it in immudb
	//
	// Option 2: neues recipient File wird von einem User signiert, der bereits im alten recipient file enthalten war.

	// Option 3: store minisign keys in recipient File; store recipient File in immudb; sign recipient File with minisign; recipient File kann nur mit einem public minisign key verifiziert werden, der in der vorherigen version gespeichert war.
	// Option 4: Combine Option 1 and 4: Store Filekeys and recipients in one file + store recipients (hash) in immudb + siging ...
}

// not used any more
func UploadFile(dataroompath string, file string, config Config) {
	filekeys := LoadFileKeyFile2(dataroompath, config)

	// check file already exists
	filename := filepath.Base(file)
	if _, ok := filekeys.Keys[filename]; ok {
		fmt.Println("File " + filename + " already exits in dataroom " + dataroompath)
		os.Exit(0)
	}

	// increment version
	filekeys.Version += 1

	// create file key
	fk := make([]byte, filekeysize)
	if _, err := rand.Read(fk); err != nil {
		panic(err)
	}

	// create random filename
	fn := make([]byte, 32)
	if _, err := rand.Read(fn); err != nil {
		panic(err)
	}

	filekeys.Keys[filename] = [2]string{hex.EncodeToString(fk), hex.EncodeToString(fn)}

	jsonFileKey, err := json.Marshal(filekeys)
	if err != nil {
		panic(err)
	}

	// create sha256 sum
	hash := sha256.Sum256(jsonFileKey)

	// encrypt + write file
	// Öffne die Datei zum Lesen
	datei, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(fk)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ivf := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(ivf); err != nil {
		panic(err)
	}

	err = os.WriteFile(dataroompath+"/"+hex.EncodeToString(fn), aesgcm.Seal(ivf, ivf, datei, nil), 0777)
	if err != nil {
		panic(err)
	}

	// encrypt + write FileKey File; check recipients file hash missing!!!
	// Konvertiere []byte in io.Reader
	reader := bytes.NewReader(jsonFileKey)

	// old without rclone
	// err = EncryptAge(filekeys.Recipients, dataroompath+"/.meta/Filekeys", reader)
	// if err != nil {
	// 	panic(err)
	// }

	err = RcloneUpload(filekeys.Recipients, reader, config.Rcloneremote, dataroompath+"/.meta/Filekeys")
	if err != nil {
		panic(err)
	}

	// write immudb
	err = WriteImmmudb(dataroompath, hash[:], config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		// rollback/delete FileKeys
		fmt.Println("INFO: Due to an immudb error the Filekeys file is deleted again")

		err2 := os.Remove(dataroompath + "/.meta/Filekeyse")
		if err2 != nil {
			fmt.Println("Error deleting the file: ", err2)
		}

		panic(err)
	}
}

func UploadFile2(dataroompath string, file string, config Config) {
	filekeys := LoadFileKeyFile2(dataroompath, config)

	// check file already exists
	filename := filepath.Base(file)
	if _, ok := filekeys.Keys[filename]; ok {
		fmt.Println("File " + filename + " already exits in dataroom " + dataroompath)
		os.Exit(0)
	}

	// increment version
	filekeys.Version += 1

	// create file key
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		panic(err)
	}

	// create random filename
	fn := make([]byte, 32)
	if _, err := rand.Read(fn); err != nil {
		panic(err)
	}

	filekeys.Keys[filename] = [2]string{identity.String(), hex.EncodeToString(fn)}

	jsonFileKey, err := json.Marshal(filekeys)
	if err != nil {
		panic(err)
	}

	// create sha256 sum
	hash := sha256.Sum256(jsonFileKey)

	// encrypt + write file
	// Öffne die Datei zum Lesen
	readerfile, err := os.Open(file)
	if err != nil {
		panic(err)
	}

	err = RcloneUploadSingle(identity.Recipient(), readerfile, config.Rcloneremote, dataroompath+"/"+hex.EncodeToString(fn))
	if err != nil {
		panic(err)
	}

	// encrypt + write FileKey File; check recipients file hash missing!!!
	// Konvertiere []byte in io.Reader
	reader := bytes.NewReader(jsonFileKey)

	// old without rclone
	// err = EncryptAge(filekeys.Recipients, dataroompath+"/.meta/Filekeys", reader)
	// if err != nil {
	// 	panic(err)
	// }

	err = RcloneUpload(filekeys.Recipients, reader, config.Rcloneremote, dataroompath+"/.meta/Filekeys")
	if err != nil {
		panic(err)
	}

	// write immudb
	err = WriteImmmudb(dataroompath, hash[:], config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		// rollback/delete FileKeys
		fmt.Println("INFO: Due to an immudb error the Filekeys file is deleted again")

		err2 := os.Remove(dataroompath + "/.meta/Filekeyse")
		if err2 != nil {
			fmt.Println("Error deleting the file: ", err2)
		}

		panic(err)
	}
}

func ShowFiles(dataroompath string, config Config) {
	filekeys := LoadFileKeyFile2(dataroompath, config)

	for key := range filekeys.Keys {
		fmt.Println(key)
	}
}

// not used any more
func DownloadFile(dataroompath string, filename string, dest string, config Config) {
	filekeys := LoadFileKeyFile2(dataroompath, config)

	// check file exists
	filekey, ok := filekeys.Keys[filename]
	if ok {
		if !validateFile(dataroompath + "/" + filekey[1]) {
			fmt.Println("ERROR: File Key exists, but File " + filekey[1] + " not found")
			os.Exit(1)
		}
	} else {
		fmt.Println("File " + filename + " not found in dataroom " + dataroompath)
		os.Exit(0)
	}

	// decrypt file
	fk, err := hex.DecodeString(filekey[0])
	if err != nil {
		panic(err)
	}

	ciphertext, err := os.ReadFile(dataroompath + "/" + filekey[1])
	// if our program was unable to read the file
	// print out the reason why it can't
	if err != nil {
		fmt.Println(err)
	}

	c, err := aes.NewCipher(fk)
	if err != nil {
		fmt.Println(err)
	}

	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}

	err = os.WriteFile(dest+"/"+filename, plaintext, 0644)
	if err != nil {
		panic(err)
	}
}

func DownloadFile2(dataroompath string, filename string, dest string, config Config) {
	filekeys := LoadFileKeyFile2(dataroompath, config)

	// check file exists
	filekey, ok := filekeys.Keys[filename]
	if ok {
		if !validateFile(dataroompath + "/" + filekey[1]) {
			fmt.Println("ERROR: File Key exists, but File " + filekey[1] + " not found")
			os.Exit(1)
		}
	} else {
		fmt.Println("File " + filename + " not found in dataroom " + dataroompath)
		os.Exit(0)
	}

	// decrypt file
	f, err := os.Create(dest + "/" + filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	identity, err := age.ParseX25519Identity(filekey[0])
	if err != nil {
		panic(err)
	}

	cmd := exec.Command("rclone", "cat", config.Rcloneremote+":"+dataroompath+"/"+filekey[1])

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}

	if err := cmd.Start(); err != nil {
		panic(err)
	}

	fkreader, err := DecryptAge2(identity, stdout)
	if err != nil {
		panic(err)
	}

	if _, err := io.Copy(f, fkreader); err != nil {
		panic(err)
	}

	if err := cmd.Wait(); err != nil {
		panic(err)
	}
}

func ChangeRecipients(config Config, dataroompath string) {

	// read new recipients file
	recfile, err := os.Open(config.Agerecipientfile)
	if err != nil {
		panic(err)
	}
	defer recfile.Close()

	var recipients []string

	scanner := bufio.NewScanner(recfile)
	for scanner.Scan() {
		recipients = append(recipients, scanner.Text())
	}

	if err = scanner.Err(); err != nil {
		panic(err)
	}

	filekeys := LoadFileKeyFile2(dataroompath, config)

	filekeys.Recipients = recipients

	jsonFileKey, err := json.Marshal(filekeys)
	if err != nil {
		panic(err)
	}

	// create sha256 sum
	hash := sha256.Sum256(jsonFileKey)

	// Konvertiere []byte in io.Reader
	reader := bytes.NewReader(jsonFileKey)

	// encrypt keyfile with new recipients; old without rclone
	// err = EncryptAge(recipients, dataroompath+"/.meta/Filekeys", reader)
	// if err != nil {
	// 	panic(err)
	// }

	err = RcloneUpload(filekeys.Recipients, reader, config.Rcloneremote, dataroompath+"/.meta/Filekeys")
	if err != nil {
		panic(err)
	}

	// create hash of recipients file and store it in immudb
	// write immudb
	err = WriteImmmudb(dataroompath, hash[:], config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		// rollback/delete FileKeys
		fmt.Println("INFO: Due to an immudb error the Filekeys file is deleted again")

		err2 := os.Remove(dataroompath + "/.meta/Filekeys")
		if err2 != nil {
			fmt.Println("Error deleting the file: ", err2)
		}

		fmt.Println("Error: writing to immudb: ", err)
		os.Exit(1)
	}
}

// Helper functions

// not used any more
func EncryptAge(recipientstrings []string, outputFile string, in io.Reader) error {

	var recipients []age.Recipient

	for _, key := range recipientstrings {
		// Parsen des Public Keys
		recipient, err := age.ParseX25519Recipient(key)
		if err != nil {
			return fmt.Errorf("failed to parse recipient %s: %v", key, err)
		}

		// Hinzufügen des Recipients zum Slice
		recipients = append(recipients, recipient)
	}

	// Erstellen der Ausgabedatei
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	w, err := age.Encrypt(outFile, recipients...)
	if err != nil {
		return fmt.Errorf("Failed to create encrypted file: %v", err)
	}

	// Kopieren der Daten von der Eingabedatei in den Verschlüsselungsstream
	if _, err := io.Copy(w, in); err != nil {
		return fmt.Errorf("failed to encrypt file: %v", err)
	}

	// Schließen des Verschlüsselungsstreams
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close encryption stream: %v", err)
	}

	return nil
}

func EncryptAge2(recipientstrings []string, out io.WriteCloser, in io.Reader) error {

	defer out.Close()
	var recipients []age.Recipient

	for _, key := range recipientstrings {
		// Parsen des Public Keys
		recipient, err := age.ParseX25519Recipient(key)
		if err != nil {
			return fmt.Errorf("failed to parse recipient %s: %v", key, err)
		}

		// Hinzufügen des Recipients zum Slice
		recipients = append(recipients, recipient)
	}

	w, err := age.Encrypt(out, recipients...)
	if err != nil {
		return fmt.Errorf("Failed to create encrypted file: %v", err)
	}

	// Kopieren der Daten von der Eingabedatei in den Verschlüsselungsstream
	if _, err := io.Copy(w, in); err != nil {
		return fmt.Errorf("failed to encrypt file: %v", err)
	}

	// Schließen des Verschlüsselungsstreams
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close encryption stream: %v", err)
	}

	return nil
}

func EncryptAge3(recipient age.Recipient, out io.WriteCloser, in io.Reader) error {

	defer out.Close()

	w, err := age.Encrypt(out, recipient)
	if err != nil {
		return fmt.Errorf("Failed to create encrypted file: %v", err)
	}

	// Kopieren der Daten von der Eingabedatei in den Verschlüsselungsstream
	if _, err := io.Copy(w, in); err != nil {
		return fmt.Errorf("failed to encrypt file: %v", err)
	}

	// Schließen des Verschlüsselungsstreams
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close encryption stream: %v", err)
	}

	return nil
}

func DecryptAge(keyfile string, file io.Reader) (io.Reader, error) {
	key, err := os.ReadFile(keyfile)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file: %v", err)
	}

	identity, err := age.ParseX25519Identity(strings.TrimSuffix(string(key), "\n"))
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key: %v", err)
	}

	// f, err := os.Open(file)
	// if err != nil {
	// 	return nil, fmt.Errorf("Failed to open file: %v", err)
	// }
	// defer f.Close()

	r, err := age.Decrypt(file, identity)
	if err != nil {
		return nil, fmt.Errorf("Failed to open encrypted file: %v", err)
	}

	return r, nil
}

func DecryptAge2(identity age.Identity, file io.Reader) (io.Reader, error) {

	// f, err := os.Open(file)
	// if err != nil {
	// 	return nil, fmt.Errorf("Failed to open file: %v", err)
	// }
	// defer f.Close()

	r, err := age.Decrypt(file, identity)
	if err != nil {
		return nil, fmt.Errorf("Failed to open encrypted file: %v", err)
	}

	return r, nil
}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}

	return true
}

func WriteImmmudb(key string, hash []byte, immudbserver string, immudbport int, immudbuser []byte, immudbpw []byte) error {
	// even though the server address and port are defaults, setting them as a reference
	opts := immudb.DefaultOptions().WithAddress(immudbserver).WithPort(immudbport)

	client := immudb.NewClient().WithOptions(opts)

	// connect with immudb server (user, password, database)
	err := client.OpenSession(context.Background(), immudbuser, immudbpw, "defaultdb")
	if err != nil {
		return fmt.Errorf("failed to open immudb session: %v", err)
	}

	// ensure connection is closed
	defer client.CloseSession(context.Background())

	// write an entry
	// upon submission, the SDK validates proofs and updates the local state under the hood
	hdr, err := client.VerifiedSet(context.Background(), []byte(key), []byte(hex.EncodeToString(hash)))
	if err != nil {
		return fmt.Errorf("failed setting a verified entry: %v", err)
	}
	fmt.Printf("Sucessfully set a verified entry: ('%s', '%s') @ tx %d\n", []byte(key), []byte(hex.EncodeToString(hash)), hdr.Id)

	return nil
}

func ReadImmudb(key string, immudbserver string, immudbport int, immudbuser []byte, immudbpw []byte) ([]byte, error) {
	// even though the server address and port are defaults, setting them as a reference
	opts := immudb.DefaultOptions().WithAddress(immudbserver).WithPort(immudbport)

	client := immudb.NewClient().WithOptions(opts)

	// connect with immudb server (user, password, database)
	err := client.OpenSession(context.Background(), immudbuser, immudbpw, "defaultdb")
	if err != nil {
		return nil, fmt.Errorf("failed to open immudb session: %v", err)
	}

	// ensure connection is closed
	defer client.CloseSession(context.Background())

	// read an entry
	// upon submission, the SDK validates proofs and updates the local state under the hood
	entry, err := client.VerifiedGet(context.Background(), []byte(key))
	if err != nil {
		return nil, fmt.Errorf("failed getting a verified entry: %v", err)
	}

	return entry.Value, nil
}

func LoadFileKeyFileLocal(dataroompath string, config Config) FileKeys {
	// read hash from immudb
	expectedhash, err := ReadImmudb(dataroompath, config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		//return nil, fmt.Errorf("Failed to open file: %v", err)
		fmt.Println("Error: Reading from immudb: ", err)
		os.Exit(1)
	}

	// decrypting Filekeys
	out := &bytes.Buffer{}

	// old without rclone
	f, err := os.Open(dataroompath + "/.meta/Filekeys")
	if err != nil {
		//return nil, fmt.Errorf("Failed to open file: %v", err)
		panic(err)
	}
	defer f.Close()

	fkreader, err := DecryptAge(config.Agekeyfile, f)
	if err != nil {
		panic(err)
	}

	if _, err := io.Copy(out, fkreader); err != nil {
		panic(err)
	}

	// compare hashes
	actualhash := sha256.Sum256(out.Bytes())
	if bytes.Equal(expectedhash, []byte(hex.EncodeToString(actualhash[:]))) {
		fmt.Println("INFO: hash validation was successful")
	} else {
		fmt.Println("ERROR: hash validation failed")
		os.Exit(1)
	}

	var filekeys FileKeys

	err = json.Unmarshal(out.Bytes(), &filekeys)
	if err != nil {
		panic(err)
	}

	return filekeys
}

func RcloneUpload(recipientstrings []string, in io.Reader, remote string, path string) error {
	cmd := exec.Command("rclone", "rcat", remote+":"+path)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("pipe error: %v", err)
	}

	go EncryptAge2(recipientstrings, stdin, in)

	_, err = cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func RcloneUploadSingle(recipient age.Recipient, in io.Reader, remote string, path string) error {
	cmd := exec.Command("rclone", "rcat", remote+":"+path)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("pipe error: %v", err)
	}

	go EncryptAge3(recipient, stdin, in)

	_, err = cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func LoadFileKeyFile2(dataroompath string, config Config) FileKeys {
	// read hash from immudb
	expectedhash, err := ReadImmudb(dataroompath, config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		//return nil, fmt.Errorf("Failed to open file: %v", err)
		fmt.Println("Error: Reading from immudb: ", err)
		os.Exit(1)
	}

	// decrypting Filekeys
	out := &bytes.Buffer{}

	cmd := exec.Command("rclone", "cat", config.Rcloneremote+":"+dataroompath+"/.meta/Filekeys")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}

	if err := cmd.Start(); err != nil {
		panic(err)
	}

	fkreader, err := DecryptAge(config.Agekeyfile, stdout)
	if err != nil {
		panic(err)
	}

	if _, err := io.Copy(out, fkreader); err != nil {
		panic(err)
	}

	if err := cmd.Wait(); err != nil {
		panic(err)
	}

	// compare hashes
	actualhash := sha256.Sum256(out.Bytes())
	if bytes.Equal(expectedhash, []byte(hex.EncodeToString(actualhash[:]))) {
		fmt.Println("INFO: hash validation was successful")
	} else {
		fmt.Println("ERROR: hash validation failed")
		os.Exit(1)
	}

	var filekeys FileKeys

	err = json.Unmarshal(out.Bytes(), &filekeys)
	if err != nil {
		panic(err)
	}

	return filekeys
}
