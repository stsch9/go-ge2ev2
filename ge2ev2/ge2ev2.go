package ge2ev2

import (
	"bufio"
	"bytes"
	"context"
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

func CreateDataroom(dataroompath string, config Config) {

	// read local recipients file
	recfile, err := os.Open(config.Agerecipientfile)
	if err != nil {
		fmt.Println("cannot open recipient file: ", err)
		os.Exit(1)
	}
	defer recfile.Close()

	var recipients []string

	scanner := bufio.NewScanner(recfile)
	for scanner.Scan() {
		recipients = append(recipients, scanner.Text())
	}

	if err = scanner.Err(); err != nil {
		fmt.Println("unexpected error: ", err)
		os.Exit(1)
	}

	// Create FileKey File
	k := make(map[string][2]string)
	fk := FileKeys{1, k, recipients}
	jsonFileKey, err := json.Marshal(fk)
	if err != nil {
		fmt.Println("unexpected error: ", err)
		os.Exit(1)
	}

	// create sha256 sum
	hash := sha256.Sum256(jsonFileKey)

	// Konvertiere []byte in io.Reader
	reader := bytes.NewReader(jsonFileKey)

	// upload filekeys file
	err = RcloneUpload(recipients, reader, config.Rcloneremote, dataroompath+"/.meta/Filekeys")
	if err != nil {
		fmt.Println("Error uploading Filekeys file: ", err)
		os.Exit(1)
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

func UploadFile(dataroompath string, file string, config Config) {
	// check lock file
	cmd := exec.Command("rclone", "ls", config.Rcloneremote+":"+dataroompath+"/.meta/Filekeys.lock")
	err := cmd.Run()
	if err != nil {
		// Prüfe, ob der Fehler ein ExitError ist
		if _, ok := err.(*exec.ExitError); !ok {
			fmt.Println("Unexpected error: ", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Lockfile Filekeys.lock exists.")
		os.Exit(0)
	}

	// set lock file
	cmd = exec.Command("rclone", "touch", config.Rcloneremote+":"+dataroompath+"/.meta/Filekeys.lock")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Prüfe, ob der Fehler ein ExitError ist
		if _, ok := err.(*exec.ExitError); ok {
			fmt.Println("Error: ", string(output))
			os.Exit(1)
		} else {
			fmt.Println("Unexpected error: ", err)
			os.Exit(1)
		}
	}

	// Load Filekeys file
	filekeys, err := LoadFileKeyFile(dataroompath, config)

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
		fmt.Println("unexpected error: ", err)
		os.Exit(1)
	}
	// create random filename
	fn := make([]byte, 32)
	if _, err := rand.Read(fn); err != nil {
		fmt.Println("unexpected error: ", err)
		os.Exit(1)
	}

	filekeys.Keys[filename] = [2]string{identity.String(), hex.EncodeToString(fn)}
	jsonFileKey, err := json.Marshal(filekeys)
	if err != nil {
		fmt.Println("unexpected error: ", err)
		os.Exit(1)
	}
	// create sha256 sum
	hash := sha256.Sum256(jsonFileKey)
	// encrypt + write file
	// Öffne die Datei zum Lesen
	readerfile, err := os.Open(file)
	if err != nil {
		fmt.Println("unexpected error: ", err)
		os.Exit(1)
	}

	err = RcloneUploadSingle(identity.Recipient(), readerfile, config.Rcloneremote, dataroompath+"/"+hex.EncodeToString(fn))
	if err != nil {
		fmt.Println("Error uploading file: ", err)
		os.Exit(1)
	}
	// encrypt + write FileKey File; check recipients file hash missing!!!
	// Konvertiere []byte in io.Reader
	reader := bytes.NewReader(jsonFileKey)
	err = RcloneUpload(filekeys.Recipients, reader, config.Rcloneremote, dataroompath+"/.meta/Filekeys")
	if err != nil {
		fmt.Println("Error uploading Filekeys file: ", err)
		os.Exit(1)
	}

	// write immudb
	err = WriteImmmudb(dataroompath, hash[:], config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		// rollback/delete FileKeys
		// ToDo!!!
		fmt.Println("INFO: Due to an immudb error the Filekeys file is deleted again")
	}

	// delete Lock File
	cmd = exec.Command("rclone", "delete", config.Rcloneremote+":"+dataroompath+"/.meta/Filekeys.lock")

	output, err = cmd.CombinedOutput()
	if err != nil {
		// Prüfe, ob der Fehler ein ExitError ist
		if _, ok := err.(*exec.ExitError); ok {
			fmt.Println("Error: ", string(output))
			os.Exit(1)
		} else {
			fmt.Println("Unexpected error: ", err)
			os.Exit(1)
		}
	}
}

func ShowFiles(dataroompath string, config Config) {
	filekeys, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for key := range filekeys.Keys {
		fmt.Println(dataroompath + "/" + key)
	}
}

func DownloadFile(dataroompath string, filename string, dest string, config Config) {
	filekeys, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// check file exists ausbessern
	filekey, ok := filekeys.Keys[filename]
	if ok {
		// decrypt file
		f, err := os.Create(dest + "/" + filename)
		if err != nil {
			fmt.Println("unexpected error: ", err)
			os.Exit(1)
		}
		defer f.Close()

		identity, err := age.ParseX25519Identity(filekey[0])
		if err != nil {
			fmt.Println("unexpected error: ", err)
			os.Exit(1)
		}

		cmd := exec.Command("rclone", "cat", config.Rcloneremote+":"+dataroompath+"/"+filekey[1])

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Println("unexpected error: ", err)
			os.Exit(1)
		}

		if err := cmd.Start(); err != nil {
			fmt.Println("unexpected error: ", err)
			os.Exit(1)
		}

		fkreader, err := DecryptAge2(identity, stdout)
		if err != nil {
			fmt.Println("unexpected error: ", err)
			os.Exit(1)
		}

		if _, err := io.Copy(f, fkreader); err != nil {
			fmt.Println("unexpected error: ", err)
			os.Exit(1)
		}

		if err := cmd.Wait(); err != nil {
			fmt.Println("unexpected error: ", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("File " + filename + " not found in dataroom " + dataroompath)
		os.Exit(0)
	}
}

func DeleteFile(dataroompath string, filename string, config Config) {
	// check lock file
	cmd := exec.Command("rclone", "ls", config.Rcloneremote+":"+dataroompath+"/.meta/Filekeys.lock")
	err := cmd.Run()
	if err != nil {
		// Prüfe, ob der Fehler ein ExitError ist
		if _, ok := err.(*exec.ExitError); !ok {
			fmt.Println("Unexpected error: ", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Lockfile Filekeys.lock exists.")
		os.Exit(0)
	}

	// set lock file
	cmd = exec.Command("rclone", "touch", config.Rcloneremote+":"+dataroompath+"/.meta/Filekeys.lock")

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Prüfe, ob der Fehler ein ExitError ist
		if _, ok := err.(*exec.ExitError); ok {
			fmt.Println("Error: ", string(output))
			os.Exit(1)
		} else {
			fmt.Println("Unexpected error: ", err)
			os.Exit(1)
		}
	}

	filekeys, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	filekey, ok := filekeys.Keys[filename]
	if ok {
		// delete filekeys entry
		delete(filekeys.Keys, filename)

		jsonFileKey, err := json.Marshal(filekeys)
		if err != nil {
			fmt.Println("Unexpected error: ", err)
			os.Exit(1)
		}

		// create sha256 sum
		hash := sha256.Sum256(jsonFileKey)

		// encrypt + write FileKey File; check recipients file hash missing!!!
		// Konvertiere []byte in io.Reader
		reader := bytes.NewReader(jsonFileKey)

		// upload filekeys file
		err = RcloneUpload(filekeys.Recipients, reader, config.Rcloneremote, dataroompath+"/.meta/Filekeys")
		if err != nil {
			// ToDo: rollback
			fmt.Println("Error writing Filekeys file: ", err)
			os.Exit(1)
		}

		// delete file via rclone
		cmd := exec.Command("rclone", "deletefile", config.Rcloneremote+":"+dataroompath+"/"+filekey[1])

		output, err := cmd.CombinedOutput()
		if err != nil {
			// Prüfe, ob der Fehler ein ExitError ist
			if _, ok := err.(*exec.ExitError); ok {
				fmt.Println("Error: ", string(output))
				os.Exit(1)
			} else {
				fmt.Println("Unexpected error: ", err)
				os.Exit(1)
			}
		}

		// write immudb
		err = WriteImmmudb(dataroompath, hash[:], config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
		if err != nil {
			// ToDo: rollback/delete FileKeys
		}
	} else {
		fmt.Println("File " + filename + " not found in dataroom " + dataroompath)
	}

	// delete Lock File
	cmd = exec.Command("rclone", "delete", config.Rcloneremote+":"+dataroompath+"/.meta/Filekeys.lock")
	output, err = cmd.CombinedOutput()
	if err != nil {
		// Prüfe, ob der Fehler ein ExitError ist
		if _, ok := err.(*exec.ExitError); ok {
			fmt.Println("Error: ", string(output))
			os.Exit(1)
		} else {
			fmt.Println("Unexpected error: ", err)
			os.Exit(1)
		}
	}

}

func ListRecipients(dataroompath string, config Config) {
	filekeys, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, rec := range filekeys.Recipients {
		fmt.Println(rec)
	}
}

func ChangeRecipients(config Config, dataroompath string) {

	// read new recipients file
	recfile, err := os.Open(config.Agerecipientfile)
	if err != nil {
		fmt.Println("Cannot open recipeint file "+config.Agerecipientfile+": ", err)
		os.Exit(0)
	}
	defer recfile.Close()

	var recipients []string

	scanner := bufio.NewScanner(recfile)
	for scanner.Scan() {
		recipients = append(recipients, scanner.Text())
	}

	if err = scanner.Err(); err != nil {
		fmt.Println("Unexpected error: ", err)
		os.Exit(1)
	}

	filekeys, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	filekeys.Recipients = recipients

	jsonFileKey, err := json.Marshal(filekeys)
	if err != nil {
		fmt.Println("Unexpected decryption error: ", err)
		os.Exit(1)
	}

	// create sha256 sum
	hash := sha256.Sum256(jsonFileKey)

	// Konvertiere []byte in io.Reader
	reader := bytes.NewReader(jsonFileKey)

	err = RcloneUpload(filekeys.Recipients, reader, config.Rcloneremote, dataroompath+"/.meta/Filekeys")
	if err != nil {
		fmt.Println("Error uploading Filekeys file: ", err)
		os.Exit(1)
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
		return fmt.Errorf("failed to create encrypted file: %v", err)
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
		return fmt.Errorf("failed to create encrypted file: %v", err)
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
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	r, err := age.Decrypt(file, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to open encrypted file: %v", err)
	}

	return r, nil
}

func DecryptAge2(identity age.Identity, file io.Reader) (io.Reader, error) {
	r, err := age.Decrypt(file, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to open encrypted file: %v", err)
	}

	return r, nil
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

func LoadFileKeyFile(dataroompath string, config Config) (FileKeys, error) {
	// read hash from immudb
	expectedhash, err := ReadImmudb(dataroompath, config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		return FileKeys{}, fmt.Errorf("error Reading from immudb: %v", err)
	}

	// decrypting Filekeys
	out := &bytes.Buffer{}

	cmd := exec.Command("rclone", "cat", config.Rcloneremote+":"+dataroompath+"/.meta/Filekeys")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return FileKeys{}, fmt.Errorf("error: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return FileKeys{}, fmt.Errorf("error: %v", err)
	}

	fkreader, err := DecryptAge(config.Agekeyfile, stdout)
	if err != nil {
		return FileKeys{}, fmt.Errorf("decryption error: %v", err)
	}

	if _, err := io.Copy(out, fkreader); err != nil {
		return FileKeys{}, fmt.Errorf("error: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return FileKeys{}, fmt.Errorf("decryption error: %v", err)
	}

	// compare hashes
	actualhash := sha256.Sum256(out.Bytes())
	if !bytes.Equal(expectedhash, []byte(hex.EncodeToString(actualhash[:]))) {
		return FileKeys{}, fmt.Errorf("error: hash vaildation failed")
	}

	var filekeys FileKeys

	err = json.Unmarshal(out.Bytes(), &filekeys)
	if err != nil {
		return FileKeys{}, fmt.Errorf("error: %v", err)
	}

	return filekeys, nil
}

// ToDo:
//		 - doku
// 		- consider brotobuf
//		- overwrite file
//		- other age recipient types
//		- lock file
//		- rollback for upload + delete
//		- parallel
//		- versioning (store hash, timestamp)
