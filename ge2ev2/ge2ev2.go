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
	"strconv"
	"strings"

	"filippo.io/age"
	immudb "github.com/codenotary/immudb/pkg/client"
)

type SecretPair struct {
	Filekey  string `json:"Filekey"`
	Filename string `json:"Filename"`
}

type FileEntry struct {
	Id          string       `json:"Id"`
	Versionkeys []SecretPair `json:"Versionkeys"`
}

type DataroomMeta struct {
	Version    int                  `json:"Version"`
	Files      map[string]FileEntry `json:"Files"`
	Recipients []string             `json:"Recipients"`
}

type Config struct {
	Immudbserver     string
	Immmudbport      int
	Immudbuser       string
	Immudbpassword   string
	Rcloneremote     string
	Rcloneparameter  string
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

	// Create DataroomMeta File
	k := make(map[string]FileEntry)
	fk := DataroomMeta{1, k, recipients}
	jsonFileKey, err := json.Marshal(fk)
	if err != nil {
		fmt.Println("unexpected error: ", err)
		os.Exit(1)
	}

	// create sha256 sum
	hash := sha256.Sum256(jsonFileKey)

	// convert []byte to io.Reader
	reader := bytes.NewReader(jsonFileKey)

	// upload DataroomMeta file
	err = RcloneUpload(recipients, reader, config.Rcloneremote, dataroompath+"/.meta/DataroomMeta", config)
	if err != nil {
		fmt.Println("Error uploading DataroomMeta file: ", err)
		os.Exit(1)
	}

	// write immudb
	err = WriteImmmudb(dataroompath, hash[:], config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		// rollback/delete DataroomMeta
		fmt.Println("INFO: Due to an immudb error the DataroomMeta file is deleted again")

		err2 := os.Remove(dataroompath + "/.meta/DataroomMeta")
		if err2 != nil {
			fmt.Println("Error deleting the file: ", err2)
		}

		fmt.Println("Error: writing to immudb: ", err)
		os.Exit(1)
	}
}

func UploadFile(dataroompath string, file string, config Config) {
	// first check immudb connection???

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

	// encrypt + write file
	readerfile, err := os.Open(file)
	if err != nil {
		fmt.Println("unexpected error: ", err)
		os.Exit(1)
	}

	err = RcloneUploadSingle(identity.Recipient(), readerfile, config.Rcloneremote, dataroompath+"/"+hex.EncodeToString(fn), config)
	if err != nil {
		fmt.Println("Error uploading file: ", err)
		os.Exit(1)
	}

	// check + set Lock File and backup DataroomMeta File
	if ok, err := CheckSetLockFile(config, dataroompath); err != nil {
		fmt.Println(err)

		cmd := exec.Command("rclone", config.Rcloneparameter, "delete", config.Rcloneremote+":"+dataroompath+"/"+hex.EncodeToString(fn))
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Prüfe, ob der Fehler ein ExitError ist
			if _, ok := err.(*exec.ExitError); ok {
				fmt.Println("Error: ", string(output))
			} else {
				fmt.Println("Unexpected error: ", err)
			}
			fmt.Println("Please delete file ", dataroompath, "/", hex.EncodeToString(fn), " manually")
		}

		os.Exit(1)
	} else if !ok {
		fmt.Println("Lockfile DataroomMeta.lock exists.")

		cmd := exec.Command("rclone", config.Rcloneparameter, "delete", config.Rcloneremote+":"+dataroompath+"/"+hex.EncodeToString(fn))
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Prüfe, ob der Fehler ein ExitError ist
			if _, ok := err.(*exec.ExitError); ok {
				fmt.Println("Error: ", string(output))
			} else {
				fmt.Println("Unexpected error: ", err)
			}
			fmt.Println("Please delete file ", dataroompath, "/", hex.EncodeToString(fn), " manually")
		}

		os.Exit(0)
	}

	// Load DataroomMeta file
	dataroommeta, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println(err)

		cmd := exec.Command("rclone", config.Rcloneparameter, "delete", config.Rcloneremote+":"+dataroompath+"/"+hex.EncodeToString(fn))
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Prüfe, ob der Fehler ein ExitError ist
			if _, ok := err.(*exec.ExitError); ok {
				fmt.Println("Error: ", string(output))
			} else {
				fmt.Println("Unexpected error: ", err)
			}
			fmt.Println("Please delete file ", dataroompath, "/", hex.EncodeToString(fn), " manually")
		}

		DeleteLockFile(config, dataroompath)
		os.Exit(1)
	}

	// check file already exists
	filename := filepath.Base(file)
	if _, ok := dataroommeta.Files[filename]; !ok {
		// if filename does not exists
		// create random file id
		fileid := make([]byte, 32)
		if _, err := rand.Read(fileid); err != nil {
			fmt.Println("unexpected error: ", err)
			os.Exit(1) // TODO: delete file
		}
		dataroommeta.Files[filename] = FileEntry{
			Id: hex.EncodeToString(fileid),
			Versionkeys: []SecretPair{
				{
					Filekey:  identity.String(),
					Filename: hex.EncodeToString(fn),
				},
			},
		}
	} else {
		newPair := SecretPair{
			Filekey:  identity.String(),
			Filename: hex.EncodeToString(fn),
		}

		dataroommeta.Files[filename] = FileEntry{
			Id:          dataroommeta.Files[filename].Id,
			Versionkeys: append(dataroommeta.Files[filename].Versionkeys, newPair),
		}
	}

	// increment version
	dataroommeta.Version += 1

	jsonFileKey, err := json.Marshal(dataroommeta)
	if err != nil {
		fmt.Println("unexpected error: ", err)
		cmd := exec.Command("rclone", config.Rcloneparameter, "delete", config.Rcloneremote+":"+dataroompath+"/"+hex.EncodeToString(fn))
		output, err := cmd.CombinedOutput()
		if err != nil {
			// check if the error is an ExitError
			if _, ok := err.(*exec.ExitError); ok {
				fmt.Println("Error: ", string(output))
			} else {
				fmt.Println("Unexpected error: ", err)
			}
			fmt.Println("Please delete file ", dataroompath, "/", hex.EncodeToString(fn), " manually")
		}

		DeleteLockFile(config, dataroompath)
		os.Exit(1)
	}
	// create sha256 sum
	hash := sha256.Sum256(jsonFileKey)

	// encrypt + write DataroomMeta file; check recipients file hash missing!!!
	// convert []byte to io.Reader
	reader := bytes.NewReader(jsonFileKey)
	err = RcloneUpload(dataroommeta.Recipients, reader, config.Rcloneremote, dataroompath+"/.meta/DataroomMeta", config)
	if err != nil {
		fmt.Println("Error uploading DataroomMeta file: ", err)
		cmd := exec.Command("rclone", config.Rcloneparameter, "delete", config.Rcloneremote+":"+dataroompath+"/"+hex.EncodeToString(fn))
		output, err := cmd.CombinedOutput()
		if err != nil {
			// check if the error is an ExitError
			if _, ok := err.(*exec.ExitError); ok {
				fmt.Println("Error: ", string(output))
			} else {
				fmt.Println("Unexpected error: ", err)
			}
			fmt.Println("Please delete file ", dataroompath, "/", hex.EncodeToString(fn), " manually")
		}

		DeleteLockFile(config, dataroompath)
		os.Exit(1)
	}

	// write immudb
	err = WriteImmmudb(dataroompath, hash[:], config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		// rollback/delete DataroomMeta
		// ToDo!!!
		fmt.Println("writing the hash value to immudb failed")
		fmt.Println("please write (", dataroompath, ",", hex.EncodeToString(hash[:]), ") in immudb")
	}

	// delete Lock File
	DeleteLockFile(config, dataroompath)
}

func ShowFiles(dataroompath string, config Config) {
	dataroommeta, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for key := range dataroommeta.Files {
		fmt.Println(dataroompath + "/" + key + " [Versions: " + strconv.Itoa(len(dataroommeta.Files[key].Versionkeys)) + "]")
	}
}

func DownloadFile(dataroompath string, filename string, dest string, config Config) {
	dataroommeta, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// check file exists
	filekey, ok := dataroommeta.Files[filename]
	if ok {
		// decrypt file
		f, err := os.Create(dest + "/" + filename)
		if err != nil {
			fmt.Println("unexpected error: ", err)
			os.Exit(1)
		}
		defer f.Close()

		identity, err := age.ParseX25519Identity(filekey.Versionkeys[len(filekey.Versionkeys)-1].Filekey)
		if err != nil {
			fmt.Println("unexpected error: ", err)
			os.Exit(1)
		}

		cmd := exec.Command("rclone", config.Rcloneparameter, "cat", config.Rcloneremote+":"+dataroompath+"/"+filekey.Versionkeys[len(filekey.Versionkeys)-1].Filename)

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

	// check + set Lock File and backup DataroomMeta File
	if ok, err := CheckSetLockFile(config, dataroompath); err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else if !ok {
		fmt.Println("Lockfile DataroomMeta.lock exists.")
		os.Exit(0)
	}

	dataroommeta, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println("error loading DataroomMeta :", err)
		DeleteLockFile(config, dataroompath)
		os.Exit(1)
	}

	var filetodelete string
	fileentry, ok := dataroommeta.Files[filename]
	if ok {
		if len(fileentry.Versionkeys) > 1 {
			// remove latest version
			filetodelete = fileentry.Versionkeys[len(fileentry.Versionkeys)-1].Filename
			fileentry.Versionkeys = fileentry.Versionkeys[:len(fileentry.Versionkeys)-1]
			dataroommeta.Files[filename] = fileentry
		} else {
			// delete DataroomMeta entry
			filetodelete = fileentry.Versionkeys[0].Filename
			delete(dataroommeta.Files, filename)
		}

		jsonFileKey, err := json.Marshal(dataroommeta)
		if err != nil {
			fmt.Println("Unexpected error: ", err)
			DeleteLockFile(config, dataroompath)
			os.Exit(1)
		}

		// create sha256 sum
		hash := sha256.Sum256(jsonFileKey)

		// encrypt + write FileKey File; check recipients file hash missing!!!
		// convert []byte to io.Reader
		reader := bytes.NewReader(jsonFileKey)

		// upload DataroomMeta file
		err = RcloneUpload(dataroommeta.Recipients, reader, config.Rcloneremote, dataroompath+"/.meta/DataroomMeta", config)
		if err != nil {
			fmt.Println("Error writing DataroomMeta file: ", err)
			DeleteLockFile(config, dataroompath)
			os.Exit(1)
		}

		// delete file via rclone
		cmd := exec.Command("rclone", config.Rcloneparameter, "deletefile", config.Rcloneremote+":"+dataroompath+"/"+filetodelete)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// check if the error is an ExitError
			if _, ok := err.(*exec.ExitError); ok {
				fmt.Println("Error deleting file: ", string(output))
			} else {
				fmt.Println("Unexpected error: ", err)
			}
			// rollback. If the file does not exist, no rollback would be necessary
			cmd = exec.Command("rclone", config.Rcloneparameter, "copyto", config.Rcloneremote+":"+dataroompath+"/.meta/DataroomMeta.backup", config.Rcloneremote+":"+dataroompath+"/.meta/DataroomMeta")
			output, err := cmd.CombinedOutput()
			if err != nil {
				// check if the error is an ExitError
				if _, ok := err.(*exec.ExitError); ok {
					fmt.Println("Error: ", string(output))
				} else {
					fmt.Println("Unexpected error: ", err)
				}
				fmt.Println("Please replace ", dataroompath, "/.meta/DataroomMeta.backup with ", dataroompath, "/.meta/DataroomMeta manually.")
			}

			DeleteLockFile(config, dataroompath)
			os.Exit(1)
		}

		// write immudb
		err = WriteImmmudb(dataroompath, hash[:], config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
		if err != nil {
			fmt.Println("writing the hash value to immudb failed")
			fmt.Println("please write (", dataroompath, ",", hex.EncodeToString(hash[:]), ") in immudb")
		}
	} else {
		fmt.Println("File " + filename + " not found in dataroom " + dataroompath)
	}

	// delete Lock File
	DeleteLockFile(config, dataroompath)
}

func ListRecipients(dataroompath string, config Config) {
	dataroommeta, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, rec := range dataroommeta.Recipients {
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

	// check + set Lock File + create DataroomMeta backup
	if ok, err := CheckSetLockFile(config, dataroompath); err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else if !ok {
		fmt.Println("Lockfile DataroomMeta.lock exists.")
		os.Exit(0)
	}

	// load DataroomMeta File
	dataroommeta, err := LoadFileKeyFile(dataroompath, config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// updade recipients in DataroomMeta File
	dataroommeta.Recipients = recipients

	jsonFileKey, err := json.Marshal(dataroommeta)
	if err != nil {
		fmt.Println("Unexpected decryption error: ", err)
		os.Exit(1)
	}

	// create sha256 sum
	hash := sha256.Sum256(jsonFileKey)

	// Konvertiere []byte in io.Reader
	reader := bytes.NewReader(jsonFileKey)

	// upload DataroomMeta file
	err = RcloneUpload(dataroommeta.Recipients, reader, config.Rcloneremote, dataroompath+"/.meta/DataroomMeta", config)
	if err != nil {
		fmt.Println("Error writing DataroomMeta file: ", err)
		DeleteLockFile(config, dataroompath)
		os.Exit(1)
	}

	// create hash of recipients file and store it in immudb
	// write immudb
	err = WriteImmmudb(dataroompath, hash[:], config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		// rollback/delete DataroomMeta
		fmt.Println("writing the hash value to immudb failed")
		fmt.Println("please write (", dataroompath, ",", hex.EncodeToString(hash[:]), ") in immudb")
	}

	// delete Lock File
	DeleteLockFile(config, dataroompath)
}

// Helper functions

func EncryptAge2(recipientstrings []string, out io.WriteCloser, in io.Reader) error {

	defer out.Close()
	var recipients []age.Recipient

	for _, key := range recipientstrings {
		// read public key
		recipient, err := age.ParseX25519Recipient(key)
		if err != nil {
			return fmt.Errorf("failed to parse recipient %s: %v", key, err)
		}

		// add recipient
		recipients = append(recipients, recipient)
	}

	w, err := age.Encrypt(out, recipients...)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %v", err)
	}

	// copy data from the input file into the encryption stream
	if _, err := io.Copy(w, in); err != nil {
		return fmt.Errorf("failed to encrypt file: %v", err)
	}

	// close the encryption stream
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

	// copy data from the input file into the encryption stream
	if _, err := io.Copy(w, in); err != nil {
		return fmt.Errorf("failed to encrypt file: %v", err)
	}

	// close the encryption stream
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
	fmt.Printf("Sucessfully set a verified entry in immudb: ('%s', '%s') @ tx %d\n", []byte(key), []byte(hex.EncodeToString(hash)), hdr.Id)

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

func RcloneUpload(recipientstrings []string, in io.Reader, remote string, path string, config Config) error {
	cmd := exec.Command("rclone", config.Rcloneparameter, "rcat", remote+":"+path)

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

func RcloneUploadSingle(recipient age.Recipient, in io.Reader, remote string, path string, config Config) error {
	cmd := exec.Command("rclone", config.Rcloneparameter, "rcat", remote+":"+path)

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

func LoadFileKeyFile(dataroompath string, config Config) (DataroomMeta, error) {
	// read hash from immudb
	expectedhash, err := ReadImmudb(dataroompath, config.Immudbserver, config.Immmudbport, []byte(config.Immudbuser), []byte(config.Immudbpassword))
	if err != nil {
		return DataroomMeta{}, fmt.Errorf("error Reading from immudb: %v", err)
	}

	// decrypting DataroomMeta
	out := &bytes.Buffer{}

	cmd := exec.Command("rclone", config.Rcloneparameter, "cat", config.Rcloneremote+":"+dataroompath+"/.meta/DataroomMeta")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return DataroomMeta{}, fmt.Errorf("error: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return DataroomMeta{}, fmt.Errorf("error: %v", err)
	}

	fkreader, err := DecryptAge(config.Agekeyfile, stdout)
	if err != nil {
		return DataroomMeta{}, fmt.Errorf("decryption error: %v", err)
	}

	if _, err := io.Copy(out, fkreader); err != nil {
		return DataroomMeta{}, fmt.Errorf("error: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return DataroomMeta{}, fmt.Errorf("decryption error: %v", err)
	}

	// compare hashes
	actualhash := sha256.Sum256(out.Bytes())
	if !bytes.Equal(expectedhash, []byte(hex.EncodeToString(actualhash[:]))) {
		return DataroomMeta{}, fmt.Errorf("error: hash vaildation failed")
	}

	var dataroommeta DataroomMeta

	err = json.Unmarshal(out.Bytes(), &dataroommeta)
	if err != nil {
		return DataroomMeta{}, fmt.Errorf("error: %v", err)
	}

	return dataroommeta, nil
}

func DeleteLockFile(config Config, dataroompath string) {
	cmd := exec.Command("rclone", config.Rcloneparameter, "delete", config.Rcloneremote+":"+dataroompath+"/.meta/DataroomMeta.lock")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Prüfe, ob der Fehler ein ExitError ist
		if _, ok := err.(*exec.ExitError); ok {
			fmt.Println("Error: ", string(output))
		} else {
			fmt.Println("Unexpected error: ", err)
		}
		fmt.Println("Please delete lock File ", dataroompath, "/.meta/DataroomMeta.lock manually")
		os.Exit(1)
	}
}

func CheckSetLockFile(config Config, dataroompath string) (bool, error) {
	// check lock file
	cmd := exec.Command("rclone", config.Rcloneparameter, "ls", config.Rcloneremote+":"+dataroompath+"/.meta/DataroomMeta.lock")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// check if the error is an ExitError
		if _, ok := err.(*exec.ExitError); !ok {
			return false, fmt.Errorf("unexpected error: %v", err)
		}
	} else if len(string(output)) != 0 {
		return false, nil
	}

	// create DataroomMeta backup
	cmd = exec.Command("rclone", config.Rcloneparameter, "copyto", config.Rcloneremote+":"+dataroompath+"/.meta/DataroomMeta", config.Rcloneremote+":"+dataroompath+"/.meta/DataroomMeta.backup")
	output, err = cmd.CombinedOutput()
	if err != nil {
		// check if the error is an ExitError
		if _, ok := err.(*exec.ExitError); ok {
			return false, fmt.Errorf("error creating DataroomMeta.backup: %v", string(output))
		} else {
			return false, fmt.Errorf("unexpected error: %v", err)
		}
	}

	// set lock file
	cmd = exec.Command("rclone", config.Rcloneparameter, "touch", config.Rcloneremote+":"+dataroompath+"/.meta/DataroomMeta.lock")
	output, err = cmd.CombinedOutput()
	if err != nil {
		// check if the error is an ExitError
		if _, ok := err.(*exec.ExitError); ok {
			return false, fmt.Errorf("error: %v", string(output))
		} else {
			return false, fmt.Errorf("unexpected error: %v", err)
		}
	}

	return true, nil
}

// ToDo:
// 		- consider brotobuf
//		- overwrite file
//		- other age recipient types
//		- rollback immudb
//		- parallel
//		- versioning (store hash, timestamp)
