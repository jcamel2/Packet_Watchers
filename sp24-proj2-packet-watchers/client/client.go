package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"bytes"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

type File struct {
	FileName string
	MacKey   []byte
	RootKey  []byte
	Counter  int
}

type FileContent struct {
	Content []byte
	MacKey  []byte
}

type Invitation struct {
	FileUUID       userlib.UUID
	SenderUsername string
	SenderPassword string
	SenderFileName string
	OwnerFileName  string
	OwnerUsername  string
	OwnerPassword  string
	Recipient      string
	IsOwner        bool
}

type Shared struct {
	SenderUUID        []byte
	SenderFileName    string
	OwnerFileName     string
	RecipientUsername string
	RecipientPassword string
	FileOwnerUsername string
	FileOwnerPassword string
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username        string
	Password        string
	MacKey          []byte
	DecKey          userlib.PKEDecKey
	SignKey         userlib.DSSignKey
	FilesShared     map[string][]Shared
	FileReceived    map[string]Shared
	InvitationsSent map[string]Invitation

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	/* Error Check */
	_, userExists := userlib.KeystoreGet(username + "Enc")
	if username == "" {
		return &userdata, errors.New("Invalid credentials")
	}

	if userExists {
		return &userdata, errors.New("User already exists")
	}

	/* Generate UUID and stuff for encryption */
	var uuidGen []byte = userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(username)), 48)
	userUUID, err := uuid.FromBytes(uuidGen[:16])
	if err != nil {
		return &userdata, err
	}

	symKey := uuidGen[16:32]
	macUUID, err := uuid.FromBytes(uuidGen[32:])
	if err != nil {
		return &userdata, err
	}

	macKey := userlib.RandomBytes(16)

	/* Public key encryption and digital signatures */
	pubEnc, privDec, err := userlib.PKEKeyGen()
	if err != nil {
		return &userdata, err
	}

	privSign, pubVerify, err := userlib.DSKeyGen()
	if err != nil {
		return &userdata, err
	}

	/* Fill fields for User */
	userdata.Username = username
	userdata.Password = password
	userdata.MacKey = macKey
	userdata.SignKey = privSign
	userdata.DecKey = privDec
	userdata.FileReceived = make(map[string]Shared)
	userdata.FilesShared = make(map[string][]Shared)
	userdata.InvitationsSent = make(map[string]Invitation)

	/* Put public keys on KeyStore */
	userlib.KeystoreSet(username+"Enc", pubEnc)
	userlib.KeystoreSet(username+"Ver", pubVerify)

	err = userdata.EncryptUserStruct(symKey, macKey, macUUID, userUUID)
	if err != nil {
		return &userdata, err
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	/* Check is user doesn't exist*/
	_, userExists := userlib.KeystoreGet(username + "Enc")
	if !userExists {
		return userdataptr, errors.New("User does not exist")
	}

	/* Generate UUID and stuff for decryption attempt to get from DataStore */
	uuidGen := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(username)), 48)
	userUUID, err := uuid.FromBytes(uuidGen[:16])

	cipherText, validCredentials := userlib.DatastoreGet(userUUID)

	/* Check for invalid credentials */
	if err != nil {
		return &userdata, err
	} else if !validCredentials {
		return &userdata, errors.New("Credentials are invalid")
	}

	symKey := uuidGen[16:32]
	macUUID, err := uuid.FromBytes(uuidGen[32:])
	if err != nil {
		return &userdata, err
	}

	err = userdata.VerifyUserStruct(symKey, macUUID, cipherText)
	if err != nil {
		return &userdata, err
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	_, fileExistsFromReceived := userdata.FileReceived[filename]
	if !fileExistsFromReceived {
		err = userdata.StoreFileStructs(filename, content, false, false)
	} else {
		err = userdata.StoreFileStructs(filename, content, false, true)
	}
	return err
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	uuidGen := userlib.Argon2Key(userlib.Hash([]byte(userdata.Password)), userlib.Hash([]byte(userdata.Username)), 48)
	userUUID := uuidGen[:16]
	uuidAndFileName := userlib.Hash([]byte(string(userUUID) + (filename)))
	fileUUID, err := uuid.FromBytes(uuidAndFileName[16:32])
	if err != nil {
		return err
	}
	_, fileExists := userlib.DatastoreGet(uuid.UUID(fileUUID))
	if !fileExists {
		err = userdata.StoreFileStructs(filename, content, true, true)
	} else {
		err = userdata.StoreFileStructs(filename, content, true, false)
	}
	return err
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	empty := []byte{}
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return empty, err
	}
	/* Get File struct */
	var filedata File

	uuidGen := userlib.Argon2Key(userlib.Hash([]byte(userdata.Password)), userlib.Hash([]byte(userdata.Username)), 48)
	userUUID := uuidGen[:16]
	userSymKey := uuidGen[16:32]
	userMacUUID := uuidGen[32:48]
	userCipher, exists := userlib.DatastoreGet(uuid.UUID(userUUID))
	if !exists {
		return empty, errors.New("User got deleted")
	}
	uuidAndFileName := userlib.Hash([]byte(string(userUUID) + (filename)))

	dataSymKey := uuidAndFileName[:16]
	fileUUID := uuidAndFileName[16:32]
	macDataUUID := uuidAndFileName[32:48]
	purposeUUID := uuidAndFileName[48:64]

	var filePurpose []byte

	userdata.VerifyUserStruct(userSymKey, uuid.UUID(userMacUUID), userCipher)

	fileDataCipher, fileExists := userlib.DatastoreGet(uuid.UUID(fileUUID))
	shared, fileExistsFromReceived := userdata.FileReceived[filename]

	if !fileExists && !fileExistsFromReceived {
		return empty, errors.New("File does not exist")
	} else if fileExistsFromReceived {
		fileOwnerUUIDGen := userlib.Argon2Key(userlib.Hash([]byte(shared.FileOwnerPassword)), userlib.Hash([]byte(shared.FileOwnerUsername)), 48)
		fileOwnerUUID := fileOwnerUUIDGen[:16]
		uuidAndFileName := userlib.Hash([]byte(string(fileOwnerUUID) + (shared.OwnerFileName)))
		dataSymKey = uuidAndFileName[:16]
		fileUUID = uuidAndFileName[16:32]
		macDataUUID = uuidAndFileName[32:48]
		purposeUUID = uuidAndFileName[48:64]
		filePurpose, exists = userlib.DatastoreGet(uuid.UUID(purposeUUID))
		if !exists {
			return empty, errors.New("Purpose does not exist")
		}

		dataSymKey, err = userlib.HashKDF(dataSymKey, filePurpose)
		if err != nil {
			return empty, err
		}
		dataSymKey = dataSymKey[:16]

		fileDataCipher, _ = userlib.DatastoreGet(uuid.UUID(fileUUID))
	} else {
		filePurpose, exists = userlib.DatastoreGet(uuid.UUID(purposeUUID))
		if !exists {
			return empty, errors.New("Purpose does not exist")
		}
		dataSymKey, err = userlib.HashKDF(dataSymKey, filePurpose)
		if err != nil {
			return empty, err
		}
		dataSymKey = dataSymKey[:16]
	}

	err = filedata.VerifyFileStruct(dataSymKey, uuid.UUID(macDataUUID), fileDataCipher)
	if err != nil {
		return empty, err
	}

	var completedContent bytes.Buffer
	var curFileContent FileContent
	for i := 0; i <= filedata.Counter; i++ {

		/* Get key, struct uuid and mac uuid for current file content */
		hashedContent, err := userlib.HashKDF(filedata.RootKey, []byte(string(i)))
		if err != nil {
			return empty, err
		}

		contentSymKey := hashedContent[:16]
		contentUUID, err := uuid.FromBytes(hashedContent[16:32])
		if err != nil {
			return empty, err
		}
		macContentUUID, err := uuid.FromBytes(hashedContent[32:48])
		if err != nil {
			return empty, err
		}

		curContentCipher, exists := userlib.DatastoreGet(contentUUID)
		if !exists {
			return empty, errors.New("Encountered error when loading file contents")
		}

		/* Decrypt and unmarshal */
		plainText := userlib.SymDec(contentSymKey, curContentCipher)
		err = json.Unmarshal(plainText, &curFileContent)
		if err != nil {
			return empty, err
		}

		/* Compare MACs */
		curMac, err := userlib.HMACEval(curFileContent.MacKey, curContentCipher)
		if err != nil {
			return empty, err
		}

		dsMac, exists := userlib.DatastoreGet(macContentUUID)
		if !exists {
			return empty, errors.New("Encountered error when loading file contents")
		}

		comp := userlib.HMACEqual(curMac, dsMac)
		if !comp {
			return empty, errors.New("File Contents have been tampered with")
		}

		/* Append current contents*/
		completedContent.WriteString(string(curFileContent.Content))
	}
	return completedContent.Bytes(), err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	_, userExists := userlib.KeystoreGet(recipientUsername + "Enc")
	if !userExists {
		return uuid.New(), errors.New("Recipient does not exist")
	}
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return uuid.New(), errors.New("User has been tampered with")
	}
	var inv Invitation
	uuidGen := userlib.Argon2Key(userlib.Hash([]byte(userdata.Password)), userlib.Hash([]byte(userdata.Username)), 48)
	userUUID := uuidGen[:16]
	userCipher, exists := userlib.DatastoreGet(uuid.UUID(userUUID))
	if !exists {
		return uuid.New(), errors.New("User got deleted")
	}
	userSymKey := uuidGen[16:32]
	userMacUUID := uuidGen[32:48]
	uuidAndFileName := userlib.Hash([]byte(string(userUUID) + (filename)))
	fileUUID := uuidAndFileName[16:32]

	userdata.VerifyUserStruct(userSymKey, uuid.UUID(userMacUUID), userCipher)

	/* Check if user created file or has received file. Depending on if we are the ownder or a recipient */
	_, fileExistsFromDataStore := userlib.DatastoreGet(uuid.UUID(fileUUID))
	shared, fileExistsFromReceived := userdata.FileReceived[filename]

	if !fileExistsFromDataStore && !fileExistsFromReceived {
		return uuid.New(), errors.New("File does not exist")
		/* We have the file UUID already generated*/
	} else if fileExistsFromDataStore {
		inv.FileUUID = uuid.UUID(fileUUID)
		inv.OwnerFileName = filename
		inv.IsOwner = true
		inv.OwnerUsername = userdata.Username
		inv.OwnerPassword = userdata.Password
		/* Use the shared struct to get the fileUUID*/
	} else {
		fileOwnerUUIDGen := userlib.Argon2Key(userlib.Hash([]byte(inv.OwnerPassword)), userlib.Hash([]byte(inv.OwnerUsername)), 48)
		fileOwnerUUID := fileOwnerUUIDGen[:16]
		fileUUID := userlib.Hash([]byte(string(fileOwnerUUID) + (shared.OwnerFileName)))
		inv.FileUUID = uuid.UUID(fileUUID)
		inv.OwnerFileName = shared.OwnerFileName
		inv.IsOwner = false
		inv.OwnerUsername = shared.FileOwnerUsername
		inv.OwnerPassword = shared.FileOwnerPassword
	}
	inv.Recipient = recipientUsername
	inv.SenderUsername = userdata.Username
	inv.SenderPassword = userdata.Password
	inv.SenderFileName = filename

	invitationPtr, err = uuid.FromBytes(userlib.Hash([]byte(recipientUsername + userdata.Username + filename))[:16])
	if err != nil {
		return uuid.New(), err
	}
	randomKey := string(userlib.RandomBytes(16))
	userdata.InvitationsSent[randomKey] = inv

	hashedInv := userlib.Hash([]byte(recipientUsername + invitationPtr.String()))
	symKey := hashedInv[:16]
	sigUUID, err := uuid.FromBytes(hashedInv[16:32])
	if err != nil {
		return uuid.New(), err
	}
	symKeyUUID, err := uuid.FromBytes(hashedInv[32:48])
	if err != nil {
		return uuid.New(), err
	}

	iv := userlib.RandomBytes(16)

	/* Sign the invitation, use Sign-Then-Encrypt */
	plainInv, err := json.Marshal(inv)
	if err != nil {
		return uuid.New(), err
	}

	sig, err := userlib.DSSign(userdata.SignKey, symKey)
	if err != nil {
		return uuid.New(), err
	}

	pubEncKey, _ := userlib.KeystoreGet(recipientUsername + "Enc")
	cipherSymKey, err := userlib.PKEEnc(pubEncKey, symKey)

	if err != nil {
		return uuid.New(), err
	}

	cipherInv := userlib.SymEnc(symKey, iv, plainInv)

	/* Put updates to DataStore */

	userdata.EncryptUserStruct(userSymKey, userdata.MacKey, uuid.UUID(userMacUUID), uuid.UUID(userUUID))
	userlib.DatastoreSet(invitationPtr, cipherInv)
	userlib.DatastoreSet(sigUUID, sig)
	userlib.DatastoreSet(symKeyUUID, cipherSymKey)

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var inv Invitation
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	cipherInv, invExists := userlib.DatastoreGet(invitationPtr)
	if !invExists {
		return errors.New("Invitation does not exist")
	}

	/* Get data to verify User struct */
	uuidGen := userlib.Argon2Key(userlib.Hash([]byte(userdata.Password)), userlib.Hash([]byte(userdata.Username)), 48)
	userUUID := uuidGen[:16]
	userSymKey := uuidGen[16:32]
	userMacUUID, err := uuid.FromBytes(uuidGen[32:48])
	if err != nil {
		return err
	}
	uuidAndFileName := userlib.Hash([]byte(string(userUUID) + (filename)))
	fileUUID := uuidAndFileName[16:32]
	cipherText, exists := userlib.DatastoreGet(uuid.UUID(userUUID))
	if !exists {
		return errors.New("User got deleted")
	}
	userdata.VerifyUserStruct(userSymKey, userMacUUID, cipherText)

	/* Get file */
	_, fileExists := userlib.DatastoreGet(uuid.UUID(fileUUID))
	if fileExists {
		return errors.New("File already exists in the users namespace")
	}

	_, fileExistsFromReceived := userdata.FileReceived[filename]
	if fileExistsFromReceived {
		return errors.New("File already exists in the users namespace")
	}

	/* Generate UUIDs for signature and symmetric key since these will be put ser*/
	hashedInv := userlib.Hash([]byte(userdata.Username + invitationPtr.String()))
	sigUUID, err := uuid.FromBytes(hashedInv[16:32])
	if err != nil {
		return err
	}
	symKeyUUID, err := uuid.FromBytes(hashedInv[32:48])
	if err != nil {
		return err
	}

	cipherSymKey, keyExists := userlib.DatastoreGet(symKeyUUID)
	if !keyExists {
		return errors.New("Key does not exist")
	}

	symKey, err := userlib.PKEDec(userdata.DecKey, cipherSymKey)
	if err != nil {
		return err
	}

	sig, sigExists := userlib.DatastoreGet(uuid.UUID(sigUUID))
	if !sigExists {
		return errors.New("Signature does not exist.")
	}

	verKey, verKeyExists := userlib.KeystoreGet(senderUsername + "Ver")
	if !verKeyExists {
		return errors.New("Verification Key does not exist")
	}

	/* Verify Signature */
	err = userlib.DSVerify(verKey, symKey, sig)
	if err != nil {
		return err
	}

	plainInv := userlib.SymDec(symKey, cipherInv)

	err = json.Unmarshal(plainInv, &inv)
	if err != nil {
		return err
	}

	senderUUIDGen := userlib.Argon2Key(userlib.Hash([]byte(inv.SenderPassword)), userlib.Hash([]byte(inv.SenderUsername)), 48)
	senderUUID := senderUUIDGen[:16]
	senderSymKey := senderUUIDGen[16:32]
	senderMacUUID, err := uuid.FromBytes(senderUUIDGen[32:48])

	_, exists = userlib.DatastoreGet(uuid.UUID(senderUUID))
	if !exists {
		return errors.New("Sender's struct got cooked")
	}

	/* Create the shared struct */
	var shared Shared
	shared.SenderUUID = senderUUID
	shared.SenderFileName = inv.SenderFileName
	shared.RecipientUsername = userdata.Username
	shared.RecipientPassword = userdata.Password
	shared.FileOwnerUsername = inv.OwnerUsername
	shared.FileOwnerPassword = inv.OwnerPassword

	var senderdata *User
	senderdata, err = GetUser(inv.SenderUsername, inv.SenderPassword)
	if err != nil {
		return err
	}

	if inv.IsOwner {
		shared.OwnerFileName = inv.OwnerFileName
	} else {
		senderDataShared, sharedExists := senderdata.FileReceived[inv.SenderFileName]
		if !sharedExists {
			return errors.New("Access has been revoked or something.")
		}
		shared.OwnerFileName = senderDataShared.OwnerFileName
	}
	/* Verify file struct before sharing */

	var file *File
	fileOwnerUUIDGen := userlib.Argon2Key(userlib.Hash([]byte(inv.OwnerPassword)), userlib.Hash([]byte(inv.OwnerUsername)), 48)
	fileOwnerUUID := fileOwnerUUIDGen[:16]
	uuidAndFileName = userlib.Hash([]byte(string(fileOwnerUUID) + (inv.OwnerFileName)))
	fileSymKey := uuidAndFileName[:16]
	fileUUID = uuidAndFileName[16:32]
	fileMacUUID := uuidAndFileName[32:48]
	purposeUUID := uuidAndFileName[48:64]

	filePurpose, exists := userlib.DatastoreGet(uuid.UUID(purposeUUID))
	if !exists {
		return errors.New("Purpose does not exist")
	}
	fileSymKey, err = userlib.HashKDF(fileSymKey, filePurpose)
	if err != nil {
		return err
	}
	fileSymKey = fileSymKey[:16]

	fileCipher, fileExists := userlib.DatastoreGet(uuid.UUID(fileUUID))
	if !fileExists {
		return errors.New("File does not exist")
	}
	err = file.VerifyFileStruct(fileSymKey, uuid.UUID(fileMacUUID), fileCipher)
	if err != nil {
		return err
	}
	/* Update recipient's FilesReceived and sender's FilesShared */
	userdata.FileReceived[filename] = shared
	senderdata.FilesShared[shared.OwnerFileName] = append(senderdata.FilesShared[shared.OwnerFileName], shared)

	for key, _ := range senderdata.InvitationsSent {
		if senderdata.InvitationsSent[key] == inv {
			delete(senderdata.InvitationsSent, key)
			break
		}
	}

	userdata.EncryptUserStruct(userSymKey, userdata.MacKey, uuid.UUID(userMacUUID), uuid.UUID(userUUID))
	if err != nil {
		return err
	}
	senderdata.EncryptUserStruct(senderSymKey, senderdata.MacKey, senderMacUUID, uuid.UUID(senderUUID))

	userlib.DatastoreDelete(invitationPtr)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	// /* Check if file exists in user's namespace */
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	uuidGen := userlib.Argon2Key(userlib.Hash([]byte(userdata.Password)), userlib.Hash([]byte(userdata.Username)), 48)
	userUUID := uuidGen[:16]
	userSymKey := uuidGen[16:32]
	userMacUUID := uuidGen[32:48]
	uuidAndFileName := userlib.Hash([]byte(string(userUUID) + (filename)))
	dataSymKey := uuidAndFileName[:16]
	fileUUID := uuidAndFileName[16:32]
	macDataUUID := uuidAndFileName[32:48]
	purposeUUID := uuidAndFileName[48:64]

	filePurpose, exists := userlib.DatastoreGet(uuid.UUID(purposeUUID))
	if !exists {
		errors.New("Purpose got cooked")
	}

	dataSymKey, err = userlib.HashKDF(dataSymKey, filePurpose)
	if err != nil {
		return err
	}

	dataSymKey = dataSymKey[:16]

	userCipher, exists := userlib.DatastoreGet(uuid.UUID(userUUID))
	if !exists {
		return errors.New("User got cooked")
	}
	userdata.VerifyUserStruct(userSymKey, uuid.UUID(userMacUUID), userCipher)

	fileCipher, fileExists := userlib.DatastoreGet(uuid.UUID(fileUUID))
	if !fileExists {
		return errors.New("File does not exist in users namespace")
	}

	// // /* Check if file is shared with recipient */
	var recipientToInvoke Shared
	shared := false
	for i := 0; i < len(userdata.FilesShared[filename]); i++ {
		if recipientUsername == userdata.FilesShared[filename][i].RecipientUsername {
			shared = true
			recipientToInvoke = userdata.FilesShared[filename][i]
			/* Remove Shared struct from owner to recipient */
			num := i + 1
			length := len(userdata.FilesShared[filename])
			copy := userdata.FilesShared[filename]
			userdata.FilesShared[filename] = userdata.FilesShared[filename][:i]
			for j := num; j < length; j++ {
				userdata.FilesShared[filename] = append(userdata.FilesShared[filename], copy[j])
			}
			break
		}
	}
	if !shared {
		// check for pending invite, if none throw error
		for key, _ := range userdata.InvitationsSent {
			if userdata.InvitationsSent[key].Recipient == recipientUsername {
				invitationPtr, err := uuid.FromBytes(userlib.Hash([]byte(recipientUsername + userdata.Username + filename))[:16])
				if err != nil {
					return err
				}
				userlib.DatastoreDelete(invitationPtr)
				delete(userdata.InvitationsSent, key)
				return nil
			}

		}
		return errors.New("File is not shared with recipient")
	}

	// /* Remove recipient from being shared with this file , along with all their children  this involves the following
	// - remove recipient in FilesShared of sender
	// - remove sender in FilesReceived of recipient
	// - Need to do this with the recipient we are revoking from and all their children
	// */
	userRecipient, err := GetUser(recipientToInvoke.RecipientUsername, recipientToInvoke.RecipientPassword)
	if err != nil {
		return err
	}

	for file, _ := range userRecipient.FileReceived {
		if userRecipient.FileReceived[file].OwnerFileName == filename {
			delete(userRecipient.FileReceived, file)
			break
		}
	}

	var invitationPtr uuid.UUID

	// Delete any pending invitations
	for key, _ := range userRecipient.InvitationsSent {
		if userRecipient.InvitationsSent[key].OwnerFileName == filename {
			invitationPtr, err = uuid.FromBytes(userlib.Hash([]byte(userRecipient.Username +
				userRecipient.InvitationsSent[key].SenderUsername +
				userRecipient.InvitationsSent[key].SenderFileName))[:16])
			if err != nil {
				return err
			}
			userlib.DatastoreDelete(invitationPtr)
			delete(userRecipient.InvitationsSent, key)
		}
	}

	/* Do recursive helper call */
	var structsToDelete []string
	for file, _ := range userRecipient.FilesShared {
		if file == filename {
			for j := 0; j < len(userRecipient.FilesShared[file]); j++ {
				structsToDelete = append(structsToDelete, file) // Get all the structs to delete
				childShared := userRecipient.FilesShared[file][j]
				childUser, err := GetUser(childShared.RecipientUsername, childShared.RecipientPassword)
				childUUIDGen := userlib.Argon2Key(userlib.Hash([]byte(childUser.Password)), userlib.Hash([]byte(childUser.Username)), 48)
				childUUID := childUUIDGen[:16]
				childSymKey := childUUIDGen[16:32]
				childMacUUID := childUUIDGen[32:48]

				childCipher, exists := userlib.DatastoreGet(uuid.UUID(childUUID))
				if !exists {
					return errors.New("Child user got cooked")
				}
				err = childUser.VerifyUserStruct(childSymKey, uuid.UUID(childMacUUID), childCipher)

				if err != nil {
					return err
				}
				childUser.revokeChildAccess(filename)
			}
		}
	}

	// delete structs from FilesShared
	for _, fileKey := range structsToDelete {
		delete(userdata.FilesShared, fileKey)
		delete(userRecipient.FilesShared, fileKey)
	}

	/* Change Owner's Purpose */
	newPurpose := userlib.RandomBytes(16)

	dataIV := userlib.RandomBytes(16)
	/* TODO: Re-encrypt file struct with new symmetric key */
	var filedata File

	filedata.VerifyFileStruct(dataSymKey, uuid.UUID(macDataUUID), fileCipher)
	plainText := userlib.SymDec(dataSymKey, fileCipher)
	err = json.Unmarshal(plainText, &filedata)
	if err != nil {
		return err
	}
	uuidAndFileName = userlib.Hash([]byte(string(userUUID) + (filename)))
	dataSymKey, err = userlib.HashKDF(uuidAndFileName[:16], newPurpose)
	if err != nil {
		return err
	}
	dataSymKey = dataSymKey[:16]
	marshalledData, err := json.Marshal((&filedata))
	if err != nil {
		return err
	}

	/* Re-Encrypt under new sym key */
	dataCipher := userlib.SymEnc(dataSymKey, dataIV, marshalledData)
	macData, err := userlib.HMACEval(filedata.MacKey, dataCipher)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(uuid.UUID(macDataUUID), macData)
	userlib.DatastoreSet(uuid.UUID(fileUUID), dataCipher)
	userlib.DatastoreSet(uuid.UUID(purposeUUID), newPurpose)

	recipUUIDGen := userlib.Argon2Key(userlib.Hash([]byte(userRecipient.Password)), userlib.Hash([]byte(userRecipient.Username)), 48)
	recipUserUUID := recipUUIDGen[:16]
	recipSymKey := recipUUIDGen[16:32]
	recipMacUUID := recipUUIDGen[32:48]

	/* Change purpose TODO*/

	userdata.EncryptUserStruct(userSymKey, userdata.MacKey, uuid.UUID(userMacUUID), uuid.UUID(userUUID))
	userRecipient.EncryptUserStruct(recipSymKey, userRecipient.MacKey, uuid.UUID(recipMacUUID), uuid.UUID(recipUserUUID))

	return nil
}

/* HELPERS HELPERS HELPERS HELPERS HELPERS HELPERS HELPERS HELPERS HELPERS HELPERS HELPERS */

func (userdata *User) revokeChildAccess(filename string) error {
	uuidGen := userlib.Argon2Key(userlib.Hash([]byte(userdata.Password)), userlib.Hash([]byte(userdata.Username)), 48)
	userUUID := uuidGen[:16]
	userSymKey := uuidGen[16:32]
	userMacUUID := uuidGen[32:48]

	/* Remove sender from FilesReceived of Recipient */
	for file, _ := range userdata.FileReceived {
		if userdata.FileReceived[file].OwnerFileName == filename {
			delete(userdata.FileReceived, file)
			break
		}
	}

	var invitationPtr uuid.UUID
	var err error

	/* Delete any pending invitations */
	for key, _ := range userdata.InvitationsSent {
		if userdata.InvitationsSent[key].OwnerFileName == filename {
			invitationPtr, err = uuid.FromBytes(userlib.Hash([]byte(userdata.InvitationsSent[key].Recipient +
				userdata.InvitationsSent[key].SenderUsername +
				userdata.InvitationsSent[key].SenderFileName))[:16])
			if err != nil {
				return err
			}
			userlib.DatastoreDelete(invitationPtr)
			delete(userdata.InvitationsSent, key)
		}
	}

	/* If child has shared the file with anyone, recursively call to revoke on those grandchildren */

	var structsToDelete []string
	for i := 0; i < len(userdata.FilesShared[filename]); i++ {
		structsToDelete = append(structsToDelete, filename)
		childShared := userdata.FilesShared[filename][i]
		childUser, err := GetUser(childShared.RecipientUsername, childShared.RecipientPassword)
		/* Verify child struct */
		childUUIDGen := userlib.Argon2Key(userlib.Hash([]byte(childUser.Password)), userlib.Hash([]byte(childUser.Username)), 48)
		childUUID := childUUIDGen[:16]
		childSymKey := childUUIDGen[16:32]
		childMacUUID := childUUIDGen[32:48]

		childCipher, exists := userlib.DatastoreGet(uuid.UUID(childUUID))
		if !exists {
			return errors.New("Child user got cooked")
		}
		err = childUser.VerifyUserStruct(childSymKey, uuid.UUID(childMacUUID), childCipher)

		if err != nil {
			return err
		}
		childUser.revokeChildAccess(filename)
	}

	// Go through structs to delete
	for _, fileKey := range structsToDelete {
		delete(userdata.FilesShared, fileKey)
	}

	userdata.EncryptUserStruct(userSymKey, userdata.MacKey, uuid.UUID(userMacUUID), uuid.UUID(userUUID))
	return nil
}

func (userdata *User) StoreFileStructs(filename string, content []byte, isAppend bool, received bool) error {
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	uuidAndFileName := []byte{}
	uuidGen := userlib.Argon2Key(userlib.Hash([]byte(userdata.Password)), userlib.Hash([]byte(userdata.Username)), 48)
	userUUID := uuidGen[:16]
	symKey := uuidGen[16:32]
	macUUID, err := uuid.FromBytes(uuidGen[32:])
	if err != nil {
		return err
	}
	userCipherText, exists := userlib.DatastoreGet(uuid.UUID(userUUID))

	if exists {
		err := userdata.VerifyUserStruct(symKey, macUUID, userCipherText)
		if err != nil {
			return err
		}
	}

	if !received {
		uuidAndFileName = userlib.Hash([]byte(string(userUUID) + (filename)))
	} else {
		shared, _ := userdata.FileReceived[filename]
		fileOwnerUUIDGen := userlib.Argon2Key(userlib.Hash([]byte(shared.FileOwnerPassword)), userlib.Hash([]byte(shared.FileOwnerUsername)), 48)
		fileOwnerUUID := fileOwnerUUIDGen[:16]
		uuidAndFileName = userlib.Hash([]byte(string(fileOwnerUUID) + (shared.OwnerFileName)))
		if err != nil {
			return err
		}
	}

	macDataKey := userlib.RandomBytes(16)
	macContentKey := userlib.RandomBytes(16)
	dataIV := userlib.RandomBytes(16)
	contentIV := userlib.RandomBytes(16)
	filePurpose := userlib.RandomBytes(16)

	/* Use purpose for extra security */
	dataSymKey, err := userlib.HashKDF(uuidAndFileName[:16], filePurpose)
	if err != nil {
		return err
	}
	/* Slice the first 16 bytes to use as key*/
	dataSymKey = dataSymKey[:16]

	fileUUID, err := uuid.FromBytes(uuidAndFileName[16:32])
	if err != nil {
		return err
	}
	macDataUUID, err := uuid.FromBytes(uuidAndFileName[32:48])
	if err != nil {
		return err
	}

	purposeUUID, err := uuid.FromBytes(uuidAndFileName[48:64])
	if err != nil {
		return err
	}

	var filedata File
	/* Make new File Struct or update current */
	if isAppend {

		fileDataCipher, fileExists := userlib.DatastoreGet(fileUUID)
		if !fileExists {
			return errors.New("File does not exist in user namespace")
		}
		filePurpose, exists = userlib.DatastoreGet(purposeUUID)
		if !exists {
			return errors.New("Purpose does not exist")
		}
		dataSymKey, err = userlib.HashKDF(uuidAndFileName[:16], filePurpose)
		if err != nil {
			return err
		}
		/* Slice the first 16 bytes to use as key*/
		dataSymKey = dataSymKey[:16]

		err = json.Unmarshal(userlib.SymDec(dataSymKey, fileDataCipher), &filedata)
		if err != nil {
			return err
		}

		/* Check MAC for File */
		currentDataMac, err := userlib.HMACEval(filedata.MacKey, fileDataCipher)
		if err != nil {
			return err
		}

		dsMac, exists := userlib.DatastoreGet(uuid.UUID(macDataUUID))

		if !exists {
			return err
		}

		comp := userlib.HMACEqual(currentDataMac, dsMac)
		if !comp {
			return errors.New("File struct has been tampered with")
		}
		/* Make new FileContent to append*/
		filedata.Counter++

	} else {
		/* Delete prev file contents if any */
		for i := 0; i < filedata.Counter; i++ {
			hashedContent, err := userlib.HashKDF(filedata.RootKey, []byte(string(i)))
			if err != nil {
				return err
			}
			contentUUID, err := uuid.FromBytes(hashedContent[16:32])
			if err != nil {
				return err
			}
			macUUID, err := uuid.FromBytes(hashedContent[32:48])
			if err != nil {
				return err
			}
			userlib.DatastoreDelete(contentUUID)
			userlib.DatastoreDelete(macUUID)

		}
		filedata.FileName = filename
		filedata.Counter = 0
		filedata.RootKey = userlib.RandomBytes(16)
		filedata.MacKey = macDataKey

		userlib.DatastoreSet(purposeUUID, filePurpose)
	}
	/* Make new FileContent with its UUID and Key */
	var filecontent FileContent
	filecontent.Content = content
	filecontent.MacKey = macContentKey
	hashedContent, err := userlib.HashKDF(filedata.RootKey, []byte(string(filedata.Counter)))
	if err != nil {
		return err
	}
	contentSymKey := hashedContent[:16]
	contentUUID, err := uuid.FromBytes(hashedContent[16:32])
	if err != nil {
		return err
	}

	macContentUUID, err := uuid.FromBytes(hashedContent[32:48])
	if err != nil {
		return err
	}

	/* Put File and its contents of DataStore */
	marshalledContent, err := json.Marshal((&filecontent))
	if err != nil {
		return err
	}

	marshalledData, err := json.Marshal((&filedata))
	if err != nil {
		return err
	}

	dataCipher := userlib.SymEnc(dataSymKey, dataIV, marshalledData)
	userlib.DatastoreSet(uuid.UUID(fileUUID), dataCipher)

	contentCipher := userlib.SymEnc(contentSymKey, contentIV, marshalledContent)
	userlib.DatastoreSet(contentUUID, contentCipher)

	macData, err := userlib.HMACEval(filedata.MacKey, dataCipher)
	if err != nil {
		return err
	}
	macContent, err := userlib.HMACEval(macContentKey, contentCipher)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(uuid.UUID(macContentUUID), macContent)
	userlib.DatastoreSet(uuid.UUID(macDataUUID), macData)

	return nil
}

/* NEED TO MAKE AN ENCRYPT AND MAC USER STRUCT HELPER */

func (userdata *User) EncryptUserStruct(symKey []byte, macKey []byte, macUUID userlib.UUID, userUUID userlib.UUID) (err error) {
	/* Generate cipher text */
	marshalled, err := json.Marshal(&userdata)
	if err != nil {
		return err
	}

	iv := userlib.RandomBytes(16)
	cipherText := userlib.SymEnc(symKey, iv, marshalled)

	/* Generate Mac */
	mac, err := userlib.HMACEval(macKey, cipherText)

	if err != nil {
		return err
	}

	userlib.DatastoreSet(macUUID, mac)
	userlib.DatastoreSet(userUUID, cipherText)

	return nil

}

func (userdata *User) VerifyUserStruct(symKey []byte, macUUID userlib.UUID, cipherText []byte) (err error) {
	plainText := userlib.SymDec(symKey, cipherText)

	marshalledErr := json.Unmarshal(plainText, &userdata)
	if marshalledErr != nil {
		return err
	}

	currentMac, err := userlib.HMACEval(userdata.MacKey, cipherText)
	if err != nil {
		return err
	}

	dsMac, dsErr := userlib.DatastoreGet(macUUID)
	if !dsErr {
		return errors.New("UUID has been altered")
	}
	comp := userlib.HMACEqual(currentMac, dsMac)
	if !comp {
		return errors.New("User struct has been tampered with")
	}

	return nil
}

/* NEED TO MAKE AN ENCRYYPT FILE STRUCT HELPER */
func (filedata *File) VerifyFileStruct(symKey []byte, macUUID userlib.UUID, cipherText []byte) (err error) {
	err = json.Unmarshal(userlib.SymDec(symKey, cipherText), &filedata)
	if err != nil {
		return err
	}
	/* Check MAC for File*/
	currentDataMac, err := userlib.HMACEval(filedata.MacKey, cipherText)
	if err != nil {
		return err
	}
	dsMac, exists := userlib.DatastoreGet(uuid.UUID(macUUID))
	if !exists {
		return err
	}
	comp := userlib.HMACEqual(currentDataMac, dsMac)
	if !comp {
		return errors.New("File struct has been tampered with")
	}
	return nil
}
