package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

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

type UUID = userlib.UUID
type PKEEncKey = userlib.PKEEncKey
type PKEDecKey = userlib.PKEDecKey
type DSSignKey = userlib.DSSignKey
type DSVerifyKey = userlib.DSVerifyKey

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username           string // store for future use (maybe)
	UserEncKey         []byte // get from Argon2Key(), protect clientNode data
	UserMacKey         []byte // 16-byte from Argon2Key(), protect clientNode data
	UserRSAPrivateKey  PKEDecKey
	UserSignPrivateKey DSSignKey
}

/* Protected by userNode */
type FileHeader struct {
	ShareId  UUID
	FHEncKey []byte
	FHMacKey []byte
}

type Data struct {
	CypherText []byte
	MAC        []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		return nil, errors.New("the username is empty")
	}
	var userdata User
	userdata.Username = username
	uid, err := getUUIDFromUser(username)
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(uid)
	if ok {
		return nil, errors.New("the given username already exist")
	}

	// Get encKey and macKey for User ON FLY!
	encKey := getEncKeyFromUser(username, []byte(password))
	macKey := getMACKeyFromUser(username, []byte(password))

	// Get encKey and macKey in User for FileHeader
	userEncKey, userMacKey, err := getNextKeyPair(encKey, macKey)
	if err != nil {
		return nil, err
	}
	userdata.UserEncKey = userEncKey
	userdata.UserMacKey = userMacKey

	// Generate RSA key pair
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.UserRSAPrivateKey = privateKey
	rsaString := username + "RSA public key"
	err = userlib.KeystoreSet(rsaString, publicKey)
	if err != nil {
		return nil, err
	}

	// Generate digital signature key pair
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	signString := username + "Digital signature key"
	userdata.UserSignPrivateKey = signKey
	err = userlib.KeystoreSet(signString, verifyKey)
	if err != nil {
		return nil, err
	}

	//Save userdata to Datastore
	err = storeObject(uid, userdata, encKey, macKey)
	if err != nil {
		return nil, err
	}
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}

/* Helper Functions */

/* Store an object into the Datastore with given UUID */
func storeObject(dataId UUID, object interface{}, encKey []byte, macKey []byte) (err error) {
	var data Data
	key := userlib.RandomBytes(16)
	// Convert the data structure to []bytes
	dataBytes, err := json.Marshal((object))
	if err != nil {
		return err
	}
	// Encrypte data and evaluate the HMAC
	cypherBytes := userlib.SymEnc(key, dataBytes, encKey)
	macBytes, err := userlib.HMACEval(macKey, dataBytes)
	if err != nil {
		return err
	}
	// put cyphertext and HMAC into data and store into Datastore
	data.CypherText = cypherBytes
	data.MAC = macBytes
	storeBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(dataId, storeBytes)
	return nil
}

/* Get an object from the Datastore */
func getObject(dataId UUID, encKey []byte, macKey []byte) (object interface{}, err error) {
	databytes, ok := userlib.DatastoreGet(dataId)
	if !ok {
		return nil, errors.New("no corresponding UUID found")
	}
	// Get data from the Datastore
	var data Data
	err = json.Unmarshal(databytes, &data)
	if err != nil {
		return nil, err
	}
	cypherBytes := data.CypherText
	macBytes := data.MAC
	// Verify the HMAC of data in Datastore
	storedMac, err := userlib.HMACEval(macKey, cypherBytes)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(storedMac, macBytes) {
		return nil, errors.New("the data from the Datastore is manipulated")
	}
	objectBytes := userlib.SymDec(encKey, cypherBytes)
	err = json.Unmarshal(objectBytes, &object)
	if err != nil {
		return nil, err
	}
	return object, nil
}

/* Get UUID from string */
func getUUIDFromUser(str string) (uid UUID, err error) {
	hashedStr := userlib.Hash([]byte(str))
	uid, err = uuid.FromBytes(hashedStr[:16])
	return
}

/* Get encryption key from username */
func getEncKeyFromUser(username string, password []byte) (encKey []byte) {
	encKey = userlib.Argon2Key(password, []byte(username), 16)
	return
}

/* Get MAC key from username + password */
func getMACKeyFromUser(username string, password []byte) (macKey []byte) {
	temp := append(password, []byte(username)...)
	macKey = userlib.Argon2Key(temp, []byte(username), 16)
	return
}

/* Get the next sublevel encryption and MAC key */
func getNextKeyPair(originalEncKey []byte, originalMACKey []byte) (newEncKey []byte, newMACKey []byte, err error) {
	newEncKey, err = userlib.HashKDF(originalEncKey, []byte("Enc Key"))
	if err != nil {
		return nil, nil, err
	}
	newMACKey, err = userlib.HashKDF(originalMACKey, []byte("MAC key"))
	if err != nil {
		return nil, nil, err
	}
	return newEncKey, newMACKey, nil
}
