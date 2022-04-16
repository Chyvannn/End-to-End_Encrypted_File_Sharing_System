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

/* The starting position for a file, save metadata for file */
/* UUID of FileHeader is create by username + filename */
type FileHeader struct {
	ShareId  UUID   // the ShareNode for a user
	FHEncKey []byte // Keys to protect share node
	FHMacKey []byte
}

/* A single node in the sharing tree, may have multiple owners */
type ShareNode struct {
	FileBodyId  UUID
	ShareNodeId UUID
	SNEncKey    []byte // Protect following ShareNode if is root, save keys of itself if not root
	SNMacKey    []byte
	FileEncKey  []byte // Shared between users sharing the same file
	FileMacKey  []byte
	IsRoot      bool   // Check if the current ShareNode is the root node
	Children    []UUID // Children list for the root ShareNode
}

type FileBody struct {
	FileBodyId    UUID
	ContentEncKey []byte // Protect all file contents
	ContentMacKey []byte
	LastContent   UUID // Store the last content being appended into the file
}

type FileContent struct {
	Content     []byte
	PrevContent UUID
}

/* All the data stored in Datastore, */
type Data struct {
	CypherText []byte
	MAC        []byte
}

type Invitation struct {
	ShareId     UUID
	ShareEncKey []byte
	ShareMacKey []byte
}

type InvitationData struct {
	CypherText []byte // RSA Encrypted Invitation data
	Signature  []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		return nil, errors.New("the username is empty")
	}
	var userdata User
	userdata.Username = username
	uid, err := getUUIDFromString([]byte(username))
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
	if len(username) == 0 {
		return nil, errors.New("the username is empty")
	}
	uid, err := getUUIDFromString([]byte(username))
	if err != nil {
		return nil, err
	}
	encKey := getEncKeyFromUser(username, []byte(password))
	macKey := getMACKeyFromUser(username, []byte(password))

	var userdata User
	err = getObject(uid, encKey, macKey, &userdata)
	if err != nil {
		return nil, errors.New("username and password do not match")
	}
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Create FileHeader
	var fileHeader FileHeader
	tempString := fmt.Sprintf("%s_%s", userdata.Username, filename) // Get FileHeader UUID on fly
	fhid, err := getUUIDFromString([]byte(tempString))
	if err != nil {
		return err
	}
	fhEncKey, fhMacKey, err := getNextKeyPair(userdata.UserEncKey, userdata.UserMacKey)
	if err != nil {
		return err
	}
	fileHeader.FHEncKey = fhEncKey
	fileHeader.FHMacKey = fhMacKey
	snid := uuid.New() // Generate direct ShareNode UUID
	fileHeader.ShareId = snid
	err = storeObject(fhid, fileHeader, userdata.UserEncKey, userdata.UserMacKey)
	if err != nil {
		return err
	}

	// Create new ShareNode
	var shareNode ShareNode // UUID generated in the previsou step
	snEncKey, snMacKey, err := getNextKeyPair(fileHeader.FHEncKey, fileHeader.FHMacKey)
	if err != nil {
		return err
	}
	shareNode.ShareNodeId = snid
	shareNode.SNEncKey = snEncKey // Direct share node always have Enc/MAC keys
	shareNode.SNMacKey = snMacKey
	fileEncKey, fileMacKey, err := getNextKeyPair(fileHeader.FHEncKey, fileHeader.FHMacKey)
	if err != nil {
		return err
	}
	shareNode.FileEncKey = fileEncKey
	shareNode.FileMacKey = fileMacKey
	shareNode.IsRoot = true // the shareNode created by StoreFile will always be the root
	shareNode.Children = nil
	fbid := uuid.New() // generate FileBody UUID
	shareNode.FileBodyId = fbid
	// Direct ShareNode is protected by the fileHeader key pairs
	err = storeObject(snid, shareNode, fileHeader.FHEncKey, fileHeader.FHMacKey)
	if err != nil {
		return err
	}

	// Create fileBody, protect by FileEncKey, FileMACKey
	var fileBody FileBody
	fileBody.FileBodyId = fbid
	fbEncKey, fbMacKey, err := getNextKeyPair(shareNode.FileEncKey, shareNode.FileMacKey)
	if err != nil {
		return err
	}
	fileBody.ContentEncKey = fbEncKey
	fileBody.ContentMacKey = fbMacKey
	fcid := uuid.New() // Generate random content UUID
	fileBody.LastContent = fcid
	err = storeObject(fbid, fileBody, shareNode.FileEncKey, shareNode.FileMacKey)
	if err != nil {
		return nil
	}

	// Create FileContent for the file
	var fileContent FileContent
	fileContent.Content = content
	fileContent.PrevContent = uuid.Nil
	err = storeObject(fcid, fileContent, fileBody.ContentEncKey, fileBody.ContentMacKey)
	if err != nil {
		return err
	}

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Get ShareNode from DataStore
	var shareNode ShareNode
	err := userdata.getShareNode(filename, &shareNode)
	if err != nil {
		return err
	}

	// Get FileBody from DataStore
	var fileBody FileBody
	err = getObject(shareNode.FileBodyId, shareNode.FileEncKey, shareNode.FileMacKey, &fileBody)
	if err != nil {
		return err
	}

	// Create new content
	var newContent FileContent
	fcid := uuid.New()
	newContent.PrevContent = fileBody.LastContent
	fileBody.LastContent = fcid
	newContent.Content = content
	err = storeObject(fcid, newContent, fileBody.ContentEncKey, fileBody.ContentMacKey)
	if err != nil {
		return err
	}

	// Update FileBody in the DataStore
	err = storeObject(fileBody.FileBodyId, fileBody, shareNode.FileEncKey, shareNode.FileMacKey)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var fileBody FileBody
	err = userdata.getFileBody(filename, &fileBody)
	if err != nil {
		return nil, err
	}

	// Get the initial content for the file
	var fileContent FileContent
	err = getObject(fileBody.LastContent, fileBody.ContentEncKey, fileBody.ContentMacKey, &fileContent)
	if err != nil {
		return nil, err
	}
	var contentBytes []byte
	// Append the next content to the front of the current content
	contentBytes = append(contentBytes, fileContent.Content...)
	for fileContent.PrevContent != uuid.Nil {
		err = getObject(fileContent.PrevContent, fileBody.ContentEncKey, fileBody.ContentMacKey, &fileContent)
		if err != nil {
			return nil, err
		}
		contentBytes = append(fileContent.Content, contentBytes...)
	}
	return contentBytes, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	var senderNode ShareNode
	err = userdata.getShareNode(filename, &senderNode)
	if err != nil {
		return uuid.Nil, err
	}
	var recipientNode ShareNode
	if senderNode.IsRoot {
		// if the sender node is owner
		// create a new ShareNode as recipient
		recipientId := uuid.New()
		recipientNode.ShareNodeId = recipientId
		recipientNode.IsRoot = false // recipient node will not be a root
		recipientNode.FileEncKey = senderNode.FileEncKey
		recipientNode.FileMacKey = senderNode.FileMacKey
		recipientNode.SNEncKey = senderNode.SNEncKey // recipient will store its own enc/mac key
		recipientNode.SNMacKey = senderNode.SNMacKey
		senderNode.Children = append(senderNode.Children, recipientId)
		err = storeObject(recipientId, recipientNode, senderNode.SNEncKey, senderNode.SNMacKey)
		if err != nil {
			return uuid.Nil, err
		}
	} else {
		recipientNode = senderNode
	}

	// Create invitation infomation
	var invitation Invitation
	invitation.ShareId = recipientNode.ShareNodeId
	invitation.ShareEncKey = recipientNode.SNEncKey
	invitation.ShareMacKey = recipientNode.SNMacKey

	// Enc and sign invitation and store in InvitationData
	rsaString := recipientUsername + "RSA public key"
	rsaEncKey, ok := userlib.KeystoreGet(rsaString)
	if !ok {
		return uuid.Nil, errors.New("recipient RSA public key doesn't exist")
	}
	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}
	cypherInvitation, err := userlib.PKEEnc(rsaEncKey, invitationBytes)
	if err != nil {
		return uuid.Nil, err
	}
	signature, err := userlib.DSSign(userdata.UserSignPrivateKey, cypherInvitation)
	if err != nil {
		return uuid.Nil, err
	}
	// Create InvitationDate to actually store in DataStore
	var invitationData InvitationData
	invitationDataId := uuid.New()
	invitationData.CypherText = cypherInvitation
	invitationData.Signature = signature
	invitationDataBytes, err := json.Marshal(invitationData)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invitationDataId, invitationDataBytes)
	return invitationDataId, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}

/********************************************************************************************************/
/****************                            Helper Functions                            ****************/
/********************************************************************************************************/

/* Store an object into the Datastore with given UUID */
func storeObject(dataId UUID, object interface{}, encKey []byte, macKey []byte) (err error) {
	var data Data
	iv := userlib.RandomBytes(16)
	// Convert the data structure to []bytes
	dataBytes, err := json.Marshal(object)
	if err != nil {
		return err
	}
	// Encrypte data and evaluate the HMAC
	cypherBytes := userlib.SymEnc(encKey, iv, dataBytes)
	macBytes, err := userlib.HMACEval(macKey, cypherBytes)
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
func getObject(dataId UUID, encKey []byte, macKey []byte, object interface{}) (err error) {
	databytes, ok := userlib.DatastoreGet(dataId)
	if !ok {
		return errors.New("no corresponding UUID found")
	}

	// Get data from the Datastore
	var data Data
	err = json.Unmarshal(databytes, &data)
	if err != nil {
		return err
	}
	cypherBytes := data.CypherText
	macBytes := data.MAC

	// Verify the HMAC of data in Datastore
	storedMac, err := userlib.HMACEval(macKey, cypherBytes)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(storedMac, macBytes) {
		return errors.New("the data from the Datastore is manipulated")
	}

	// Decrypt object
	objectBytes := userlib.SymDec(encKey, cypherBytes)
	err = json.Unmarshal(objectBytes, object)
	if err != nil {
		return err
	}
	return
}

/* Get ShareNode from username and filename */
func (userdata *User) getShareNode(filename string, shareNode interface{}) (err error) {
	tempString := fmt.Sprintf("%s_%s", userdata.Username, filename) // Get FileHeader UUID on fly
	fhid, err := getUUIDFromString([]byte(tempString))
	if err != nil {
		return err
	}
	// Get FileHeader from DataStore
	var fileHeader FileHeader
	err = getObject(fhid, userdata.UserEncKey, userdata.UserMacKey, &fileHeader)
	if err != nil {
		return err
	}

	// Get ShareNode from DataStore
	err = getObject(fileHeader.ShareId, fileHeader.FHEncKey, fileHeader.FHMacKey, &shareNode)
	if err != nil {
		return err
	}
	return
}

/* Get FileBody from username and filename*/
func (userdata *User) getFileBody(filename string, fileBody interface{}) (err error) {
	var shareNode ShareNode
	err = userdata.getShareNode(filename, &shareNode)
	if err != nil {
		return err
	}
	// Get FileBody from DataStore
	err = getObject(shareNode.FileBodyId, shareNode.FileEncKey, shareNode.FileMacKey, &fileBody)
	if err != nil {
		return err
	}
	return
}

/* Get UUID from byte string */
func getUUIDFromString(bytes []byte) (uid UUID, err error) {
	hashedBytes := userlib.Hash(bytes)
	uid, err = uuid.FromBytes(hashedBytes[:16])
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
	return newEncKey[:16], newMACKey[:16], nil
}
