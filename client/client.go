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
	UserBaseKey        []byte
	UserRSAPrivateKey  PKEDecKey
	UserSignPrivateKey DSSignKey
}

/* The starting position for a file, save metadata for file */
/* UUID of FileHeader is create by username + filename */
type FileHeader struct {
	ShareId   UUID   // the ShareNode for a user
	FHBaseKey []byte // protect direct ShareNode
}

/* A single node in the sharing tree, may have multiple owners */
type ShareNode struct {
	FileBodyId  UUID
	ShareNodeId UUID
	SNBaseKey   []byte // Protect following ShareNode if is root, save keys of itself if not root
	FileBaseKey []byte // Shared between users sharing the same file
	IsRoot      bool   // Check if the current ShareNode is the root node
	Children    []UUID // Children list for the root ShareNode
}

type FileBody struct {
	FBBaseKey   []byte // Protect all file contents
	LastContent UUID   // Store the last content being appended into the file
}

type FileContent struct {
	Content     []byte
	PrevContent UUID
}

type Invitation struct {
	ShareId           UUID
	InvitationBaseKey []byte
}

/* All the data stored in Datastore, */
type Data struct {
	CypherText []byte
	MAC        []byte
}

/* Invitation data store in DataStore*/
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

	// Get base key per User ON FLY!
	baseKey := getBaseKey(username, []byte(password))
	// Get enc and mac key of User from baseKey
	encKey, macKey, err := getKeyPairFromBase(baseKey)
	if err != nil {
		return nil, err
	}

	// Get encKey and macKey in User for FileHeader
	userBaseKey, err := getNextBaseKey(baseKey)
	if err != nil {
		return nil, err
	}
	userdata.UserBaseKey = userBaseKey

	// Generate RSA key pair
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.UserRSAPrivateKey = privateKey
	rsaString := username + "RSA_Public_Key"
	err = userlib.KeystoreSet(rsaString, publicKey)
	if err != nil {
		return nil, err
	}

	// Generate digital signature key pair
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	signString := username + "Digital_Signature_Key"
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
	baseKey := getBaseKey(username, []byte(password))
	encKey, macKey, err := getKeyPairFromBase(baseKey)
	if err != nil {
		return nil, err
	}

	var userdata User
	err = getObject(uid, encKey, macKey, &userdata)
	if err != nil {
		return nil, errors.New("username and password do not match")
	}
	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Create FileHeader
	var fileHeader FileHeader
	tempString := fmt.Sprintf("%s_%s", userdata.Username, filename) // Get FileHeader UUID on fly
	fhid, err := getUUIDFromString([]byte(tempString))
	if err != nil {
		return
	}
	userEncKey, userMacKey, err := getKeyPairFromBase(userdata.UserBaseKey)
	if err != nil {
		return
	}
	fileHeaderBaseKey, err := getNextBaseKey(userdata.UserBaseKey)
	if err != nil {
		return
	}
	fileHeader.FHBaseKey = fileHeaderBaseKey
	snid := uuid.New() // Generate direct ShareNode UUID
	fileHeader.ShareId = snid
	err = storeObject(fhid, fileHeader, userEncKey, userMacKey)
	if err != nil {
		return
	}

	// Create new ShareNode
	var shareNode ShareNode // UUID generated in the previsou step
	shareNode.ShareNodeId = snid
	shareNodeBaseKey, err := getNextBaseKey(fileHeaderBaseKey)
	if err != nil {
		return
	}
	shareNode.SNBaseKey = shareNodeBaseKey
	fileBaseKey, err := getNextBaseKey(shareNodeBaseKey)
	if err != nil {
		return
	}
	shareNode.FileBaseKey = fileBaseKey
	shareNode.IsRoot = true // the shareNode created by StoreFile will always be the root
	shareNode.Children = nil
	fbid := uuid.New() // generate FileBody UUID
	shareNode.FileBodyId = fbid
	// Direct ShareNode is protected by the fileHeader key pairs
	fileHeaderEncKey, fileHeaderMacKey, err := getKeyPairFromBase(fileHeaderBaseKey)
	if err != nil {
		return
	}
	err = storeObject(snid, shareNode, fileHeaderEncKey, fileHeaderMacKey)
	if err != nil {
		return
	}

	// Create fileBody, protect by FileEncKey, FileMACKey
	var fileBody FileBody
	fileBodyBaseKey, err := getNextBaseKey(shareNodeBaseKey)
	if err != nil {
		return
	}
	fileBody.FBBaseKey = fileBodyBaseKey
	fcid := uuid.New() // Generate random content UUID
	fileBody.LastContent = fcid
	fileEncKey, fileMacKey, err := getKeyPairFromBase(fileBaseKey)
	if err != nil {
		return
	}
	err = storeObject(fbid, fileBody, fileEncKey, fileMacKey)
	if err != nil {
		return
	}

	// Create FileContent for the file
	var fileContent FileContent
	fileContent.Content = content
	fileContent.PrevContent = uuid.Nil
	fileBodyEncKey, fileBodyMacKey, err := getKeyPairFromBase(fileBodyBaseKey)
	if err != nil {
		return
	}
	err = storeObject(fcid, fileContent, fileBodyEncKey, fileBodyMacKey)
	if err != nil {
		return
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
	fileEncKey, fileMacKey, err := getKeyPairFromBase(shareNode.FileBaseKey)
	if err != nil {
		return err
	}
	err = getObject(shareNode.FileBodyId, fileEncKey, fileMacKey, &fileBody)
	if err != nil {
		return err
	}
	// Create new content
	var newContent FileContent
	fcid := uuid.New()
	newContent.PrevContent = fileBody.LastContent
	fileBody.LastContent = fcid
	newContent.Content = content
	fileBodyEncKey, fileBodyMacKey, err := getKeyPairFromBase(fileBody.FBBaseKey)
	if err != nil {
		return err
	}
	err = storeObject(fcid, newContent, fileBodyEncKey, fileBodyMacKey)
	if err != nil {
		return err
	}

	// Update FileBody in the DataStore
	err = storeObject(shareNode.FileBodyId, fileBody, fileEncKey, fileMacKey)
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
	fileBodyEncKey, fileBodyMacKey, err := getKeyPairFromBase(fileBody.FBBaseKey)
	if err != nil {
		return nil, err
	}
	err = getObject(fileBody.LastContent, fileBodyEncKey, fileBodyMacKey, &fileContent)
	if err != nil {
		return nil, err
	}
	var contentBytes []byte
	// Append the next content to the front of the current content
	contentBytes = append(contentBytes, fileContent.Content...)
	for fileContent.PrevContent != uuid.Nil {
		err = getObject(fileContent.PrevContent, fileBodyEncKey, fileBodyMacKey, &fileContent)
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
		recipientNode.SNBaseKey = senderNode.SNBaseKey
		recipientNode.FileBaseKey = senderNode.FileBaseKey // recipient will store its own enc/mac key
		senderNode.Children = append(senderNode.Children, recipientId)
		senderNodeEncKey, senderNodeMacKey, err := getKeyPairFromBase(senderNode.SNBaseKey)
		if err != nil {
			return uuid.Nil, err
		}
		err = storeObject(recipientId, recipientNode, senderNodeEncKey, senderNodeMacKey)
		if err != nil {
			return uuid.Nil, err
		}
	} else {
		recipientNode = senderNode
	}

	// Create invitation infomation
	var invitation Invitation
	invitation.ShareId = recipientNode.ShareNodeId
	invitation.InvitationBaseKey = recipientNode.SNBaseKey

	// Enc and sign invitation and store in InvitationData
	rsaString := recipientUsername + "RSA_Public_Key"
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
	// return nil
	invitationDataBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("can not find the invitation in DataStore")
	}
	var invitationData InvitationData
	err := json.Unmarshal(invitationDataBytes, &invitationData)
	if err != nil {
		return err
	}
	cypherInvitation := invitationData.CypherText
	signature := invitationData.Signature
	signString := senderUsername + "Digital_Signature_Key"
	signVerifyKey, ok := userlib.KeystoreGet(signString)
	if !ok {
		return errors.New("can not find the sender signature verify key")
	}
	err = userlib.DSVerify(signVerifyKey, cypherInvitation, signature)
	if err != nil {
		return err
	}
	invitationBytes, err := userlib.PKEDec(userdata.UserRSAPrivateKey, cypherInvitation)
	if err != nil {
		return err
	}
	var invitation Invitation
	err = json.Unmarshal(invitationBytes, &invitation)
	if err != nil {
		return err
	}
	var fileHeader FileHeader
	tempString := fmt.Sprintf("%s_%s", userdata.Username, filename) // Get FileHeader UUID on fly
	fhid, err := getUUIDFromString([]byte(tempString))
	if err != nil {
		return err
	}
	fileHeader.ShareId = invitation.ShareId
	fileHeader.FHBaseKey = invitation.InvitationBaseKey
	userEncKey, userMacKey, err := getKeyPairFromBase(userdata.UserBaseKey)
	if err != nil {
		return err
	}
	err = storeObject(fhid, fileHeader, userEncKey, userMacKey)
	if err != nil {
		return err
	}
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
	userEncKey, userMacKey, err := getKeyPairFromBase(userdata.UserBaseKey)
	if err != nil {
		return
	}
	err = getObject(fhid, userEncKey, userMacKey, &fileHeader)
	if err != nil {
		return
	}

	// Get ShareNode from DataStore
	fileHeaderEncKey, fileHeaderMacKey, err := getKeyPairFromBase(fileHeader.FHBaseKey)
	if err != nil {
		return
	}
	err = getObject(fileHeader.ShareId, fileHeaderEncKey, fileHeaderMacKey, &shareNode)
	if err != nil {
		return
	}
	return
}

/* Get FileBody from username and filename*/
func (userdata *User) getFileBody(filename string, fileBody interface{}) (err error) {
	var shareNode ShareNode
	err = userdata.getShareNode(filename, &shareNode)
	if err != nil {
		return
	}
	// Get FileBody from DataStore
	fileEncKey, fileMacKey, err := getKeyPairFromBase(shareNode.FileBaseKey)
	if err != nil {
		return
	}
	err = getObject(shareNode.FileBodyId, fileEncKey, fileMacKey, &fileBody)
	if err != nil {
		return
	}
	return
}

/* Get UUID from byte string */
func getUUIDFromString(bytes []byte) (uid UUID, err error) {
	hashedBytes := userlib.Hash(bytes)
	uid, err = uuid.FromBytes(hashedBytes[:16])
	return
}

/* Get base key from username + password to derive enc/mac key*/
func getBaseKey(username string, password []byte) (baseKey []byte) {
	temp := append(password, []byte(username)...)
	baseKey = userlib.Argon2Key(temp, []byte(username), 16)
	return
}

/* Get encryption & MAC key from base key */
func getKeyPairFromBase(baseKey []byte) (encKey []byte, macKey []byte, err error) {
	encKey, err = userlib.HashKDF(baseKey, []byte("Encryption_Key"))
	if err != nil {
		return nil, nil, err
	}
	macKey, err = userlib.HashKDF(baseKey, []byte("MAC_Key"))
	if err != nil {
		return nil, nil, err
	}
	return encKey[:16], macKey[:16], nil
}

func getNextBaseKey(originalBaseKey []byte) (newBaseKey []byte, err error) {
	newBaseKey, err = userlib.HashKDF(originalBaseKey[:16], []byte("Base_Key"))
	if err != nil {
		return nil, err
	}
	return newBaseKey[:16], nil
}
