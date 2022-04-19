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
	UserRSAPrivateKey  PKEDecKey // Public key --> username + "RSA_Public_Key"
	UserSignPrivateKey DSSignKey // Public key --> username + "Digital_Signature_Key"
}

/* The starting position for a file, save metadata for file
 * UUID of FileHeader is create by username + filename */
type FileHeader struct { // UUID <-- "username_filename"
	ShareId   UUID   // the ShareNode for a user
	FHBaseKey []byte // protect direct ShareNode
}

/* A single node in the sharing tree, may have multiple owners
 * Root ShareNode UUID is generated randomly
 * Sublevel ShareNode Id is generate from owner + direct recipient username */
type ShareNode struct { // root UUID <-- random, child UUID <--
	FileBodyId UUID
	//TODO: delete ShareNodeID ???
	ShareNodeId UUID
	//TODO: delete IsRoot
	IsRoot       bool     // Check if the current ShareNode is the root node
	OwnerName    string   // "" if is the owner, the owner name otherwise
	InvitationId UUID     // Invitation is also the lockbox
	SNBaseKey    []byte   // Protect following ShareNode if is root, save keys of itself if not root
	FileBaseKey  []byte   // Protect FileBody only used by root nodes
	ChildrenName []string // Children's name list for the root ShareNode
}

type FileBody struct { // UUID <-- random
	FBBaseKey   []byte // Protect all file contents
	LastContent UUID   // Store the last content being appended into the file
}

type FileContent struct { // UUID <-- random
	Content     []byte
	PrevContent UUID
}

type Invitation struct {
	ShareId           UUID
	InvitationBaseKey []byte
}

/* All the data stored in Datastore, */
type SymEncData struct {
	CypherText []byte
	MAC        []byte
}

/* Invitation data store in DataStore*/
type PublicEncData struct {
	CypherText []byte // RSA Encrypted Invitation data
	Signature  []byte
}

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
	baseKey := getUserBaseKey(username, []byte(password))
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
	err = storeSymEncObject(uid, userdata, encKey, macKey)
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
	baseKey := getUserBaseKey(username, []byte(password))
	encKey, macKey, err := getKeyPairFromBase(baseKey)
	if err != nil {
		return nil, err
	}

	var userdata User
	err = getSymEncObject(uid, encKey, macKey, &userdata)
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
	fileHeaderBaseKey, err := getFileHeaderBaseKey(userdata.UserBaseKey, filename)
	if err != nil {
		return
	}
	fileHeader.FHBaseKey = fileHeaderBaseKey
	snid := uuid.New() // Generate direct ShareNode UUID
	fileHeader.ShareId = snid
	err = storeSymEncObject(fhid, fileHeader, userEncKey, userMacKey)
	if err != nil {
		return
	}

	// Create new ShareNode
	var shareNode ShareNode // UUID generated in the previsou step
	fbid := uuid.New()      // generate FileBody UUID
	shareNode.FileBodyId = fbid
	// shareNode.ShareNodeId = snid
	// shareNode.IsRoot = true
	shareNode.OwnerName = "" // username will always be greater than zero,
	shareNode.InvitationId = uuid.Nil
	// ShareNode created by StoreFile will always be the root node
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
	shareNode.ChildrenName = nil
	// Direct ShareNode is protected by the FileHeader key pairs
	fileHeaderEncKey, fileHeaderMacKey, err := getKeyPairFromBase(fileHeaderBaseKey)
	if err != nil {
		return
	}
	err = storeSymEncObject(snid, shareNode, fileHeaderEncKey, fileHeaderMacKey)
	if err != nil {
		return
	}

	// Create fileBody, protect by FileEncKey, FileMACKey
	var fileBody FileBody
	fileBodyBaseKey, err := getNextBaseKey(fileBaseKey)
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
	err = storeSymEncObject(fbid, fileBody, fileEncKey, fileMacKey)
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
	err = storeSymEncObject(fcid, fileContent, fileBodyEncKey, fileBodyMacKey)
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
	err = userdata.getFileBody(filename, &fileBody)
	if err != nil {
		return err
	}

	// Get file base key
	fileBaseKey, err := userdata.getSNFileBaseKey(shareNode)
	if err != nil {
		return err
	}
	fileEncKey, fileMacKey, err := getKeyPairFromBase(fileBaseKey)
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
	err = storeSymEncObject(fcid, newContent, fileBodyEncKey, fileBodyMacKey)
	if err != nil {
		return err
	}

	// Update FileBody in the DataStore
	err = storeSymEncObject(shareNode.FileBodyId, fileBody, fileEncKey, fileMacKey)
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
	err = getSymEncObject(fileBody.LastContent, fileBodyEncKey, fileBodyMacKey, &fileContent)
	if err != nil {
		return nil, err
	}
	var contentBytes []byte
	// Append the next content to the front of the current content
	contentBytes = append(contentBytes, fileContent.Content...)
	for fileContent.PrevContent != uuid.Nil {
		err = getSymEncObject(fileContent.PrevContent, fileBodyEncKey, fileBodyMacKey, &fileContent)
		if err != nil {
			return nil, err
		}
		contentBytes = append(fileContent.Content, contentBytes...)
	}
	return contentBytes, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	var senderFileHeader FileHeader
	err = userdata.getFileHeader(filename, &senderFileHeader)
	if err != nil {
		return uuid.Nil, err
	}

	var senderNode ShareNode
	err = userdata.getShareNode(filename, &senderNode)
	if err != nil {
		return uuid.Nil, err
	}
	var recipientNode ShareNode
	if senderNode.IsRoot {
		// if the sender node is root, create a new ShareNode as recipient
		tempString := fmt.Sprintf("%s_%s_%s", userdata.Username, recipientUsername, filename)
		// fmt.Println("\nCreateInvitation: ", tempString)
		recipientId, err := getUUIDFromString([]byte(tempString))
		// fmt.Println("\nCreateInvitation UUID: ", recipientId)
		if err != nil {
			return uuid.Nil, err
		}
		recipientNode.ShareNodeId = recipientId
		recipientNode.IsRoot = false                       // recipient node will not be a root
		recipientNode.FileBaseKey = senderNode.FileBaseKey // recipient shares the same FileKey with sender
		recipientNode.FileBodyId = senderNode.FileBodyId   // recipient shares the same FileBody with sender

		senderNode.ChildrenName = append(senderNode.ChildrenName, recipientUsername)
		childBaseKey, err := getChildBaseKey(senderNode.SNBaseKey, recipientUsername)
		if err != nil {
			return uuid.Nil, err
		}
		recipientNode.SNBaseKey = childBaseKey
		senderNodeEncKey, senderNodeMacKey, err := getKeyPairFromBase(childBaseKey)
		if err != nil {
			return uuid.Nil, err
		}
		err = storeSymEncObject(recipientId, recipientNode, senderNodeEncKey, senderNodeMacKey)
		if err != nil {
			return uuid.Nil, err
		}
		senderFHEncKey, senderFHMacKey, err := getKeyPairFromBase(senderFileHeader.FHBaseKey)
		if err != nil {
			return uuid.Nil, err
		}
		err = storeSymEncObject(senderFileHeader.ShareId, senderNode, senderFHEncKey, senderFHMacKey)
		if err != nil {
			return uuid.Nil, err
		}
	} else {
		// if sender is not the root, use current ShareNode as recipient
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
	var invitationData PublicEncData
	tempString := fmt.Sprintf("Invitation: %s_%s_%s", userdata.Username, filename, recipientUsername)
	invitationDataId, err := getUUIDFromString([]byte(tempString))
	if err != nil {
		return uuid.Nil, err
	}
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
	tempString := fmt.Sprintf("%s_%s", userdata.Username, filename) // Get FileHeader UUID on fly
	fhid, err := getUUIDFromString([]byte(tempString))
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(fhid)
	if ok {
		return errors.New("filename already exist in current userspace")
	}

	invitationDataBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("can not find the invitation in DataStore")
	}
	// Delete invitation after user get from DataStore
	userlib.DatastoreDelete(invitationPtr)
	var invitationData PublicEncData
	err = json.Unmarshal(invitationDataBytes, &invitationData)
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
	fileHeader.ShareId = invitation.ShareId
	fileHeader.FHBaseKey = invitation.InvitationBaseKey
	userEncKey, userMacKey, err := getKeyPairFromBase(userdata.UserBaseKey)
	if err != nil {
		return err
	}
	err = storeSymEncObject(fhid, fileHeader, userEncKey, userMacKey)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Get the owner FileHeader, unchanged after revoke access
	var ownerFileHeader FileHeader
	err := userdata.getFileHeader(filename, &ownerFileHeader)
	if err != nil {
		return err
	}
	fileHeaderEncKey, fileHeaderMacKey, err := getKeyPairFromBase(ownerFileHeader.FHBaseKey)
	if err != nil {
		return err
	}

	var ownerNode ShareNode
	err = getSymEncObject(ownerFileHeader.ShareId, fileHeaderEncKey, fileHeaderMacKey, &ownerNode)
	if err != nil {
		return err
	}

	if !ownerNode.IsRoot {
		return errors.New("current user does not own the file")
	}

	// Get UUID of the recipient ShareNode, check that the file is shared
	tempString := fmt.Sprintf("%s_%s_%s", userdata.Username, recipientUsername, filename)
	recipientShareId, err := getUUIDFromString([]byte(tempString))
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(recipientShareId)
	if !ok {
		return errors.New("the current filename is not shared")
	}

	// Check if the invitation is already accepted
	tempString = fmt.Sprintf("Invitation: %s_%s_%s", userdata.Username, filename, recipientUsername)
	invitationDataId, err := getUUIDFromString([]byte(tempString))
	if err != nil {
		return err
	}
	_, ok = userlib.DatastoreGet(invitationDataId)
	if ok { // Invitation not accepted
		userlib.DatastoreDelete(invitationDataId)
		for i := 0; i < len(ownerNode.ChildrenName); i++ {
			if ownerNode.ChildrenName[i] == recipientUsername {
				ownerNode.ChildrenName[i] = ""
				userlib.DatastoreDelete(recipientShareId)
				return nil
			}
		}
		return nil
	}

	// Derive new FileBaseKey and SNBaseKey from the old ones
	newFileBaseKey, err := getNextBaseKey(ownerNode.FileBaseKey)
	if err != nil {
		return err
	}
	newSNBaseKey, err := getNextBaseKey(ownerNode.SNBaseKey)
	if err != nil {
		return err
	}

	// Get old/new file enc/mac key from old/new file base key
	oldFileEncKey, oldFileMacKey, err := getKeyPairFromBase(ownerNode.FileBaseKey)
	if err != nil {
		return err
	}
	newFileEncKey, newFileMacKey, err := getKeyPairFromBase(newFileBaseKey)
	if err != nil {
		return err
	}
	ownerNode.FileBaseKey = newFileBaseKey

	for i := 0; i < len(ownerNode.ChildrenName); i++ {
		if ownerNode.ChildrenName[i] == "" {
			continue
		}
		// Get current children's ShareNode id
		tempString := fmt.Sprintf("%s_%s_%s", userdata.Username, ownerNode.ChildrenName[i], filename)
		childId, err := getUUIDFromString([]byte(tempString))
		if err != nil {
			return err
		}
		if ownerNode.ChildrenName[i] != recipientUsername {
			// If the current child is not the one we will revoke, recypher all the information
			// Get old child base key and then enc & mac key
			oldChildBaseKey, err := getChildBaseKey(ownerNode.SNBaseKey, ownerNode.ChildrenName[i])
			if err != nil {
				return err
			}
			oldSNEncKey, oldSNMacKey, err := getKeyPairFromBase(oldChildBaseKey)
			if err != nil {
				return err
			}
			var shareNode ShareNode
			err = getSymEncObject(childId, oldSNEncKey, oldSNMacKey, &shareNode)
			if err != nil {
				return err
			}
			// Update key pairs in remaining ShareNodes
			shareNode.FileBaseKey = newFileBaseKey
			newChildBaseKey, err := getChildBaseKey(newSNBaseKey, ownerNode.ChildrenName[i])
			if err != nil {
				return err
			}
			shareNode.FileBaseKey = newFileBaseKey
			shareNode.SNBaseKey = newChildBaseKey
			newSNEncKey, newSNMacKey, err := getKeyPairFromBase(newChildBaseKey)
			if err != nil {
				return err
			}
			// Recypher ShareNode on DataStore
			err = storeSymEncObject(childId, shareNode, newSNEncKey, newSNMacKey)
			if err != nil {
				return err
			}
		} else {
			// If recipient found, zero out the recipient name in owner's list
			ownerNode.ChildrenName[i] = ""
			userlib.DatastoreDelete(childId)
		}
	}
	ownerNode.SNBaseKey = newSNBaseKey

	err = storeSymEncObject(ownerFileHeader.ShareId, ownerNode, fileHeaderEncKey, fileHeaderMacKey)
	if err != nil {
		return err
	}

	// Get FileBody to recypher FileBody
	var fileBody FileBody
	err = getSymEncObject(ownerNode.FileBodyId, oldFileEncKey, oldFileMacKey, &fileBody)
	if err != nil {
		return err
	}

	// Generate new FileBody base key
	newFBBaseKey, err := getNextBaseKey(fileBody.FBBaseKey)
	if err != nil {
		return err
	}
	oldFBEncKey, oldFBMacKey, err := getKeyPairFromBase(fileBody.FBBaseKey)
	if err != nil {
		return err
	}
	newFBEncKey, newFBMacKey, err := getKeyPairFromBase(newFBBaseKey)
	if err != nil {
		return err
	}
	fileBody.FBBaseKey = newFBBaseKey

	// Recypher the fileBody
	err = storeSymEncObject(ownerNode.FileBodyId, fileBody, newFileEncKey, newFileMacKey)
	if err != nil {
		return err
	}

	// Recypher the entire file with updated fileBaseKey
	var fileContent FileContent
	err = getSymEncObject(fileBody.LastContent, oldFBEncKey, oldFBMacKey, &fileContent)
	if err != nil {
		return err
	}
	err = storeSymEncObject(fileBody.LastContent, fileContent, newFBEncKey, newFBMacKey)
	if err != nil {
		return err
	}

	for fileContent.PrevContent != uuid.Nil {
		err = getSymEncObject(fileContent.PrevContent, oldFBEncKey, oldFBMacKey, &fileContent)
		if err != nil {
			return err
		}
		err = storeSymEncObject(fileContent.PrevContent, fileContent, newFBEncKey, newFBMacKey)
		if err != nil {
			return err
		}
	}

	return nil
}

/********************************************************************************************************/
/****************                            Helper Functions                            ****************/
/********************************************************************************************************/

/* Store an object into the Datastore with given UUID */
func storeSymEncObject(dataId UUID, object interface{}, encKey []byte, macKey []byte) (err error) {
	var data SymEncData
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
func getSymEncObject(dataId UUID, encKey []byte, macKey []byte, object interface{}) (err error) {
	databytes, ok := userlib.DatastoreGet(dataId)
	if !ok {
		return errors.New("no corresponding UUID found")
	}

	// Get data from the Datastore
	var data SymEncData
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

/* Store an object into the Datastore with given UUID */
func storePublicEncObject(dataId UUID, object interface{}, publicKey PKEEncKey, signKey DSSignKey) (err error) {
	var data PublicEncData
	// Convert the data structure to []bytes
	dataBytes, err := json.Marshal(object)
	if err != nil {
		return err
	}
	// Encrypte data and evaluate the HMAC
	cypherBytes, err := userlib.PKEEnc(publicKey, dataBytes)
	if err != nil {
		return err
	}

	signature, err := userlib.DSSign(signKey, cypherBytes)
	if err != nil {
		return err
	}

	// put cyphertext and HMAC into data and store into Datastore
	data.CypherText = cypherBytes
	data.Signature = signature
	storeBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(dataId, storeBytes)
	return nil
}

/* Get an object from the Datastore */
func getPublicEncObject(dataId UUID, privateKey PKEDecKey, verifyKey DSVerifyKey, object interface{}) (err error) {
	databytes, ok := userlib.DatastoreGet(dataId)
	if !ok {
		return errors.New("no corresponding UUID found")
	}

	// Get data from the Datastore
	var data PublicEncData
	err = json.Unmarshal(databytes, &data)
	if err != nil {
		return err
	}
	cypherBytes := data.CypherText
	signature := data.Signature

	// Verify the signature of data in Datastore
	err = userlib.DSVerify(verifyKey, cypherBytes, signature)
	if err != nil {
		return err
	}

	// Decrypt object
	plainBytes, err := userlib.PKEDec(privateKey, cypherBytes)
	if err != nil {
		return err
	}
	err = json.Unmarshal(plainBytes, object)
	if err != nil {
		return err
	}
	return
}

/* Get Fileheader from username and filename */
func (userdata *User) getFileHeader(filename string, fileHeader interface{}) (err error) {
	tempString := fmt.Sprintf("%s_%s", userdata.Username, filename) // Get FileHeader UUID on fly
	fhid, err := getUUIDFromString([]byte(tempString))
	if err != nil {
		return err
	}
	userEncKey, userMacKey, err := getKeyPairFromBase(userdata.UserBaseKey)
	if err != nil {
		return
	}
	// Get FileHeader from DataStore
	err = getSymEncObject(fhid, userEncKey, userMacKey, &fileHeader)
	if err != nil {
		return
	}
	return
}

/* Get ShareNode from username and filename */
func (userdata *User) getShareNode(filename string, shareNode interface{}) (err error) {
	var fileHeader FileHeader
	err = userdata.getFileHeader(filename, &fileHeader)
	if err != nil {
		return
	}
	// Get ShareNode from DataStore
	fileHeaderEncKey, fileHeaderMacKey, err := getKeyPairFromBase(fileHeader.FHBaseKey)
	if err != nil {
		return
	}
	err = getSymEncObject(fileHeader.ShareId, fileHeaderEncKey, fileHeaderMacKey, &shareNode)
	if err != nil {
		return err
	}
	return
}

/* Get file base key from ShareNode */
func (userdata *User) getSNFileBaseKey(shareNode ShareNode) (fileBaseKey []byte, err error) {
	if shareNode.OwnerName == "" {
		// ShareNode is the root node, get key from ShareNode
		return shareNode.FileBaseKey, nil
	} else {
		// ShareNode is the child node, get key from Invitation
		var invitation Invitation
		signKey := shareNode.OwnerName + "Digital_Signature_Key"
		verifyKey, ok := userlib.KeystoreGet(signKey)
		if !ok {
			return nil, errors.New("cannot find digital signature verify key")
		}
		err = getPublicEncObject(shareNode.InvitationId, userdata.UserRSAPrivateKey, verifyKey, &invitation)
		if err != nil {
			return nil, err
		}
		return invitation.InvitationBaseKey, nil
	}
}

/* Get FileBody from username and filename*/
func (userdata *User) getFileBody(filename string, fileBody interface{}) (err error) {
	var shareNode ShareNode
	err = userdata.getShareNode(filename, &shareNode)
	if err != nil {
		return
	}
	fileBaseKey, err := userdata.getSNFileBaseKey(shareNode)
	if err != nil {
		return
	}
	fileEncKey, fileMacKey, err := getKeyPairFromBase(fileBaseKey)
	if err != nil {
		return
	}
	err = getSymEncObject(shareNode.FileBodyId, fileEncKey, fileMacKey, &fileBody)
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
func getUserBaseKey(username string, password []byte) (baseKey []byte) {
	temp := append(password, []byte(username)...)
	baseKey = userlib.Argon2Key(temp, []byte(username), 16)
	return
}

/* Get FileHeader base key from user base key and filename*/
func getFileHeaderBaseKey(originalBaseKey []byte, filename string) (newBaseKey []byte, err error) {
	newBaseKey, err = userlib.HashKDF(originalBaseKey, []byte(filename))
	if err != nil {
		return nil, err
	}
	return newBaseKey[:16], nil
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

/* Get encryption & MAC key for the ShareNode of a given recipient */
func getChildBaseKey(baseKey []byte, recipientName string) (childBaseKey []byte, err error) {
	childBaseKey, err = userlib.HashKDF(baseKey, []byte(recipientName))
	if err != nil {
		return nil, err
	}
	return childBaseKey[:16], nil
}

/* Get next base key from current one */
func getNextBaseKey(originalBaseKey []byte) (newBaseKey []byte, err error) {
	newBaseKey, err = userlib.HashKDF(originalBaseKey, []byte("Base_Key"))
	if err != nil {
		return nil, err
	}
	return newBaseKey[:16], nil
}
