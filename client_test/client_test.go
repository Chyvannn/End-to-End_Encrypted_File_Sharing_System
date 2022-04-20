package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const wrongPassword = "PaSSWoRd"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	var horace *client.User
	var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var bobLaptop *client.User
	var err error

	// A bunch of filenames that may be useful.
	nonExistFile := "notExistFile.txt"
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	bobFile2 := "bobFile2.txt"
	charlesFile := "charlesFile.txt"
	sameNameFile := "sameNameFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"
	graceFile := "graceFile.txt"
	horaceFile := "horaceFile.txt"
	iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {
		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			userlib.DebugMsg("\nFile Content: %s\n", data)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(aliceFile)
			userlib.DebugMsg("\nFile Content: %s\n", data)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(aliceFile)
			userlib.DebugMsg("\nFile Content: %s\n", data)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Init/GetUser Tests", func() {
		Specify("Init/GetUser Test: empty username for InitUser.", func() {
			_, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Init/GetUser Test: Testing User with 0 length password", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", emptyString)
			Expect(err).To(BeNil())
		})

		Specify("Init/GetUser Test: Testing multiple user instances.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Init/GetUser Test: Testing get user with wrong password.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceDesktop, err = client.GetUser("alice", wrongPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Init/GetUser Test: Testing duplicate initialization.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Init/GetUser Test: Testing GetUser after malicious action.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			// GetUser success before attempting DataStore
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			dataMap := userlib.DatastoreGetMap()
			for key, elem := range dataMap {
				elem = userlib.RandomBytes(len(elem))
				userlib.DatastoreSet(key, elem)
			}

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Init/GetUser Test: Testing GetUser after malicious action.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			// GetUser success before attempting DataStore
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DatastoreClear()

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Store/Load/AppendToFile Tests", func() {
		Specify("Store/Load/AppendToFile Test: Testing same filename in different userspace", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(sameNameFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = bob.StoreFile(sameNameFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(sameNameFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = bob.LoadFile(sameNameFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Store/Load/AppendToFile Test: Testing empty file", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(emptyString))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(emptyString)))
		})

		Specify("Store/Load/AppendToFile Test: Testing single User Store/Load of single file.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Store/Load/AppendToFile Test: Testing overwriting file.", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Store/Load/AppendToFile Test: Testing integrity on LoadFile.", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DatastoreClear()
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Store/Load/AppendToFile Test: Testing LoadFile on not existing filename.", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			_, err := alice.LoadFile(nonExistFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Store/Load/AppendToFile Test: Testing AppendToFile on not existing filename.", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err := alice.AppendToFile(nonExistFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Store/Load/AppendToFile Test: Testing integrity on AppendToFile.", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DatastoreClear()
			err := alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Efficiency Tests", func() {
		Specify("Efficiency Test: Testing AppendToFile efficiency.", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			for i := 0; i < 10000; i++ {
				err = alice.AppendToFile(aliceFile, []byte(contentTwo))
				Expect(err).To(BeNil())
			}
			beforeAppend_10000 := userlib.DatastoreGetBandwidth()
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			afterAppend_10000 := userlib.DatastoreGetBandwidth()

			bandWidth_10000 := afterAppend_10000 - beforeAppend_10000
			lowBandWidth := bandWidth_10000 < 10000
			Expect(lowBandWidth).To(BeTrue())
		})

		Specify("Efficiency Test: Testing Key number does not depend on Append Number.", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			dataMap := userlib.KeystoreGetMap()
			sizeBeforeAppend := len(dataMap)

			for i := 0; i < 10000; i++ {
				err = alice.AppendToFile(aliceFile, []byte(contentTwo))
				Expect(err).To(BeNil())
			}

			dataMap = userlib.KeystoreGetMap()
			sizeAfterAppend := len(dataMap)
			sizeEqual := sizeBeforeAppend == sizeAfterAppend
			Expect(sizeEqual).To(BeTrue())
		})

		Specify("Efficiency Test: Testing Key number does not depend on Share Number.", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", emptyString)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", emptyString)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", emptyString)
			Expect(err).To(BeNil())
			eve, err = client.InitUser("eve", emptyString)
			Expect(err).To(BeNil())
			frank, err = client.InitUser("frank", emptyString)
			Expect(err).To(BeNil())
			grace, err = client.InitUser("grace", emptyString)
			Expect(err).To(BeNil())
			horace, err = client.InitUser("horace", emptyString)
			Expect(err).To(BeNil())
			ira, err = client.InitUser("ira", emptyString)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			dataMap := userlib.KeystoreGetMap()
			sizeBeforeShare := len(dataMap)

			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invitation, bobFile)
			Expect(err).To(BeNil())

			invitation, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invitation, charlesFile)
			Expect(err).To(BeNil())

			invitation, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("bob", invitation, dorisFile)
			Expect(err).To(BeNil())

			invitation, err = doris.CreateInvitation(dorisFile, "ira")
			Expect(err).To(BeNil())
			err = ira.AcceptInvitation("doris", invitation, iraFile)
			Expect(err).To(BeNil())

			invitation, err = doris.CreateInvitation(dorisFile, "eve")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("doris", invitation, eveFile)
			Expect(err).To(BeNil())

			invitation, err = doris.CreateInvitation(dorisFile, "frank")
			Expect(err).To(BeNil())
			err = frank.AcceptInvitation("doris", invitation, frankFile)
			Expect(err).To(BeNil())

			invitation, err = frank.CreateInvitation(frankFile, "grace")
			Expect(err).To(BeNil())
			err = grace.AcceptInvitation("frank", invitation, graceFile)
			Expect(err).To(BeNil())

			invitation, err = grace.CreateInvitation(graceFile, "horace")
			Expect(err).To(BeNil())
			err = horace.AcceptInvitation("grace", invitation, horaceFile)
			Expect(err).To(BeNil())

			dataMap = userlib.KeystoreGetMap()
			sizeAfterShare := len(dataMap)
			sizeEqual := sizeBeforeShare == sizeAfterShare
			Expect(sizeEqual).To(BeTrue())
		})
	})

	Describe("Create/AcceptInvitation Tests", func() {
		Specify("Create/AcceptInvitation Test: Testing access file before accept invitation.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Create/AcceptInvitation Test: Testing filename does not exist.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			_, err := alice.CreateInvitation(nonExistFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Create/AcceptInvitation Test: Testing recipient does not exist.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			_, err := alice.CreateInvitation(aliceFile, "Nobody")
			Expect(err).ToNot(BeNil())
		})

		Specify("Create/AcceptInvitation Test: Testing malicious action on CreateInvitation.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DatastoreClear()

			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Create/AcceptInvitation Test: Testing AcceptInvitation with existing filename.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitation, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Create/AcceptInvitation Test: Testing malicious AcceptInvitatation.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreClear()

			err = bob.AcceptInvitation("alice", invitation, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Create/AcceptInvitation Test: Testing different user instance can accept invitation.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bobLaptop.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
		})
	})

	Describe("Revoke Tests", func() {
		Specify("Revoke Test: Testing Alice share with bob.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			_, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())

		})

		Specify("Revoke Test: Testing Alice revoke access from Bob, and Bob want to accept invitation again.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile2)
			Expect(err).ToNot(BeNil())

			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Revoke Test: Testing filename does not exist in sender namespace.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile(aliceFile, []byte(contentOne))

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(nonExistFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Revoke Test: Testing filename not currently shared.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile(aliceFile, []byte(contentOne))

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Revoke Test: Testing invitation not accepted before revoke.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Revoke Test: Testing malicious revoke.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile(aliceFile, []byte(contentOne))

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DatastoreClear()

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Revoke Test: Testing revoke also revoke indirect children access.", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", emptyString)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", emptyString)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", emptyString)
			Expect(err).To(BeNil())
			eve, err = client.InitUser("eve", emptyString)
			Expect(err).To(BeNil())
			frank, err = client.InitUser("frank", emptyString)
			Expect(err).To(BeNil())
			grace, err = client.InitUser("grace", emptyString)
			Expect(err).To(BeNil())
			horace, err = client.InitUser("horace", emptyString)
			Expect(err).To(BeNil())
			ira, err = client.InitUser("ira", emptyString)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invitation, bobFile)
			Expect(err).To(BeNil())

			invitation, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invitation, charlesFile)
			Expect(err).To(BeNil())

			invitation, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("bob", invitation, dorisFile)
			Expect(err).To(BeNil())

			invitation, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("bob", invitation, eveFile)
			Expect(err).To(BeNil())

			invitation, err = eve.CreateInvitation(eveFile, "grace")
			Expect(err).To(BeNil())
			err = grace.AcceptInvitation("eve", invitation, graceFile)
			Expect(err).To(BeNil())

			invitation, err = eve.CreateInvitation(eveFile, "horace")
			Expect(err).To(BeNil())
			err = horace.AcceptInvitation("eve", invitation, horaceFile)
			Expect(err).To(BeNil())

			invitation, err = eve.CreateInvitation(eveFile, "ira")
			Expect(err).To(BeNil())
			err = ira.AcceptInvitation("eve", invitation, iraFile)
			Expect(err).To(BeNil())

			invitation, err = charles.CreateInvitation(charlesFile, "frank")
			Expect(err).To(BeNil())
			err = frank.AcceptInvitation("charles", invitation, frankFile)
			Expect(err).To(BeNil())

			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = frank.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = grace.LoadFile(graceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = horace.LoadFile(horaceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = ira.LoadFile(iraFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			_, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())
			_, err = eve.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())
			_, err = frank.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			_, err = grace.LoadFile(graceFile)
			Expect(err).ToNot(BeNil())
			_, err = horace.LoadFile(horaceFile)
			Expect(err).ToNot(BeNil())
			_, err = ira.LoadFile(iraFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Revoke Test: Testing sharing after revocation.", func() {
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", emptyString)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", emptyString)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", emptyString)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invitation, bobFile)
			Expect(err).To(BeNil())

			invitation, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invitation, charlesFile)
			Expect(err).To(BeNil())

			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			invitation, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("alice", invitation, dorisFile)
			Expect(err).To(BeNil())

			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})
	})
})
