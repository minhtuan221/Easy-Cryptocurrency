package blockchain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"os"
	"sort"
	"time"

	base58 "github.com/m0t0k1ch1/base58"
)

// Utility functions:
func PrettyPrint(data interface{}) string {

	json, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(json))
	return string(json)
}

/*
1. create privatekey publickey
2. convert big.int to bytes
3. convert byte to base64
4. decode base64 to bytes
5. convert byte to big.int
6. use big.int for signture
*/
type Wallet struct {
	curve      elliptic.Curve
	privatekey *ecdsa.PrivateKey
	publickey  ecdsa.PublicKey
}

// GenerateKey use to generate new private/public Key pair
func (self *Wallet) GenerateKey(crytoCurve elliptic.Curve) {
	self.curve = crytoCurve
	privatekey, err := ecdsa.GenerateKey(self.curve, rand.Reader)

	// error handling
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	self.privatekey = privatekey
	self.publickey = privatekey.PublicKey
	// fmt.Println("The private key is: ", self.privatekey)
}

func (self *Wallet) GetPrivateKey() string {
	privatekey := self.privatekey
	// priv := new(big.Int)
	priv := privatekey.D

	// fmt.Println("my priv now is: ", priv, reflect.TypeOf(priv))
	// encodedStr := hex.EncodeToString(priv.Bytes())
	encoded58 := EncodeBase58(priv.Bytes())
	fmt.Printf("Your Base58 is %s\n", encoded58)

	// fmt.Printf("Your private key is %s\n", encodedStr)
	return encoded58
}

func EncodeBase58(message []byte) string {

	b58 := base58.NewBitcoinBase58()

	address, err := b58.EncodeToString(message)
	if err != nil {
		log.Fatal(err)
	}
	return address
}

func DecodeBase58(message string) ([]byte, error) {
	b58 := base58.NewBitcoinBase58()

	pkhBytes, err := b58.DecodeString(message)
	if err != nil {
		log.Fatal(err)
	}
	return pkhBytes, nil
}

func (self *Wallet) GetPublicKey() string {
	x := self.publickey.X
	y := self.publickey.Y
	// fmt.Println(x, y)
	publickey := x.Bytes()
	publickey = append(publickey, y.Bytes()...)
	// fmt.Println("my publickey now is: ", publickey)
	// encodedStr := hex.EncodeToString(publickey)
	encoded58 := EncodeBase58(publickey)
	fmt.Printf("Your Base58 is %s\n", encoded58)
	// fmt.Printf("Your public key is %s\n", encodedStr)
	return encoded58
}

func (self *Wallet) Signature(message string) string {

	var h hash.Hash
	h = md5.New()
	r := big.NewInt(0)
	s := big.NewInt(0)

	io.WriteString(h, message)
	signhash := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, self.privatekey, signhash)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	encodedStr := EncodeBase58(signature) //hex.EncodeToString(signature)

	// fmt.Printf("Your Signature is %s\n", encodedStr)
	return encodedStr
}

func StringToKeypair(strPublickey string) (*big.Int, *big.Int, error) {

	decoded, err := DecodeBase58(strPublickey) //hex.DecodeString(strPublickey)
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}

	// fmt.Printf("The decoded publickey string %x\n", decoded)
	if len(decoded) != 64 {
		return nil, nil, errors.New("Decoded String is not 64 bytes")
	}
	x := decoded[:32]
	y := decoded[32:]
	// fmt.Println("x is:", x)
	// fmt.Println("y is:", y)

	// reconvert byte to r and s
	X := new(big.Int)
	X.SetBytes(x)
	Y := new(big.Int)
	Y.SetBytes(y)
	return X, Y, err
}

func (self *Wallet) Verify(message, StringPublickey, signature string) bool {

	// format the message
	var h hash.Hash
	h = md5.New()
	io.WriteString(h, message)
	signhash := h.Sum(nil)

	// get the key pair of signature
	r, s, err := StringToKeypair(signature)
	// fmt.Println("r,s is:", r, s)

	// get the key pair of publickey
	x, y, err := StringToKeypair(StringPublickey)
	// fmt.Println("x,y, err is:", r, s, err)
	if err != nil {
		log.Fatal(err)
	}
	// Initiate publickey from key pair
	var publickey ecdsa.PublicKey
	publickey.Curve = self.curve
	publickey.X = x
	publickey.Y = y
	// Verify
	verifystatus := ecdsa.Verify(&publickey, signhash, r, s)
	// fmt.Println(verifystatus) // should be true
	return verifystatus
}

func testWallet() {
	pubkeyCurve := elliptic.P256()
	var wallet Wallet
	wallet.GenerateKey(pubkeyCurve)
	fmt.Println("Private key :", wallet.GetPrivateKey())
	publickey := wallet.GetPublicKey()
	fmt.Println("Public key :", publickey)
	mes := "hello world"
	mysign := wallet.Signature(mes)

	fmt.Println("Message is", mes)
	verified := wallet.Verify(mes, publickey, mysign)
	fmt.Println("Verified signature", verified)

	// get the key pair of publickey error
	x2, y2, err2 := StringToKeypair(publickey)
	fmt.Println("Test Checking error is:", x2, y2, err2)

	if err2 != nil {
		log.Fatal(err2)
	}
}

//Trans New transaction store trading information
type Trans struct {
	PreviousTX []string
	Sender     string  //`json:"sender"`
	Balance    float64 //`json:"balance"`
	Receiver   string  //`json:"receiver"`
	Amount     float64 //`json:"amount"`
	Timestamp  string  //`json:"timestamp"`
	Signature  string
}

func (self *Trans) ForCheckSign() (string, error) {
	// fmt.Println(self)
	strs := self.PreviousTX
	sort.Strings(strs)

	mapD := map[string]interface{}{"Sender": self.Sender, "Receiver": self.Receiver, "Balance": self.Balance, "Amount": self.Amount, "Timestamp": self.getTime(), "PreviousTX": strs}
	b, err := json.Marshal(mapD)
	// fmt.Println(string(b))
	if err != nil {
		fmt.Println(err)
		return "nil", err
	}
	return string(b), nil
}
func (self *Trans) ForHash() (string, error) {
	// fmt.Println(self)
	strs := self.PreviousTX
	sort.Strings(strs)

	mapD := map[string]interface{}{"Sender": self.Sender, "Receiver": self.Receiver, "Balance": self.Balance, "Amount": self.Amount, "Timestamp": self.getTime(), "PreviousTX": strs, "Signature": self.Signature}
	b, err := json.Marshal(mapD)
	// fmt.Println(string(b))
	if err != nil {
		fmt.Println(err)
		return "nil", err
	}
	return string(b), nil
}
func (self *Trans) getTime() string {
	self.Timestamp = string(time.Now().Format(time.RFC850))
	return self.Timestamp
}

func (self *Trans) Hash() string {
	data, _ := self.ForHash()
	hash := sha256.New()
	hash.Write([]byte(data))
	md := hash.Sum(nil)
	mdStr := EncodeBase58(md)
	return mdStr
}

func testTrans() {
	Curve := elliptic.P256()
	var user01, user02 Wallet
	user01.GenerateKey(Curve)
	user02.GenerateKey(Curve)
	trans01 := Trans{Sender: user01.GetPublicKey(), Balance: 1000, Receiver: user02.GetPublicKey(), Amount: 10.5, Timestamp: "today", PreviousTX: []string{"c", "b", "a"}}
	json01, _ := trans01.ForCheckSign()
	trans01.Signature = user01.Signature(json01)

	checksign := user02.Verify(json01, trans01.Sender, trans01.Signature)
	fmt.Println("check signature of transaction: ", checksign)
	beforeHash, _ := trans01.ForHash()
	fmt.Println("Transaction before hash: \n", beforeHash)
	fmt.Println("Transaction hash is: \n", trans01.Hash())
	PrettyPrint(trans01)
}
func main() {
	fmt.Println("this is Blockchain")
}
