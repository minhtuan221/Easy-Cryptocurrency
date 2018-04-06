package blockchain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"math"
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

// Wallet for generate Private Key, Public Key
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
	// fmt.Printf("Your Base58 is %s\n", encoded58)

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
	// fmt.Printf("Your Base58 is %s\n", encoded58)
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
		// return nil, nil, errors.New("Decoded String is not 64 bytes")
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
	if err != nil {
		// log.Fatal(err)
		fmt.Println(err)
		return false
	}
	// get the key pair of publickey
	x, y, err := StringToKeypair(StringPublickey)
	// fmt.Println("x,y, err is:", r, s, err)
	if err != nil {
		// log.Fatal(err)
		fmt.Println(err)
		return false
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
	Remain     float64
	Timestamp  string //`json:"timestamp"`
	Signature  string
	Fee        float64
}

func (self *Trans) Ready() {
	strs := self.PreviousTX
	sort.Strings(strs)
	self.Remain = self.Balance - self.Amount - self.Fee
	self.Timestamp = self.getTime()
}

func (self *Trans) ForCheckSign() (string, error) {
	// fmt.Println(self)

	mapD := map[string]interface{}{"Sender": self.Sender, "Receiver": self.Receiver, "Balance": self.Balance, "Amount": self.Amount, "Timestamp": self.Timestamp, "PreviousTX": self.PreviousTX, "Remain": self.Remain}
	b, err := json.Marshal(mapD)
	// fmt.Println(string(b))
	if err != nil {
		fmt.Println(err)
		return "nil", err
	}
	return string(b), nil
}

func (self *Trans) ForSend() (string, error) {
	// fmt.Println(self)

	mapD := map[string]interface{}{"Sender": self.Sender, "Receiver": self.Receiver, "Balance": self.Balance, "Amount": self.Amount, "Timestamp": self.Timestamp, "PreviousTX": self.PreviousTX, "Remain": self.Remain, "Signature": self.Signature}
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
	data, _ := self.ForSend()
	hash := sha256.New()
	hash.Write([]byte(data))
	md := hash.Sum(nil)
	mdStr := EncodeBase58(md)
	return mdStr
}

// Block use to collect transaction and check all transaction is ok.
// Then create hash ID for every transaction
type Block struct {
	Index        int
	Previoushash string
	Reward       float64
	MinerBy      string
	Transactions map[string]Trans
	Proof        int64
	Timestamp    string
	Hash         string
	curve        elliptic.Curve
}

func (block *Block) Init(crytoCurve elliptic.Curve) bool {
	block.curve = crytoCurve
	block.Transactions = make(map[string]Trans)
	return true
}

func (block *Block) CheckSignature(trans Trans) bool {
	var w Wallet
	w.GenerateKey(block.curve)
	json01, _ := trans.ForCheckSign()
	checksign := w.Verify(json01, trans.Sender, trans.Signature)
	return checksign
}

func (block *Block) CheckInfo(trans Trans) bool {
	if trans.Balance < 0 {
		return false
	}
	if trans.Amount <= 0 {
		return false
	}
	if trans.Remain < 0 {
		return false
	}
	if trans.Balance < trans.Amount+trans.Remain {
		return false
	}
	if trans.Sender == trans.Receiver {
		return false
	}
	return true
}

func StrToTrans(beforeHash string) Trans {
	var recTrans Trans
	var jsonBlob = []byte(beforeHash)
	err := json.Unmarshal(jsonBlob, &recTrans)
	if err != nil {
		fmt.Println("error:", err)
	}
	return recTrans
}

func (block *Block) Add(trans Trans) bool {

	// check if the transaction is reward miner or not
	if trans.Receiver != block.MinerBy {

		if block.CheckSignature(trans) == false {
			fmt.Println("Add transaction failed signature")
			PrettyPrint(block)
			return false
		}
		if block.CheckInfo(trans) == false {
			fmt.Println("Add transaction failed info, balance")
			PrettyPrint(block)
			return false
		}
	}
	block.Transactions[trans.Hash()] = trans
	return true
}

func (block *Block) SortTransactions() {
	Transactions := block.Transactions
	// sort the key of transaction
	keys := make([]string, len(Transactions))
	for key := range Transactions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	newTransactions := make(map[string]Trans)
	for index := 0; index < len(keys); index++ {
		if keys[index] != "" {
			newTransactions[keys[index]] = Transactions[keys[index]]
		}
	}
	block.Transactions = newTransactions
}
func (block *Block) Ready() {
	block.GetTime()
	block.RewardMiner()
	block.SortTransactions()
	// return block.Timestamp
}

func (block *Block) GetTime() {
	block.Timestamp = string(time.Now().Format(time.RFC850))
	// return block.Timestamp
}

func (block *Block) GetFee() float64 {
	// Get block fee
	var fee float64
	fee = 0.0
	for _, anyTrans := range block.Transactions {
		fee += anyTrans.Balance - anyTrans.Amount - anyTrans.Remain
	}
	return fee
}

func (block *Block) RewardMiner() {

	// Get block reward amount
	rewardAmount := block.Reward + block.GetFee()

	// Transaction of rewarding miner
	trans00 := Trans{Sender: "0", Balance: rewardAmount, Receiver: block.MinerBy, Amount: rewardAmount, Timestamp: "today", PreviousTX: []string{}}
	trans00.Ready()
	block.Add(trans00)
}

func CreateKeyValuePairs(m map[string]Trans) string {
	b := ""
	listKey := make([]string, len(m))
	for key, _ := range m {
		listKey = append(listKey, key)
	}
	sort.Strings(listKey)
	for index := 0; index < len(listKey); index++ {
		if listKey[index] != "" {
			b += fmt.Sprintf("{%s:%s},", listKey[index], m[listKey[index]])
		}
	}

	return b
}

type Blockchain struct {
	Chain     []Block
	History   map[string]Trans
	Lastblock Block
	Curve     elliptic.Curve
}

// Init block is the first step of creating a blockchain
func (BC *Blockchain) Init(crytoCurve elliptic.Curve, genesisBlock Block) bool {
	BC.Curve = crytoCurve
	BC.History = make(map[string]Trans)
	Ok := BC.createGenesisBlock(genesisBlock)
	return Ok
}

// createGenesisBlock is the subprocess of Init blockchain.
// It's the first block, can only add once when there are no other block before
func (BC *Blockchain) createGenesisBlock(genesisBlock Block) bool {

	// check if the chain is empty
	if len(BC.Chain) > 0 {
		return false
	}
	genesisBlock.Index = 1
	genesisBlock.Previoushash = "0"
	genesisBlock.Ready()
	fmt.Println("Your Genesis Block is: ------------------------")
	PrettyPrint(genesisBlock)
	genesisBlock.Proof = BC.MineProof(genesisBlock)

	genesisBlock.Hash = BC.HashBlock(genesisBlock, genesisBlock.Proof)

	fmt.Println("Your Genesis Block after hash is: ------------------------")
	PrettyPrint(genesisBlock)
	BC.Chain = append(BC.Chain, genesisBlock)
	BC.Lastblock = BC.Chain[len(BC.Chain)-1]

	// append transaction to history
	for key, trans := range genesisBlock.Transactions {
		BC.History[key] = trans
	}
	return true
}

// CreateBlock and use that block for stack transaction into it
func (BC *Blockchain) CreateBlock(MinerAddress string) Block {
	var block Block
	block.Init(BC.Curve)
	block.Index = len(BC.Chain) + 1
	block.Previoushash = BC.Lastblock.Hash
	block.Reward = BC.GetReward(block.Index)
	block.MinerBy = MinerAddress
	return block
}

func (BC *Blockchain) MineProof(block Block) int64 {
	var proof int64
	proof = 0
	// block.Ready() // cannot get ready here because This function cannot change block from inside.
	for true {
		newHash := BC.HashBlock(block, proof)
		if BC.ValidProof(newHash) {
			fmt.Println("Proof:", proof, "| Hash is:", newHash)
			// PrettyPrint(block)
			break
		}
		proof++
	}
	return proof
}

func (BC *Blockchain) ValidProof(hash string) bool {
	if hash[:4] == "0000" {
		return true
	}
	return false
}

func (BC *Blockchain) HashBlock(block Block, proof int64) string {

	// block.Previoushash = BC.Lastblock.Hash
	block.Proof = proof
	data := fmt.Sprintf("{%s,%s,%s,%s,%s}", string(block.Index), block.Previoushash, CreateKeyValuePairs(block.Transactions), string(block.Proof), block.Timestamp)
	hash := sha256.New()
	hash.Write([]byte(data))
	md := hash.Sum(nil)
	mdStr := hex.EncodeToString(md)
	return mdStr
}

//AddBlock use to add the block was created from the previous step after It appended many transaction
func (BC *Blockchain) AddBlock(block Block, proof int64) bool {

	block.Proof = proof
	block.Hash = BC.HashBlock(block, proof)
	if len(BC.Chain) > 0 {
		// Check proof of work
		if !BC.ValidProof(block.Hash) {
			fmt.Println("Add block failed proof of work: Proof:", proof, "| Hash", block.Hash)
			// PrettyPrint(block)
			return false
		}

		// check the index is ok
		if block.Index != len(BC.Chain)+1 {
			fmt.Println("Add block failed index")
			return false
		}

		// check any transaction in block is valid
		for key, trans := range block.Transactions {
			// check balance of any transaction
			realBal := BC.GetBalance(trans.Sender)
			if trans.Balance > realBal && trans.Sender != "0" {
				fmt.Println("Error: Block contain transaction not enough money!:", key)
				fmt.Println("Real Balance is:", trans)
				return false
			}

			// check if signature is correct
			if trans.Sender != "0" {

				var testUser Wallet
				testUser.GenerateKey(BC.Curve)
				checksign, _ := trans.ForCheckSign()
				if testUser.Verify(checksign, trans.Sender, trans.Signature) != true {
					fmt.Println("Error: Signature of transaction of transaction is failed!:", key)
					fmt.Println("Real Balance is:", trans)
					return false
				}
			}

			// check if transaction is duplicate
			if val, ok := BC.History[key]; ok {
				//Transaction is ready exist
				fmt.Println("Transaction is ready exist. ID=", val)
				return false
			}

			// check reward transaction
			if key == "0" {
				if trans.Amount > block.GetFee()+BC.GetReward(block.Index) {
					return false
				}
			}
		}
	}

	BC.Chain = append(BC.Chain, block)
	BC.Lastblock = BC.Chain[len(BC.Chain)-1]
	// append transaction to history
	for key, trans := range block.Transactions {
		BC.History[key] = trans
	}
	return true
}

func (BC *Blockchain) GetHistory(userAddress string) []Trans {

	var accHistory []Trans
	for _, trans := range BC.History {
		if trans.Sender == userAddress || trans.Receiver == userAddress {
			accHistory = append(accHistory, trans)
		}
	}

	return accHistory
}

func (BC *Blockchain) GetBalance(userAddress string) float64 {

	var balance float64
	balance = 0.0
	accHistory := BC.GetHistory(userAddress)
	for _, trans := range accHistory {
		if trans.Receiver == userAddress {
			balance += trans.Amount
		}
		if trans.Sender == userAddress {
			balance -= trans.Amount
		}
	}

	return balance
}

func (BC *Blockchain) GetReward(index int) float64 {
	// INITIAL_COINS_PER_BLOCK coins per block.
	// Reduce by haft every HALVING_FREQUENCY blocks
	// index = len(self.chain)+1
	INITIAL_COINS_PER_BLOCK := 50.0
	HALVING_FREQUENCY := 100000
	reward := INITIAL_COINS_PER_BLOCK
	HalvingTime := int(index/HALVING_FREQUENCY) + 1
	for i := 1; i < HalvingTime; i++ {
		reward = math.Max(reward/2, 5)
	}
	return reward
}

func (BC *Blockchain) ResolveConflict(newchain []Block) bool {

	if len(BC.Chain) < len(newchain) {
		return false
	}

	lastblock := newchain[0]
	var blockchainTest Blockchain
	blockchainTest.Init(BC.Curve, newchain[0])
	var block Block
	for currentIndex := 1; currentIndex < len(newchain); currentIndex++ {
		block = newchain[currentIndex]
		// check if any block-hash of the newchain is valid
		if block.Previoushash != BC.HashBlock(lastblock, lastblock.Proof) {
			return false
		}

		// Simulate the process of block for cheking
		if blockchainTest.AddBlock(block, lastblock.Proof) == false {
			return false
		}
		lastblock = block
	}
	BC.Chain = blockchainTest.Chain
	BC.History = blockchainTest.History
	return true
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
	beforeHash, _ := trans01.ForSend()
	fmt.Println("Transaction before hash: \n", beforeHash)
	fmt.Println("Transaction hash is: \n", trans01.Hash())
	PrettyPrint(trans01)
}
func main() {
	testTrans()
	testWallet()
	fmt.Println("this is Blockchain")
}
