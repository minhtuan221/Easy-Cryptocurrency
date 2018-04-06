package main

import (
	"Easy-Cryptocurrency/blockchain"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
)

func main() {
	Curve := elliptic.P256()
	var user01, user02 blockchain.Wallet
	// var tran02 blockchain.Trans
	user01.GenerateKey(Curve)
	user02.GenerateKey(Curve)
	trans01 := blockchain.Trans{Sender: user01.GetPublicKey(), Balance: 1000, Receiver: user02.GetPublicKey(), Amount: 10.5, Timestamp: "today", PreviousTX: []string{"c", "b", "a"}}
	json01, _ := trans01.ForCheckSign()
	trans01.Signature = user01.Signature(json01)

	checksign := user02.Verify(json01, trans01.Sender, trans01.Signature)
	fmt.Println("check signature of transaction: ", checksign)
	trans01.Ready()
	beforeHash, _ := trans01.ForSend()
	fmt.Println("Transaction before hash: \n", beforeHash)
	fmt.Println("Transaction hash is: \n", trans01.Hash())
	blockchain.PrettyPrint(trans01)

	// Receive transaction from string json and parse to transaction again
	var recTrans blockchain.Trans
	var jsonBlob = []byte(beforeHash)
	err := json.Unmarshal(jsonBlob, &recTrans)
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println("Receiveing Transacions is: \n", recTrans)

	fmt.Println("======================Test blockchain transacion============================")
	// Create 3 new users
	var user03, user04, user05 blockchain.Wallet
	user03.GenerateKey(Curve)
	user04.GenerateKey(Curve)
	user05.GenerateKey(Curve)

	// Create 3 transaction
	trans03 := blockchain.Trans{Sender: user01.GetPublicKey(), Balance: 1000, Receiver: user02.GetPublicKey(), Amount: 299, Timestamp: "today", PreviousTX: []string{"c", "b", "a"}}
	trans03.Ready()
	json01, _ = trans03.ForCheckSign()
	trans03.Signature = user01.Signature(json01)

	trans04 := blockchain.Trans{Sender: user01.GetPublicKey(), Balance: 701, Receiver: user03.GetPublicKey(), Amount: 500, Timestamp: "today", PreviousTX: []string{}}
	trans04.Ready()
	json01, _ = trans04.ForCheckSign()
	trans04.Signature = user01.Signature(json01)

	trans05 := blockchain.Trans{Sender: user01.GetPublicKey(), Balance: 201, Receiver: user04.GetPublicKey(), Amount: 100, Timestamp: "today", PreviousTX: []string{}}
	trans05.Fee = 5
	trans05.Ready()
	json01, _ = trans05.ForCheckSign()
	trans05.Signature = user01.Signature(json01)

	// Initiate a block
	// Block is a small unit of blockchain
	// Block must be create from the blockchain of the miner for valid
	var blockchain01 blockchain.Blockchain
	// create genesis transaction
	genesisTrans := blockchain.Trans{Sender: "0", Balance: 1000, Receiver: user01.GetPublicKey(), Amount: 1000, Timestamp: "today", PreviousTX: []string{}}
	genesisTrans.Ready()

	// create genesis block
	var genesisBlock blockchain.Block
	genesisBlock.Init(Curve)
	genesisBlock.Transactions["0"] = genesisTrans
	blockchain01.Init(Curve, genesisBlock)

	// create a block after genesis
	block01 := blockchain01.CreateBlock(user01.GetPublicKey())

	// Add transaction to block
	// tmp, _ = trans03.ForSend()
	block01.Add(trans03)

	// tmp, _ = trans04.ForSend()
	block01.Add(trans04)

	// tmp, _ = trans05.ForSend()
	block01.Add(trans05)

	block01.SortTransactions() // Sort Transaction before add block to blockchain
	// fmt.Println("Your second Block is: \n")
	// blockchain.PrettyPrint(block01)
	block01.Ready()

	proof01 := blockchain01.MineProof(block01)

	blockchain01.AddBlock(block01, proof01)

	fmt.Println("=========================================================================")
	fmt.Println("Your Blockchain is: \n")
	blockchain.PrettyPrint(blockchain01)

	history := blockchain01.GetHistory(user02.GetPublicKey())
	balance := blockchain01.GetBalance(user01.GetPublicKey())
	fmt.Println("Your history is: ------------------")
	blockchain.PrettyPrint(history)

	fmt.Println("Your User01 Balance is: ------------------", balance)

	fmt.Println("Your User02 Balance is: ------------------", blockchain01.GetBalance(user02.GetPublicKey()))
	fmt.Println("Your User03 Balance is: ------------------", blockchain01.GetBalance(user03.GetPublicKey()))

	fmt.Println("Your User04 Balance is: ------------------", blockchain01.GetBalance(user04.GetPublicKey()))
	fmt.Println("Your User05 Balance is: ------------------", blockchain01.GetBalance(user05.GetPublicKey()))
	// blockchain.PrettyPrint(balance)
}
