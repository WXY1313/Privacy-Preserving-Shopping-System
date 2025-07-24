package main

import (
	bn256 "Obfushop/bn256"
	"Obfushop/compile/contract"
	"Obfushop/crypto/AC"
	"Obfushop/crypto/Convert"
	"Obfushop/utils"
	"context"
	"fmt"
	"log"

	//"Obfushop/crypto/Convert"

	"crypto/rand"
	"crypto/sha256"

	//"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	//=============================Contract Deploy===========================//
	contract_name := "BC_SID"
	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	privatekey := utils.GetENV("PRIVATE_KEY_1")

	auth := utils.Transact(client, privatekey, big.NewInt(0))

	address, tx := utils.Deploy(client, contract_name, auth)

	receipt, _ := bind.WaitMined(context.Background(), client, tx)
	if err != nil {
		log.Fatalf("Tx receipt failed: %v", err)
	}
	fmt.Printf("Deploy Gas used: %d\n", receipt.GasUsed)

	Contract, err := contract.NewContract(common.HexToAddress(address.Hex()), client)
	if err != nil {
		fmt.Println(err)
	}
	//=============================Setup Phase==============================//
	//1.Shopping-chain setup
	paramters := AC.Setup()           //Generate ACs parameters
	issuerkey := AC.KeyGen(paramters) //Generate issuer's key pair
	auth0 := utils.Transact(client, privatekey, big.NewInt(0))
	tx0, _ := Contract.UploadAcsParams(auth0, Convert.G1ToG1Point(paramters.G1), Convert.G2ToG2Point(issuerkey.PK1), Convert.G2ToG2Point(issuerkey.PK2))
	receipt0, err := bind.WaitMined(context.Background(), client, tx0)
	if err != nil {
		log.Fatalf("Tx receipt failed: %v", err)
	}
	fmt.Printf("UploadIssuerKey Gas used: %d\n", receipt0.GasUsed)

	//=============================Register=================================//
	//1.Generate user's key pair (skB, pkB), where pkB=(pkB1,pkB2)
	skB, _ := rand.Int(rand.Reader, bn256.Order)
	pkB1 := new(bn256.G1).ScalarBaseMult(skB)
	pkB2 := new(bn256.G2).ScalarBaseMult(skB)

	//2.User obtains his credential
	attribute := "age>18"
	hash := sha256.Sum256([]byte(attribute + skB.String()))
	m := new(big.Int).SetBytes(hash[:])
	d, req := AC.PrepareBlindSign(paramters, m)
	signature := AC.BlindSign(paramters, issuerkey, req)
	Cred := AC.ObtainCred(signature, d)

	//3. Generate proof of credential
	proof, _ := AC.ProveCred(pkB1, paramters, skB, issuerkey, Cred, m)

	//4.Construct digtal shopping identity and uploads the shopping-chain
	auth1 := utils.Transact(client, privatekey, big.NewInt(0))
	tx1, _ := Contract.VerifyProof1(auth1, Convert.G1ToG1Point(pkB1), Convert.G2ToG2Point(pkB2), Convert.G2ToG2Point(new(bn256.G2).ScalarMult(issuerkey.PK1, skB)), Convert.G2ToG2Point(new(bn256.G2).ScalarMult(issuerkey.PK2, skB)), Convert.G2ToG2Point(proof.W), Convert.G2ToG2Point(proof.PiV.RG),
		Convert.G1ToG1Point(proof.U), Convert.G1ToG1Point(proof.V), Convert.G1ToG1Point(proof.PiV.RH),
		proof.PiV.C, proof.PiV.Rr, proof.PiV.Rm, Convert.G1ToG1Point(proof.S), attribute)
	receipt1, err := bind.WaitMined(context.Background(), client, tx1)
	if err != nil {
		log.Fatalf("Tx receipt failed: %v", err)
	}
	fmt.Printf("Verify1Proof Gas used: %d\n", receipt1.GasUsed)
	auth2 := utils.Transact(client, privatekey, big.NewInt(0))
	tx2, _ := Contract.VerifyProof2(auth2, Convert.G1ToG1Point(proof.C_), Convert.G1ToG1Point(proof.V), Convert.G1ToG1Point(proof.Pi_R.RG),
		Convert.G1ToG1Point(pkB1), Convert.G1ToG1Point(proof.C), Convert.G1ToG1Point(proof.Pi_R.RH), proof.Pi_R.C, proof.Pi_R.Z)
	receipt2, err := bind.WaitMined(context.Background(), client, tx2)
	if err != nil {
		log.Fatalf("Tx receipt failed: %v", err)
	}
	fmt.Printf("Verify2Proof Gas used: %d\n", receipt2.GasUsed)
	fmt.Printf("Total VerifyProof Gas used: %d\n", receipt1.GasUsed+receipt2.GasUsed)
	ProofResult, _ := Contract.GetProofResult(&bind.CallOpts{})
	fmt.Printf("The proof verification:%v\n", ProofResult)
	SIDAttr, _ := Contract.GetSID(&bind.CallOpts{}, Convert.G1ToG1Point(pkB1))
	fmt.Printf("The SID attribute:%v\n", SIDAttr)

	//

}
