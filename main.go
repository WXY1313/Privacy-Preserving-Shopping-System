package main

import (
	"Obfushop/bn256"
	"Obfushop/compile/contract"
	"Obfushop/compile/contract/Event"
	"Obfushop/crypto/AC"
	"Obfushop/crypto/AES"
	"Obfushop/crypto/Convert"
	"Obfushop/crypto/OABE"
	"Obfushop/utils"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Compute G1Point size
func sizeOfG1Point(p contract.BCSIDG1Point) int {

	structSize := int(unsafe.Sizeof(p))
	dataSize := len(p.X.Bytes()) + len(p.Y.Bytes())

	return structSize + dataSize
}

// Compute G2Point size
func sizeOfG2Point(p contract.BCSIDG2Point) int {
	structSize := int(unsafe.Sizeof(p))
	dataSize := 0

	if p.X[0] != nil {
		dataSize += len(p.X[0].Bytes())
	}
	if p.X[0] != nil {
		dataSize += len(p.X[0].Bytes())
	}
	if p.Y[0] != nil {
		dataSize += len(p.Y[0].Bytes())
	}
	if p.Y[0] != nil {
		dataSize += len(p.Y[0].Bytes())
	}

	return structSize + dataSize
}

// Compute *big.Int size
func sizeOfBigInt(n *big.Int) int {
	return len(n.Bytes())
}

// Compute srting size
func sizeOfString(s string) int {
	structSize := int(unsafe.Sizeof(s))
	dataSize := len(s)
	return structSize + dataSize
}

func main() {
	iterations := 1
	attributeNum := 2

	//=============================Contract Deploy===========================//
	contract_name := "BC_SID"
	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}
	privatekey := utils.GetENV("PRIVATE_KEY_1")
	privatekeyBuyer := utils.GetENV("PRIVATE_KEY_2")
	privatekeySeller := utils.GetENV("PRIVATE_KEY_3")
	privatekeyLogistics := utils.GetENV("PRIVATE_KEY_4")
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
	tx0, _ := Contract.UploadACsParams(auth0, Convert.G1ToG1Point(paramters.G1), Convert.G2ToG2Point(paramters.G2), Convert.G1ToG1Point(issuerkey.PK1), Convert.G1ToG1Point(issuerkey.PK2))
	receipt0, err := bind.WaitMined(context.Background(), client, tx0)
	if err != nil {
		log.Fatalf("Tx receipt failed: %v", err)
	}
	fmt.Printf("UploadIssuerKey Gas used: %d\n", receipt0.GasUsed)

	//==================================Register=====================================//
	var attributeACsSet = []string{"Age>18", "B", "C", "D", "E", "F", "G", "H", "I", "J"}

	//1.User obtains his credential
	hashSet := make([][32]byte, attributeNum)
	mSet := make([]*big.Int, attributeNum)
	dSet := make([]*big.Int, attributeNum)
	reqSet := make([]*AC.Req, attributeNum)
	signatureSet := make([]*AC.BlindSignature, attributeNum)
	credSet := make([]*AC.Cred, attributeNum)
	for i := 0; i < attributeNum; i++ {
		hashSet[i] = sha256.Sum256([]byte(attributeACsSet[i]))
		mSet[i] = new(big.Int).SetBytes(hashSet[i][:])
		dSet[i], reqSet[i] = AC.PrepareBlindSign(paramters, mSet[i])
		signatureSet[i] = AC.BlindSign(paramters, issuerkey, reqSet[i])
		credSet[i] = AC.ObtainCred(signatureSet[i], dSet[i])
	}

	ProofAttrSet := make([]string, attributeNum)
	for i := 0; i < attributeNum; i++ {
		ProofAttrSet[i] = attributeACsSet[i]
	}

	//Algorithm1:Generate shopping identity
	var skB *big.Int
	var pkB *bn256.G1
	var pi_pkB *AC.DL
	Proofs := make([]*AC.Proof, attributeNum)

	start := time.Now() // 记录开始时间
	for i := 0; i < iterations; i++ {
		skB, _ = rand.Int(rand.Reader, bn256.Order)
		pkB = new(bn256.G1).ScalarBaseMult(skB)
		pi_pkB = AC.DLProof(new(bn256.G1).ScalarBaseMult(big.NewInt(int64(1))), pkB, skB)
		for i := 0; i < attributeNum; i++ {
			Proofs[i], _ = AC.ProveCred(paramters, skB, issuerkey, credSet[i], mSet[i])
		}
	}
	elapsed := time.Since(start)
	fmt.Printf("Time cost of Algorithm1: : %.6f ms\n", elapsed.Seconds()*1000/float64(iterations))

	//Verify shopping identity
	ProofsUSet := make([]contract.BCSIDG2Point, attributeNum)
	ProofsSSet := make([]contract.BCSIDG2Point, attributeNum)
	ProofsValueSet := make([]*big.Int, attributeNum)
	for i := 0; i < attributeNum; i++ {
		ProofsUSet[i] = Convert.G2ToG2Point(Proofs[i].U)
		ProofsSSet[i] = Convert.G2ToG2Point(Proofs[i].S)
		ProofsValueSet[i] = Proofs[i].Value
	}

	auth11 := utils.Transact(client, privatekeyBuyer, big.NewInt(0))
	tx11, _ := Contract.RegisterSIDSet(auth11, Convert.G1ToG1Point(pkB), Convert.G1ToG1Point(pi_pkB.RG), pi_pkB.C, pi_pkB.Z,
		ProofsUSet, ProofsSSet, ProofAttrSet)
	receipt11, err := bind.WaitMined(context.Background(), client, tx11)
	if err != nil {
		log.Fatalf("Tx receipt failed: %v", err)
	}
	SIDAttr, _ := Contract.GetSIDSet(&bind.CallOpts{}, Convert.G1ToG1Point(pkB))
	fmt.Printf("The buyer's SID attribute:%v\n", SIDAttr)
	fmt.Printf("Algorithm2 Gas used: %d\n", receipt11.GasUsed)

	pkB2 := new(bn256.G2).ScalarBaseMult(skB)
	fmt.Printf("Size of G1Point: %.6f KB\n", float64(sizeOfG1Point(Convert.G1ToG1Point(pkB)))/1024)
	fmt.Printf("Size of G2Point: %.6f KB\n", float64(sizeOfG2Point(Convert.G2ToG2Point(pkB2)))/1024)
	fmt.Printf("Size of uint256: %.6f KB\n", float64(sizeOfBigInt(pi_pkB.C))/1024)
	fmt.Printf("Size of string: %.6f KB\n", float64(sizeOfString(attributeACsSet[0]))/1024)

	//====================================Shopping=====================================//
	attribute := "Age>18"
	//1.Merchant sets productID and its price.
	productID := "Wine123"
	auth2 := utils.Transact(client, privatekeySeller, big.NewInt(0))
	tx2, _ := Contract.SetProductPrice(auth2, productID, big.NewInt(123347328473432382))
	receipt2, err := bind.WaitMined(context.Background(), client, tx2)
	if err != nil {
		log.Fatalf("Tx receipt failed: %v", err)
	}
	fmt.Printf("Merchant set the  product Gas used: %d\n", receipt2.GasUsed)
	sellerAddr := auth2.From

	//2. Buyer Obtain product price;
	price, err := Contract.GetProduct(&bind.CallOpts{}, sellerAddr, productID)
	if err != nil {
		log.Fatalf("GetProduct 调用失败: %v", err)
	}
	fmt.Printf("商品 %s 的价格为: %s gwei\n", productID, price.String())

	//3.Buyer sends a shopping order
	totalPrice := new(big.Int).Mul(price, big.NewInt(3))         // 单价 * 数量 = 总价 （单位：gWei）
	auth3 := utils.Transact(client, privatekeyBuyer, totalPrice) // ⬅️ 发送 totalPrice wei
	tx3, _ := Contract.BuyerCreateOrder(auth3, sellerAddr, productID, big.NewInt(3), Convert.G1ToG1Point(pkB))
	receipt3, err := bind.WaitMined(context.Background(), client, tx3)
	if err != nil {
		log.Fatalf("Transaction mining failed: %v", err)
	}
	fmt.Printf("Order creation tx hash: %v\n", tx3.Hash().Hex())

	fmt.Printf("BuyerCreateOrder GasUsed = %d\n", receipt3.GasUsed)
	fmt.Printf("BuyerCreateOrder 状态码: %v（1 表示成功）\n", receipt3.Status)
	buyerAddr := auth3.From

	//3.Merchant comfirm a shopping order.
	//  `Merchant obtains a transaction`
	parsedABI, _ := abi.JSON(strings.NewReader(contract.ContractABI))
	header, _ := client.HeaderByNumber(context.Background(), nil)
	order, err := Event.PollEventsBySeller(client, common.HexToAddress(address.Hex()), parsedABI, buyerAddr, header.Number.Uint64()-50) // 可监听最近50个区块
	if err != nil {
		log.Fatalf("查询订单事件失败: %v", err)
	}
	fmt.Printf("订单相关信息:%v\n", order)
	//`Merchant comfirm the order`
	auth4 := utils.Transact(client, privatekeySeller, big.NewInt(0)) // ⬅️ 发送 totalPrice wei
	tx4, _ := Contract.SellerAcceptOrder(auth4, order[0].Buyer, order[0].OrderID, attribute)
	receipt4, err := bind.WaitMined(context.Background(), client, tx4)
	if err != nil {
		log.Fatalf("Transaction mining failed: %v", err)
	}
	fmt.Printf("SellerAcceptOrder GasUsed = %d\n", receipt4.GasUsed)

	//======================================Logistics=========================================//
	// 系统参数生成
	MSK, PK := OABE.Setup()
	//生成用户公私钥对
	sku, _ := rand.Int(rand.Reader, bn256.Order)
	pku := new(bn256.G1).ScalarMult(PK.G1, sku)

	//1.Buyer encrypts our delivery address
	//TransAddr := "A4 Estate||A3 Road||A2 County||A1 City||A province "
	DelivAddr := []byte("5st Villa")
	keyR, _ := rand.Int(rand.Reader, bn256.Order)
	keyAES := new(bn256.GT).ScalarBaseMult(keyR)
	//加密派件地址
	//Algorithm 3
	tau := "(Owner  OR (Community_A AND Hovering_drone))"
	ABECT, xsMap, _, _ := OABE.Encrypt(keyAES, tau, PK)
	cipherAddr, err := AES.EncryptAndEncode(DelivAddr, keyAES.Marshal())
	if err != nil {
		log.Fatalf("加密失败: %v", err)
	}
	fmt.Println("加密后的Base64字符串:", cipherAddr)

	//2.Logistics company generate a logistics order
	N, _ := rand.Int(rand.Reader, bn256.Order)
	code := Convert.StringToBigInt(order[0].OrderID + "||" + string(new(bn256.G1).ScalarBaseMult(N).Marshal()))
	SN := new(bn256.G1).ScalarMult(pkB, N)
	auth5 := utils.Transact(client, privatekeyLogistics, big.NewInt(0)) // ⬅️ 发送 totalPrice wei
	tx5, _ := Contract.CreateLogisticsOrder(auth5, sellerAddr, buyerAddr, order[0].OrderID, code, Convert.G1ToG1Point(SN))
	receipt5, err := bind.WaitMined(context.Background(), client, tx5)
	if err != nil {
		log.Fatalf("Transaction mining failed: %v", err)
	}
	fmt.Printf("CreateLogisticsOrder GasUsed = %d\n", receipt5.GasUsed)

	// 3.Logistics site updates status
	auth6 := utils.Transact(client, privatekeyLogistics, big.NewInt(0)) // ⬅️ 发送 totalPrice wei
	tx6, _ := Contract.UpdateStatus(auth6, order[0].OrderID, "A3 Road")
	receipt6, err := bind.WaitMined(context.Background(), client, tx6)
	if err != nil {
		log.Fatalf("Transaction mining failed: %v", err)
	}
	fmt.Printf("UpdateStatus GasUsed = %d\n", receipt6.GasUsed)

	//4.Drone obtains own attribute key
	Su := map[string]bool{"Community_A": true, "Hovering_drone": true}
	var attributeSet []string
	for key, _ := range Su {
		attributeSet = append(attributeSet, key)
	}
	SK := OABE.KeyGen(pku, MSK, PK, attributeSet)

	//5.Drone decrypts the intermediate result to obtain delivery address
	//Algorithm 4
	IR := OABE.ODecrypt(Su, ABECT, SK, xsMap, PK) //外包解密
	_keyAES := OABE.Decrypt(IR, sku, ABECT)       //无人机解密
	_DelivAddr, err := AES.DecodeAndDecrypt(cipherAddr, _keyAES.Marshal())
	if err != nil {
		fmt.Println("解密失败:", err)
	}
	fmt.Printf("派件地址为: %s\n", string(_DelivAddr))

	//=======================================Confirm========================================//
	//1.Buyer obtains pickup code
	_SN, _ := Contract.GetSN(&bind.CallOpts{}, order[0].OrderID)
	fmt.Printf("加密随机数为：%v\n", _SN)
	_N := new(bn256.G1).ScalarMult(Convert.G1PointToG1(_SN), skB.ModInverse(skB, bn256.Order))

	//2.Buyer confirm receipt
	auth7 := utils.Transact(client, privatekeyBuyer, big.NewInt(0)) // ⬅️ 发送 totalPrice wei
	tx7, _ := Contract.BuyerConfirmWithCode(auth7, sellerAddr, order[0].OrderID, string(_N.Marshal()))
	receipt7, err := bind.WaitMined(context.Background(), client, tx7)
	if err != nil {
		log.Fatalf("Transaction mining failed: %v", err)
	}
	fmt.Printf("BuyerConfirmWithCode GasUsed = %d\n", receipt7.GasUsed)

	sellerBalance, _ := Contract.GetBalanceOf(&bind.CallOpts{}, sellerAddr)
	fmt.Printf("Seller balance:%v\n", sellerBalance)

	//3.Seller withdraw the payment
	auth8 := utils.Transact(client, privatekeySeller, big.NewInt(0)) // ⬅️ 发送 totalPrice wei
	tx8, _ := Contract.WithdrawPayment(auth8, buyerAddr, order[0].OrderID)
	receipt8, err := bind.WaitMined(context.Background(), client, tx8)
	if receipt8.Status != 1 {
		log.Fatalf("❌ 提现交易失败，链上回滚")
	}
	if err != nil {
		log.Fatalf("Transaction mining failed: %v", err)
	}
	fmt.Printf("WithdrawPayment GasUsed = %d\n", receipt8.GasUsed)

	parsedABI1, err := abi.JSON(strings.NewReader(contract.ContractABI))
	if err != nil {
		log.Fatalf("❌ ABI 解析失败: %v", err)
	}
	events, err := Event.GetPaymentEventsByOrderID(client, common.HexToAddress(address.Hex()), parsedABI1, order[0].OrderID)
	if err != nil {
		log.Fatalf("❌ 事件监听失败: %v", err)
	}
	if len(events) == 0 {
		fmt.Println("⚠️ 未监听到提现事件（SellerGetPayment），可能提现未成功或 orderID 不匹配")
	} else {
		for _, ev := range events {
			fmt.Printf("✅ 提现成功：订单 %v，卖家 %v，买家 %v，金额 %v wei\n",
				ev.OrderID, ev.Seller.Hex(), ev.Buyer.Hex(), ev.Payment.String())
		}
	}
}

//Time cost that user generates proofs for different number attributes (2,4,6,8,10)
//2.481406 ms; 4.931844 ms;7.469147 ms;9.646680 ms; 12.265281 ms

//Gas cost that multi-user (2,4,6,8,10) verify roofs for different number attributes (2,4,6,8,10)
//userNum=1: 508939; 826014; 1143297;1460596;1778151
//userNum=2: 1020534;1657112;2293806;2930916;3568118
//userNum=4: 2041056;3314116;4587852;5861808;7136176
//userNum=6: 3061506;4971204;6881622;8792688;10704414
//userNum=8: 4082040;6628436;9175608;11723688;14272352
//userNum=10: 5102610;8285428;11469354;14654364;17840554

//Communication cost (KB) that multi-user (2,4,6,8,10) verify roofs for different number attributes (2,4,6,8,10)
//UserNum=1:0.897461;1.553711;2.209961;2.872070;3.530273
//userNum=2: 1.794922; 3.109375;4.425781;5.742188; 7.060547;
//userNum=4: 3.589844;6.220703;8.853516;11.484375;14.106445
//userNum=6: 5.383789;9.333984;13.277344;17.224609;21.169922
//userNum=8: 7.171875;12.437500;17.699219;22.972656;28.227539
//userNum=10:8.965820;15.551758;22.126953;28.703125;35.285156

//Algorithm 1 (n=2,4,6,8,10)
//2.698676 ms; 5.150207 ms;7.536498 ms;10.012565 ms;12.388331 ms

//Algorithm 2 (n=2,4,6,8,10)
//393933;711035;1028237;1345610;1662964
