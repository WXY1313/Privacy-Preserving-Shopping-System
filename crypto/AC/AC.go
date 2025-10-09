package AC

import (
	bn256 "Obfushop/bn256"
	"crypto/rand"
	"log"
	"math/big"
)

type IssuerKey struct {
	SK1 *big.Int
	SK2 *big.Int
	PK1 *bn256.G1
	PK2 *bn256.G1
}

type Params struct {
	Order *big.Int
	G1    *bn256.G1
	H1    *bn256.G1
	G2    *bn256.G2
}

type Req struct {
	gamma *bn256.G2
	Cm    *bn256.G1   // 承诺 cm
	C     []*bn256.G2 // ElGamal 密文 (aᵢ, bᵢ)
	PiS   *PiS        // 零知识证明 π_s
}

type BlindSignature struct {
	U *bn256.G2 // Hash(cm)
	C []*bn256.G2
}

type Cred struct {
	U     *bn256.G2
	Sigma *bn256.G2
}

type Proof struct {
	Value *big.Int
	U     *bn256.G2 //
	S     *bn256.G2 //
	// W     *bn256.G1
	// V     *bn256.G1
	// DLEQ  *DLEQ
}

func Setup() *Params {
	//Generate public parameters
	order := bn256.Order
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	hScalar, _ := new(big.Int).SetString("9868996996480530350723936346388037348513707152826932716320380442065450531909", 10)
	h1 := new(bn256.G1).ScalarBaseMult(hScalar)
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	return &Params{
		Order: order,
		G1:    g1,
		H1:    h1,
		G2:    g2,
	}

}

func KeyGen(params *Params) *IssuerKey {
	x, _ := rand.Int(rand.Reader, params.Order)
	y, _ := rand.Int(rand.Reader, params.Order)

	X := new(bn256.G1).ScalarBaseMult(x)
	Y := new(bn256.G1).ScalarBaseMult(y)

	return &IssuerKey{
		SK1: x,
		SK2: y,
		PK1: X,
		PK2: Y,
	}

}

func PrepareBlindSign(params *Params, m *big.Int) (*big.Int, *Req) {

	d, _ := rand.Int(rand.Reader, params.Order)
	gamma := new(bn256.G2).ScalarBaseMult(d)

	o, _ := rand.Int(rand.Reader, params.Order)
	Cm := new(bn256.G1).Add(new(bn256.G1).ScalarBaseMult(o), new(bn256.G1).ScalarMult(params.H1, m))

	u, _ := bn256.HashG2(string(Cm.Marshal()))
	k, _ := rand.Int(rand.Reader, params.Order)
	C := make([]*bn256.G2, 2)
	C[0] = new(bn256.G2).ScalarBaseMult(k)
	C[1] = new(bn256.G2).Add(new(bn256.G2).ScalarMult(gamma, k), new(bn256.G2).ScalarMult(u, m))

	// 5. 构建零知识证明 π_s
	piS, _ := MakePiS(params, gamma, C, Cm, k, o, m)

	// 6. 返回 commitment
	return d, &Req{
		gamma: gamma,
		Cm:    Cm,
		C:     C,
		PiS:   piS,
	}
}

func BlindSign(params *Params, issuerkey *IssuerKey, req *Req) *BlindSignature {

	_, err := VerifyPiS(params, req.gamma, req.C, req.Cm, req.PiS)
	if err != nil {
		log.Fatal("proof verification failed:", err)
	}
	//fmt.Println("π_s valid:", Result)

	// 1. 计算 h = HashG2(cm)
	hBytes := req.Cm.Marshal()
	u, err := bn256.HashG2(string(hBytes))

	_C := make([]*bn256.G2, 2)
	_C[0] = new(bn256.G2).ScalarMult(req.C[0], issuerkey.SK2)
	_C[1] = new(bn256.G2).Add(new(bn256.G2).ScalarMult(u, issuerkey.SK1), new(bn256.G2).ScalarMult(req.C[1], issuerkey.SK2))

	return &BlindSignature{
		U: u,
		C: _C,
	}
}

func ObtainCred(blindSigs *BlindSignature, d *big.Int) *Cred {
	// Step 1: 解盲BlindSignature → Signature
	sigma := new(bn256.G2).Add(blindSigs.C[1], new(bn256.G2).Neg(new(bn256.G2).ScalarMult(blindSigs.C[0], d)))

	return &Cred{
		U:     blindSigs.U,
		Sigma: sigma,
	}
}

func ProveCred(params *Params, sk *big.Int, issuerkey *IssuerKey, cred *Cred, m *big.Int) (*Proof, error) {
	// 1.r, randomize sigma
	r, _ := rand.Int(rand.Reader, params.Order)
	u := new(bn256.G2).ScalarMult(cred.U, r)
	u.ScalarMult(u, sk)
	s := new(bn256.G2).ScalarMult(cred.Sigma, r)
	// w := new(bn256.G1).ScalarMult(issuerkey.PK1, sk)
	// v := new(bn256.G1).ScalarMult(issuerkey.PK2, sk)
	//dleq, _ := DLEQProof(params, params.G1, issuerkey.PK1, issuerkey.PK2, sk, pk1, w, v)

	// 4. output theta
	proof := &Proof{
		Value: m,
		U:     u,
		S:     s,
	}
	return proof, nil
}

func VerifyCred(params *Params, pk1 *bn256.G1, pk2 *bn256.G2, issuerkey *IssuerKey, proof *Proof) (bool, error) {

	// Check h != identity && pairing matches
	if proof.U.String() == new(bn256.G2).ScalarBaseMult(big.NewInt(0)).String() {
		//fmt.Printf("proof.U False!!!\n")
		return false, nil
	}
	if bn256.Pair(params.G1, pk2).String() != bn256.Pair(pk1, params.G2).String() {
		return false, nil
	}
	// if !VerifyDLEQ(params, params.G1, issuerkey.PK1, issuerkey.PK2, pk1, proof.W, proof.V, proof.DLEQ) {
	// 	fmt.Printf("DLEQ False!!!\n")
	// 	return false, nil
	// }
	left3 := bn256.Pair(new(bn256.G1).Add(issuerkey.PK1, new(bn256.G1).ScalarMult(issuerkey.PK2, proof.Value)), proof.U)
	right3 := bn256.Pair(pk1, proof.S)
	return left3.String() == right3.String(), nil

	// left1 := bn256.Pair(pk1, issuerkey.PK1)
	// right1 := bn256.Pair(params.G1, proof.PiV.Base1)
	// if left1.String() != right1.String() {
	// 	return false, nil
	// }

	// left2 := bn256.Pair(pk1, issuerkey.PK2)
	// right2 := bn256.Pair(params.G1, proof.PiV.Base2)
	// if left2.String() != right2.String() {
	// 	return false, nil
	// }
}
