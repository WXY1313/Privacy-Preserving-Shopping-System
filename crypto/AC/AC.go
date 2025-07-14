package AC

import (
	bn256 "Obfushop/bn256"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
)

type IssuerKey struct {
	SK1 *big.Int
	SK2 *big.Int
	PK1 *bn256.G2
	PK2 *bn256.G2
}

type Params struct {
	Order *big.Int
	G1    *bn256.G1
	H1    *bn256.G1
	G2    *bn256.G2
}

type Req struct {
	gamma *bn256.G1
	Cm    *bn256.G1   // 承诺 cm
	C     []*bn256.G1 // ElGamal 密文 (aᵢ, bᵢ)
	PiS   *PiS        // 零知识证明 π_s
}

type BlindSignature struct {
	U *bn256.G1 // Hash(cm)
	C []*bn256.G1
}

type Cred struct {
	U     *bn256.G1
	Sigma *bn256.G1
}

type Proof struct {
	W   *bn256.G2 // commitment in G2
	V   *bn256.G1 // randomization in G1
	U   *bn256.G1 //
	S   *bn256.G1 //
	PiV *PiV      // PiV      interface{}  // optional zero-knowledge proof
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

	X := new(bn256.G2).ScalarBaseMult(x)
	Y := new(bn256.G2).ScalarBaseMult(y)

	return &IssuerKey{
		SK1: x,
		SK2: y,
		PK1: X,
		PK2: Y,
	}

}

func PrepareBlindSign(params *Params, m *big.Int) (*big.Int, *Req) {

	d, _ := rand.Int(rand.Reader, params.Order)
	gamma := new(bn256.G1).ScalarBaseMult(d)

	o, _ := rand.Int(rand.Reader, params.Order)
	Cm := new(bn256.G1).Add(new(bn256.G1).ScalarBaseMult(o), new(bn256.G1).ScalarMult(params.H1, m))

	u, _ := bn256.HashG1(string(Cm.Marshal()))
	k, _ := rand.Int(rand.Reader, params.Order)
	C := make([]*bn256.G1, 2)
	C[0] = new(bn256.G1).ScalarBaseMult(k)
	C[1] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(gamma, k), new(bn256.G1).ScalarMult(u, m))

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

	Result, err := VerifyPiS(params, req.gamma, req.C, req.Cm, req.PiS)
	if err != nil {
		log.Fatal("proof verification failed:", err)
	}
	fmt.Println("π_s valid:", Result)

	// 1. 计算 h = HashG1(cm)
	hBytes := req.Cm.Marshal()
	u, err := bn256.HashG1(string(hBytes))

	_C := make([]*bn256.G1, 2)
	_C[0] = new(bn256.G1).ScalarMult(req.C[0], issuerkey.SK2)
	_C[1] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(u, issuerkey.SK1), new(bn256.G1).ScalarMult(req.C[1], issuerkey.SK2))

	return &BlindSignature{
		U: u,
		C: _C,
	}
}

func ObtainCred(blindSigs *BlindSignature, d *big.Int) *Cred {
	// Step 1: 解盲BlindSignature → Signature
	sigma := new(bn256.G1).Add(blindSigs.C[1], new(bn256.G1).Neg(new(bn256.G1).ScalarMult(blindSigs.C[0], d)))

	return &Cred{
		U:     blindSigs.U,
		Sigma: sigma,
	}
}

func ProveCred(params *Params, sk *big.Int, issuerkey *IssuerKey, cred *Cred, m *big.Int) (*Proof, error) {

	// 1. r', randomize sigma
	_r, _ := rand.Int(rand.Reader, params.Order)
	_u := new(bn256.G1).ScalarMult(cred.U, _r)
	_s := new(bn256.G1).ScalarMult(cred.Sigma, _r)

	// 2. compute Kappa = r·g2 + alpha + ∑ betaᵢ·mᵢ
	r, _ := rand.Int(rand.Reader, params.Order)
	w := new(bn256.G2).Add(new(bn256.G2).ScalarBaseMult(r), new(bn256.G2).Add(issuerkey.PK1, new(bn256.G2).ScalarMult(issuerkey.PK2, m)))
	w.ScalarMult(w, sk)
	v := new(bn256.G1).ScalarMult(_u, r)

	// 4. 构造 π_v 证明
	piv, _ := MakePiV(params, sk, issuerkey, cred.U, _u, m, r, w, v)

	// 4. output theta
	proof := &Proof{
		W:   w,
		V:   v,
		U:   _u,
		S:   _s,
		PiV: piv,
	}
	return proof, nil
}

func VerifyCred(params *Params, pk1 *bn256.G1, pk2 *bn256.G2, issuerkey *IssuerKey, proof *Proof) (bool, error) {

	//  π_v 证明校验
	result, err := VerifyPiV(params, pk2, proof.U, proof.W, proof.V, proof.PiV)
	if err != nil {
		log.Fatal("proof verification failed:", err)
		if result == false {
			return false, nil
		}
	}
	//fmt.Println("π_v valid:", result)

	// Check h != identity && pairing matches
	if proof.U.String() == new(bn256.G1).ScalarBaseMult(big.NewInt(0)).String() {
		return false, nil
	}

	left1 := bn256.Pair(pk1, issuerkey.PK1)
	right1 := bn256.Pair(params.G1, proof.PiV.Base1)
	if left1.String() != right1.String() {
		return false, nil
	}

	left2 := bn256.Pair(pk1, issuerkey.PK2)
	right2 := bn256.Pair(params.G1, proof.PiV.Base2)
	if left2.String() != right2.String() {
		return false, nil
	}

	left3 := bn256.Pair(proof.U, proof.W)
	right3 := bn256.Pair(new(bn256.G1).Add(proof.S, proof.V), pk2)
	return left3.String() == right3.String(), nil
}
