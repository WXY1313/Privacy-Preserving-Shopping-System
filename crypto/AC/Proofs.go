package AC

import (
	"Obfushop/bn256"
	//"Obfushop/crypto/RDKG"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type PiS struct {
	C  *big.Int // challenge
	Rk *big.Int // responses for k
	Rm *big.Int // responses for m
	Ro *big.Int // response for r
}

type DL struct {
	C  *big.Int  // challenge
	Z  *big.Int  // responses for k
	RG *bn256.G1 // responses for m
}

func ToChallenge(elements []*bn256.G2) *big.Int {
	hasher := sha256.New()
	for _, e := range elements {
		hasher.Write(e.Marshal())
	}
	return new(big.Int).SetBytes(hasher.Sum(nil))
}

func ToChallengeMixed(g1s []*bn256.G1, g2s []*bn256.G2) *big.Int {
	hasher := sha256.New()
	for _, g := range g1s {
		hasher.Write(g.Marshal())
	}
	for _, g := range g2s {
		hasher.Write(g.Marshal())
	}
	return new(big.Int).SetBytes(hasher.Sum(nil))
}

func MakePiS(params *Params, gamma *bn256.G2, ciphertext []*bn256.G2, cm *bn256.G1,
	k *big.Int, o *big.Int, m *big.Int) (*PiS, error) {

	// 1. Generate random witnesses
	wo, _ := rand.Int(rand.Reader, params.Order)
	wk, _ := rand.Int(rand.Reader, params.Order)
	wm, _ := rand.Int(rand.Reader, params.Order)

	// 2. h = HashG1(cm)
	u, _ := bn256.HashG2(string(cm.Marshal()))

	// 3. Compute Aw = g1^wk[i]
	Aw := new(bn256.G2).ScalarMult(params.G2, wk)

	// 4. Compute Bw[i] = gamma^wk * h^wm
	Bw := new(bn256.G2).Add(new(bn256.G2).ScalarMult(gamma, wk), new(bn256.G2).ScalarMult(u, wm))

	// 5. Compute Cw = g1^wr * h_1^wm_1
	Cw := new(bn256.G1).Add(new(bn256.G1).ScalarMult(params.G1, wo), new(bn256.G1).ScalarMult(params.H1, wm))

	// 6. Compute challenge
	toHashG1 := []*bn256.G1{cm, Cw}
	toHashG2 := []*bn256.G2{u, Aw, Bw}
	c := ToChallengeMixed(toHashG1, toHashG2)

	// 7. Responses
	ro := new(big.Int).Sub(wo, new(big.Int).Mul(c, o))
	ro.Mod(ro, params.Order)

	rk := new(big.Int).Sub(wk, new(big.Int).Mul(c, k))
	rk.Mod(rk, params.Order)

	rm := new(big.Int).Sub(wm, new(big.Int).Mul(c, m))
	rm.Mod(rm, params.Order)

	return &PiS{C: c, Rk: rk, Rm: rm, Ro: ro}, nil
}

func VerifyPiS(params *Params, gamma *bn256.G2, ciphertext []*bn256.G2, cm *bn256.G1, proof *PiS) (bool, error) {

	// 1. h = HashG1(cm)
	u, _ := bn256.HashG2(string(cm.Marshal()))

	// 2. Recompute Aw, Bw
	a := ciphertext[0]
	b := ciphertext[1]

	Aw := new(bn256.G2).Add(new(bn256.G2).ScalarMult(a, proof.C), new(bn256.G2).ScalarMult(params.G2, proof.Rk))

	part := new(bn256.G2).Add(new(bn256.G2).ScalarMult(gamma, proof.Rk), new(bn256.G2).ScalarMult(u, proof.Rm))

	Bw := new(bn256.G2).Add(new(bn256.G2).ScalarMult(b, proof.C), part)

	// 3. Recompute Cw
	Cw := new(bn256.G1).Add(new(bn256.G1).ScalarMult(cm, proof.C), new(bn256.G1).ScalarMult(params.G1, proof.Ro))
	Cw.Add(Cw, new(bn256.G1).ScalarMult(params.H1, proof.Rm))

	// 4. Recompute challenge
	toHashG1 := []*bn256.G1{cm, Cw}
	toHashG2 := []*bn256.G2{u, Aw, Bw}
	cPrime := ToChallengeMixed(toHashG1, toHashG2)

	return cPrime.Cmp(proof.C) == 0, nil
}

func DLProof(G *bn256.G1, xG *bn256.G1, x *big.Int) *DL {
	//生成承诺
	r, _ := rand.Int(rand.Reader, bn256.Order)
	rG := new(bn256.G1).ScalarMult(G, r)

	// 计算挑战
	new_hash := sha256.New()
	new_hash.Write(xG.Marshal())
	new_hash.Write(rG.Marshal())

	cb := new_hash.Sum(nil)
	c := new(big.Int).SetBytes(cb)
	c.Mod(c, bn256.Order)

	// 生成相应
	z := new(big.Int).Mul(c, x)
	z.Sub(r, z)
	z.Mod(z, bn256.Order)

	return &DL{C: c, Z: z, RG: rG}
}

// Verify verifies the DLEQ proof
func VerifyDL(c, z *big.Int, G, xG, rG *bn256.G1) bool {
	zG := new(bn256.G1).ScalarMult(G, z)
	cxG := new(bn256.G1).ScalarMult(xG, c)
	a := new(bn256.G1).Add(zG, cxG)
	if !(rG.String() == a.String()) {
		return false
	}
	return true
}

// func DLEQProof(params *Params, _g1, _g2, _g3 *bn256.G1, _x *big.Int, _xG1, _xG2, _xG3 *bn256.G1) (*DLEQ, error) {

// 	//生成承诺
// 	k, err := rand.Int(rand.Reader, params.Order)
// 	if err != nil {
// 		return nil, err
// 	}
// 	kG1 := new(bn256.G1).ScalarMult(_g1, k)
// 	kG2 := new(bn256.G1).ScalarMult(_g2, k)
// 	kG3 := new(bn256.G1).ScalarMult(_g3, k)

// 	// 计算挑战
// 	new_hash := sha256.New()
// 	new_hash.Write(_xG1.Marshal())
// 	new_hash.Write(_xG2.Marshal())
// 	new_hash.Write(_xG3.Marshal())
// 	new_hash.Write(kG1.Marshal())
// 	new_hash.Write(kG2.Marshal())
// 	new_hash.Write(kG3.Marshal())

// 	cb := new_hash.Sum(nil)
// 	challenge := new(big.Int).SetBytes(cb)
// 	challenge.Mod(challenge, params.Order)

// 	// 生成相应
// 	response := new(big.Int).Mul(challenge, _x)
// 	response.Sub(k, response)
// 	response.Mod(response, params.Order)

// 	return &DLEQ{C: challenge, Z: response, RG1: kG1, RG2: kG2, RG3: kG3}, nil
// }

// func VerifyDLEQ(params *Params, _g1, _g2, _g3 *bn256.G1, _xG1, _xG2, _xG3 *bn256.G1, Pi *DLEQ) bool {

// 	zG1 := new(bn256.G1).ScalarMult(_g1, Pi.Z)
// 	zG2 := new(bn256.G1).ScalarMult(_g2, Pi.Z)
// 	zG3 := new(bn256.G1).ScalarMult(_g3, Pi.Z)
// 	cxG1 := new(bn256.G1).ScalarMult(_xG1, Pi.C)
// 	cxG2 := new(bn256.G1).ScalarMult(_xG2, Pi.C)
// 	cxG3 := new(bn256.G1).ScalarMult(_xG3, Pi.C)
// 	a := new(bn256.G1).Add(zG1, cxG1)
// 	b := new(bn256.G1).Add(zG2, cxG2)
// 	c := new(bn256.G1).Add(zG3, cxG3)
// 	if !(Pi.RG1.String() == a.String() && Pi.RG2.String() == b.String() && Pi.RG3.String() == c.String()) {
// 		return false
// 	}
// 	return true
// }
