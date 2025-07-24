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

type PiV struct {
	Base1 *bn256.G2
	Base2 *bn256.G2
	RG    *bn256.G2
	RH    *bn256.G1
	C     *big.Int // challenge
	Rm    *big.Int // 响应属性
	Rr    *big.Int // 响应随机数 t
}

type Pi_r struct {
	C  *big.Int // challenge
	Z  *big.Int // 响应随机数 t
	RG *bn256.G1
	RH *bn256.G1
}

func ToChallenge(elements []*bn256.G1) *big.Int {
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

func MakePiS(params *Params, gamma *bn256.G1, ciphertext []*bn256.G1, cm *bn256.G1,
	k *big.Int, o *big.Int, m *big.Int) (*PiS, error) {

	// 1. Generate random witnesses
	wo, _ := rand.Int(rand.Reader, params.Order)
	wk, _ := rand.Int(rand.Reader, params.Order)
	wm, _ := rand.Int(rand.Reader, params.Order)

	// 2. h = HashG1(cm)
	u, _ := bn256.HashG1(string(cm.Marshal()))

	// 3. Compute Aw = g1^wk[i]
	Aw := new(bn256.G1).ScalarMult(params.G1, wk)

	// 4. Compute Bw[i] = gamma^wk * h^wm
	Bw := new(bn256.G1).Add(new(bn256.G1).ScalarMult(gamma, wk), new(bn256.G1).ScalarMult(u, wm))

	// 5. Compute Cw = g1^wr * h_1^wm_1
	Cw := new(bn256.G1).Add(new(bn256.G1).ScalarMult(params.G1, wo), new(bn256.G1).ScalarMult(params.H1, wm))

	// 6. Compute challenge
	toHash := []*bn256.G1{cm, u, Aw, Bw, Cw}
	c := ToChallenge(toHash)

	// 7. Responses
	ro := new(big.Int).Sub(wo, new(big.Int).Mul(c, o))
	ro.Mod(ro, params.Order)

	rk := new(big.Int).Sub(wk, new(big.Int).Mul(c, k))
	rk.Mod(rk, params.Order)

	rm := new(big.Int).Sub(wm, new(big.Int).Mul(c, m))
	rm.Mod(rm, params.Order)

	return &PiS{C: c, Rk: rk, Rm: rm, Ro: ro}, nil
}

func VerifyPiS(params *Params, gamma *bn256.G1, ciphertext []*bn256.G1, cm *bn256.G1, proof *PiS) (bool, error) {

	// 1. h = HashG1(cm)
	u, _ := bn256.HashG1(string(cm.Marshal()))

	// 2. Recompute Aw, Bw
	a := ciphertext[0]
	b := ciphertext[1]

	Aw := new(bn256.G1).Add(new(bn256.G1).ScalarMult(a, proof.C), new(bn256.G1).ScalarMult(params.G1, proof.Rk))

	part := new(bn256.G1).Add(new(bn256.G1).ScalarMult(gamma, proof.Rk), new(bn256.G1).ScalarMult(u, proof.Rm))

	Bw := new(bn256.G1).Add(new(bn256.G1).ScalarMult(b, proof.C), part)

	// 3. Recompute Cw
	Cw := new(bn256.G1).Add(new(bn256.G1).ScalarMult(cm, proof.C), new(bn256.G1).ScalarMult(params.G1, proof.Ro))
	Cw.Add(Cw, new(bn256.G1).ScalarMult(params.H1, proof.Rm))

	// 4. Recompute challenge
	toHash := []*bn256.G1{cm, u, Aw, Bw, Cw}
	cPrime := ToChallenge(toHash)

	return cPrime.Cmp(proof.C) == 0, nil
}

func MakePiV(params *Params, sk *big.Int, issuerkey *IssuerKey, u, _u *bn256.G1, m *big.Int, r *big.Int, w *bn256.G2, v *bn256.G1) (*PiV, error) {

	base1 := new(bn256.G2).ScalarMult(issuerkey.PK1, sk)
	base2 := new(bn256.G2).ScalarMult(issuerkey.PK2, sk)
	// 1. 生成随机性
	wm, _ := rand.Int(rand.Reader, params.Order)
	wr, _ := rand.Int(rand.Reader, params.Order)

	// 2. 计算 Aw = wt·g2 + α + ∑ wmᵢ·βᵢ
	Aw := new(bn256.G2).Add(new(bn256.G2).ScalarMult(params.G2, wr), issuerkey.PK1)
	Aw.Add(Aw, new(bn256.G2).ScalarMult(issuerkey.PK2, wm))
	Aw.ScalarMult(Aw, sk)

	// 3. Bw = wt·h'
	Bw := new(bn256.G1).ScalarMult(_u, wr)

	// 4. 构造挑战 c
	g1Inputs := []*bn256.G1{_u, v, Bw}
	g2Inputs := []*bn256.G2{w, Aw}
	c := ToChallengeMixed(g1Inputs, g2Inputs)

	// 5. 响应 rm=wm-c*mi
	rm := new(big.Int).Sub(wm, new(big.Int).Mul(c, m))
	rm.Mod(rm, params.Order)

	rr := new(big.Int).Sub(wr, new(big.Int).Mul(c, r))
	rr.Mod(rr, params.Order)

	return &PiV{Base1: base1, Base2: base2, RG: Aw, RH: Bw, C: c, Rm: rm, Rr: rr}, nil
}

func VerifyPiV(pk *bn256.G2, _u *bn256.G1, w *bn256.G2, v *bn256.G1, proof *PiV) bool {

	// 1. Aw' = c·kappa + rt·g2 + (1 - c)·α + ∑ rmᵢ·βᵢ
	Aw := new(bn256.G2).ScalarMult(w, proof.C)
	Aw.Add(Aw, new(bn256.G2).ScalarMult(pk, proof.Rr)) //pk^r

	Aw.Add(Aw, proof.Base1)                                                       //pk^x
	Aw.Add(Aw, new(bn256.G2).Neg(new(bn256.G2).ScalarMult(proof.Base1, proof.C))) //pk^{-cx}
	Aw.Add(Aw, new(bn256.G2).ScalarMult(proof.Base2, proof.Rm))                   //pk^{y(wm-cm)}

	// 2. Bw = c·nu + rt·h'
	Bw := new(bn256.G1).ScalarMult(v, proof.C)
	Bw.Add(Bw, new(bn256.G1).ScalarMult(_u, proof.Rr))

	if Aw.String() == proof.RG.String() && Bw.String() == proof.RH.String() {
		return true
	}

	return false
}

func MakePi_r(params *Params, _c, pk1 *bn256.G1, _r *big.Int, v *bn256.G1, c *bn256.G1) (*Pi_r, error) {

	//生成承诺
	k, err := rand.Int(rand.Reader, params.Order)
	if err != nil {
		return nil, err
	}
	rG := new(bn256.G1).ScalarMult(_c, k)
	rH := new(bn256.G1).ScalarMult(pk1, k)

	// 计算挑战
	new_hash := sha256.New()
	new_hash.Write(v.Marshal())
	new_hash.Write(c.Marshal())
	new_hash.Write(rG.Marshal())
	new_hash.Write(rH.Marshal())

	cb := new_hash.Sum(nil)
	challenge := new(big.Int).SetBytes(cb)
	challenge.Mod(challenge, params.Order)

	// 生成相应
	response := new(big.Int).Mul(challenge, _r)
	response.Sub(k, response)
	response.Mod(response, params.Order)

	return &Pi_r{C: challenge, Z: response, RG: rG, RH: rH}, nil
}

func VerifyPi_r(params *Params, _c, pk1 *bn256.G1, v *bn256.G1, c *bn256.G1, Pi *Pi_r) bool {

	zG := new(bn256.G1).ScalarMult(_c, Pi.Z)
	zH := new(bn256.G1).ScalarMult(pk1, Pi.Z)
	cxG := new(bn256.G1).ScalarMult(v, Pi.C)
	cxH := new(bn256.G1).ScalarMult(c, Pi.C)
	a := new(bn256.G1).Add(zG, cxG)
	b := new(bn256.G1).Add(zH, cxH)
	if !(Pi.RG.String() == a.String() && Pi.RH.String() == b.String()) {
		return false
	}
	return true
}
