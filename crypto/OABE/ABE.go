package OABE

import (
	bn256 "Obfushop/bn256"
	"Obfushop/crypto/Convert"
	"crypto/rand"
	"math/big"
)

type Params struct {
	G1 *bn256.G1
	G2 *bn256.G2
	GT *bn256.GT
}

type AttributeKey struct {
	D        *bn256.G1
	KeyValue map[string]map[*bn256.G1]*bn256.G2
}

type Ciphertext struct {
	Policy    *PolicyNode
	C         *bn256.GT
	CC        *bn256.G2
	NodeValue map[string]map[*big.Int]map[*bn256.G1]*bn256.G2
}

func Setup() (*big.Int, *Params) {
	//Generate public parameters
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	alpha, _ := rand.Int(rand.Reader, bn256.Order)
	gt := new(bn256.GT).ScalarMult(bn256.Pair(g1, g2), alpha)
	return alpha, &Params{
		G1: g1,
		G2: g2,
		GT: gt,
	}
}

func KeyGen(PKu *bn256.G1, MSK *big.Int, PK *Params, Su []string) *AttributeKey {
	r, _ := rand.Int(rand.Reader, bn256.Order)
	rx := make([]*big.Int, len(Su))
	keyValue := make(map[string]map[*bn256.G1]*bn256.G2)

	for i := 0; i < len(Su); i++ {
		rx[i], _ = rand.Int(rand.Reader, bn256.Order)
		dx := new(bn256.G1).Add(new(bn256.G1).ScalarMult(PKu, r), new(bn256.G1).ScalarMult(Convert.StringToG1(Su[i]), rx[i]))
		_dx := new(bn256.G2).ScalarMult(PK.G2, rx[i])

		// 确保 keyValue[Su[i]] 已经初始化
		if _, exists := keyValue[Su[i]]; !exists {
			keyValue[Su[i]] = make(map[*bn256.G1]*bn256.G2)
		}

		// 现在可以安全地赋值
		keyValue[Su[i]][dx] = _dx
	}
	d := new(bn256.G1).ScalarMult(PKu, new(big.Int).Add(MSK, r))

	return &AttributeKey{
		D:        d,
		KeyValue: keyValue,
	}
}

func Encrypt(m *bn256.GT, tau string, PK *Params) (*Ciphertext, xsMapType, *bn256.GT, *big.Int) {
	s, _ := rand.Int(rand.Reader, bn256.Order)
	c := new(bn256.GT).Add(m, new(bn256.GT).ScalarMult(PK.GT, s))
	_c := new(bn256.G2).ScalarMult(PK.G2, s)
	// 解析策略表达式为树
	policy, err := ParsePolicy(tau)
	if err != nil {
		panic("ParsePolicy error: " + err.Error())
	}
	// 打印策略树结构
	//PrintPolicyTree(policy, 0)

	//attributeNum := len(CountAttributes(policy))
	//fmt.Printf("策略中包含属性:%v\n", CountAttributes(policy))

	// 执行秘密分享
	shares, xsMap, err := ComputeShares(s, policy, FieldOrder)
	if err != nil {
		panic("ComputeShares error: " + err.Error())
	}

	nodeValue := make(map[string]map[*big.Int]map[*bn256.G1]*bn256.G2)
	// 打印所有属性份额
	for i := 0; i < len(shares); i++ {
		s := shares[i] // 通过索引访问元素
		//fmt.Printf("%s: X=%v, S=%v\n", s.Attribute, s.X, s.Share)
		cy := new(bn256.G2).ScalarMult(PK.G2, s.Share)
		_cy := new(bn256.G1).ScalarMult(Convert.StringToG1(s.Attribute), s.Share)
		// 初始化嵌套的 map
		if _, exists := nodeValue[s.Attribute]; !exists {
			nodeValue[s.Attribute] = make(map[*big.Int]map[*bn256.G1]*bn256.G2)
		}
		if _, exists := nodeValue[s.Attribute][s.X]; !exists {
			nodeValue[s.Attribute][s.X] = make(map[*bn256.G1]*bn256.G2)
		}
		// 现在可以安全地赋值
		nodeValue[s.Attribute][s.X][_cy] = cy
	}

	return &Ciphertext{
		Policy:    policy,
		C:         c,
		CC:        _c,
		NodeValue: nodeValue,
	}, xsMap, new(bn256.GT).ScalarMult(PK.GT, s), s
}

func ODecrypt(attributeSet map[string]bool, CT *Ciphertext, SK *AttributeKey, xsMap xsMapType, PK *Params) *bn256.GT {
	// ======== 切换不同属性集，验证左右子树恢复 ========
	// 左子树满足策略：A + C
	//attrs := map[string]bool{"Age>18": true, "Man": true}
	// 右子树满足策略：D + E + G
	//attrs := map[string]bool{"D": true, "F": true, "G": true}

	attributePolicy := CountAttributes(CT.Policy)
	//attrs := map[string]bool{}
	//提取所给属性集中满足策略树的属性
	// for i := 0; i < len(attributeSet); i++ {
	// 	if Contains(attributePolicy, attributeSet[i]) != "" {
	// 		attrs[attributeSet[i]] = true
	// 	}
	// }
	// fmt.Printf("满足策略的属性有：:%v\n", attrs)

	// 构造 attrX 映射
	attrX := make(map[string]*big.Int)
	for attr, s := range CT.NodeValue {
		if attributeSet[attr] {
			for x, _ := range s {
				attrX[attr] = x

			}
		}
	}
	//fmt.Printf("OABE attrX:%v\n", attrX)

	// 计算拉格朗日系数
	coeffs := GetCoefficientsNoPrune(CT.Policy, attributeSet, attrX, xsMap, FieldOrder)

	// for attr, coeff := range coeffs {
	// 	fmt.Printf("%s -> %v\n", attr, coeff)
	// }

	// 根据属性份额和系数恢复秘密
	var usedShares []DecShare
	for attr, keyValue := range SK.KeyValue {
		var usedshare DecShare
		if Contains(attributePolicy, attr) != "" {
			usedshare.Attribute = attr
			for x, cyValue := range CT.NodeValue[attr] {
				usedshare.X = x
				for _cy, cy := range cyValue {
					for dx, _dx := range keyValue {
						left := bn256.Pair(dx, cy)
						right := bn256.Pair(_cy, _dx)
						usedshare.Share = new(bn256.GT).Add(left, new(bn256.GT).Neg(right))
						usedShares = append(usedShares, usedshare)
					}
				}
			}
		}
	}
	temp := RecoverSecret(usedShares, coeffs, FieldOrder)
	recovered := new(bn256.GT).Add(bn256.Pair(SK.D, CT.CC), new(bn256.GT).Neg(temp))
	return recovered
}

func Decrypt(IR *bn256.GT, SKu *big.Int, CT *Ciphertext) *bn256.GT {
	invSKu := new(big.Int).ModInverse(SKu, FieldOrder) // 先创建新变量存储逆元
	temp := new(bn256.GT).ScalarMult(IR, invSKu)
	m := new(bn256.GT).Add(CT.C, new(bn256.GT).Neg(temp))
	return m
}

func BSWDecrypt(attributeSet map[string]bool, CT *Ciphertext, SK *AttributeKey, xsMap xsMapType, PK *Params) *bn256.GT {

	attributePolicy := CountAttributes(CT.Policy)
	// 构造 attrX 映射
	attrX := make(map[string]*big.Int)
	for attr, s := range CT.NodeValue {
		if attributeSet[attr] {
			for x, _ := range s {
				attrX[attr] = x
			}
		}
	}
	// 计算拉格朗日系数
	coeffs := GetCoefficientsNoPrune(CT.Policy, attributeSet, attrX, xsMap, FieldOrder)
	// 根据属性份额和系数恢复秘密
	var usedShares []DecShare
	for attr, keyValue := range SK.KeyValue {
		var usedshare DecShare
		if Contains(attributePolicy, attr) != "" {
			usedshare.Attribute = attr
			for x, cyValue := range CT.NodeValue[attr] {
				usedshare.X = x
				for _cy, cy := range cyValue {
					for dx, _dx := range keyValue {
						left := bn256.Pair(dx, cy)
						right := bn256.Pair(_cy, _dx)
						usedshare.Share = new(bn256.GT).Add(left, new(bn256.GT).Neg(right))
						usedShares = append(usedShares, usedshare)
					}
				}
			}
		}
	}
	temp := RecoverSecret(usedShares, coeffs, FieldOrder)
	recovered := new(bn256.GT).Add(bn256.Pair(SK.D, CT.CC), new(bn256.GT).Neg(temp))
	m := new(bn256.GT).Add(CT.C, new(bn256.GT).Neg(recovered))
	return m
}
