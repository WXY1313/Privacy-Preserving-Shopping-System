package OABE

import (
	bn256 "Obfushop/bn256"
	"Obfushop/crypto/Convert"
	"crypto/rand"
	"fmt"
	"math/big"
)

type Params struct {
	G1 *bn256.G1
	G2 *bn256.G2
	GT *bn256.GT
}

type AttributeKey struct {
	R        *big.Int
	D        *bn256.G1
	KeyValue map[string]map[*bn256.G1]*bn256.G2
}

type Ciphertext struct {
	S         *big.Int
	Policy    *PolicyNode
	C         *bn256.GT
	_C        *bn256.G2
	NodeValue map[string]map[*big.Int]map[*bn256.G1]*bn256.G2
}

func Setup() (*big.Int, *Params) {
	//Generate public parameters
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	alpha, _ := rand.Int(rand.Reader, bn256.Order)
	gt := new(bn256.GT).ScalarBaseMult(alpha)
	//fmt.Printf("gt=%v\n", gt)

	return alpha, &Params{
		G1: g1,
		G2: g2,
		GT: gt,
	}
}

func KeyGen(MSK *big.Int, PK *Params, Su []string) *AttributeKey {
	r, _ := rand.Int(rand.Reader, bn256.Order)
	rx := make([]*big.Int, len(Su))
	keyValue := make(map[string]map[*bn256.G1]*bn256.G2)

	for i := 0; i < len(Su); i++ {
		rx[i], _ = rand.Int(rand.Reader, bn256.Order)
		dx := new(bn256.G1).Add(new(bn256.G1).ScalarBaseMult(r), new(bn256.G1).ScalarMult(Convert.StringToG1(Su[i]), rx[i]))
		_dx := new(bn256.G2).ScalarBaseMult(rx[i])

		// 确保 keyValue[Su[i]] 已经初始化
		if _, exists := keyValue[Su[i]]; !exists {
			keyValue[Su[i]] = make(map[*bn256.G1]*bn256.G2)
		}

		// 现在可以安全地赋值
		keyValue[Su[i]][dx] = _dx
	}
	d := new(bn256.G1).ScalarBaseMult(new(big.Int).Add(MSK, r))

	return &AttributeKey{
		R:        r,
		D:        d,
		KeyValue: keyValue,
	}
}

func Encrypt(m *bn256.GT, tau string, PK *Params) (*Ciphertext, xsMapType) {
	s, _ := rand.Int(rand.Reader, bn256.Order)
	c := new(bn256.GT).Add(m, new(bn256.GT).ScalarMult(PK.GT, s))
	_c := new(bn256.G2).ScalarMult(PK.G2, s)
	// 解析策略表达式为树
	policy, err := ParsePolicy(tau)
	if err != nil {
		panic("ParsePolicy error: " + err.Error())
	}
	// 打印策略树结构
	PrintPolicyTree(policy, 0)

	//attributeNum := len(CountAttributes(policy))
	fmt.Printf("策略中包含属性:%v\n", CountAttributes(policy))

	// 执行秘密分享
	shares, xsMap, err := ComputeShares(s, policy, FieldOrder)
	if err != nil {
		panic("ComputeShares error: " + err.Error())
	}

	nodeValue := make(map[string]map[*big.Int]map[*bn256.G1]*bn256.G2)
	// 打印所有属性份额
	for i := 0; i < len(shares); i++ {
		s := shares[i] // 通过索引访问元素
		fmt.Printf("%s: X=%v, S=%v\n", s.Attribute, s.X, s.Share)
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
		S:         s,
		Policy:    policy,
		C:         c,
		_C:        _c,
		NodeValue: nodeValue,
	}, xsMap
}

func ODecrypt(attributeSet map[string]bool, CT *Ciphertext, SK *AttributeKey, xsMap xsMapType) *bn256.GT {
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
	fmt.Printf("OABE attrX:%v\n", attrX)

	// 计算拉格朗日系数
	coeffs := GetCoefficientsNoPrune(CT.Policy, attributeSet, attrX, xsMap, FieldOrder)

	fmt.Println("Coeffs:")
	for attr, coeff := range coeffs {
		fmt.Printf("%s -> %v\n", attr, coeff)
	}

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
						// testShare := bn256.Pair(new(bn256.G1).ScalarBaseMult(SK.R), cy)
						// if usedshare.Share.String() == testShare.String() {
						// 	fmt.Printf("测试成功！！！\n")
						// }
					}
				}
			}
		}
	}
	recovered := RecoverSecret(usedShares, coeffs, FieldOrder)
	//testrecovered := bn256.Pair(new(bn256.G1).ScalarBaseMult(SK.R), new(bn256.G2).ScalarBaseMult(CT.S))
	// fmt.Printf("testIR=%v\n", testrecovered)
	// if recovered.String() == testrecovered.String() {
	// 	fmt.Printf("测试成功！！！\n")
	// 	fmt.Printf("IR=%v\n", recovered)
	// }
	return recovered
}

func Decrypt(IR *bn256.GT, CT *Ciphertext, SK *AttributeKey, PK *Params, MSK *big.Int) *bn256.GT {

	//temp := new(bn256.GT).Add(bn256.Pair(SK.D, CT._C), new(bn256.GT).Neg(IR))
	left1 := bn256.Pair(new(bn256.G1).ScalarBaseMult(MSK), new(bn256.G2).ScalarBaseMult(CT.S))
	left2 := bn256.Pair(new(bn256.G1).ScalarBaseMult(SK.R), new(bn256.G2).ScalarBaseMult(CT.S))
	left := new(bn256.GT).Add(left1, left2)
	ir := bn256.Pair(new(bn256.G1).ScalarBaseMult(SK.R), new(bn256.G2).ScalarBaseMult(CT.S))
	//temp := new(bn256.GT).Add(bn256.Pair(SK.D, CT._C), new(bn256.GT).Neg(IR))
	temp := new(bn256.GT).Add(left, new(bn256.GT).Neg(ir))
	//testTemp := new(bn256.GT).ScalarMult(PK.GT, CT.S)
	//testTemp := new(bn256.GT).ScalarMult(new(bn256.GT).ScalarBaseMult(MSK), CT.S)
	fmt.Printf("MSK=%v\n", MSK)

	if PK.GT.String() == new(bn256.GT).ScalarBaseMult(MSK).String() {
		fmt.Printf("测试成功！！！\n")
	}
	m := new(bn256.GT).Add(CT.C, new(bn256.GT).Neg(temp))
	return m
}
