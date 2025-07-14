package main

import (
	"Obfushop/bn256"
	"Obfushop/crypto/OABE"
	"crypto/rand"
	"fmt"
)

func main() {
	// 系统参数生成
	MSK, PK := OABE.Setup()
	fmt.Printf("PK.GT=%v\n", PK.GT)
	fmt.Printf("TestGT=%v\n", new(bn256.GT).ScalarBaseMult(MSK))

	// 敏感信息加密
	// 随机生成一个秘密
	secret, _ := rand.Int(rand.Reader, bn256.Order)
	m := new(bn256.GT).ScalarBaseMult(secret)
	fmt.Printf("m:%v\n", m)
	// 原始策略表达式
	// policyStr := "(A AND (B OR C)) OR (D AND (t-of-(2,E,F,G)))"
	tau := "(Age>18 AND (Man OR Student)) OR (Computer AND (t-of-(2,China,Sichuan,Teacher)))"
	CT, xsMap := OABE.Encrypt(m, tau, PK)

	// 生成用户属性密钥
	// 左子树满足策略：A + C
	//attrs :=
	// 右子树满足策略：D + E + G
	//attrs := map[string]bool{"D": true, "F": true, "G": true}

	Su := map[string]bool{"Age>18": true, "Man": true}
	var attributeSet []string
	for key, _ := range Su {
		attributeSet = append(attributeSet, key)
	}
	SK := OABE.KeyGen(MSK, PK, attributeSet)

	// 外包解密
	IR := OABE.ODecrypt(Su, CT, SK, xsMap)

	// 用户解密
	_m := OABE.Decrypt(IR, CT, SK, PK, MSK)
	fmt.Printf("_m=%v\n", _m)
	// 验证正确性
	if m.String() == _m.String() {
		fmt.Println("Secret recovery successful.")
	} else {
		fmt.Println("Secret recovery failed.")
	}
}
