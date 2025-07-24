package OABE

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	bn256 "Obfushop/bn256"
)

var FieldOrder = bn256.Order

type NodeType int

const (
	ATTR NodeType = iota
	THRESHOLD
)

type PolicyNode struct {
	Type      NodeType
	Threshold int
	Attribute string
	Children  []*PolicyNode
}

type AttributeShare struct {
	Attribute string
	Share     *big.Int
	X         *big.Int
}

type DecShare struct {
	Attribute string
	Share     *bn256.GT
	X         *big.Int
}

type xsMapType map[*PolicyNode][]*big.Int

// EvaluatePolynomial evaluates a polynomial at x modulo p
func EvaluatePolynomial(coeffs []*big.Int, x *big.Int, p *big.Int) *big.Int {
	result := big.NewInt(0)
	xPower := big.NewInt(1)
	for _, coeff := range coeffs {
		term := new(big.Int).Mul(coeff, xPower)
		term.Mod(term, p)
		result.Add(result, term)
		result.Mod(result, p)
		xPower.Mul(xPower, x)
		xPower.Mod(xPower, p)
	}
	return result
}

// GenerateShares generates shares of a secret using a threshold polynomial
func GenerateShares(secret *big.Int, k int, n int, p *big.Int, startX int) ([]*big.Int, []*big.Int, error) {
	if k > n {
		return nil, nil, errors.New("threshold k must be <= n")
	}
	coeffs := make([]*big.Int, k)
	coeffs[0] = new(big.Int).Set(secret)
	for i := 1; i < k; i++ {
		randCoeff, _ := rand.Int(rand.Reader, p)
		coeffs[i] = randCoeff
	}
	xs := make([]*big.Int, n)
	ys := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(startX + i))
		y := EvaluatePolynomial(coeffs, x, p)
		xs[i] = x
		ys[i] = y
	}
	return xs, ys, nil
}

// LagrangeCoefficients calculates Lagrange interpolation coefficients for given x values modulo p
func LagrangeCoefficients(xList []*big.Int, p *big.Int) map[string]*big.Int {
	coeffs := make(map[string]*big.Int)
	for i, xi := range xList {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j, xj := range xList {
			if i == j {
				continue
			}
			num.Mul(num, new(big.Int).Neg(xj))
			num.Mod(num, p)
			diff := new(big.Int).Sub(xi, xj)
			diff.Mod(diff, p)
			den.Mul(den, diff)
			den.Mod(den, p)
		}
		denInv := new(big.Int).ModInverse(den, p)
		coeff := new(big.Int).Mul(num, denInv)
		coeff.Mod(coeff, p)
		coeffs[xi.String()] = coeff
	}
	return coeffs
}

// ModSub performs modular subtraction (a - b) mod p
func ModSub(a, b, p *big.Int) *big.Int {
	res := new(big.Int).Sub(a, b)
	res.Mod(res, p)
	if res.Sign() < 0 {
		res.Add(res, p)
	}
	return res
}

// RecoverSecretAt recovers the secret using given shares and modulo p (unused in方案A)
func RecoverSecretAt(xs []*big.Int, ys []*big.Int, xRecover *big.Int, p *big.Int) *big.Int {
	secret := big.NewInt(0)
	for i := range xs {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := range xs {
			if i == j {
				continue
			}
			num.Mul(num, ModSub(xRecover, xs[j], p))
			num.Mod(num, p)
			den.Mul(den, ModSub(xs[i], xs[j], p))
			den.Mod(den, p)
		}
		denInv := new(big.Int).ModInverse(den, p)
		if denInv == nil {
			panic("ModInverse returned nil")
		}
		coeff := new(big.Int).Mul(num, denInv)
		coeff.Mod(coeff, p)

		term := new(big.Int).Mul(coeff, ys[i])
		secret.Add(secret, term)
		secret.Mod(secret, p)
	}
	return secret
}

func ComputeShares(secret *big.Int, node *PolicyNode, p *big.Int) ([]AttributeShare, xsMapType, error) {
	var result []AttributeShare
	xsMap := make(xsMapType)
	xGen := NewXGenerator()
	err := computeSharesHelperWithX(secret, node, &result, p, big.NewInt(1), xsMap, xGen)
	return result, xsMap, err
}

// XGenerator 用于生成唯一 startX
type XGenerator struct {
	counter int
}

func NewXGenerator() *XGenerator {
	return &XGenerator{counter: 1}
}

func (gen *XGenerator) Next() int {
	gen.counter += 100 // 每个节点起始值相隔 100，避免交叉
	return gen.counter
}

func computeSharesHelperWithX(secret *big.Int, node *PolicyNode, result *[]AttributeShare, p *big.Int, x *big.Int, xsMap xsMapType, xGen *XGenerator) error {
	if node == nil {
		return nil
	}
	if node.Type == ATTR {
		*result = append(*result, AttributeShare{
			Attribute: node.Attribute,
			X:         new(big.Int).Set(x),
			Share:     new(big.Int).Set(secret),
		})
		return nil
	}

	n := len(node.Children)
	k := node.Threshold

	startX := xGen.Next() // 每一层使用独立 startX 起点
	xs, ys, err := GenerateShares(secret, k, n, p, startX)
	if err != nil {
		return err
	}

	xsMap[node] = make([]*big.Int, n)
	for i := 0; i < n; i++ {
		newX := new(big.Int).Mul(x, xs[i])
		newX.Mod(newX, p)
		xsMap[node][i] = newX
		err := computeSharesHelperWithX(ys[i], node.Children[i], result, p, newX, xsMap, xGen)
		if err != nil {
			return err
		}
	}
	return nil
}

func ParsePolicy(policy string) (*PolicyNode, error) {
	converted, err := ConvertPolicyExpr(policy)
	if err != nil {
		return nil, err
	}
	return parseThresholdExpr(converted)
}

func parseThresholdExpr(s string) (*PolicyNode, error) {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return nil, errors.New("empty policy expression")
	}
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		inner := s[1 : len(s)-1]
		if balancedBrackets(inner) {
			s = inner
		} else {
			break
		}
	}

	if strings.HasPrefix(s, "t-of-(") {
		re := regexp.MustCompile(`t-of-\((\d+),(.+)\)$`)

		matches := re.FindStringSubmatch(s)
		if len(matches) != 3 {
			return nil, fmt.Errorf("invalid threshold format: %s", s)
		}
		k, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid threshold value: %s", matches[1])
		}
		rest := matches[2]
		parts, err := splitTopLevel(rest)
		if err != nil {
			return nil, err
		}
		if k > len(parts) {
			return nil, fmt.Errorf("threshold k (%d) > number of children (%d)", k, len(parts))
		}
		children := []*PolicyNode{}
		for _, part := range parts {
			child, err := parseThresholdExpr(part)
			if err != nil {
				return nil, err
			}
			children = append(children, child)
		}
		return &PolicyNode{
			Type:      THRESHOLD,
			Threshold: k,
			Children:  children,
		}, nil
	}

	return &PolicyNode{Type: ATTR, Attribute: s}, nil
}

func balancedBrackets(s string) bool {
	count := 0
	for _, ch := range s {
		if ch == '(' {
			count++
		} else if ch == ')' {
			count--
			if count < 0 {
				return false
			}
		}
	}
	return count == 0
}

func splitTopLevel(s string) ([]string, error) {
	depth := 0
	parts := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts, nil
}

func PrintPolicyTree(node *PolicyNode, level int) {
	if node == nil {
		return
	}
	indent := strings.Repeat("  ", level)
	switch node.Type {
	case ATTR:
		fmt.Printf("%s- ATTR: %s\n", indent, node.Attribute)
	case THRESHOLD:
		fmt.Printf("%s- THRESHOLD %d-of-%d\n", indent, node.Threshold, len(node.Children))
	}
	for _, child := range node.Children {
		PrintPolicyTree(child, level+1)
	}
}

func ConvertPolicyExpr(s string) (string, error) {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "2-of-", "t-of-")
	return parseExpr(s)
}

func parseExpr(s string) (string, error) {
	if len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' && isSurroundedByParentheses(s) {
		s = s[1 : len(s)-1]
	}

	if strings.HasPrefix(s, "t-of-") {
		re := regexp.MustCompile(`t-of-\((\d+),(.+)\)`)
		matches := re.FindStringSubmatch(s)
		if len(matches) != 3 {
			return "", fmt.Errorf("invalid threshold format: %s", s)
		}
		k := matches[1]
		rest := matches[2]
		parts, err := splitTopLevel(rest)
		if err != nil {
			return "", err
		}
		newParts := []string{}
		for _, p := range parts {
			conv, err := parseExpr(p)
			if err != nil {
				return "", err
			}
			newParts = append(newParts, conv)
		}
		return fmt.Sprintf("t-of-(%s,%s)", k, strings.Join(newParts, ",")), nil
	}

	pos, op := findTopLevelOperator(s)
	if pos == -1 {
		return s, nil
	}

	left := s[:pos]
	right := s[pos+len(op):]

	leftParts, err := splitTopLevel(left)
	if err != nil {
		return "", err
	}
	rightParts, err := splitTopLevel(right)
	if err != nil {
		return "", err
	}

	children := append(leftParts, rightParts...)

	threshold := "1"
	if op == "AND" {
		threshold = fmt.Sprintf("%d", len(children))
	}

	newChildren := []string{}
	for _, c := range children {
		cc, err := parseExpr(c)
		if err != nil {
			return "", err
		}
		newChildren = append(newChildren, cc)
	}

	return fmt.Sprintf("t-of-(%s,%s)", threshold, strings.Join(newChildren, ",")), nil
}

func isSurroundedByParentheses(s string) bool {
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '(' {
			count++
		} else if s[i] == ')' {
			count--
			if count == 0 && i != len(s)-1 {
				return false
			}
		}
	}
	return count == 0
}

func findTopLevelOperator(s string) (pos int, op string) {
	depth := 0
	for i := 0; i <= len(s)-3; i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		default:
			if depth == 0 {
				if len(s[i:]) >= 3 && s[i:i+3] == "AND" {
					return i, "AND"
				}
				if len(s[i:]) >= 2 && s[i:i+2] == "OR" {
					return i, "OR"
				}
			}
		}
	}
	return -1, ""
}

// 计算属性对应的 X (横坐标) 映射，方便后续拉格朗日插值使用
func BuildAttrXMap(shares []AttributeShare) map[string]*big.Int {
	attrX := make(map[string]*big.Int)
	for _, share := range shares {
		attrX[share.Attribute] = share.X
	}
	return attrX
}

// —— 方案A核心函数：不剪枝恢复时计算系数 ——
// GetCoefficientsNoPrune 计算满足属性份额的拉格朗日系数，不剪枝，直接用原始策略树
// ✅ 适用于“不剪枝”的秘密恢复方案 A
// subtreeSatisfiable 判断某个子树是否由满足的属性集构成
func subtreeSatisfiable(node *PolicyNode, attrs map[string]bool) bool {
	if node.Type == ATTR {
		return attrs[node.Attribute]
	}
	count := 0
	for _, c := range node.Children {
		if subtreeSatisfiable(c, attrs) {
			count++
		}
	}
	return count >= node.Threshold
}

// 修复后的：GetCoefficientsNoPrune（带子树可满足性判断）
func GetCoefficientsNoPrune(root *PolicyNode, attrs map[string]bool, attrX map[string]*big.Int, xsMap xsMapType, p *big.Int) map[string]*big.Int {
	coeffs := make(map[string]*big.Int)

	var helper func(node *PolicyNode, coeff *big.Int)
	helper = func(node *PolicyNode, coeff *big.Int) {
		if node.Type == ATTR {
			if attrs[node.Attribute] {
				coeffs[node.Attribute] = new(big.Int).Set(coeff)
			}
			return
		}

		xList := []*big.Int{}
		idxs := []int{}

		// 只选择满足子树策略的子节点
		for i, child := range node.Children {
			if subtreeSatisfiable(child, attrs) {
				xi := xsMap[node][i]
				if xi != nil {
					xList = append(xList, xi)
					idxs = append(idxs, i)
				}
			}
		}

		// 不足阈值，无法恢复
		if len(xList) < node.Threshold {
			return
		}

		lag := LagrangeCoefficients(xList, p)
		for _, i := range idxs {
			xi := xsMap[node][i]
			lc := lag[xi.String()]
			childCoeff := new(big.Int).Mul(coeff, lc)
			childCoeff.Mod(childCoeff, p)
			helper(node.Children[i], childCoeff)
		}
	}

	helper(root, big.NewInt(1))
	return coeffs
}

func findFirstAttrX(node *PolicyNode, attrX map[string]*big.Int) *big.Int {
	if node.Type == ATTR {
		return attrX[node.Attribute]
	}
	for _, c := range node.Children {
		x := findFirstAttrX(c, attrX)
		if x != nil {
			return x
		}
	}
	return nil
}

// containsAttribute 递归检查子树是否包含指定属性
func containsAttribute(node *PolicyNode, attr string) bool {
	if node == nil {
		return false
	}
	if node.Type == ATTR {
		return node.Attribute == attr
	}
	for _, c := range node.Children {
		if containsAttribute(c, attr) {
			return true
		}
	}
	return false
}

// getAnyAttr 从属性系数map中随便取一个属性名
func getAnyAttr(m map[string]*big.Int) string {
	for k := range m {
		return k
	}
	return ""
}

// RecoverSecretDirectly 根据满足的属性份额和拉格朗日系数恢复秘密
func RecoverSecretDirectly(shares []AttributeShare, coeffs map[string]*big.Int, p *big.Int) *big.Int {
	secret := big.NewInt(0)
	for _, share := range shares {
		coeff, ok := coeffs[share.Attribute]
		if !ok {
			continue
		}
		t := new(big.Int).Mul(coeff, share.Share)
		t.Mod(t, p)
		secret.Add(secret, t)
		secret.Mod(secret, p)
	}
	return secret
}

// RecoverSecretDirectly 根据满足的属性份额和拉格朗日系数恢复秘密
// RecoverSecretDirectly 计算通过 GT 群元素恢复的秘密
func RecoverSecret(shares []DecShare, coeffs map[string]*big.Int, p *big.Int) *bn256.GT {
	secret := new(bn256.GT).ScalarBaseMult(big.NewInt(int64(0)))
	for _, share := range shares {
		coeff, _ := coeffs[share.Attribute]
		// if !ok {
		// 	continue
		// }
		//t := new(big.Int).Mul(coeff, share.Share)
		//t.Mod(t, p)
		t := new(bn256.GT).ScalarMult(share.Share, coeff)
		secret = new(bn256.GT).Add(secret, t)
	}
	return secret
}

// CountAttributes 返回策略树中的所有属性，以 string 数组形式
func CountAttributes(node *PolicyNode) []string {
	if node == nil {
		return nil
	}

	// 如果是 ATTR 类型节点，返回属性名的数组
	if node.Type == ATTR {
		return []string{node.Attribute}
	}

	// 否则，递归统计子节点中的属性
	var attributes []string
	for _, child := range node.Children {
		attributes = append(attributes, CountAttributes(child)...)
	}

	return attributes
}

// Contains 返回一个字符串，如果它存在于数组中，否则返回空字符串
func Contains(arr []string, target string) string {
	for _, element := range arr {
		if element == target {
			return target
		}
	}
	return "" // 如果没有找到目标元素，返回空字符串
}
