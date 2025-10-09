// SPDX-License-Identifier: UNLICENSED
//pragma experimental ABIEncoderV2;
pragma solidity ^0.8.0;

contract BC_SID {
    // p = p(u) = 36u^4 + 36u^3 + 24u^2 + 6u + 1
    uint256 constant FIELD_ORDER = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // Number of elements in the field (often called `q`)
    // n = n(u) = 36u^4 + 36u^3 + 18u^2 + 6u + 1
    uint256 constant GEN_ORDER = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 constant CURVE_B = 3;

    // a = (p+1) / 4
    uint256 constant CURVE_A = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }


    // 比较 proof.U 是否为 G2 群的单位元
    function isG2Zero(G2Point memory point2) public view returns (bool) {
        // 比较 proof.U 的 X 和 Y 是否都为单位元
        uint256[2] memory G2_ZERO_X = [uint256(0), uint256(0)];
        uint256[2] memory G2_ZERO_Y = [uint256(0), uint256(0)];
        if (point2.X[0] == G2_ZERO_X[0] && point2.X[1] == G2_ZERO_X[1] && 
            point2.Y[0] == G2_ZERO_Y[0] && point2.Y[1] == G2_ZERO_Y[1]) {
            return true; // 等于单位元
        }
        return false; // 不等于单位元
    }


    //G1相关运算

    /// return the sum of two points of G1
    function g1add(G1Point memory p1, G1Point memory p2) view internal returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly("memory-safe") {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        // Use "invalid" to make gas estimation work
        //switch success case 0 { invalid }
        }
        require(success);
    }

    /// return the product of a point on G1 and a scalar, i.e.
    /// p == p.mul(1) and p.add(p) == p.mul(2) for all points p.
    function g1mul(G1Point memory p, uint256 s) view internal returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly("memory-safe") {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        // Use "invalid" to make gas estimation work
        //switch success case 0 { invalid }
        }
        require (success);
    }

    function g1neg(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }


  

    function DLVerify(G1Point memory g1, G1Point memory y1, G1Point memory a1, 
                       uint256 c, uint256 z) public payable returns (bool)
    {
        G1Point memory g1G = g1mul(g1, z);
        G1Point memory y1G = g1mul(y1, c);
        G1Point memory pt1 =  g1add(g1G, y1G);
        if ((a1.X != pt1.X) || (a1.Y != pt1.Y))
        {
            return false;
        }
        return true;
    }

    /// return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) view internal returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint[1] memory out;
        bool success;
        assembly("memory-safe") {
            success := staticcall(sub(gas()	, 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        // Use "invalid" to make gas estimation work
        //switch success case 0 { invalid }
        }
        require(success);
        return out[0] != 0;
    }

    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) view internal returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }


    //映射相关运算
    // 将G1Point转换为映射使用的key
    function GetPointKey(G1Point memory pk) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(pk.X, pk.Y));
    }
    // 添加映射项
    function AddMapping(G1Point memory pk, string memory attribute) public {
        bytes32 key = GetPointKey(pk);
        SID[key]=attribute;
    }
    // 获取对应字符串数组
    function GetMapping(G1Point memory pk) public view returns (string memory) {
        return SID[GetPointKey(pk)];
    }

    // Function to convert a string to uint256 using keccak256 hash
    function stringToUint256(string memory attribute) public pure returns (uint256) {
        // 使用 sha256 计算哈希
        bytes32 hash = sha256(abi.encodePacked(attribute));
        // 将 bytes32 转换为 uint256 并返回
        return uint256(hash);
    }

    mapping(bytes32 => string) public SID;
    mapping(bytes32 => string[])public SIDSet;
    G1Point G1;
    G2Point G2;
    G1Point[2] IssuerKey;

    //Upload issuer's key
    function UploadACsParams(G1Point memory _g1,G2Point memory _g2,G1Point memory _pkx, G1Point memory _pky) public {
        G1=_g1;
        G2=_g2;
        IssuerKey[0]=_pkx;
        IssuerKey[1]=_pky;
    }

    function RegisterSID(G1Point memory _pk1,G1Point memory _a1, uint256 _c, uint256 _z, G2Point memory _u, G2Point memory _s, uint256 _m,string memory _attr) public returns (bool) 
    {
        if(isG2Zero(_u)||_m!=stringToUint256(_attr))
        {
            return false;
        }
        if(!DLVerify(G1, _pk1 , _a1, _c, _z)){
            return false;
        }
        if(pairingProd2(g1add(IssuerKey[0], g1mul(IssuerKey[1], _m)), _u, g1neg(_pk1), _s)){
            SID[GetPointKey(_pk1)]=_attr;
        }
        return true;
    }


    function getSID(G1Point memory pk) public view returns (string memory) {
        return SID[GetPointKey(pk)];
    }
    
    function RegisterSIDSet(G1Point memory _pk1,G1Point memory _a1, uint256 _c, uint256 _z,G2Point[] memory _u, G2Point[] memory _s,string[] memory _attr) public returns (bool) 
    {
        string[] memory sidSet = new string[](_attr.length);
        uint256[] memory m = new uint256[](_attr.length);
        if(!DLVerify(G1, _pk1 , _a1, _c, _z)){
            return false;
        }

        for (uint i=0;i<_u.length;i++){
            if(isG2Zero(_u[i]))
            {
                return false;
            }
            m[i]=stringToUint256(_attr[i]);
            if(pairingProd2(g1add(IssuerKey[0], g1mul(IssuerKey[1], m[i])), _u[i], g1neg(_pk1), _s[i])){
                sidSet[i]=_attr[i];
            }
        }
        SIDSet[GetPointKey(_pk1)]=sidSet;
        return true;
    }


    function getSIDSet(G1Point memory pk) public view returns (string[] memory) {
        return SIDSet[GetPointKey(pk)];
    }

    function CheckClaim(G1Point memory pk, string memory attribute) public view returns (bool) {
        bytes32 key = GetPointKey(pk);
        for (uint i=0;i<SIDSet[key].length;i++){
            if (keccak256(abi.encodePacked(SIDSet[key][i])) == keccak256(abi.encodePacked(attribute))){
                return true;
            }
        }
        return false;
        //return keccak256(abi.encodePacked(SID[key])) == keccak256(abi.encodePacked(attribute));
    }



    //Shopping Order
    struct Purchase {
        string productID;
        uint256 quantity;
        uint256 price;  //gwei
        string orderID;
        uint256 lockedAmount;
        G1Point buyerPubKey;
        bool isOngoing;
        bool isLocked;
        bool isBuyerConfirm;
    }

    mapping(address => mapping(string => uint256)) public productPrices;

    // orderBook[seller][buyer] => Purchase
    // 改为三级映射，支持多个订单
    mapping(address => mapping(address => mapping(string => Purchase))) public orderBook;
    mapping(address => uint256) balances; //stores the Eth balances of sellers

    event BroadcastPubKey(
        address indexed _seller,
        address indexed _buyer,
        string productID,
        uint256 quantity,
        uint256 buyerPubKeyX,
        uint256 buyerPubKeyY,
        uint256 totalPrice,
        string orderID);

    event SellerAccepted(
    address indexed seller,
    address indexed buyer,
    string orderID);

    event SellerGetPayment(
    address indexed seller,
    address indexed buyer,
    string orderID,
    uint256 payment);

    //卖家设置商品价格函数
    function setProductPrice(string memory productID, uint256 unitPrice) public {
        require(unitPrice > 0, "Unit price must be greater than zero");
        productPrices[msg.sender][productID] = unitPrice;
    }
    //买家获得商品价格
    function GetProduct(address _addr, string memory _productID) public view returns (uint256){
        return productPrices[_addr][_productID];
    }

    //使用block信息和地址hash生成 orderID 
    function _generateOrderID(address buyer) internal view returns (string memory) {
        bytes32 raw = keccak256(abi.encodePacked(block.timestamp, buyer, msg.sender, blockhash(block.number - 1)));
            return toHexString(raw);
    }

    function toHexString(bytes32 data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint i = 0; i < 32; i++) {
            str[i*2] = hexChars[uint8(data[i] >> 4)];
            str[1+i*2] = hexChars[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    // 买家创建订单，生成唯一orderID，返回给买家
    function buyerCreateOrder(
        address _seller,
        string memory _productID,
        uint256 _quantity,
        G1Point memory _buyerPK) public payable returns (string memory)
    {
        require(_quantity > 0, "Quantity must be positive");
        uint256 unitPrice = productPrices[_seller][_productID];
        require(unitPrice > 0, "Product not found");

        uint256 totalPrice = unitPrice * _quantity;
        require(msg.value == totalPrice, "Incorrect ETH sent");

        string memory _orderID = _generateOrderID(msg.sender);
        Purchase storage existing = orderBook[_seller][msg.sender][_orderID];
        require(!existing.isOngoing, "Order already exists");

        orderBook[_seller][msg.sender][_orderID] = Purchase({
            productID: _productID,
            quantity: _quantity,
            price: totalPrice,
            orderID: _orderID,
            lockedAmount: msg.value,
            buyerPubKey: _buyerPK,
            isOngoing: false,
            isLocked: true,
            isBuyerConfirm: false
        });

        emit BroadcastPubKey(
            _seller,
            msg.sender,
            _productID,
            _quantity,
            _buyerPK.X,
            _buyerPK.Y,
            totalPrice,
            _orderID
        );
        return _orderID;
    }
    
    // 卖家确认订单，需传orderID
    function sellerAcceptOrder(
        address _buyer,
        string memory _orderID,
        string memory attribute
    ) public {
        Purchase storage order = orderBook[msg.sender][_buyer][_orderID];
        require(order.isLocked, "Funds not locked");

        bool checkPassed = CheckClaim(order.buyerPubKey, attribute);
        if (!checkPassed) {
            uint256 refundAmount = order.price;
            delete orderBook[msg.sender][_buyer][_orderID];
            (bool success, ) = payable(_buyer).call{value: refundAmount}("");
            require(success, "Refund failed");
            return;
        }
        order.isOngoing = true;
        // orderID字段可保持不变或更新为确认时生成的ID
        emit SellerAccepted(msg.sender, _buyer, _orderID);
    }

    //买家确认交易成功（如收到商品）
    event OrderCompleted(address indexed buyer, address indexed seller, uint256 amount);
    function GetConfirmResult(address _sellerAddr, address _buyerAddr, string memory _orderID) public view returns (bool){
        return orderBook[_sellerAddr][_buyerAddr][_orderID].isBuyerConfirm;
    }

    function buyerConfirmWithCode(
        address _seller,
        string memory _orderID,
        string memory verificationCode
    ) public {
        Purchase storage order = orderBook[_seller][msg.sender][_orderID];
        
        require(order.isOngoing, "Order not active");
        require(order.isLocked, "Funds not locked");
        //equire(VerifyCode(_orderID,verificationCode), "Invalid code");
        if (VerifyCode(_orderID,verificationCode)){
            order.isBuyerConfirm=true;
        }
            

        uint256 amount = order.price;
        delete orderBook[_seller][msg.sender][_orderID];
        balances[_seller] += amount;

        emit OrderCompleted(msg.sender, _seller, amount);
    }

    //卖家提现余额
    function withdrawPayment(address _buyerAddr, string memory _orderID) public payable {   
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No funds to withdraw");
        balances[msg.sender] = 0;

        (bool success, ) = payable(msg.sender).call{value: balance}("");
        require(success, "Transfer failed.");

        emit SellerGetPayment(
            msg.sender,
            _buyerAddr,
            _orderID,
            balance
        );
    }

    function getBalanceOf(address seller) public view returns (uint256) {
        return balances[seller];
    }

    // 买家取消订单，前提订单未被确认（sellerPubKey == 0）
    function buyerCancelOrder(address _seller, string memory _orderID) public {
        Purchase storage order = orderBook[_seller][msg.sender][_orderID];
        require(order.isOngoing, "Order not active");

        uint256 refundAmount = order.lockedAmount;
        delete orderBook[_seller][msg.sender][_orderID];

        (bool success, ) = payable(msg.sender).call{value: refundAmount}("");
        require(success, "Refund failed");
    }

    // 卖家取消订单，前提订单已被确认（sellerPubKey != 0）
    function sellerCancelOrder(address _buyer, string memory _orderID) public {
        Purchase storage order = orderBook[msg.sender][_buyer][_orderID];
        require(order.isOngoing, "Order not active");

        uint256 refundAmount = order.lockedAmount;
        delete orderBook[msg.sender][_buyer][_orderID];

        (bool success, ) = payable(_buyer).call{value: refundAmount}("");
        require(success, "Refund failed");
    }

//=========================================Logistics Order===================================//
    struct Logistics {
        G1Point buyerPubKey;
        bool isOngoing;
        string currentSite;
        uint256 code;
        G1Point SN;
    }

    mapping(string => Logistics) public orderLogistics;

    // 创建物流订单
    function CreateLogisticsOrder(
        address _sellerAddr,
        address _buyerAddr,
        string memory _orderID,
        uint256 _code,           // 原 string _code 改为 uint256，保持类型一致
        G1Point memory _SN       // 保留 G1Point 类型
    ) public payable {
        Logistics storage existing = orderLogistics[_orderID];
        require(!existing.isOngoing, "Logistics order already exists");

        Purchase memory orderMessage = orderBook[_sellerAddr][_buyerAddr][_orderID];

        orderLogistics[_orderID] = Logistics({
            buyerPubKey: orderMessage.buyerPubKey,
            isOngoing: true,
            currentSite: "",
            code: _code,
            SN: _SN
        });
    }

    // 更新物流状态
    function UpdateStatus(string memory _orderID, string memory _siteID) public {
        Logistics storage order = orderLogistics[_orderID];
        require(order.isOngoing, "Order not active");
        order.currentSite = _siteID;
    }

    // 查询当前位置
    function GetCurrentSite(string memory _orderID) public view returns (string memory) {
        return orderLogistics[_orderID].currentSite;
    }

    function GetSN(string memory _orderID) public view returns (G1Point memory) {
        return orderLogistics[_orderID].SN;
    }

    // 验证提货码
    function VerifyCode(string memory _orderID, string memory _code) public view returns (bool) {
        string memory temp = string(abi.encodePacked(_code,"||", _orderID));
        uint256 hashed = stringToUint256(temp);
        return hashed == orderLogistics[_orderID].code;
    }

    function getOrder(address _seller, address _buyer, string memory _orderID) public view returns (
        string memory productID,
        string memory orderID,
        uint256 quantity,
        uint256 price,
        bool isOngoing,
        bool isLocked,
        bool isBuyerConfirm) {
            Purchase storage order = orderBook[_seller][_buyer][_orderID];
            return (
                order.productID,
                order.orderID,
                order.quantity,
                order.price,
                order.isOngoing,
                order.isLocked,
                order.isBuyerConfirm
            );
    }

}