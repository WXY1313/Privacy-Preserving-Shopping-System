package Event

import (
	"context"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type OrderEventInfo struct {
	OrderID string
	Buyer   common.Address
}

type SellerGetPaymentEvent struct {
	Seller  common.Address
	Buyer   common.Address
	OrderID string
	Payment *big.Int
}

// 监听 BroadcastPubKey 事件中和指定 seller 地址相关的记录
// 监听 BroadcastPubKey 事件中和指定 seller 地址相关的记录
func PollEventsBySeller(
	client *ethclient.Client,
	contractAddress common.Address,
	contractABI abi.ABI,
	seller common.Address,
	startBlock uint64,
) ([]OrderEventInfo, error) {
	query := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(startBlock),
		Addresses: []common.Address{contractAddress},
		Topics: [][]common.Hash{
			{contractABI.Events["BroadcastPubKey"].ID}, // topic0: 事件签名
		},
	}

	logs, err := client.FilterLogs(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("failed to filter logs: %w", err)
	}

	var results []OrderEventInfo

	for _, vLog := range logs {
		// 检查是否有足够的 Topics（至少 3 个）
		if len(vLog.Topics) < 3 {
			log.Printf("Invalid log: insufficient Topics")
			continue // 跳过无效日志
		}

		// 提取 indexed 参数 buyer（topic[2]）
		buyer := common.HexToAddress(vLog.Topics[2].Hex())

		// 仅处理与指定 seller 地址相关的日志
		if buyer != seller {
			continue // 跳过与目标卖家无关的事件
		}

		// 解码非indexed数据部分
		var eventData struct {
			ProductID    string
			Quantity     *big.Int
			BuyerPubKeyX *big.Int
			BuyerPubKeyY *big.Int
			TotalPrice   *big.Int
			OrderID      string
		}

		err := contractABI.UnpackIntoInterface(&eventData, "BroadcastPubKey", vLog.Data)
		if err != nil {
			log.Printf("❌ Failed to unpack log: %v", err)
			continue
		}

		// 将事件数据添加到结果集中
		results = append(results, OrderEventInfo{
			OrderID: eventData.OrderID,
			Buyer:   buyer,
		})
	}
	return results, nil
}

// 监听最近50个区块内，orderID匹配的SellerGetPayment事件
func GetPaymentEventsByOrderID(
	client *ethclient.Client,
	contractAddress common.Address,
	contractABI abi.ABI,
	targetOrderID string,
) ([]SellerGetPaymentEvent, error) {
	// 获取最新区块高度
	latestHeader, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("❌ 获取最新区块失败: %w", err)
	}

	fromBlock := new(big.Int).Sub(latestHeader.Number, big.NewInt(50))
	if fromBlock.Sign() < 0 {
		fromBlock = big.NewInt(0)
	}

	// 构建日志查询（只过滤事件类型）
	query := ethereum.FilterQuery{
		FromBlock: fromBlock,
		ToBlock:   latestHeader.Number,
		Addresses: []common.Address{contractAddress},
		Topics:    [][]common.Hash{{contractABI.Events["SellerGetPayment"].ID}},
	}

	logs, err := client.FilterLogs(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("❌ 日志查询失败: %w", err)
	}

	var matched []SellerGetPaymentEvent
	for _, vLog := range logs {
		// 解码日志数据
		var event SellerGetPaymentEvent

		if len(vLog.Topics) >= 3 {
			event.Seller = common.HexToAddress(vLog.Topics[1].Hex())
			event.Buyer = common.HexToAddress(vLog.Topics[2].Hex())
		}

		// 解码 Data 区域
		var unpacked struct {
			OrderID string
			Payment *big.Int
		}
		if err := contractABI.UnpackIntoInterface(&unpacked, "SellerGetPayment", vLog.Data); err != nil {
			continue // 忽略解析失败的日志
		}
		event.OrderID = unpacked.OrderID
		event.Payment = unpacked.Payment

		if event.OrderID == targetOrderID {
			matched = append(matched, event)
		}
	}

	return matched, nil
}
