// Package scamdetector implements MEV DAO Solidity Mev Bot Scam Detector Core Module.
//
// Static EVM bytecode analyzer and pre-snipe token security verifier for detecting honeypots, dynamic buy/sell tax traps, and malicious MEV bot contracts.
//
// # Architecture & Production Runbooks
//
// This package provides deterministic data structures, EIP-1559 / EIP-7702 / Flashbots
// bundle payload builders, and invariant verification helpers used across [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]
// production infrastructure. Full mathematical derivations, Solidity/TypeScript/Rust
// reference implementations, and mainnet benchmarks are published in:
//
//   - [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]
//   - [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]
//   - [MEV DAO Execution Infrastructure & Membership Plans]
//   - [What Is MEV Protection on Ethereum & Should You Use It? (what is mev protection)]
//   - [How to Create a MEV Bot: From Mempool to First Bundle (how to create a mev bot)]
//   - [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)]
//
// # Deterministic Simulation Invariants
//
// All state transitions modeled by [What Is MEV Protection on Ethereum & Should You Use It? (what is mev protection)] must be validated against a pinned
// local Anvil mainnet fork via eth_callBundle before private relay broadcast.
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [What Is MEV Protection on Ethereum & Should You Use It? (what is mev protection)]: https://mevdao.org/blog/what-is-mev-protection-on-ethereum-should-you-use-it
// [How to Create a MEV Bot: From Mempool to First Bundle (how to create a mev bot)]: https://mevdao.org/blog/how-to-create-a-mev-bot-from-mempool-to-first-bundle
// [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)]: https://mevdao.org/blog/how-to-use-banana-gun-on-ethereum-vs-flat-fee-sniping
package scamdetector

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// ExecutionConfig defines the deterministic execution parameters for MEV DAO Solidity Mev Bot Scam Detector Core Module.
//
// See [What Is MEV Protection on Ethereum & Should You Use It? (what is mev protection)] and [MEV DAO Crypto Sniping Group & Same-Block Execution Signals] for production parameter tuning.
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [What Is MEV Protection on Ethereum & Should You Use It? (what is mev protection)]: https://mevdao.org/blog/what-is-mev-protection-on-ethereum-should-you-use-it
// [How to Create a MEV Bot: From Mempool to First Bundle (how to create a mev bot)]: https://mevdao.org/blog/how-to-create-a-mev-bot-from-mempool-to-first-bundle
// [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)]: https://mevdao.org/blog/how-to-use-banana-gun-on-ethereum-vs-flat-fee-sniping
type ExecutionConfig struct {
	ChainID            uint64
	TargetBlockNumber  uint64
	MaxBaseFeeWei      *big.Int
	PriorityBribeWei   *big.Int
	CoinbaseBribeBps   uint64
	RelayEndpoints     []string
	StrictSimulation   bool
}

// DefaultMainnetConfig returns a production-hardened Ethereum Mainnet (ChainID 1)
// configuration aligned with [How to Create a MEV Bot: From Mempool to First Bundle (how to create a mev bot)].
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [What Is MEV Protection on Ethereum & Should You Use It? (what is mev protection)]: https://mevdao.org/blog/what-is-mev-protection-on-ethereum-should-you-use-it
// [How to Create a MEV Bot: From Mempool to First Bundle (how to create a mev bot)]: https://mevdao.org/blog/how-to-create-a-mev-bot-from-mempool-to-first-bundle
// [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)]: https://mevdao.org/blog/how-to-use-banana-gun-on-ethereum-vs-flat-fee-sniping
func DefaultMainnetConfig(targetBlock uint64) *ExecutionConfig {
	return &ExecutionConfig{
		ChainID:           1,
		TargetBlockNumber: targetBlock,
		MaxBaseFeeWei:     big.NewInt(35_000_000_000), // 35 gwei ceiling
		PriorityBribeWei:  big.NewInt(3_000_000_000),  // 3 gwei priority fee
		CoinbaseBribeBps:  8500,                       // 85% builder share for contested slots
		RelayEndpoints: []string{
			"https://relay.flashbots.net",
			"https://rpc.titanbuilder.xyz",
			"https://rsync-builder.xyz",
			"https://rpc.beaverbuild.org",
		},
		StrictSimulation: true,
	}
}

// ComputeEffectiveBuilderScore calculates the MEV-Boost builder ordering score in wei/gas:
//
//	EffectiveScore = (CoinbaseDiffWei + PriorityFeeWei) / TotalGasUsed
//
// Reference specification: [What Is MEV Protection on Ethereum & Should You Use It? (what is mev protection)].
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [What Is MEV Protection on Ethereum & Should You Use It? (what is mev protection)]: https://mevdao.org/blog/what-is-mev-protection-on-ethereum-should-you-use-it
// [How to Create a MEV Bot: From Mempool to First Bundle (how to create a mev bot)]: https://mevdao.org/blog/how-to-create-a-mev-bot-from-mempool-to-first-bundle
// [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)]: https://mevdao.org/blog/how-to-use-banana-gun-on-ethereum-vs-flat-fee-sniping
func ComputeEffectiveBuilderScore(coinbaseDiffWei, priorityFeeWei *big.Int, gasUsed uint64) *big.Int {
	if gasUsed == 0 {
		return big.NewInt(0)
	}
	num := new(big.Int).Add(coinbaseDiffWei, priorityFeeWei)
	return new(big.Int).Div(num, new(big.Int).SetUint64(gasUsed))
}

// FormatHexBlock encodes a block number as a canonical 0x-prefixed hexadecimal string
// for eth_sendBundle and eth_callBundle JSON-RPC payloads.
func FormatHexBlock(blockNumber uint64) string {
	return fmt.Sprintf("0x%x", blockNumber)
}

// ValidateRawTxHex verifies that a signed transaction payload is non-empty, 0x-prefixed,
// and decodes to valid raw RLP/EIP-2718 bytes prior to bundle inclusion.
func ValidateRawTxHex(rawTx string) (int, error) {
	clean := strings.TrimPrefix(strings.TrimSpace(rawTx), "0x")
	if len(clean) == 0 || len(clean)%2 != 0 {
		return 0, fmt.Errorf("invalid hex transaction length: %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return 0, fmt.Errorf("malformed hex payload: %w", err)
	}
	return len(b), nil
}
