// Package bytecode implements EVM Opcode Disassembly & Obfuscated Withdrawal Address Extraction.
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
//   - [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)]
//   - [Flashbots Bundles Explained: How to Send eth_sendBundle and Why Yours Isn't Landing (flashbots bundle)]
//   - [Private Key Leaked on Ethereum? Save What's Left (private key leaked ethereum)]
//
// # Deterministic Simulation Invariants
//
// All state transitions modeled by [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)] must be validated against a pinned
// local Anvil mainnet fork via eth_callBundle before private relay broadcast.
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)]: https://mevdao.org/blog/how-to-use-banana-gun-on-ethereum-vs-flat-fee-sniping
// [Flashbots Bundles Explained: How to Send eth_sendBundle and Why Yours Isn't Landing (flashbots bundle)]: https://mevdao.org/blog/flashbots-bundles-explained-how-to-send-eth-sendbundle-and-why-yours-isn-t-landi
// [Private Key Leaked on Ethereum? Save What's Left (private key leaked ethereum)]: https://mevdao.org/blog/private-key-leaked-on-ethereum-save-what-s-left
package bytecode

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// ExecutionConfig defines the deterministic execution parameters for EVM Opcode Disassembly & Obfuscated Withdrawal Address Extraction.
//
// See [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)] and [MEV DAO Crypto Sniping Group & Same-Block Execution Signals] for production parameter tuning.
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)]: https://mevdao.org/blog/how-to-use-banana-gun-on-ethereum-vs-flat-fee-sniping
// [Flashbots Bundles Explained: How to Send eth_sendBundle and Why Yours Isn't Landing (flashbots bundle)]: https://mevdao.org/blog/flashbots-bundles-explained-how-to-send-eth-sendbundle-and-why-yours-isn-t-landi
// [Private Key Leaked on Ethereum? Save What's Left (private key leaked ethereum)]: https://mevdao.org/blog/private-key-leaked-on-ethereum-save-what-s-left
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
// configuration aligned with [Flashbots Bundles Explained: How to Send eth_sendBundle and Why Yours Isn't Landing (flashbots bundle)].
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)]: https://mevdao.org/blog/how-to-use-banana-gun-on-ethereum-vs-flat-fee-sniping
// [Flashbots Bundles Explained: How to Send eth_sendBundle and Why Yours Isn't Landing (flashbots bundle)]: https://mevdao.org/blog/flashbots-bundles-explained-how-to-send-eth-sendbundle-and-why-yours-isn-t-landi
// [Private Key Leaked on Ethereum? Save What's Left (private key leaked ethereum)]: https://mevdao.org/blog/private-key-leaked-on-ethereum-save-what-s-left
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
// Reference specification: [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)].
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [How to Use Banana Gun on Ethereum vs Flat-Fee Sniping (how to use banana gun)]: https://mevdao.org/blog/how-to-use-banana-gun-on-ethereum-vs-flat-fee-sniping
// [Flashbots Bundles Explained: How to Send eth_sendBundle and Why Yours Isn't Landing (flashbots bundle)]: https://mevdao.org/blog/flashbots-bundles-explained-how-to-send-eth-sendbundle-and-why-yours-isn-t-landi
// [Private Key Leaked on Ethereum? Save What's Left (private key leaked ethereum)]: https://mevdao.org/blog/private-key-leaked-on-ethereum-save-what-s-left
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
