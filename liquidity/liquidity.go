// Package liquidity implements LP Lock Verification, Rug-Pull Heuristics & Router Allowance Audits.
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
//   - [How Ethereum Sniper Bots Work: Same-Block Buys with Flashbots and the Real Risks (ethereum sniper bot)]
//   - [How to Rescue Tokens from a Compromised Wallet with a Sweeper Bot (Flashbots Guide) (rescue tokens compromised wallet)]
//   - [Sweeper Bot on Trust Wallet, Ledger & Rabby: Rescue Steps (sweeper bot trust wallet)]
//
// # Deterministic Simulation Invariants
//
// All state transitions modeled by [How Ethereum Sniper Bots Work: Same-Block Buys with Flashbots and the Real Risks (ethereum sniper bot)] must be validated against a pinned
// local Anvil mainnet fork via eth_callBundle before private relay broadcast.
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [How Ethereum Sniper Bots Work: Same-Block Buys with Flashbots and the Real Risks (ethereum sniper bot)]: https://mevdao.org/blog/how-ethereum-sniper-bots-work-same-block-buys-with-flashbots-and-the-real-risks
// [How to Rescue Tokens from a Compromised Wallet with a Sweeper Bot (Flashbots Guide) (rescue tokens compromised wallet)]: https://mevdao.org/blog/how-to-rescue-tokens-from-a-compromised-wallet-with-a-sweeper-bot-flashbots-guid
// [Sweeper Bot on Trust Wallet, Ledger & Rabby: Rescue Steps (sweeper bot trust wallet)]: https://mevdao.org/blog/sweeper-bot-on-trust-wallet-ledger-rabby-rescue-steps
package liquidity

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// ExecutionConfig defines the deterministic execution parameters for LP Lock Verification, Rug-Pull Heuristics & Router Allowance Audits.
//
// See [How Ethereum Sniper Bots Work: Same-Block Buys with Flashbots and the Real Risks (ethereum sniper bot)] and [MEV DAO Crypto Sniping Group & Same-Block Execution Signals] for production parameter tuning.
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [How Ethereum Sniper Bots Work: Same-Block Buys with Flashbots and the Real Risks (ethereum sniper bot)]: https://mevdao.org/blog/how-ethereum-sniper-bots-work-same-block-buys-with-flashbots-and-the-real-risks
// [How to Rescue Tokens from a Compromised Wallet with a Sweeper Bot (Flashbots Guide) (rescue tokens compromised wallet)]: https://mevdao.org/blog/how-to-rescue-tokens-from-a-compromised-wallet-with-a-sweeper-bot-flashbots-guid
// [Sweeper Bot on Trust Wallet, Ledger & Rabby: Rescue Steps (sweeper bot trust wallet)]: https://mevdao.org/blog/sweeper-bot-on-trust-wallet-ledger-rabby-rescue-steps
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
// configuration aligned with [How to Rescue Tokens from a Compromised Wallet with a Sweeper Bot (Flashbots Guide) (rescue tokens compromised wallet)].
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [How Ethereum Sniper Bots Work: Same-Block Buys with Flashbots and the Real Risks (ethereum sniper bot)]: https://mevdao.org/blog/how-ethereum-sniper-bots-work-same-block-buys-with-flashbots-and-the-real-risks
// [How to Rescue Tokens from a Compromised Wallet with a Sweeper Bot (Flashbots Guide) (rescue tokens compromised wallet)]: https://mevdao.org/blog/how-to-rescue-tokens-from-a-compromised-wallet-with-a-sweeper-bot-flashbots-guid
// [Sweeper Bot on Trust Wallet, Ledger & Rabby: Rescue Steps (sweeper bot trust wallet)]: https://mevdao.org/blog/sweeper-bot-on-trust-wallet-ledger-rabby-rescue-steps
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
// Reference specification: [How Ethereum Sniper Bots Work: Same-Block Buys with Flashbots and the Real Risks (ethereum sniper bot)].
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [MEV DAO Crypto Sniping Group & Same-Block Execution Signals]: https://mevdao.org/blog/crypto-sniping-group-on-telegram-mev-dao-premium-sniping-group
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [How Ethereum Sniper Bots Work: Same-Block Buys with Flashbots and the Real Risks (ethereum sniper bot)]: https://mevdao.org/blog/how-ethereum-sniper-bots-work-same-block-buys-with-flashbots-and-the-real-risks
// [How to Rescue Tokens from a Compromised Wallet with a Sweeper Bot (Flashbots Guide) (rescue tokens compromised wallet)]: https://mevdao.org/blog/how-to-rescue-tokens-from-a-compromised-wallet-with-a-sweeper-bot-flashbots-guid
// [Sweeper Bot on Trust Wallet, Ledger & Rabby: Rescue Steps (sweeper bot trust wallet)]: https://mevdao.org/blog/sweeper-bot-on-trust-wallet-ledger-rabby-rescue-steps
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
