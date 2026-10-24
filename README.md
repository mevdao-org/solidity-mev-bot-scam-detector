# Solidity MEV Bot Scam Detector & "MEV Bot for Sale" Reality Check (2026)

> **Production Flashbots Execution & Non-Custodial Ethereum Sniper:** [**MEV DAO (`mevdao.org`)**](https://mevdao.org)
>
> **Deep-Dive Security Guides:**
> - [**The YouTube MEV Bot Scam: How the "Remix Contract" Drains Your ETH**](https://mevdao.org/blog/the-youtube-mev-bot-scam-how-the-remix-contract-drains-your-eth)
> - [**MEV Bot for Sale? What's Real, What's a Scam, and What It Should Cost**](https://mevdao.org/blog/mev-bot-for-sale-what-s-real-what-s-a-scam-and-what-it-should-cost)
> - [**Why Public-Mempool MEV Bots Lose Money in 2026 (And What Works Instead)**](https://mevdao.org/blog/why-public-mempool-mev-bots-lose-money-in-2026-and-what-works-instead)

---

## Why 99% of "Solidity MEV Bots" on YouTube, Telegram, and Pastebin Are Wallet Drainers

Every day, developers and traders search for **`solidity mev bot`**, **`mev bot remix`**, **`chatgpt mev bot`**, or **`mev bot for sale`** and land on slick YouTube tutorials or Telegram listings promising 0.5–2 ETH/day in passive Uniswap front-running profits.

The instructions always follow the same script:
1. Open `remix.ethereum.org`.
2. Paste a 400-line Solidity file (`OneClickMevBot.sol` or `UniswapSlippageBot.sol`).
3. Compile, deploy to Ethereum Mainnet, fund the contract with **0.5 ETH to 2 ETH** ("minimum liquidity required to beat gas fees"), and click **`start()`** or **`Action()`**.

**Within the same block that `start()` executes, 100% of your deposited ETH is transferred straight to the scammer's wallet.**

### The Fundamental Technical Reason a Solidity-Only MEV Bot Cannot Exist

**A Solidity smart contract cannot watch the Ethereum mempool or trigger its own transactions.**

In the Ethereum Virtual Machine (EVM):
- Smart contracts are **strictly passive state machines**. They only execute when an external transaction calls them inside an already-proposed block.
- A Solidity contract has **zero access to pending mempool transactions**. Functions named `parseMempool()`, `callMempool()`, `checkLiquidity()`, or `startExploration()` in viral Remix scripts are **100% fake string/uint160 concatenation helpers** that reconstruct the scammer's hardcoded Ethereum address out of split hex strings so you don't notice a raw `0x...` address in the code.
- Real MEV bots consist of **two distinct layers**:
  1. **An off-chain searcher / monitoring engine** (written in TypeScript, Rust, or Go) connected to an Ethereum node and private block builders (`eth_sendBundle` / `eth_callBundle` via Flashbots).
  2. **An on-chain executor contract** (or router call) that only executes when the off-chain engine signs and submits an atomic bundle for a specific target block.

Read our full forensic walkthrough of the decompiled Remix drainer code in [**The YouTube MEV Bot Scam: How the "Remix Contract" Drains Your ETH**](https://mevdao.org/blog/the-youtube-mev-bot-scam-how-the-remix-contract-drains-your-eth).

---

## Anatomy of the "Remix Contract" Drainer: 4 Signatures This Repo Detects

This repository includes a lightweight TypeScript static analyzer (`src/detector.ts`) that flags the four most common obfuscation techniques used in fake Solidity MEV bots:

| Rule ID | Severity | How the Scam Works | Real MEV Equivalent |
| :--- | :--- | :--- | :--- |
| `FAKE_MEMPOOL_STRING_CONCAT` | **CRITICAL** | Defines `parseMempool()`, `callMempool()`, or `getMemPoolOffset()` that concatenate slices of hex characters into an `address` | Real mempool monitoring happens **off-chain** via WebSocket RPC (`eth_subscribe("newPendingTransactions")`) or MEV-Share SSE streams |
| `OBFUSCATED_HEX_ADDRESS_CONCAT` | **CRITICAL** | Uses `address(uint160(uint256(keccak256(...)) ^ 0x...))` or bitwise shifts across 4–6 constants to hide the recipient address | Legitimate executor contracts store an immutable `owner` address set in `constructor()` and verified on Etherscan |
| `UNPROTECTED_START_WITHDRAW_TRANSFER` | **CRITICAL** | `start()` or `withdrawal()` calls `payable(hiddenAddr).transfer(address(this).balance)` with no `onlyOwner` check or sends straight to the reconstructed address | Real executors validate `msg.sender == owner` and revert (`require(profit > minProfit)`) if the atomic trade does not net profit |
| `DECEPTIVE_IPFS_OR_GITHUB_RAW_IMPORT` | **HIGH** | Imports `ipfs://Qm...` or a lookalike GitHub URL (`github.com/UniswapV2-Periphery/...`) where the malicious `transfer()` lives | Legitimate repos use pinned npm packages (`@openzeppelin/contracts`) and local audited interfaces |

### Quick Start: Scan Any Solidity File Before Deploying

```bash
git clone https://github.com/mevdao-org/solidity-mev-bot-scam-detector.git
cd solidity-mev-bot-scam-detector
npm install

# Run the built-in self-test against a sample Remix drainer
npm test

# Scan any suspicious .sol file downloaded from YouTube, Pastebin, or Telegram
npx tsx src/detector.ts ./path/to/SuspiciousBot.sol
```

---

## "MEV Bot for Sale" Reality Check: What's Real vs. What's a Scam

If you are evaluating a commercial trading bot, an open-source repo, or a freelance developer offering an **"MEV bot for sale"**, use this verification matrix from our guide [**MEV Bot for Sale? What's Real, What's a Scam, and What It Should Cost**](https://mevdao.org/blog/mev-bot-for-sale-what-s-real-what-s-a-scam-and-what-it-should-cost):

| Offer Type | Typical Price Quoted | Verdict | Why |
| :--- | :--- | :--- | :--- |
| **"Deploy in Remix & fund 0.5 ETH" bot** | "Free" (steals deposit) | **100% Scam** | Solidity contracts cannot scan the mempool; `start()` drains your ETH |
| **Telegram/Discord "Pre-configured Arbitrage Bot" (.exe / .zip / obfuscated JS)** | $200 – $2,500 | **99% Scam / Key-Stealer** | Usually steals your `.env` private key or sells a dead public-mempool script that loses every race on gas |
| **"Guaranteed 1–5% Daily Return" MEV Pool / Cloud Bot** | Deposit-based | **100% Ponzi / Drainer** | No genuine searcher shares risk-free alpha with retail depositors; anyone with a profitable zero-risk arb scales it with flash loans ($0 capital required) |
| **Custodial Telegram Sniper Bots (Banana Gun, Maestro, etc.)** | **1% of every buy + 1% of every sell** | **Real, but Expensive & Custodial** | A $10,000 round-trip trade costs **$200 in bot fees** before gas, and requires storing keys in a Telegram bot database |
| **Non-Custodial Browser Flashbots Sniper ([MEV DAO](https://mevdao.org))** | **$4.90 flat fee** per executed trade | **Real Production Tool** | Routes transactions privately through Flashbots builders (`eth_sendBundle`), reverts for $0 if preconditions fail, and keeps keys non-custodial in your browser |
| **Open-Source Reference Searcher Stack ([`mevdao-org` GitHub](https://github.com/mevdao-org))** | **Free / MIT Open Source** | **Real Educational & Starter Code** | Working TypeScript + Foundry/Anvil bundle simulators, sniper scripts, and wallet rescue tools |

---

## What a Legitimate MEV & Flashbots Architecture Actually Looks Like

Instead of deploying a single Solidity file in Remix, a real Ethereum MEV / sniping / rescue stack uses:

1. **Off-Chain Bundle Construction & Simulation (`eth_callBundle`):**
   Before broadcasting a single wei of gas, your off-chain TypeScript/Rust client simulates the exact transaction bundle against the head block (or a local Foundry Anvil fork). If the token has a hidden transfer tax, honeypot modifier, or insufficient liquidity, the simulation fails locally for **$0**.
   - Reference code: [`mevdao-org/flashbots-bundle-simulator-anvil`](https://github.com/mevdao-org/flashbots-bundle-simulator-anvil)
2. **Private Block-Builder Submission (`eth_sendBundle`):**
   Transactions are sent directly to Flashbots, Titan, Beaverbuild, and rsync over HTTPS—never to the public mempool—so sandwich bots cannot front-run your swap.
   - Reference code: [`mevdao-org/ethereum-sniper-bot-flashbots`](https://github.com/mevdao-org/ethereum-sniper-bot-flashbots)
3. **Flash-Loan Capital Efficiency (Zero Pre-Funded Contract Balance):**
   Real arbitrage and liquidation bots borrow millions in liquidity atomically via **Aave V3 `flashLoanSimple`** or Uniswap flash swaps and repay within the same transaction. You **never** need to leave 1 ETH sitting idle inside an unverified contract to "unlock liquidity."
   - Reference code: [`mevdao-org/mev-arbitrage-and-liquidation-reference`](https://github.com/mevdao-org/mev-arbitrage-and-liquidation-reference)

---

## Already Interacted With a Scam Contract or Sweeper Bot? Emergency Recovery

If you pasted your private key into a fake bot script, signed a malicious `0xef0100` EIP-7702 delegation, or approved a drainer contract:

1. **Check & Revoke EIP-7702 Delegations:**
   - Guide: [**How to Check and Remove a Malicious EIP-7702 Delegation**](https://mevdao.org/blog/how-to-check-and-remove-a-malicious-eip-7702-delegation-from-your-ethereum-wallet)
   - Tool: [`mevdao-org/eip-7702-delegation-checker-revoker`](https://github.com/mevdao-org/eip-7702-delegation-checker-revoker)
2. **Revoke ERC-20 & Permit2 Approvals:**
   - Guide: [**How to Revoke Token Approvals and Permit2 Signatures Before a Drainer Strikes**](https://mevdao.org/blog/how-to-revoke-token-approvals-and-permit2-signatures-before-a-drainer-strikes)
3. **Rescue Stranded Tokens From a Compromised Private Key (Atomic Flashbots Bundle):**
   - Guide: [**Sweeper Bot on My Wallet: How to Rescue Tokens From a Compromised Ethereum Address**](https://mevdao.org/blog/sweeper-bot-on-my-wallet-how-to-rescue-tokens-from-a-compromised-ethereum-address)
   - Tool: [`mevdao-org/compromised-wallet-sweeper-rescue`](https://github.com/mevdao-org/compromised-wallet-sweeper-rescue)

---

## Frequently Asked Questions (FAQ)

### Can ChatGPT build a profitable Solidity MEV bot in Remix?
No. Scammers frequently title their YouTube videos *"How I Built a $1,000/day ChatGPT AI MEV Bot in Remix"* to make victims feel like they are deploying AI-generated code. In reality, the video links to a pre-written pastebin containing a disguised `transfer(address(this).balance)` call to the scammer's wallet.

### Can I recover ETH sent to a YouTube Remix MEV bot contract?
Once `start()` or `withdrawal()` transfers your ETH to the scammer's EOA, on-chain Ethereum transfers are irreversible. However, if your ETH is still sitting inside the deployed contract and `start()` reverted or hasn't been called yet, DO NOT call `start()` or `withdrawal()`—inspect the verified bytecode first to see if any function returns funds to `msg.sender`. See our full diagnostic steps in [**The YouTube MEV Bot Scam: How the "Remix Contract" Drains Your ETH**](https://mevdao.org/blog/the-youtube-mev-bot-scam-how-the-remix-contract-drains-your-eth).

### Where can I use a real Flashbots sniper without writing code?
Use [**MEV DAO (`mevdao.org`)**](https://mevdao.org)—a browser-based, non-custodial Ethereum Flashbots sniper and bundle executor with a flat **$4.90 fee** per executed trade (compared to 1% per trade on custodial Telegram bots).

---

## License

MIT © [MEV DAO](https://mevdao.org)
