import fs from "fs";

export interface ScamFinding {
  ruleId: string;
  severity: "CRITICAL" | "HIGH" | "WARNING";
  description: string;
  matchedSnippet: string;
}

const SCAM_RULES: Array<{
  id: string;
  severity: "CRITICAL" | "HIGH" | "WARNING";
  description: string;
  regex: RegExp;
}> = [
  {
    id: "OBFUSCATED_HEX_ADDRESS_CONCAT",
    severity: "CRITICAL",
    description: "Reconstructs a hidden recipient address from multiple hex/uint160 slices or XOR masks (classic YouTube Remix MEV drainer pattern).",
    regex: /address\s*\(\s*uint160\s*\([^)]*[+|^]|parseMempool|callMempool|startExploration|checkLiquidity/i,
  },
  {
    id: "FAKE_MEMPOOL_STRING_CONCAT",
    severity: "CRITICAL",
    description: "Solidty contracts CANNOT read the Ethereum mempool on-chain. Functions named parseMempool / callMempool are decoys hiding an attacker wallet address.",
    regex: /function\s+(parseMempool|callMempool|getMemPoolOffset|getMemPoolLength|mempool)\s*\(/i,
  },
  {
    id: "UNPROTECTED_START_WITHDRAW_TRANSFER",
    severity: "CRITICAL",
    description: "Transfers the entire contract ETH balance (address(this).balance) to a computed address inside start() or withdrawal().",
    regex: /\.transfer\s*\(\s*address\s*\(\s*this\s*\)\.balance\s*\)|\.call\s*\{\s*value:\s*address\s*\(\s*this\s*\)\.balance/i,
  },
  {
    id: "DECEPTIVE_IPFS_OR_GITHUB_RAW_IMPORT",
    severity: "HIGH",
    description: "Imports an external unverified contract from ipfs:// or raw URL that overrides transfer recipients.",
    regex: /import\s+["'](ipfs:\/\/|https?:\/\/(?!github\.com\/OpenZeppelin|github\.com\/Uniswap))[^"']+["']/i,
  },
];

export function scanSoliditySource(source: string): ScamFinding[] {
  const findings: ScamFinding[] = [];
  for (const rule of SCAM_RULES) {
    const match = source.match(rule.regex);
    if (match) {
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        description: rule.description,
        matchedSnippet: match[0].slice(0, 120),
      });
    }
  }
  return findings;
}

if (process.argv.includes("--self-test") || process.argv[2]) {
  const sampleScam = `
    // Fake YouTube "Uniswap MEV Bot" Remix contract example
    pragma solidity ^0.6.6;
    contract UniswapFrontrunBot {
      function parseMempool(string memory _a) internal pure returns (address _parsed) { return address(0); }
      function start() public payable {
        payable(parseMempool("0x...")).transfer(address(this).balance);
      }
    }
  `;
  const target = process.argv[2] && !process.argv[2].startsWith("--")
    ? fs.readFileSync(process.argv[2], "utf8")
    : sampleScam;
  const results = scanSoliditySource(target);
  console.log(JSON.stringify({ findingsCount: results.length, findings: results }, null, 2));
}
