# 🏦 DeFi Protocol — Upgradeable Yield Aggregator

A modular **DeFi Yield Aggregator** built using **Solidity**, **Foundry**, and **OpenZeppelin Upgradeable Contracts**.  
This protocol implements the foundational architecture of many modern DeFi systems — including **Vaults**, **Controllers**, **Strategies**, and **ERC20 Tokens** — in an upgradeable and testable way.

---

## ⚙️ Overview

This protocol demonstrates a simplified, modular yield system similar to **Yearn Finance** or **Balancer**, where users deposit tokens into a **Vault**, which allocates capital to a **Strategy** through a **Controller** to generate yield.

All components are **upgradeable (UUPS pattern)**, allowing safe on-chain upgrades of logic while preserving user funds and storage.

---

## 🧩 Architecture

### 🔹 Token (`src/Token.sol`)
- ERC20 upgradeable token used for deposits and yield rewards.
- Initially mints `1,000,000` tokens to the deployer.
- `mint()` function is available to the owner for testing or research purposes.
- Implements `UUPSUpgradeable` for upgrade safety.

**Key Functions**
- `initialize(name, symbol, supply, owner)`
- `mint(to, amount)` — only owner can mint
- `_authorizeUpgrade(newImpl)` — restricts upgrades to owner

---

### 🔹 Strategy (`src/Strategy.sol`)
- Simulates a yield-generating strategy.
- Accepts deposits from the Controller.
- Can simulate “yield” by minting extra tokens to itself.
- Returns harvested profits to the Vault or Controller.

**Core Features**
- `invest(amount)` — receives tokens from Controller
- `withdraw(amount, to)` — returns funds on user withdrawal
- `harvest()` — transfers simulated yield to the Vault
- `simulateYield(amount)` — test function to fake yield
- `emergencyWithdrawAll(to)` — owner-only safeguard

**Access Control**
- `onlyController` and `onlyOwnerOrController` modifiers restrict operations
- Fully upgradeable via UUPS pattern

---

### 🔹 Controller (`src/Controller.sol`)
- Middle layer between Vault and Strategy.
- Manages investment flow and yield harvesting.
- Acts as the **execution manager** for Vault deposits and withdrawals.

**Responsibilities**
- Transfers tokens to the Strategy for investment.
- Handles withdrawals and yield harvesting.
- Emits detailed logs for investment events.

**Key Functions**
- `initialize(token, strategy)`
- `invest(amount)` — deposits tokens into Strategy
- `withdraw(amount, to)` — requests withdrawal from Strategy
- `harvest()` — collects yield from Strategy
- `_authorizeUpgrade(newImpl)` — upgrade restricted to owner

---

### 🔹 Vault (`src/Vault.sol`)
- User-facing component for deposits and withdrawals.
- Mints proportional “shares” to represent ownership of total assets.
- Uses the Controller to allocate funds and harvest yield.
- Implements upgradeability and non-reentrancy protections.

**Core Logic**
1. **Deposit**
   - User deposits ERC20 tokens.
   - Vault mints proportional shares based on current total assets.
   - Tokens are approved and sent to Controller → Strategy.
2. **Withdraw**
   - Burns user’s shares.
   - Retrieves underlying assets (including yield) via Controller.
3. **Total Assets**
   - Aggregates balances across Vault, Controller, and Strategy.

**Key Functions**
- `deposit(amount)`
- `withdraw(shares)`
- `_totalAssets()` — view of protocol-wide token holdings

---

### 🔹 Deployment Script (`script/deploy.s.sol`)
Deploys all four core contracts, links them together, and logs their addresses.

**Flow**
1. Deploys Token, Strategy, Controller, and Vault.
2. Initializes each with their dependencies.
3. Sets inter-contract references (`setController`, `setVault`).
4. Logs deployed addresses to console.

**Usage**
```bash
forge script script/deploy.s.sol:DeployProtocol \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_API_KEY
```


### Upgrade Script (`script/upgrade.s.sol`)

Used to perform contract upgrades on deployed proxies using the UUPS pattern.

Flow

Reads VAULT_PROXY from .env.

Deploys a new Vault implementation.

Calls upgradeTo(newImplementation) on the proxy.

### Tests (test/)

Comprehensive tests using Foundry’s `forge-std/Test.sol`.

controller.t.sol

Tests the Controller + Strategy interaction.

✅ `testInvestAndHarvest()`

User invests via Controller.

Strategy receives tokens.

Simulated yield harvested back to Controller.

`vault.t.sol`

Tests the full user flow across Vault, Controller, and Strategy.

✅ `testDepositSharesMinted()` — ensures correct share minting

✅ `testWithdrawReturnsTokens()` — user receives full funds on withdrawal

✅ `testHarvestIncreasesAssets()` — yield harvesting increases total assets

Run tests:
```
    forge test -vv
```
🧰 Environment Setup

Create a .env file:

```
    PRIVATE_KEY=your_private_key_without_quotes
    RPC_URL=https://sepolia.infura.io/v3/<your-infura-project-id>
    ETHERSCAN_API_KEY=<your-etherscan-api-key>
```

Then load:

source .env

### Installation & Build
git clone <repo-url>
cd `defi-protocol`
forge install
forge build

### Deployment

Deploy to Sepolia

```
forge script script/deploy.s.sol:DeployProtocol \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_API_KEY
```


Upgrade Vault
```
forge script script/upgrade.s.sol:UpgradeVault \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast
```
🧠 Design Philosophy

Modularity: Each contract handles a single concern.

Upgradeability: Future-proof UUPS-based proxy pattern.

Security: Reentrancy guard, ownership control, and tested flows.

Composability: Vault-Controller-Strategy separation enables flexible strategy upgrades.

🧪 Future Improvements

Multi-strategy support with weighted allocation.

Governance-controlled upgrade and strategy rotation.

Real yield integration via lending protocols (Aave, Compound).

Frontend UI for deposits and analytics.

📜 License

MIT License © 2025
Built with ❤️ using Foundry and OpenZeppelin.

👨‍💻 Project Structure
```
    defi-protocol/
    │
    ├── src/
    │   ├── Token.sol        # ERC20 upgradeable deposit token
    │   ├── Controller.sol   # Investment router between Vault and Strategy
    │   ├── Strategy.sol     # Yield simulator and fund manager
    │   └── Vault.sol        # User-facing vault managing deposits & shares
    │
    ├── script/
    │   ├── deploy.s.sol     # Automated deployment script
    │   └── upgrade.s.sol    # UUPS upgrade script
    │
    ├── test/
    │   ├── controller.t.sol # Controller and Strategy tests
    │   └── vault.t.sol      # Full flow vault tests
    │
    ├── .env                 # Environment variables (private key, RPC, API)
    ├── foundry.toml         # Foundry config
    └── README.md            # Project documentation
```


🧩 Summary

This project provides a complete Foundry-based upgradeable DeFi protocol framework — perfect for:

Research on modular DeFi systems,

Teaching upgradeable contract design,

Building more advanced real-world yield aggregators.