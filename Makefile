.PHONY: build test clean deploy anvil coverage install

# Default RPC + Key (override with export or inline VAR=value)
#RPC_URL?=http://127.0.0.1:8545
#PRIVATE_KEY?=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

include .env
export

build:
	forge build

clean:
	forge clean

test:
	forge test -vvv

coverage:
	forge coverage --report lcov

anvil:
	anvil

deploy:
	forge script script/DeployLendingPool.s.sol \
		--rpc-url $(RPC_URL) \
		--private-key $(PRIVATE_KEY) \
		--broadcast \
		--etherscan-api-key $(ETHERSCAN_API_KEY) \
		--verify
		 --legacy \
  		--slow \
  		--with-gas-price 2gwei

deploy2:
	forge script script/SetupMarkets.s.sol \
		--rpc-url $(RPC_URL) \
		--private-key $(PRIVATE_KEY) \
		--broadcast

install:
	forge install OpenZeppelin/openzeppelin-contracts@v5.0.0 \
	              smartcontractkit/chainlink-brownie-contracts@1.2.0
