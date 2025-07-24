rm -rf ./contract/*.bin
rm -rf ./contract/*.abi
rm -rf ./contract/*.go

Name=BC_SID
solc --evm-version paris --via-ir --optimize --abi ./contract/$Name.sol -o contract --overwrite
solc --evm-version paris --via-ir --optimize --bin ./contract/$Name.sol -o contract --overwrite
abigen --abi=./contract/$Name.abi --bin=./contract/$Name.bin --pkg=contract --out=./contract/$Name.go
