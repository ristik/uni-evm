cargo build --release

./setup-development.sh --clean
./update-config.sh

RUST_LOG=debug ./target/release/uni-evm > uni-evm-debug.log 2>&1 &

sleep 15

echo "=== Sending TX 1 ==="
cast send --value 0.01ether \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  --rpc-url http://localhost:8545

echo "=== Sending TX 2 ==="
cast send --value 0.02ether \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  --rpc-url http://localhost:8545

