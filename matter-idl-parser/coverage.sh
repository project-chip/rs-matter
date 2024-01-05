#!/usr/bin/env bash


gcov_coverage() {
# need nightly for -Zprofile
rustup default nightly
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
export RUSTDOCFLAGS="-Cpanic=abort"
cargo build --verbose $CARGO_OPTIONS
cargo test --verbose $CARGO_OPTIONS

# Validate only. Since these are not tests, commented out for now
# cargo run                \
#    --example file_parser \
#    -- /usr/local/google/home/andreilitvin/devel/connectedhomeip/examples/all-clusters-app/all-clusters-common/all-clusters-app.matter
# Actual coverage

mkdir -p target/coverage
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/coverage/

}

tarpaulin_coverage(){
    cargo tarpaulin -o Html --engine llvm --output-dir target/coverage
}

case $1 in
  help)
      echo "Usage: "
      echo "  $0 [grcov,tarpaulin]"
      ;;
  grcov)
      echo "GRCOV coverage"
      gcov_coverage
      echo "output in target/coverage/index.html"
      ;;
  tarpaulin)
      echo "tarpaulin coverage"
      tarpaulin_coverage
      echo "output in target/coverage/tarpaulin-report.html"
  ;;
  *)
    tarpaulin_coverage;
  ;;

esac

