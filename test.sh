#!/bin/sh
CHIP_HOME="../connectedhomeip"
RS_MATTER=`pwd`
RS_MATTER_DATA="/tmp/rs-matter"

rm -rf ${RS_MATTER_DATA}
cd ${CHIP_HOME}
#${CHIP_HOME}/scripts/run_in_build_env.sh "${CHIP_HOME}/scripts/tests/run_test_suite.py --log-level warn --target TestAccessControlCluster --runner chip_tool_python --chip-tool ${CHIP_HOME}/out/host/chip-tool run --iterations 1 --test-timeout-seconds 120 --all-clusters-app ${RS_MATTER}/target/debug/examples/onoff_light --lock-app ${RS_MATTER}/target/debug/examples/onoff_light"
#${CHIP_HOME}/scripts/run_in_build_env.sh "${CHIP_HOME}/scripts/tests/run_test_suite.py --log-level warn --target TestBasicInformation --runner chip_tool_python --chip-tool ${CHIP_HOME}/out/host/chip-tool run --iterations 1 --test-timeout-seconds 120 --all-clusters-app ${RS_MATTER}/target/debug/examples/onoff_light --lock-app ${RS_MATTER}/target/debug/examples/onoff_light"
${CHIP_HOME}/scripts/run_in_build_env.sh "${CHIP_HOME}/scripts/tests/run_test_suite.py --log-level warn --target TestAttributesById --runner chip_tool_python --chip-tool ${CHIP_HOME}/out/host/chip-tool run --iterations 1 --test-timeout-seconds 120 --all-clusters-app ${RS_MATTER}/target/debug/examples/onoff_light --lock-app ${RS_MATTER}/target/debug/examples/onoff_light"
cd ${RS_MATTER}
