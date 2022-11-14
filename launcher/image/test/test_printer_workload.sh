
#!/bin/bash
set -euo pipefail
source util/read_serial.sh

echo 'Running printer workload test'

VM_NAME=$(cat /workspace/vm_name.txt)

echo 'Reading from serial port:'
SERIAL_OUTPUT=$(read_serial)
echo $SERIAL_OUTPUT

echo $SERIAL_OUTPUT | grep 'printer container ran with:' || echo 'TEST FAILED' > /workspace/status.txt
echo $SERIAL_OUTPUT | grep 'printer container env:' || echo 'TEST FAILED' > /workspace/status.txt
echo $SERIAL_OUTPUT | grep 'printer OIDC token exists!' || echo 'TEST FAILED' > /workspace/status.txt
