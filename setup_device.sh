set -euo pipefail

echo "=========Commissioning Device==========" && 
  chip-tool pairing code-wifi 12344321 ESP_DEMO_2G ESP@India#2233 34970112332 | grep "TOO"

echo "=========Adding Group Keyset: 0==========" && 
  chip-tool groupkeymanagement key-set-write '{"groupKeySetID": "0xabcd", "groupKeySecurityPolicy": 0, "epochKey0": "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf", "epochStartTime0": 2220000, "epochKey1": "d1d1d2d3d4d5d6d7d8d9dadbdcdddedf", "epochStartTime1": 2220001, "epochKey2": "d2d1d2d3d4d5d6d7d8d9dadbdcdddedf", "epochStartTime2": 2220002 }' 12344321 0 | grep "TOO"

echo "==========Writing Group Key-Map============" && 
 chip-tool groupkeymanagement write group-key-map '[{"groupId":"0xdcba","groupKeySetID":"0xabcd","fabricIndex":"1"}]' 12344321 0 | grep "TOO"

echo "=========Adding endpoint 1 to Group==========" && 
 chip-tool groups add-group 0xdcba Custom_Group 12344321 1 | grep "TOO"

echo "=========Updating ACL==============" &&
  chip-tool accesscontrol write acl '[{"fabricIndex":1,"privilege":5,"authMode":2,"subjects":[112233],"targets":null},{"fabricIndex":1,"privilege":3,"authMode":3,"subjects":[56506],"targets":[{"cluster":null,"endpoint":1,"deviceType":null}]}]' 12344321 0 | grep "TOO"
