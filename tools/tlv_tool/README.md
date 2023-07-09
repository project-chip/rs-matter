# TLV Tool
A simple tool for printing Matter TLVs or Matter-encoded certificates.

```
$ # For printing a Matter TLV List
$ tlv_tool --hex "15, 24, 0, 1, 18"

$ # For printing a Matter TLV List in hexstring
$ tlv_tool --hexstring "1524000118"

$ # For printing a Matter encoded certificate
$ tlv_tool --cert "0x15, 0x00"
```
