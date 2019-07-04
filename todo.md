
# spinal.crypto


:ok: Implemented /
:arrows_counterclockwise: In process /
:no_entry_sign: Not implemented 

### Symmetric

| Algo                                               |  Status                    | Remark              |
|:-------------------------------------------------- |:--------------------------:|:------------------- |
| DESCore_Std                                        |  :ok:                      |  Not tested on FPGA |
| TripleDESCore_Std                                  |  :ok:                      |  Not tested on FPGA |
| AESCore_Std (128/192/256-bit)                      |  :ok:                      |  Not tested on FPGA |
| Block Cipher mode operation (CBC,ECB,CTR,OFB,CFB)  |  :ok:                      |  CTR not implemented|
| Twofish                                            |  :ok:                      |  Not tested on FPGA |
| RC6                                                |  :no_entry_sign:           |  -                  |


### Asymmetric 

| Algo                                               |  Status                    | Remark              |
|:-------------------------------------------------- |:--------------------------:|:------------------- |
| RSA                                                |  :no_entry_sign:           |  -                  |
| Elliptic curve cryptography                        |  :no_entry_sign:           |  -                  |



### Hash 

| Algo                                               |  Status                    | Remark              |
|:-------------------------------------------------- |:--------------------------:|:------------------- |
| MD5Core_Std                                        |  :ok:                      |  Not tested on FPGA |
| SHA2Core_Std                                       |  :ok:                      |  Not tested on FPGA |
| SHA3Core_Std                                       |  :ok:                      |  Not tested on FPGA |
| MD6                                                |  :no_entry_sign:           |  -                  |

### MAC

| Algo                                               |  Status                    | Remark              |
|:-------------------------------------------------- |:--------------------------:|:------------------- |
| HMACCore_Std                                       |  :ok:                      |  Not tested on FPGA |  


### Misc

| Algo                                               |  Status                    | Remark              |
|:-------------------------------------------------- |:--------------------------:|:------------------- |
| LFSR (Fibonacci/Galois)                            |  :ok:                      |  Not tested on FPGA |
| TRNG with PLL                                      |  :no_entry_sign:           |  -                  |
| CRC                                                |  :ok:                      |  Test only CRC 8, 16, 32 |
| Keccak                                             |  :ok:                      |  Not tested on FPGA |





