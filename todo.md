
# spinal.crypto


:ok: Implemented /
:arrows_counterclockwise: In process /
:no_entry_sign: Not implemented 

### Symmetric

| Algo                                               |  Status                    | Remark              |
|:-------------------------------------------------- |:--------------------------:|:------------------- |
| DESCore_Std                                        |  :ok:                      |  Not tested on FPGA |
| TripleDESCore_Std                                  |  :ok:                      |  Not tested on FPGA |
| AESCore_Std (128/192/256-bit)                      |  :arrows_counterclockwise: |  -                  |
| Block Cipher mode operation (CBC,ECB,CTR,OFB,CFB)  |  :arrows_counterclockwise: |  -                  |
| Twofish                                            |  :no_entry_sign:           |  -                  |
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
| SHA                                                |  :no_entry_sign:           |  -                  |
| MD6                                                |  :no_entry_sign:           |  -                  |

### MAC

| Algo                                               |  Status                    | Remark              |
|:-------------------------------------------------- |:--------------------------:|:------------------- |
| HMACCore_Std                                       |  :ok:                      |  Not tested on FPGA |  


### Misc

| Algo                                               |  Status                    | Remark              |
|:-------------------------------------------------- |:--------------------------:|:------------------- |
| LFSR (Fibonacci/Galois)                            |  :arrows_counterclockwise: |  -                  |
| TRNG with PLL                                      |  :no_entry_sign:           |  -                  |
| CRC                                                |  :arrows_counterclockwise: |  -                  |





