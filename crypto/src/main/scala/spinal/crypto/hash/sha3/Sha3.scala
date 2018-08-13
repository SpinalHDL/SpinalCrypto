/*                                                                           *\
**        _____ ____  _____   _____    __                                    **
**       / ___// __ \/  _/ | / /   |  / /   Crypto                           **
**       \__ \/ /_/ // //  |/ / /| | / /    (c) Dolu, All rights reserved    **
**      ___/ / ____// // /|  / ___ |/ /___                                   **
**     /____/_/   /___/_/ |_/_/  |_/_____/  MIT Licence                      **
**                                                                           **
** Permission is hereby granted, free of charge, to any person obtaining a   **
** copy of this software and associated documentation files (the "Software"),**
** to deal in the Software without restriction, including without limitation **
** the rights to use, copy, modify, merge, publish, distribute, sublicense,  **
** and/or sell copies of the Software, and to permit persons to whom the     **
** Software is furnished to do so, subject to the following conditions:      **
**                                                                           **
** The above copyright notice and this permission notice shall be included   **
** in all copies or substantial portions of the Software.                    **
**                                                                           **
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS   **
** OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF                **
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.    **
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY      **
** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT **
** OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR  **
** THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                **
\*                                                                           */
package spinal.crypto.hash.sha3


/**
  * SHA3 families
  *
  * The SHA-3 family consists of four cryptographic hash functions and two extendable-output
  * functions (XOFs). The cryptographic hash functions are called SHA3-224, SHA3-256, SHA3-
  * 384, and SHA3-512; and the XOFs are called SHAKE128 and SHAKE256.
  */
trait SHA3_Type{ def hashWidth: Int; def r: Int ; def c: Int ; def hashComputationWidth: Int }
object SHA3_224     extends SHA3_Type { def hashWidth = 224 ; def r = 1152 ; def c =  448 ; def hashComputationWidth = 256 }
object SHA3_256     extends SHA3_Type { def hashWidth = 256 ; def r = 1088 ; def c =  512 ; def hashComputationWidth = 256 }
object SHA3_384     extends SHA3_Type { def hashWidth = 384 ; def r =  832 ; def c =  768 ; def hashComputationWidth = 384 }
object SHA3_512     extends SHA3_Type { def hashWidth = 512 ; def r =  576 ; def c = 1024 ; def hashComputationWidth = 512 }
//object SHAKE128     extends SHA3_Type { def hashWidth = 128 ; def r =  1344 ; def c = 256 ; def hashComputationWidth = 128 }
//object SHAKE256     extends SHA3_Type { def hashWidth = 256 ; def r =  1088 ; def c = 512 ; def hashComputationWidth = 256 }