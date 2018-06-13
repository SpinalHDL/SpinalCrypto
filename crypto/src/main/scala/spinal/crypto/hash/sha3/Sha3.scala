package spinal.crypto.hash.sha3

/*
The SHA-3 family consists of four cryptographic hash functions and two extendable-output
functions (XOFs). The cryptographic hash functions are called SHA3-224, SHA3-256, SHA3-
384, and SHA3-512; and the XOFs are called SHAKE128 and SHAKE256.
 */

/**
  * Define all SHA3 families
  */
trait SHA3_Type{ def hashWidth: Int; def r: Int ; def c: Int }
object SHA3_224     extends SHA3_Type { def hashWidth = 224 ; def r = 1152 ; def c =  448 }
object SHA3_256     extends SHA3_Type { def hashWidth = 256 ; def r = 1088 ; def c =  512 }
object SHA3_384     extends SHA3_Type { def hashWidth = 384 ; def r =  832 ; def c =  768 }
object SHA3_512     extends SHA3_Type { def hashWidth = 512 ; def r =  576 ; def c = 1024 }



object Sha3 {

}
