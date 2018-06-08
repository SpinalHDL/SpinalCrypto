package spinal.crypto.hash.sha3



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
