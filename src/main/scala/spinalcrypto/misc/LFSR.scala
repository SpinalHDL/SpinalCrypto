package spinalcrypto.misc

import spinal.core._

import scala.collection.mutable.ListBuffer

/******************************************************************************
  * Linear feedback shift register (LFSR)
  *   There are 2 types of LFSR : Fibonacci and Galois
  */
object LFSR{

  /**
    * Shift register direction
    */
  trait LFSR_SHIFT_DIR
  case object SHIFT_LEFT  extends LFSR_SHIFT_DIR
  case object SHIFT_RIGHT extends LFSR_SHIFT_DIR


  /****************************************************************************
    * LFSR Fibonacci
    *
    * Right :
    *        ____ ____ ____     _____ _____ _____
    *   /-->|_31_|_30_|_29_|...|__2__|__1__|__0__|
    *   |          |              |           |
    *   \<--------XOR<-----------XOR<---------/
    *
    *   e.g : val result = LSFR(myBits, Seq(30,2,0))
    *
    * Left :
    *     ____ ____ ____     _____ _____ _____
    *    |_31_|_30_|_29_|...|__2__|__1__|__0__|<-\
    *      |                   |     |           |
    *      \----------------->XOR-->XOR----------/
    *
    *   e.g : val result = LSFR(myBits, Seq(31,2,1), LFSR_SHIFT_DIR.SHIFT_LEFT)
    *
    * @param that       : Signal to shift
    * @param xorBits    : List of index that must be xor
    * @param rightLeft  : Shift direction (SHIFT_RIGHT, SHIFT_LEFT)
    */
  def fibonacci(that : Bits, xorBits : Seq[Int], rightLeft : LFSR_SHIFT_DIR = SHIFT_RIGHT) : Bits = {

    assert(that.getWidth >= xorBits.size,  "xorBits length is bigger than the bit vector length")
    assert(xorBits.max <= that.getWidth-1, "number in xorBits is bigger than the index of the MSB of the bit vector")
    assert(xorBits.size >= 2, "At least 2 indexes must be specified in xorBits")

    val ret      = cloneOf(that)
    val feedback = (xorBits.map(that(_)).reduce(_ ^ _)).dontSimplifyIt()

    if(rightLeft == SHIFT_RIGHT){
      ret := feedback ## (that >> 1)
    }else{
      ret := (that << 1)(that.high downto 1) ## feedback
    }

    ret
  }


  /****************************************************************************
    * LFSR Galois
    *
    * Right :
    *        _____ _____        _____         _____ _____
    *    /->|__4__|__3__|-XOR->|__2__|--XOR->|__1__|__0__|
    *    |_________________|_____________|____________|
    *
    *    e.g: val result = LFSR_Galois(myBits, Seq(1,2))
    *
    * Left :
    *       _____ _____        _____         _____ _____
    *      |__4__|__3__|<-XOR-|__2__|<--XOR-|__1__|__0__|<-\
    *         |____________|_____________|_________________|
    *
    *    e.g: val result = LFSR_Galois(myBits, Seq(2,3), LFSR_SHIFT_DIR.SHIFT_LEFT)
    *
    * @param that       : Signal to shift
    * @param xorBits    : List of index that must be xor
    * @param rightLeft  : Shift direction (SHIFT_RIGHT, SHIFT_LEFT)
    */
  def galois(that : Bits, xorBits : Seq[Int],  rightLeft : LFSR_SHIFT_DIR = SHIFT_RIGHT): Bits ={

    assert(that.getWidth >= xorBits.size,  "xorBits length is bigger than the bit vector length")
    assert(xorBits.max <= that.getWidth-1, "number in xorBits is bigger than the index of the MSB of the bit vector")

    val ret = cloneOf(that)

    val bitsList = new ListBuffer[Bool]()

    if (rightLeft == SHIFT_RIGHT){

      for (index <- that.high to 0 by -1){
        if (index == that.high) {
          bitsList += that.lsb
        }else if(xorBits.contains(index)) {
          bitsList += that(index + 1) ^ that(0)
        }else{
          bitsList += that(index+1)
        }
      }
      ret := Cat(bitsList.reverse)
    }else{

      for (index <- 0 to that.high){
        if(index == 0){
          bitsList += that.msb
        }else if(xorBits.contains(index)) {
          bitsList += that(index - 1) ^ that.msb
        }else{
          bitsList += that(index - 1)
        }
      }
      ret := Cat(bitsList)
    }
    ret
  }
}
