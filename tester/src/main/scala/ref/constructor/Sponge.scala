package ref.constructor



object Sponge {

  def apply(msg: Array[Byte], c: Int, r: Int, d: Int): Array[Byte] ={

    val msgCut = msg.sliding(r / 8, r / 8)
    val rReg = Array.fill(r / 8)(0x00.toByte)
    val cReg = Array.fill(c / 8)(0x00.toByte)

    /**
      * Absorbing
      */
    for(m <- msgCut){

      //println("msg", msg.length,  m.map(x => f"$x%02X").mkString(","))

      // XOR
      val xored = rReg.zip(m).map{case(a,b) => (a ^ b).toByte}
      //println("xor", xored.length, xored.map(x => f"$x%02X").mkString(","))

      // SHIFT
      val shift = (xored ++ cReg).slice(1, xored.length + cReg.length) :+ 0x00.toByte
      //println("shift", shift.length, shift.map(x => f"$x%02X").mkString(","))

      //println(rReg.length, cReg.length, shift.length)

      // COPY
      for(i <- 0 until rReg.length) rReg(i) = shift(i)
      for(i <- 0 until cReg.length) cReg(i) = shift(i + rReg.length - 1)
    }


    //println("rReg", rReg.length, rReg.map(x => f"$x%02X").mkString(","))
    //println("cReg", cReg.length, cReg.map(x => f"$x%02X").mkString(","))

    /**
      * Squeezing
      */
    val nbrSqueeze = scala.math.floor(d / r.toDouble).toInt
    val zReg = Array.fill((nbrSqueeze + 1) * (r / 8))(0x00.toByte)

    if(d > r){

      for(x <- 0 until nbrSqueeze){
        for(i <- 0 until rReg.length) zReg(i + x * (r/8)) = rReg(i)

        // SHIFT
        val shift = (rReg ++ cReg).slice(1, rReg.length + cReg.length) :+ 0x00.toByte
        //println("shift", shift.length, shift.map(x => f"$x%02X").mkString(","))

        // COPY
        for(i <- 0 until rReg.length) rReg(i) = shift(i)
        for(i <- 0 until cReg.length) cReg(i) = shift(i + rReg.length - 1)
      }

      for(i <- 0 until rReg.length) zReg(i + nbrSqueeze * (r/8)) = rReg(i)
    }



    return if(d > r) zReg.slice(0, d / 8) else rReg.slice(0, d / 8)
  }
}
