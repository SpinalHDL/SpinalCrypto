package ref.padding

object Pad_xB_1_Ref {

  /**
    * Software model
    * @param dIn          string message
    * @param dataInWidth  symbol width
    * @param outWidth     Size of the output of the padding
    * @return Hexadecimal string
    */
  def apply(dIn: String, dataInWidth: Int, outWidth: Int): List[String]= {

    var data: Array[Byte] = dIn.map(_.toByte).toArray :+ 0x06.toByte

    var nbr = scala.math.ceil(dIn.length / (outWidth / 8).toDouble).toInt
    if(dIn.length % (outWidth / 8)  == 0) nbr += 1
    val endSize = nbr * outWidth / 8

    data = data ++ List.fill(endSize - data.length)(0x00.toByte)

    data(data.size - 1) = (data.last | 0x80).toByte

    data.sliding(outWidth / 8, outWidth / 8).map(_.map(x => f"$x%02X").mkString("")).toList
  }
}
