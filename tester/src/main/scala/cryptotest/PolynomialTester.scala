package cryptotest

import org.scalatest.funsuite.AnyFunSuite
import spinal.crypto._


class PolynomialTester extends AnyFunSuite {

  test("Polynomial creation") {

    val p1 = p"x^3 + x^2 + x + 1"
    assert(p1.coefficient == List(3,2,1,0), s"String polynomial Error $p1")

    val p2 = p"b1111"
    assert(p2.coefficient == List(3,2,1,0), s"String polynomial Error $p2")

    val p3 = p"32'x04C11DB7"
    assert(p3.coefficient == List(32, 26, 23, 22, 16, 12, 11, 10, 8, 7, 5, 4, 2, 1, 0), s"String polynomial Error $p3")

    val p4 = p"16'x8BB7"
    val p5 = p"x^16+x^15+x^11+x^9+x^8+x^7+x^5+x^4+x^2+x+1 "
    assert(p4 == p5, s"String polynomial Error $p4 is not equal to $p5")
  }
}
