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
package spinal.crypto.devtype

import spinal.core._
import spinal.lib.tools._

import scala.collection.mutable
import scala.collection.mutable.ListBuffer
import scala.util.control.Breaks._


/**
  * DNode is the base class of all develop nodes
  */
abstract class DNode{

  /** Unique id for each nodes */
  private val id: Int = DNode.incId()

  /** Return the unique id of the node */
  def getId(): Int = id

  /** Children of the Node */
  private val children = ListBuffer[DNode]()

  /** Set a list of children*/
  def setChildren(listChildren: List[DNode]): this.type ={
    children.clear()
    listChildren.foreach { c => children += c  }
    this
  }

  /** Return the list of children of the node */
  def getChildren(): List[DNode] = children.toList


  /** Compute the number of nodes  */
  def countNodes: Int = this.children.foldLeft(1)(_ + _.countNodes)

  /**
    * Generate a lispyTree
    * e.g : (N0 (N1 N2 N3) (N4 N5 N3) N8)
    */
  def lispyTree: String =
    if (children == Nil) this.toString()
    else "(" + this.toString + " " + children.map(_.lispyTree).mkString(" ") + ")"

  /**
    *  Generate a dot graph from the current node
    *  e.g : graph dotDebug{
    *           n0 -- n1
    *           n1 -- n2
    *           n1 -- n3
    *         }
    */
  def dot(nameGraph: String = "dotDebug"): String = {

    def parseTree[T](node: DNode): List[String] = node.getChildren() match {
      case Nil            => List(s"${node.toString}_${node.getId()}")
      case x:List[DNode]  => x.map(x => s"${node}_${node.getId()}  ->  ${x.toString}_${x.getId()}") ::: x.flatMap(c => parseTree(c))
    }

    // build graph
    s""" digraph $nameGraph { \n ${parseTree(this).map("\t" + _).mkString("\n")} \n }"""
  }


  /**
    * Compare two nodes together. Return true if the nodes and its children are equal
    */
  def === (that: DNode): Boolean = {

    def isChildrenEqual(c1: List[DNode], c2: List[DNode]): Boolean = {
      if (c1.length != c2.length){
        false
      }else{
        // Each time a children form b match a, we remove the children of the list
        val listChildren = ListBuffer(c2: _ *)

        for (child_a <- c1){
          breakable{
            for((child_b, i) <- listChildren.zipWithIndex){
              if (parseTree(child_a, child_b)){
                listChildren.remove(i)
                break
              }
            }
            return false
          }
        }

        if(listChildren.isEmpty) true else false
      }
    }

    def parseTree(n1: DNode, n2: DNode): Boolean = (n1, n2) match{
      case (a: DBool, b: DBool)                => a.name == b.name
      case (a: DBoolLiteral, b: DBoolLiteral)  => a.value == b.value
      case (a: DOperation, b: DOperation) if a.operation == b.operation =>
        isChildrenEqual(a.getChildren(), b.getChildren())
      case (a: DBits, b: DBits) =>
        isChildrenEqual(a.getChildren(), b.getChildren())
      case _ => false
    }

    parseTree(this, that)
  }

  def =/=(that: DNode): Boolean = !(this === that)


  /**
    * Get all children and return a map with the number of occurrence of each children
    */
  private def ctnChildrenOccurrence(children: List[DNode]): mutable.LinkedHashMap[DNode, Int] = {

    val map = mutable.LinkedHashMap[DNode, Int]()

    for(child <- children){
      breakable {
        for (key <- map.keys) {
          if (child === key) {
            val cnt = map(key)
            map(key) = cnt + 1
            break
          }
        }
        map += (child -> 1)
      }
    }

    map
  }

  /**
    * If there is literal simplfy them
    * if xor a a => a
    * if and false a b => false
    * if xor a c d d d => xor a c d
    */
  private def reduceGraph(baseNode: DNode): DNode = {

    def isDBoolLiteral(node: DNode, state: Boolean): Boolean = node match{
      case a: DBoolLiteral if a.value == state => true
      case _ => false
    }

    def removeDuplicateOperator(listNode: List[DNode], op: DBitwiseOp): List[DNode] ={
      listNode.map(x => x match{
        case a: DOperation if a.operation == op => a.getChildren()
        case _ => List(x)
      }).flatten
    }

    def parseTree(node: DNode): List[DNode] = node match{
      case a: DOperation if a.operation == XOR =>

        val mapChild = ctnChildrenOccurrence(a.getChildren().map(parseTree(_)).flatten)

        // remove all even child and false node
        val mapNew1 = mapChild.filter(x => (x._2 % 2 != 0) & !isDBoolLiteral(x._1, false))

        if(mapNew1.size == 0) return List(DBoolLiteral(false))

        // if there is one True (invert one entry)
        if(mapNew1.map(x => isDBoolLiteral(x._1, true)).reduce(_ | _)){

          // invert the first entry
          if(mapNew1.size == 1) return List(DBoolLiteral(true))


          // remove all true
          val result = mapNew1.filter(x => !isDBoolLiteral(x._1, true))

          // invert the first entry
          return List(a.setChildren((!result.keys.toList.head) :: result.keys.toList.tail))
        }

        if (mapNew1.size == 1) return mapNew1.keys.toList


        val l = removeDuplicateOperator(mapNew1.keys.toList, XOR)

        val maps = ctnChildrenOccurrence(l)

        val r = maps.filter(x => x._2 % 2 != 0)

        if (r.size == 1) return r.keys.toList

        return List(a.setChildren(r.keys.toList))

      case a: DOperation if a.operation == AND =>

        val mapChild = ctnChildrenOccurrence(a.getChildren().map(parseTree(_)).flatten)

        // if there is a true => remove it
        val newMap = mapChild.filter(x => !isDBoolLiteral(x._1, true))

        if(newMap.size == 0) return List(DBoolLiteral(true))


        // if there is one false => remove all
        if (newMap.map(x => isDBoolLiteral(x._1, false)).reduce(_ | _)){
          return List(DBoolLiteral(false))
        }

        if (newMap.size == 1) return newMap.keys.toList

        // if the children is a AND  => take its children and remove the and
        val l = removeDuplicateOperator(newMap.keys.toList, AND)

        val maps = ctnChildrenOccurrence(l)

        if(maps.size == 1) return maps.keys.toList

        return List(a.setChildren(maps.keys.toList))

      case a: DOperation if a.operation == OR =>

        val mapChild = ctnChildrenOccurrence(a.getChildren().map(parseTree(_)).flatten)

        // if there is a false => remove it
        val newMap = mapChild.filter(x => !isDBoolLiteral(x._1, false))

        if(newMap.size == 0) return List(DBoolLiteral(false))

        // if there is a true => remove all
        if (newMap.map(x => isDBoolLiteral(x._1, true)).reduce(_ | _)){
          return List(DBoolLiteral(true))
        }

        // if the children is a or => take its children and remove the or
        val l = removeDuplicateOperator(newMap.keys.toList, OR)

        val maps = ctnChildrenOccurrence(l)

        if(maps.size == 1) return maps.keys.toList

        List(a.setChildren(maps.keys.toList))

      case a: DNode => List(a)
      case _        => throw new Exception(s"Error while reducing graph.")
    }

    parseTree(baseNode).head
  }


  /**
    * Simplify the graph
    */
  def simplify: this.type = this match{
      case b: DBits =>
        DBits("Bits", b.getWidth bits).setChildren(b.getChildren().map(reduceGraph(_))).asInstanceOf[this.type]
      case _ =>
        reduceGraph(this).asInstanceOf[this.type]
  }

  /**
    * Return a list of all variable of the tree
    */
  def getAllVariables(node: DNode): List[DNode] = {

    def parseTree(n: DNode): List[DBool] = n match {
      case x: DBool => List(x)
      case _        => (n.getChildren().map(parseTree(_))).flatten
    }

    ctnChildrenOccurrence(parseTree(node)).keys.toList
  }


  def processGraphWithInput(node: DNode, inputs: mutable.LinkedHashMap[DNode, Boolean]): Boolean = {

    // rebuild the graph with the given value
    def parseTree(n: DNode): List[DNode] =  n match {
      case x: DBool      => List(DBoolLiteral(inputs(x)))
      case x: DOperation => List(DOperation(x.operation).setChildren(x.getChildren().map(parseTree(_)).flatten))
      case _ =>  throw new Exception(s"DNode not supported by this function $n")
    }

    val newGraph = parseTree(node)


    // simplify the graph
    newGraph.head.simplify match {
      case a: DBoolLiteral => a.value
      case _ => throw new Exception (s"Only DBoolLiteral is supported at this stage")
    }

  }


  /**
    * Return the list of MinTerms
    */
  def getMinTerms: (List[Int], List[DNode]) = {

    // simplify the graph
    this.simplify

    // list all variable
    val variables = this.getAllVariables(this)

    // execute all posibility
    val result = ListBuffer[Int]()
    for(i <- 0 until math.pow(2, variables.size).toInt){
      val binValue = BigIntToListBoolean(i, variables.size bits)
      val map = mutable.LinkedHashMap[DNode, Boolean]()
      variables.zip(binValue).foreach(e => map.update(e._1, e._2))

      if(processGraphWithInput(this, map)){
        result += i
      }
    }

    (result.toList, variables)
  }

  /** AND operation */
  def &(that: DNode): DNode = doOperation(AND, this, that)
  def &(that: DBitVector): this.type = doOperation(AND, this, that).asInstanceOf[this.type]
  /** XOR operation */
  def ^(that: DNode): DNode = doOperation(XOR, this, that)
  def ^(that: DBitVector): this.type = doOperation(XOR, this, that).asInstanceOf[this.type]
  /** OR operation */
  def |(that: DNode): DNode = doOperation(OR, this, that)
  def |(that: DBitVector): this.type = doOperation(OR, this, that).asInstanceOf[this.type]
  /** NOT operation */
  def unary_!(): DNode = DOperation(NOT, this)

  /** Concatenation */
  def ##(that: DNode): DBits = (this, that) match{
    case (a: DBits, b: DBits) =>
      DBits("Bits", a.getWidth + 1 bits).setChildren(b.getChildren() ::: a.getChildren())
    case (a: DBits, b:DNode) =>
      DBits("Bits", a.getWidth + 1 bits).setChildren(b :: a.getChildren())
    case (a: DNode, b:DBits) =>
      DBits("Bits", b.getWidth + 1 bits).setChildren(b.getChildren() ::: List(a))
    case (a: DNode, b: DNode) =>
      DBits("Bits", 2 bits).setChildren(List(b, a))
    case _ => throw new Exception(s"Error while concatenating these types ${this.getClass.getName} and ${that.getClass.getName}")
  }


  /**
    * Create a new node for the operation
    */
  private def doOperation(op: DBitwiseOp, left: DNode, right: DNode): DNode = (left, right) match{
    case (a: DBits, b: DBits) => DBits("Bits", a.getWidth bits).setChildren((a.getChildren().zip(b.getChildren())).map(a => doOperation(op, a._1, a._2)))
    case (a: DNode, b: DNode) => DOperation(op, a, b)
    case _ => throw new Exception(s"Error while creating new operation : no operation available for type ${left.getClass.getName} and ${right.getClass.getName}")
  }


  /**
    *  Transform the node into a Bool spinal expression
    */
  def toBool: Bool = {

    def parseTree(baseNode: DNode): Bool = baseNode match {
      case a: DOperation if a.operation == NOT => a.operation.spinal(parseTree(a.getChildren().head))
      case a: DOperation                       => a.getChildren().map(parseTree(_)).reduce(a.operation.spinal(_, _))
      case a: DBool if a.data != null          => a.data
      case a: DBool => throw new Exception("Error while converting expression into Spinal : no Spinal type associated to DBool")
      case _        => throw new Exception("Error while converting expression into Spinal : this node is not supported " + baseNode.getClass.getName)
    }
    parseTree(this.simplify)
  }


  /**
    * Transform the node into a string expression
    * e.g : ((a_0 & b_0) ^ b_1)
    */
  def toBoolString: String = {

    def parseTree(baseNode: DNode): String = baseNode match {
      case a: DOperation if a.operation == NOT => a.operation.symbol + "(" + parseTree(a.getChildren().head) +")"
      case a: DOperation                       => "(" + a.getChildren().map(parseTree(_)).mkString(s" ${a.operation.symbol} ") + ")"
      case a: DBool                            => a.name
      case _ => throw new Exception("Error while converting expression into string: this node is not supported " + baseNode.getClass.getName)
    }
    parseTree(this.simplify)
  }

}

// TODO must be Thread safe
object DNode{
  private var id = 0
  def incId(): Int ={ id += 1; id - 1}
  def resetId: Unit = id = 0
}



/** Base class for all operations */
trait DBitwiseOp { def name: String; def symbol: String; def spinal(a:Bool*):Bool }
/** AND operation */
object AND  extends DBitwiseOp { def name = "AND"; def symbol = "&" ; def spinal(a:Bool*) = a.reduce(_ & _) }
/** XOR operation **/
object XOR  extends DBitwiseOp { def name = "XOR"; def symbol = "^" ; def spinal(a:Bool*) = a.reduce(_ ^ _)}
/** OR operation */
object OR   extends DBitwiseOp { def name = "OR" ; def symbol = "|" ; def spinal(a:Bool*) = a.reduce(_ | _) }
/** Not operation */
object NOT  extends DBitwiseOp { def name = "NOT"; def symbol = "!" ; def spinal(a:Bool*) = !a.head}


/**
  * Operation node between nodes
  */
case class DOperation(operation: DBitwiseOp, children: DNode*) extends DNode{

  this.setChildren(children.toList)

  override def toString(): String = s"${operation.name}"
}


/**
  *
  */
abstract class DBaseType extends DNode{
}


/**
  * DBool reprensent a boolean
  */
case class DBool(name: String, data: Bool = null) extends DBaseType {

  override def toString(): String = s"$name"
}


/**
  *
  */
abstract class DBitVector(name: String, size: BitCount, data: Bits) extends DBaseType{

  // Create children
  this.setChildren((0 until size.value).map(x =>  DBool(s"${name}_${x}", if(data != null) data(x) else null)).toList)


  /** Extract a bits of a given index */
  def apply(index: Int): DNode = this.getChildren()(index)

  /** Inverse operator */
  def unary_~(): this.type  = this.setChildren(this.getChildren().map(c => !c))

  /** Logical left operator */
  def |<<(that: Int) : DBits = {

    def shiftLeft(list: List[DNode], length:Int ): DBits = length match{
      case 0 => DBits("Bits", this.size).setChildren(list)
      case _ => shiftLeft( (DBoolLiteral(false) :: list).take(this.size.value), length-1)
    }

    shiftLeft(this.getChildren(), that)
  }

  /** Logical right operator */
  def |>>(that: Int) : DBits = {

    def shiftRight(list: List[DNode], length:Int ): DBits = length match{
      case 0 => DBits("Bits", this.size).setChildren(list)
      case _ => shiftRight( (list ::: List(DBoolLiteral(false))).tail, length-1)
    }

    shiftRight(this.getChildren(), that)
  }

  /** Return the Most significant bits */
  def msb: DNode = this(this.size.value-1)
  /** Return the less significant bits */
  def lsb: DNode = this(0)

  /** Return the width of the data */
  def getWidth: Int = size.value

  /** Return the name */
  def getName: String = name


  /** Transform the tree into a Bits spinal expression */
  def toBits: Bits = Cat(this.getChildren().map(x => x.toBool))


  /** Return a range of the current DBits */
  def apply(range: Range): DNode = {
    if (range.min == range.max){
      return this(range.last)
    }
    assert(range.max+1 <= this.getWidth, "Range bigger thant the current DBits")
    DBits("Bits", range.length bits).setChildren(this.getChildren().slice(range.min, range.max+1))
  }

  /** Transform the tree into a string boolean expression */
  def toBitsString: String = {
    val res  = this.getChildren().zipWithIndex.map(x => "r(" + x._2 + ")" + " = " +  x._1.toBoolString)
    res.mkString("\n")
  }

  override def toString(): String = s"$name"
}

/**
  *
  */
case class DBits(n: String, length: BitCount, d: Bits = null) extends DBitVector(n, length, d) {
}


/**
  *
  */
object DBits{

  def apply(list: List[Boolean], value: DNode): DBits = {
    val bits = DBits("Bits", list.length bits)
    bits.setChildren(list.map(b => if(b) value else DBoolLiteral(false)))
    bits
  }

  def apply(name: String, data: Bits): DBits = DBits(name, data.getWidth bits, data)
}


/**
  *
  */
abstract class DLiteral extends DNode{
}


/**
  * Literal Boolean value
  */
case class DBoolLiteral(value: Boolean) extends DLiteral{
  override def toString(): String = s"${value}"
}


/**
  * DBitsLiteral are a DBits with DBoolLiteral children
  */
object DBitsLiteral{

  def apply(str: String, radix: Int): DBits = radix match{
    case 2  =>
      assert(str.matches("[0-1]*") == true, s"String $str must contains only 0 or 1 character")
      DBits("Bits", str.length bits).setChildren(str.reverse.map(x => DBoolLiteral(x == '1')).toList)
    case 16 =>
      assert(str.toLowerCase.matches("[a-f0-9]*"), s"String $str must contains only [a-fA-F0-9] character")
      val listBool = str.reverse.map(x => BigIntToListBoolean(BigInt(Integer.parseInt(x.toString, 16)),  4 bits)).flatten
      DBits("Bits", str.length*4 bits).setChildren(listBool.map(x => DBoolLiteral(x)).toList)
    case _  => throw new Exception(s"Radix not supported $radix")
  }

  def apply(value: BigInt, size: BitCount): DBits = {
    DBits("Bits", size).setChildren(BigIntToListBoolean(value, size).map(x => DBoolLiteral(x)))
  }
}