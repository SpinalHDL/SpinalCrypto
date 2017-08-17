/*                                                                           *\
**        _____ ____  _____   _____    __                                    **
**       / ___// __ \/  _/ | / /   |  / /   Crypto                           **
**       \__ \/ /_/ // //  |/ / /| | / /    (c) Dolu, All rights reserved    **
**      ___/ / ____// // /|  / ___ |/ /___                                   **
**     /____/_/   /___/_/ |_/_/  |_/_____/                                   **
**                                                                           **
**      This library is free software; you can redistribute it and/or        **
**    modify it under the terms of the GNU Lesser General Public             **
**    License as published by the Free Software Foundation; either           **
**    version 3.0 of the License, or (at your option) any later version.     **
**                                                                           **
**      This library is distributed in the hope that it will be useful,      **
**    but WITHOUT ANY WARRANTY; without even the implied warranty of         **
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU      **
**    Lesser General Public License for more details.                        **
**                                                                           **
**      You should have received a copy of the GNU Lesser General Public     **
**    License along with this library.                                       **
\*                                                                           */
package spinal


package object crypto {


  implicit class LiteralBuilder(private val sc: StringContext) {
    def p(args: Any*): String = getString(args)

    private def getString(args: Any*): String = {

      val pi = sc.parts.iterator
      val ai = args.iterator
      val bldr = new StringBuilder(pi.next().toString)

      while (ai.hasNext) {
        if (ai.hasNext && !ai.next.isInstanceOf[List[_]]) bldr append ai.next
        if (pi.hasNext && !pi.next.isInstanceOf[List[_]]) bldr append pi.next
      }

      bldr.result.replace("_", "")
    }
  }
}
