name := "SpinalCrypto"

version := "1.0"

scalaVersion := "2.11.6"

EclipseKeys.withSource := true

libraryDependencies ++= Seq(
  "com.github.spinalhdl" % "spinalhdl-core_2.11" % "0.10.14",
  "com.github.spinalhdl" % "spinalhdl-lib_2.11" % "0.10.14",
  "com.github.spinalhdl" % "vexriscv_2.11" % "latest.release",
  "org.scalatest" % "scalatest_2.11" % "2.2.1"
)


