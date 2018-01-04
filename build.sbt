name := "SpinalCrypto"

version := "1.0"

scalaVersion := "2.11.6"

EclipseKeys.withSource := true

libraryDependencies ++= Seq(
  "com.github.spinalhdl" % "spinalhdl-core_2.11" % "1.1.2",
  "com.github.spinalhdl" % "spinalhdl-lib_2.11" % "1.1.2",
  "com.github.spinalhdl" % "vexriscv_2.11" % "latest.release",
  "org.scalatest" % "scalatest_2.11" % "2.2.1"
)


scalaVersion := "2.11.6"
addCompilerPlugin("org.scala-lang.plugins" % "scala-continuations-plugin_2.11.6" % "1.0.2")
scalacOptions += "-P:continuations:enable"
fork := true

