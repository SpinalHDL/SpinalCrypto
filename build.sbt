import sbt.Keys._
import sbt._


val defaultSettings = Defaults.coreDefaultSettings ++ xerial.sbt.Sonatype.sonatypeSettings ++ Seq(
    organization := "com.github.spinalhdl",
    version      := SpinalVersion.crypto,
    scalaVersion := SpinalVersion.compiler,
    fork         := true,

    libraryDependencies += "org.scala-lang" % "scala-library" % SpinalVersion.compiler
  )


lazy val crypto = (project in file("crypto"))
  .settings(
    defaultSettings,
    name     := "SpinalHDL Crypto",
    version  := SpinalVersion.crypto,

    libraryDependencies += "com.github.spinalhdl" % "spinalhdl-core_2.11" % "1.4.0",
    libraryDependencies += "com.github.spinalhdl" % "spinalhdl-lib_2.11"  % "1.4.0"
  )


lazy val crypto_tester = (project in file("tester"))
  .settings(
    defaultSettings,
    name    := "SpinalHDL Crypto Tester",
    version := SpinalVersion.tester,

    libraryDependencies += "com.github.spinalhdl" % "vexriscv_2.11" % "latest.release",
    libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.60",
    libraryDependencies += "org.scalatest" % "scalatest_2.11" % "2.2.1"
  )
  .dependsOn(crypto)


