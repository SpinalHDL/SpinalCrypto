import sbt.Keys._
import sbt._


val defaultSettings = Defaults.coreDefaultSettings ++ xerial.sbt.Sonatype.sonatypeSettings ++ Seq(
    organization := "com.github.spinalhdl",
    version      := CryptoVersion.crypto,
    scalaVersion := CryptoVersion.scalaCompiler,
    fork         := true,

    libraryDependencies += "org.scala-lang" % "scala-library" % CryptoVersion.scalaCompiler,
    libraryDependencies += compilerPlugin("com.github.spinalhdl" % "spinalhdl-idsl-plugin_2.11" % CryptoVersion.spinal)
  )


lazy val crypto = (project in file("crypto"))
  .settings(
    defaultSettings,
    name     := "SpinalHDL Crypto",
    version  := CryptoVersion.crypto,

    libraryDependencies += "com.github.spinalhdl" % "spinalhdl-core_2.11" % CryptoVersion.spinal,
    libraryDependencies += "com.github.spinalhdl" % "spinalhdl-lib_2.11"  % CryptoVersion.spinal,

  )


lazy val crypto_tester = (project in file("tester"))
  .settings(
    defaultSettings,
    name    := "SpinalHDL Crypto Tester",
    version := CryptoVersion.tester,
      
    libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.60",
    libraryDependencies += "org.scalatest" % "scalatest_2.11" % "2.2.1"
  )
  .dependsOn(crypto)


