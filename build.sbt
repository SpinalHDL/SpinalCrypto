import sbt.Keys._
import sbt._


val defaultSettings = Defaults.coreDefaultSettings ++ xerial.sbt.Sonatype.sonatypeSettings ++ Seq(
    organization := "com.github.spinalhdl",
    version      := CryptoVersion.crypto,
    crossScalaVersions := CryptoVersion.scalaCompilers,
    scalaVersion := CryptoVersion.scalaCompilers(0),
    fork         := true,

    libraryDependencies += "org.scala-lang" % "scala-library" % scalaVersion.value,
    libraryDependencies += compilerPlugin("com.github.spinalhdl" %% "spinalhdl-idsl-plugin" % CryptoVersion.spinal)
  )


lazy val crypto = (project in file("crypto"))
  .settings(
    defaultSettings,
    name     := "SpinalHDL Crypto",
    version  := CryptoVersion.crypto,

    libraryDependencies += "com.github.spinalhdl" %% "spinalhdl-core" % CryptoVersion.spinal,
    libraryDependencies += "com.github.spinalhdl" %% "spinalhdl-lib"  % CryptoVersion.spinal,

  )


lazy val crypto_tester = (project in file("tester"))
  .settings(
    defaultSettings,
    name    := "SpinalHDL Crypto Tester",
    version := CryptoVersion.tester,
      
    libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.60",
    libraryDependencies += "org.scalatest" %% "scalatest" % "3.2.10"
  )
  .dependsOn(crypto)


