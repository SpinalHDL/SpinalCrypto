import sbt.Keys._
import sbt._



object SpinalBuild extends Build {


  lazy val crypto = Project(
    id = "SpinalHDL-crypto",
    base = file("crypto"),
    settings = defaultSettings  ++  Seq(
      name    := "SpinalHDL Crypto",
      version := SpinalVersion.crypto,
      libraryDependencies += "com.github.spinalhdl" % "spinalhdl-core_2.11" % "1.2.2",
      libraryDependencies += "com.github.spinalhdl" % "spinalhdl-lib_2.11" % "1.2.2"
    )
  )


  lazy val crypto_tester = Project(
    id = "SpinalHDL-Crypto-Tester",
    base = file("tester"),
    settings = defaultSettings ++ Seq(
      name         := "SpinalHDL Crypto Tester",
      version      := SpinalVersion.tester,
      publishTo    := None,
      publish      := {},
      publishLocal := {},
      libraryDependencies += "com.github.spinalhdl" % "vexriscv_2.11" % "latest.release",
      libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.60",
      libraryDependencies += "org.scalatest" % "scalatest_2.11" % "2.2.1"
    )
  ) dependsOn (crypto)



  lazy val defaultSettings = Seq(
    organization := "com.github.spinalhdl",
    scalaVersion := SpinalVersion.compiler,

    //SpinalSim
    addCompilerPlugin("org.scala-lang.plugins" % "scala-continuations-plugin_2.11.6" % "1.0.2"),
    libraryDependencies += "org.scala-lang.plugins" %% "scala-continuations-library" % "1.0.2",
    scalacOptions       += "-P:continuations:enable",
    fork := true
  )

}