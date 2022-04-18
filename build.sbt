// CryptoVersion is defined in project/Version.scala

lazy val root = (project in file("."))
  .settings(
    name := "SpinalHDL Crypto",
    organization := "com.github.spinalhdl",
    version := CryptoVersion.crypto,
    crossScalaVersions := CryptoVersion.scalaCompilers,
    scalaVersion := CryptoVersion.scalaCompilers(0),

    Compile / scalaSource := baseDirectory.value / "crypto" / "src" / "main",
    Test / scalaSource := baseDirectory.value / "tester" / "src" / "main",

    libraryDependencies += "com.github.spinalhdl" %% "spinalhdl-core" % CryptoVersion.spinal,
    libraryDependencies += "com.github.spinalhdl" %% "spinalhdl-lib"  % CryptoVersion.spinal,
    libraryDependencies += "org.scala-lang" % "scala-library" % scalaVersion.value,
    libraryDependencies += compilerPlugin("com.github.spinalhdl" %% "spinalhdl-idsl-plugin" % CryptoVersion.spinal),
    libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.60",
    libraryDependencies += "org.scalatest" %% "scalatest" % "3.2.10"
  )

fork := true
