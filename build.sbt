organization := "com.github.jarlah"

name := "AuthenticScala"

version := "0.1"

scalaVersion := "2.12.6"

enablePlugins(ScalafmtPlugin)

scalafmtOnCompile := true

libraryDependencies += "org.scalactic" %% "scalactic" % "3.0.5"
libraryDependencies += "org.scalatest" %% "scalatest" % "3.0.5" % "test"
libraryDependencies += "commons-codec" % "commons-codec" % "1.11"
