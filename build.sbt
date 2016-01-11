name := "oauth2.0-scala"

scalaVersion in ThisBuild := "2.11.7"

organization in ThisBuild := "io.github.algd"

version in ThisBuild := "0.3.0-SNAPSHOT"

scalacOptions in ThisBuild := Seq("-unchecked", "-deprecation", "-target:jvm-1.8", "-encoding", "utf8", "-feature")

lazy val root = (project in file("."))
  .aggregate(
    `oauth2-scala-core`,
    `oauth2-scala-akka-http`)
  .settings(
    publishArtifact := false
  )

lazy val `oauth2-scala-core` = project
  .settings(
    libraryDependencies ++= Seq(
        "com.github.nscala-time" %% "nscala-time" % "2.6.0",
        "org.scalatest"          %% "scalatest"   % "2.2.6" % "test")
  )

lazy val `oauth2-scala-akka-http` = project
  .settings(
    mainClass in Compile := None,
    libraryDependencies +=
      "com.typesafe.akka" %% "akka-http-experimental" % "2.0.1"
  ).dependsOn(`oauth2-scala-core`)