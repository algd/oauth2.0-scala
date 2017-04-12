lazy val commonSettings = Seq(
  organization := "io.github.algd",
  version := "0.5.0",
  licenses := Seq(("Apache-2.0", url("https://spdx.org/licenses/Apache-2.0.html"))),
  scmInfo := Some(ScmInfo(
    browseUrl = url("https://github.com/algd/oauth2.0-scala"),
    connection = "scm:git:git@github.com:algd/oauth2.0-scala.git"
  )),
  crossScalaVersions := Seq("2.11.8", "2.12.1"),
  scalacOptions := Seq(
    "-unchecked",
    "-deprecation",
    "-target:jvm-1.8",
    "-encoding", "utf8",
    "-feature"
  )
)

lazy val root = (project in file("."))
  .settings(commonSettings)
  .settings(
    name := "oauth2.0-scala",
    publishLocal := {},
    publish := {}
  )
  .aggregate(`oauth2-scala-core`, `oauth2-scala-akka-http`)
  .dependsOn(`oauth2-scala-core`, `oauth2-scala-akka-http`)

lazy val `oauth2-scala-core` = project
  .settings(commonSettings)
  .settings(
    libraryDependencies ++= Seq(
      "com.github.nscala-time" %% "nscala-time" % "2.16.0",
      "org.scalatest"          %% "scalatest"   % "3.0.1" % "test"
    )
  )

lazy val `oauth2-scala-akka-http` = project
  .settings(commonSettings)
  .settings(
    mainClass in Compile := None,
    libraryDependencies +=
      "com.typesafe.akka" %% "akka-http" % "10.0.5"
  ).dependsOn(`oauth2-scala-core`)