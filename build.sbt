name := "oauth2.0-scala"

scalaVersion in ThisBuild := "2.11.7"

organization in ThisBuild := "com.algd"

version in ThisBuild := "0.2.0"

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
    libraryDependencies ++= {
      val scalaTestV  = "2.2.4"
      Seq(
        "com.github.nscala-time" %% "nscala-time" % "2.0.0",
        "org.scalatest"     %% "scalatest"                            % scalaTestV % "test"
      )
    }
  )

lazy val `oauth2-scala-akka-http` = project
  .settings(
    mainClass in Compile := None,
    libraryDependencies ++= {
      val akkaV       = "2.4.0"
      val akkaStreamV = "1.0"
      val scalaTestV  = "2.2.4"
      Seq(
        "com.typesafe.akka" %% "akka-actor"                           % akkaV,
        "com.typesafe.akka" %% "akka-stream-experimental"             % akkaStreamV,
        "com.typesafe.akka" %% "akka-http-experimental"               % akkaStreamV
      )
    }
  ).dependsOn(`oauth2-scala-core`)