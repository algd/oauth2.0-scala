

scalaVersion in ThisBuild := "2.11.5"

organization in ThisBuild := "com.algd"

scalacOptions in ThisBuild := Seq("-unchecked", "-deprecation", "-encoding", "utf8", "-feature")

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
      val akkaV       = "2.4-M1"
      val akkaStreamV = "1.0-RC3"
      val scalaTestV  = "2.2.4"
      Seq(
        "com.typesafe.akka" %% "akka-actor"                           % akkaV,
        "com.typesafe.akka" %% "akka-stream-experimental"             % akkaStreamV,
        "com.typesafe.akka" %% "akka-http-core-experimental"          % akkaStreamV,
        "com.typesafe.akka" %% "akka-http-spray-json-experimental"    % akkaStreamV
      )
    }
  ).dependsOn(`oauth2-scala-core`)