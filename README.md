OAuth2.0 scala
=========
This library provides the necessary tools to implement an OAuth 2.0 server.
It is based on [RFC 6749](https://tools.ietf.org/html/rfc6749).
### Getting Started
This project is using scala 2.11.8. To get started with SBT, add the following to your `build.sbt`
file:
```scala
resolvers += "bintray algd" at "http://dl.bintray.com/content/algd/maven"
```
In case you want to use the akka-http module add the following. It is using akka 2.4.4.
```scala
libraryDependencies += "io.github.algd" %% "oauth2-scala-akka-http" % "0.4.0"
```
Otherwise only add:
```scala
libraryDependencies += "io.github.algd" %% "oauth2-scala-core" % "0.4.0"
```

### Authorize endpoint

After creating a class that extends `DataManager`, you can instantiate an OAuth authorizer enabling the flows you are interested in:
```scala
val myDataManager: DataManager[MyUser] = new MyDataManager

val authorizer = new BaseAuthorizer(myDataManager) +
                 new ImplicitAuthorizer +
                 new CodeAuthorizer

val params = Map("some_oauth_param" -> "value")
                
val response = authorizer(user, params)
```
This even allows you to create your custom authorizers.
The response of an authorizer will be a `Future[UriResponse]` containing a validation error or a successful response ready to be converted to a redirection uri.

### Token endpoint
After creating a class that extends `DataManager`, you can instantiate an OAuth token granter enabling the flows you are interested in:
```scala
val myDataManager: DataManager[MyUser] = new MyDataManager

val granter = new BaseGranter(myDataManager) +
              new AuthorizationCodeGranter +
              new PasswordGranter +
              new ClientCredentialsGranter +
              new RefreshTokenGranter

val params = Map("some_oauth_param" -> "value")
                
val response = granter(params)
```
This even allows you to create your custom granters.
The response of a granter will be a `Future[TokenResponse]` containing a validation error or a new issued token info.

### Akka Http integration
If you are using the akka http module you can extend or import `OAuth2Support` to enable implicit conversions for authorizers and granters. For example:
```scala
import OAuth2Support._
...
(path("authorize") & post & parameterMap) { params =>
    val user = ...
    authorizer.route(user, params) // ToEntityMarshaller[OAuthError] required
}
...
(path("token") & post & entity(as[FormData])) { form =>
    granter.route(form.fields.toMap)      
}
```
### DataManager implementation
TODO





