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
The [DataManager class](src/main/scala/io/github/algd/oauth/data/DataManager.scala) is in charge of integrating the logic with the persistence layer.
You should extend the User class adding the data you think that is meaningful when the token is validated.

Every method receives an implicit OAuthParams instance that contains all the parameters received by the Granter/Authorizer. You can use this if you want to store some data or to do more validations using custom extra parameters from the request or the context.

##### GetClient(id) / GetClient(id, secret)

The **getClient** method retrieves the data associated to a client in case it exists and the secret, if provided, is valid.
```scala
// Authorization code/implicit grant flow
def getClient(id: String)
(implicit params: OAuthParams, ec: ExecutionContext): Future[Option[Client]]
...
// For every OAuth2 flow
def getClient(id: String, secret: String)
(implicit params: OAuthParams, ec: ExecutionContext): Future[Option[Client]]
```
Example of client record:

|Field|Value|
|-----|-----|
|***id***|*client_id*|
|**secret**|e16b2ab8d12314bf4efbd6203906ea6c|
|**name**|Test Client|
|**scope**|create,update,delete|
|**grants**|authorization_code,implicit,refresh_token,password,client_credentials|
|**redirect_uri**|http://test-domain.com|

##### GetUser(user, password)

The **getUser** method returns some data of the user after validating its username and password (the returned user id can be the same as the username). 
```scala
def getUser(username: String, password: String)
(implicit params: OAuthParams, ec: ExecutionContext): Future[Option[T]]
```
##### GenerateAccessToken(info) / GenerateRefreshToken(info) / GenerateAuthCode(info)
These methods receive the authorization data that contains the client, scope and optional user and returns a string that will be used later to retrieve this information.
```scala
def generateAuthCode(authInfo: AuthorizationData[T])
(implicit params: OAuthParams, ec: ExecutionContext) : Future[String]
...
def generateAccessToken(authInfo: AuthorizationData[T])
(implicit params: OAuthParams, ec: ExecutionContext) : Future[String]
...
def generateRefreshToken(authInfo: AuthorizationData[T])
(implicit params: OAuthParams, ec: ExecutionContext) : Future[String]
```
This string could be for example the encrypted token information or a key used to retrieve the information if it was stored.

Example of Authorization Code AuthInfo record:

|Field|Value|
|-----|-----|
|***code***|*ABCD*|
|**client**|client_id|
|**scope**|create,update|
|**redirect_uri**|http://test-domain.com/oauth2/callback|
|**creation_date**|1473639713645|

##### GetUserScope(userInfo)
The **getUserScope** method retrieves a set with the permissions of the user given the user info. It could be using some data of the class to deduce the scope, querying a database, etc.
```scala
def getUserScope(user: Option[T])
(implicit params: OAuthParams, ec: ExecutionContext): Future[Option[Set[String]]]
```

##### GetGrantedScope(clientScope, userScope, requestedScope)
The **getGrantedScope** method calculates the actual scope of the token. The default implementation is the intersection of permissions of the client scope, the user scope (if it is not client credentials flow) and the requested scope (if provided).
```scala
def getGrantedScope(clientScope: Set[String],
    userScope: Option[Set[String]],
    requestedScope: Option[Set[String]])
    (implicit params: OAuthParams, ec: ExecutionContext): Future[Set[String]] = Future.successful{
    Seq(Some(clientScope), userScope, requestedScope).flatten.reduce(_&_)
}
```

##### IsValidRedirectUri(uri, clientUris)
This method is used when a redirect uri is provided in the authorization code or implicit grant flows. Some examples of validation could be:
- clientUris.contains(uri)
- clientUris.exists(uri.startsWith)
```scala
def isValidRedirectUri(uri: String, clientUris: List[String])
(implicit params: OAuthParams): Boolean
```

##### BuildAuthorizationData(client, user, scope, redirectUri)
This method creates an instance of AuthorizationData that will be associated to an authorization code, token or refresh token. You can override the default implementation if you want to store more information or change the way the creation time is asigned.
```scala
def buildAuthorizationData(client: Client, user: Option[T], scope: Option[Set[String]], redirectUri: Option[String] = None)
    (implicit params: OAuthParams, ec: ExecutionContext) : Future[AuthorizationData[T]] = Future.successful {
    AuthorizationData(client, user, scope, redirectUri)
    /* Or with more info...
    AuthorizationData(client, user, scope, redirectUri).withData("app" -> "testApp") */
}
```

##### GetAuthCodeData(code) / GetAccessTokenData(token) / GetRefreshTokenData(refreshToken)
These methods returns the AuthorizationData associated to the code/token/refresh token given a string. So it could be, for example, extracting the information from the string or looking for the value with this key in a database.
```scala
def getAuthCodeData(code: String)
(implicit params: OAuthParams, ec: ExecutionContext): Future[Option[AuthorizationData[T]]]
...
def getAccessTokenData(token: String)
(implicit params: OAuthParams, ec: ExecutionContext) : Future[Option[AuthorizationData[T]]]
...
def getRefreshTokenData(refreshToken: String)
(implicit params: OAuthParams, ec: ExecutionContext): Future[Option[AuthorizationData[T]]]
```
