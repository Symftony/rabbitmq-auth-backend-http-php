# rabbitmq-auth-backend-http-php

PHP implementation of HTTP-based authorisation and authentication for RabbitMQ

## Installation

The recommended way to install is through [Composer](https://getcomposer.org/). Require the symftony/rabbitmq-auth-backend-http-php package:

```
$ composer require symftony/rabbitmq-auth-backend-http-php 
```

## Usage

You can check the [example folder](tree/master/example).

### Use as lib

To use as simple library you must create some service to provide a fully configurable authentication and authorization

#### Authentication

First of all you need to choose/configure your [user provider](https://github.com/symfony/symfony/tree/master/src/Symfony/Component/Security/Core/Authentication/Provider)

```php
$userProvider = new InMemoryUserProvider(array(
    'admin' => array(
        'password' => 'password',
        'roles' => array('Administrator'),
    ),
    'user1' => array(
        'password' => 'user_pass',
    ),
));
```

You need a authentication checker in order to compare the `TokenInterface` with `user`.

```php
$authenticationChecker = new ChainAuthenticationChecker(array(
    new UserPasswordTokenChecker(), // Check the username AND the password, during the authentication process
    new UserTokenChecker(), // Check only username, append with topic, vhost, resource action
));
```

The authenticator is use `UserProvider` to find the user and the `AuthenticationChecker` to know if the token is authenticate.  

```php
$authenticator = new Authenticator(
    $userProvider,
    $authenticationChecker
);

$authenticationManager = new AuthenticationProviderManager(array($authenticator));
```

Now the `Token` is authenticated

#### Authorization

After authenticate, we need to authorize the token to access a resource.

`AccessDecisionManager` is use to allow/deny the token access. `AccessDecisionManager` need an array of `VoterInterface` to do the check.
You need to implement your own voter, in order to choose if the token is granted or not.

```php
$accessDecisionManager = new AccessDecisionManager(array(
    new CustomVoter()
));
```

`AuthorizationChecker` is the manager of authorization process

```php
$tokenStorage = new TokenStorage();
$authorizationChecker = new AuthorizationChecker(
    $tokenStorage,
    $authenticationManager,
    $accessDecisionManager
);
```

Now you have all services to authenticate and authorize a token to access a resource.

In order to simplify the RabbitMQ auth check you can use the `Security` class.

```php
$security = new Security($authenticationManager, $authorizationChecker);
// $isAuthenticate = $this->security->authenticate($token);
// $hasAccess = $this->security->vhost($token, {IP});
// $hasAccess = $this->security->resource($token, {RESOURCE}, {NAME}, {PERMISSION});
// $hasAccess = $this->security->topic($token, {RESOURCE},{NAME},{PERMISSION},{ROUTING_KEY},{VARIABLE_MAP_USERNAME},{VARIABLE_MAP_VHOST});
```

### Use in Symfony framework

You need to create the `Security` service and register the controller as service

> You can check the [Symfony documentation](https://symfony.com/doc/current/security.html) about security

```yaml
# app/config/services.yml
services:
    RabbitMQAuth\Security:
        arguments:
            - '@security.authentication.manager'
            - '@security.authorization_checker'
    
    RabbitMQAuth\Controller\AuthController:
        arguments:
            - '@security.token_storage'
            - '@RabbitMQAuth\Security'
```

Define the 4 routes.  

```yaml
# app/config/routing.yml
auth_user:
    path: /auth_user
    defaults:  { _controller: RabbitMQAuth\Controller\AuthController::userAction }
auth_topic:
    path: /auth_topic
    defaults:  { _controller: RabbitMQAuth\Controller\AuthController::topicAction }
auth_resource:
    path: /auth_resource
    defaults:  { _controller: RabbitMQAuth\Controller\AuthController::resourceAction }
auth_vhost:
    path: /auth_vhost
    defaults:  { _controller: RabbitMQAuth\Controller\AuthController::vhostAction }    
```
