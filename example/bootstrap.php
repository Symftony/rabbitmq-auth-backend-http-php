<?php

require_once '../vendor/autoload.php';
require_once 'CustomVoter.php';

use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use RabbitMQAuth\Authentication\Authenticator;
use RabbitMQAuth\Authentication\ChainAuthenticationChecker;
use RabbitMQAuth\Authentication\UserPasswordTokenChecker;
use RabbitMQAuth\Authentication\UserTokenChecker;
use RabbitMQAuth\Controller\AuthController;
use RabbitMQAuth\Security;

$tokenStorage = new TokenStorage();

$userProvider = new InMemoryUserProvider(array(
    'admin' => array(
        'password' => 'password',
        'roles' => array('Administrator'),
    ),
    'user1' => array(
        'password' => 'user_pass',
    ),
));

$authenticator = new Authenticator(
    $userProvider,
    new ChainAuthenticationChecker(array(
        new UserPasswordTokenChecker(),
        new UserTokenChecker(),
    ))
);

$authenticationManager = new AuthenticationProviderManager(array($authenticator));

$accessDecisionManager = new AccessDecisionManager(array(
    new CustomVoter()
));

$authorizationChecker = new AuthorizationChecker(
    $tokenStorage,
    $authenticationManager,
    $accessDecisionManager
);

$security = new Security($authenticationManager, $authorizationChecker);

$authController = new AuthController($tokenStorage, $security);
