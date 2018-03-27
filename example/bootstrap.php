<?php

require_once '../vendor/autoload.php';

use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use RabbitMQAuth\Authentication\Authenticator;
use RabbitMQAuth\Authentication\ChainAuthenticationChecker;
use RabbitMQAuth\Authentication\UserPasswordTokenChecker;
use RabbitMQAuth\Authentication\UserTokenChecker;
use RabbitMQAuth\Authorization\DefaultVoter;
use RabbitMQAuth\Controller\AuthController;
use RabbitMQAuth\Security;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

$userProvider = new InMemoryUserProvider(array(
    'admin' => array(
        'password' => 'admin',
        'roles' => array(
            'administrator',
            // 'impersonator', // report to https://www.rabbitmq.com/validated-user-id.html
        ),
    ),
    'management-user' => array(
        'password' => 'management-user',
        'roles' => array(
            'management',
        ),
    ),
    'monitoring-user' => array(
        'password' => 'monitoring-user',
        'roles' => array(
            'monitoring',
        ),
    ),
    'policymaker-user' => array(
        'password' => 'policymaker-user',
        'roles' => array(
            'policymaker',
        ),
    ),
    'user-1' => array(
        'password' => 'user-1',
        'roles' => array(
            'management',
        ),
    ),
));

$permissions = array(
    'admin' => array(
        'isAdmin' => true,
    ),
    'user-1' => array(
        '/' => array(
            'ip' => '.*',
            'read' => '.*',
            'write' => '.*',
            'configure' => '.*',
        ),
    ),
);

$authenticator = new Authenticator(
    $userProvider,
    new ChainAuthenticationChecker(array(
        new UserPasswordTokenChecker(),
        new UserTokenChecker(),
    ))
);

$authenticationManager = new AuthenticationProviderManager(array($authenticator));

$defaultVoter = new DefaultVoter($permissions);

$accessDecisionManager = new AccessDecisionManager(array($defaultVoter));

$tokenStorage = new TokenStorage();

$authorizationChecker = new AuthorizationChecker(
    $tokenStorage,
    $authenticationManager,
    $accessDecisionManager
);

$security = new Security($authenticationManager, $authorizationChecker);
$authController = new AuthController($tokenStorage, $security);

if (class_exists('Monolog\Logger')) {
    $stream = new StreamHandler('log.log', Logger::DEBUG);
    $authenticator->setLogger((new Logger('rabbitmq_authenticator'))->pushHandler($stream));
    $defaultVoter->setLogger((new Logger('rabbitmq_default_voter'))->pushHandler($stream));
    $security->setLogger((new Logger('rabbitmq_security'))->pushHandler($stream));
}
