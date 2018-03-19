<?php

namespace RabbitMQAuth;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RabbitMQAuth\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

class Security implements LoggerAwareInterface
{
    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var AuthenticationManagerInterface
     */
    private $authenticationManager;

    /**
     * @var AuthorizationCheckerInterface
     */
    private $authorizationChecker;

    /**
     * @param AuthenticationManagerInterface $authenticationManager
     * @param AuthorizationCheckerInterface  $authorizationChecker
     */
    public function __construct(
        AuthenticationManagerInterface $authenticationManager,
        AuthorizationCheckerInterface $authorizationChecker
    ) {
        $this->authenticationManager = $authenticationManager;
        $this->authorizationChecker = $authorizationChecker;

        $this->logger = new NullLogger();
    }

    /**
     * @param LoggerInterface $logger
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param TokenInterface $token
     *
     * @return bool
     */
    public function authenticate(TokenInterface $token)
    {
        try {
            $this->logger->debug('Try to authenticate.', array('token' => $token));
            $this->authenticationManager->authenticate($token);

            return true;
        } catch (AuthenticationException $exception) {
            $this->logger->debug('Authentication failed.', array('token' => $token, 'exception' => $exception));

            return false;
        }
    }

    /**
     * @param TokenInterface $token
     * @param                $ip
     *
     * @return bool
     */
    public function vhost(TokenInterface $token, $ip)
    {
        return $this->hasAccess(
            $token,
            array(
                'ip' => $ip,
            ),
            'vhost'
        );
    }

    /**
     * @param TokenInterface $token
     * @param                $resource
     * @param                $name
     * @param                $permission
     *
     * @return bool
     */
    public function resource(TokenInterface $token, $resource, $name, $permission)
    {
        return $this->hasAccess(
            $token,
            array(
                'resource' => $resource,
                'name' => $name,
                'permission' => $permission,
            ),
            'resource'
        );
    }

    /**
     * @param TokenInterface $token
     * @param                $resource
     * @param                $name
     * @param                $permission
     * @param                $routing_key
     * @param                $variable_map_username
     * @param                $variable_map_vhost
     * @return bool
     */
    public function topic(TokenInterface $token, $resource, $name, $permission, $routing_key, $variable_map_username, $variable_map_vhost)
    {
        return $this->hasAccess(
            $token,
            array(
                'resource' => $resource,
                'name' => $name,
                'permission' => $permission,
                'routing_key' => $routing_key,
                'variable_map_username' => $variable_map_username,
                'variable_map_vhost' => $variable_map_vhost,
            ),
            'topic'
        );
    }

    /**
     * @param TokenInterface $token
     * @param array          $attributes
     * @param null           $subject
     *
     * @return bool
     */
    protected function hasAccess(TokenInterface $token, array $attributes, $subject = null)
    {
        try {
            $this->authenticationManager->authenticate($token);
            $isGranted = $this->authorizationChecker->isGranted($attributes, $subject);
            $this->logger->debug(
                sprintf('Access granted to "%s".', $subject),
                array('token' => $token, 'attributes' => $attributes, 'subject' => $subject)
            );

            return $isGranted;
        } catch (AuthenticationException $exception) {
            $this->logger->debug(
                sprintf('Access forbidden to "%s". %s', $subject, $exception->getMessage()),
                array('token' => $token, 'attributes' => $attributes, 'subject' => $subject, 'exception' => $exception)
            );

            return false;
        }
    }
}
