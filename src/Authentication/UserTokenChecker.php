<?php

namespace RabbitMQAuth\Authentication;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RabbitMQAuth\Authentication\Token\UserToken;
use RabbitMQAuth\Exception\AuthenticationFailException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class UserTokenChecker implements AuthenticationCheckerInterface, LoggerAwareInterface
{
    /**
     * @var LoggerInterface
     */
    protected $logger;

    public function __construct()
    {
        $this->logger = new NullLogger();
    }

    /**
     * Sets a logger.
     *
     * @param LoggerInterface $logger
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param UserInterface  $user
     * @param TokenInterface $token
     */
    public function checkAuthentication(UserInterface $user, TokenInterface $token)
    {
        if ($user->getUsername() !== $token->getUsername()) {
            $this->logger->debug(sprintf('Username not match. "%s" ≠ "%s".', $user->getUsername(), $token->getUsername()), array('user' => $user, 'token' => $token));
            throw new AuthenticationFailException('Username not match.');
        }
    }

    /**
     * @param TokenInterface $token
     *
     * @return bool
     */
    public function support(TokenInterface $token)
    {
        return $token instanceof UserToken;
    }
}
