<?php

namespace RabbitMQAuth\Authentication;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class ChainAuthenticationChecker implements AuthenticationCheckerInterface, LoggerAwareInterface
{
    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var array
     */
    private $authenticationCheckers;

    /**
     * @param array $authenticationCheckers
     */
    public function __construct(array $authenticationCheckers)
    {
        foreach ($authenticationCheckers as $authenticationChecker) {
            if (!$authenticationChecker instanceof AuthenticationCheckerInterface) {
                throw new \InvalidArgumentException(
                    sprintf('Expected argument of type "%s", "%s" given', '\RabbitMQAuth\Authentication\AuthenticationCheckerInterface', is_object($authenticationChecker) ? get_class($authenticationChecker) : gettype($authenticationChecker))
                );
            }
        }

        $this->authenticationCheckers = $authenticationCheckers;
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
        foreach ($this->authenticationCheckers as $authenticationChecker) {
            if ($authenticationChecker->support($token)) {
                $authenticationChecker->checkAuthentication($user, $token);

                return;
            }
        }
    }

    /**
     * @param TokenInterface $token
     *
     * @return bool
     */
    public function support(TokenInterface $token)
    {
        foreach ($this->authenticationCheckers as $authenticationChecker) {
            if ($authenticationChecker->support($token)) {
                return true;
            }
        }

        return false;
    }
}
