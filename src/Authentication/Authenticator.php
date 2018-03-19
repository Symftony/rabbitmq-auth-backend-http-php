<?php

namespace RabbitMQAuth\Authentication;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RabbitMQAuth\Exception\AuthenticationException;
use RabbitMQAuth\Exception\AuthenticationFailException;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class Authenticator implements AuthenticationProviderInterface, LoggerAwareInterface
{
    /**
     * The logger instance.
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    /**
     * @var AuthenticationCheckerInterface
     */
    private $authenticationChecker;

    /**
     * @param UserProviderInterface          $userProvider
     * @param AuthenticationCheckerInterface $authenticationChecker
     */
    public function __construct(
        UserProviderInterface $userProvider,
        AuthenticationCheckerInterface $authenticationChecker
    ) {
        $this->userProvider = $userProvider;
        $this->authenticationChecker = $authenticationChecker;
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
     * @param TokenInterface $token
     *
     * @return TokenInterface
     */
    public function authenticate(TokenInterface $token)
    {
        try {
            $user = $this->userProvider->loadUserByUsername($token->getUsername());

            $this->authenticationChecker->checkAuthentication($user, $token);
            $token->setUser($user);
            $token->setAuthenticated(true);
            $this->logger->info('Token authenticated.', array('token' => $token));

            return $token;
        } catch (AuthenticationException $exception) {
            $exception->setToken($token);
            $this->logger->info(sprintf('Can\'t authenticate token : %s.', $exception->getMessage()), array('exception' => $exception, 'token' => $token));

            throw $exception;
        } catch (\RuntimeException $exception) {
            $exception->setToken($token);
            $this->logger->info(sprintf('Can\'t authenticate token : %s.', $exception->getMessage()), array('exception' => $exception, 'token' => $token));

            throw new AuthenticationFailException('Can\'t authenticate token.', 0, $exception);
        }
    }

    /**
     * @param TokenInterface $token
     * @return mixed
     */
    public function supports(TokenInterface $token)
    {
        return $this->authenticationChecker->support($token);
    }
}
