<?php

namespace RabbitMQAuth\Tests\Authentication;

use Prophecy\Prophecy\ObjectProphecy;
use Psr\Log\LoggerInterface;
use RabbitMQAuth\Authentication\AuthenticationCheckerInterface;
use RabbitMQAuth\Authentication\Authenticator;
use RabbitMQAuth\Authentication\Token\UserToken;
use RabbitMQAuth\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\User;

class AuthenticatorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var UserToken
     */
    private $token;

    /**
     * @var InMemoryUserProvider
     */
    private $userProvider;

    /**
     * @var AuthenticationCheckerInterface|ObjectProphecy
     */
    private $authenticationCheckerMock;

    /**
     * @var LoggerInterface|ObjectProphecy
     */
    private $loggerMock;

    /**
     * @var Authenticator
     */
    private $authenticator;

    public function setUp()
    {
        $this->token = new UserToken('user');

        $this->userProvider = new InMemoryUserProvider(array(
            'user' => array(
                'password' => 'user_password',
                'roles' => array('user_role_1'),
            ),
        ));
        $this->authenticationCheckerMock = $this->prophesize('RabbitMQAuth\Authentication\AuthenticationCheckerInterface');

        $this->loggerMock = $this->prophesize('Psr\Log\LoggerInterface');

        $this->authenticator = new Authenticator(
            $this->userProvider,
            $this->authenticationCheckerMock->reveal()
        );

        $this->authenticator->setLogger($this->loggerMock->reveal());
    }

    public function testAuthenticate()
    {
        $user = new User('user', 'user_password', array('user_role_1'));

        $this->authenticationCheckerMock
            ->checkAuthentication($user, $this->token)
            ->shouldBeCalled();

        $this->loggerMock
            ->info('Token authenticated.', array('token' => $this->token))
            ->shouldBeCalled();

        $this->assertEquals(
            $this->token,
            $this->authenticator->authenticate($this->token)
        );
    }

    /**
     * @expectedException \RabbitMQAuth\Exception\AuthenticationException
     * @expectedExceptionMessage my_fake_exception_message
     */
    public function testAuthenticateWillThrowAuthenticationException()
    {
        $user = new User('user', 'user_password', array('user_role_1'));

        $this->authenticationCheckerMock
            ->checkAuthentication($user, $this->token)
            ->willThrow(new AuthenticationException('my_fake_exception_message'))
            ->shouldBeCalled();

        try {
            $this->authenticator->authenticate($this->token);
        } catch (AuthenticationException $exception) {
            $this->assertEquals($this->token, $exception->getToken());
            $this->loggerMock
                ->info(
                    'Can\'t authenticate token : my_fake_exception_message.',
                    array('exception' => $exception, 'token' => $this->token)
                )
                ->shouldBeCalled();

            throw $exception;
        }
    }

    public function testSupports()
    {
        $this->authenticationCheckerMock
            ->support($this->token)
            ->willReturn(true)
            ->shouldBeCalled();

        $this->assertTrue($this->authenticator->supports($this->token));
    }
}
