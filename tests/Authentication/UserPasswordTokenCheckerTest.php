<?php

namespace RabbitMQAuth\Tests\Authentication;

use Prophecy\Prophecy\ObjectProphecy;
use RabbitMQAuth\Authentication\UserPasswordTokenChecker;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class UserPasswordTokenCheckerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var UserInterface|ObjectProphecy
     */
    private $userMock;

    /**
     * @var TokenInterface|ObjectProphecy
     */
    private $tokenMock;

    /**
     * @var UserPasswordTokenChecker
     */
    private $userPasswordTokenChecker;

    public function setUp()
    {
        $this->userMock = $this->prophesize('Symfony\Component\Security\Core\User\UserInterface');
        $this->tokenMock = $this->prophesize('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');

        $this->userPasswordTokenChecker = new UserPasswordTokenChecker();
    }

    public function testCheckAuthentication()
    {
        $this->userMock
            ->getUsername()
            ->willReturn('my_fake_username')
            ->shouldBeCalled();
        $this->userMock
            ->getPassword()
            ->willReturn('my_fake_password')
            ->shouldBeCalled();

        $this->tokenMock
            ->getUsername()
            ->willReturn('my_fake_username')
            ->shouldBeCalled();
        $this->tokenMock
            ->getCredentials()
            ->willReturn('my_fake_password')
            ->shouldBeCalled();

        $this->userPasswordTokenChecker->checkAuthentication(
            $this->userMock->reveal(),
            $this->tokenMock->reveal()
        );
    }

    /**
     * @dataProvider authenticationFailDataProvider
     *
     * @param $userUsername
     * @param $userPassword
     * @param $tokenUsername
     * @param $tokenPassword
     * @param $expectedExceptionMessage
     */
    public function testCheckAuthenticationWillThrowAuthenticationFailException($userUsername, $userPassword, $tokenUsername, $tokenPassword, $expectedExceptionMessage)
    {
        $this->setExpectedException('\RabbitMQAuth\Exception\AuthenticationFailException', $expectedExceptionMessage);

        $this->userMock
            ->getUsername()
            ->willReturn($userUsername)
            ->shouldBeCalled();
        if ($userPassword) {
            $this->userMock
                ->getPassword()
                ->willReturn($userPassword)
                ->shouldBeCalled();
        }

        $this->tokenMock
            ->getUsername()
            ->willReturn($tokenUsername)
            ->shouldBeCalled();
        if ($tokenPassword) {
            $this->tokenMock
                ->getCredentials()
                ->willReturn($tokenPassword)
                ->shouldBeCalled();
        }

        $this->userPasswordTokenChecker->checkAuthentication(
            $this->userMock->reveal(),
            $this->tokenMock->reveal()
        );
    }

    public function authenticationFailDataProvider()
    {
        return array(
            array(
                'username', null, 'other_name', null, 'Username not match.',
            ),
            array(
                'username', 'password', 'username', 'other_password', 'Wrong Password.',
            ),
        );
    }

    public function supportDataProvider()
    {
        return array(
            array($this->prophesize('RabbitMQAuth\Authentication\Token\UserToken')->reveal(), false),
            array($this->prophesize('RabbitMQAuth\Authentication\Token\UserPasswordToken')->reveal(), true),
        );
    }

    /**
     * @dataProvider supportDataProvider
     *
     * @param $token
     * @param $expected
     */
    public function testSupport($token, $expected)
    {
        $this->assertEquals($expected, $this->userPasswordTokenChecker->support($token));
    }
}
