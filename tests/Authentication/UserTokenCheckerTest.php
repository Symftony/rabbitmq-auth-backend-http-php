<?php

namespace RabbitMQAuth\Tests\Authentication;

use Prophecy\Prophecy\ObjectProphecy;
use RabbitMQAuth\Authentication\UserPasswordTokenChecker;
use RabbitMQAuth\Authentication\UserTokenChecker;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class UserTokenCheckerTest extends \PHPUnit_Framework_TestCase
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

        $this->userPasswordTokenChecker = new UserTokenChecker();
    }

    public function testCheckAuthentication()
    {
        $this->userMock
            ->getUsername()
            ->willReturn('my_fake_username')
            ->shouldBeCalled();

        $this->tokenMock
            ->getUsername()
            ->willReturn('my_fake_username')
            ->shouldBeCalled();

        $this->userPasswordTokenChecker->checkAuthentication(
            $this->userMock->reveal(),
            $this->tokenMock->reveal()
        );
    }

    /**
     * @expectedException \RabbitMQAuth\Exception\AuthenticationFailException
     * @expectedExceptionMessage Username not match.
     */
    public function testCheckAuthenticationWillThrowAuthenticationFailException()
    {
        $this->userMock
            ->getUsername()
            ->willReturn('username')
            ->shouldBeCalled();

        $this->tokenMock
            ->getUsername()
            ->willReturn('other_name')
            ->shouldBeCalled();

        $this->userPasswordTokenChecker->checkAuthentication(
            $this->userMock->reveal(),
            $this->tokenMock->reveal()
        );
    }

    public function supportDataProvider()
    {
        return array(
            array($this->prophesize('RabbitMQAuth\Authentication\Token\UserToken')->reveal(), true),
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
