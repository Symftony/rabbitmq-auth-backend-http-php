<?php

namespace RabbitMQAuth\Tests\Authentication;

use Prophecy\Prophecy\ObjectProphecy;
use RabbitMQAuth\Authentication\AuthenticationCheckerInterface;
use RabbitMQAuth\Authentication\ChainAuthenticationChecker;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class ChainAuthenticationCheckerTest extends \PHPUnit_Framework_TestCase
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
     * @var AuthenticationCheckerInterface|ObjectProphecy
     */
    private $authenticationCheckerMock;

    /**
     * @var ChainAuthenticationChecker
     */
    private $chainAuthenticationChecker;

    public function setUp()
    {
        $this->userMock = $this->prophesize('Symfony\Component\Security\Core\User\UserInterface');
        $this->tokenMock = $this->prophesize('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');

        $this->authenticationCheckerMock = $this->prophesize('RabbitMQAuth\Authentication\AuthenticationCheckerInterface');

        $this->chainAuthenticationChecker = new ChainAuthenticationChecker(array(
            $this->authenticationCheckerMock->reveal(),
        ));
    }

    public function testCheckAuthentication()
    {
        $this->authenticationCheckerMock
            ->support($this->tokenMock->reveal())
            ->willReturn(true)
            ->shouldBeCalled();

        $this->authenticationCheckerMock
            ->checkAuthentication($this->userMock->reveal(), $this->tokenMock->reveal())
            ->shouldBeCalled();

        $this->chainAuthenticationChecker->checkAuthentication(
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
        $this->setExpectedException('\Exception', $expectedExceptionMessage);

        $this->authenticationCheckerMock
            ->support($this->tokenMock->reveal())
            ->willReturn(true)
            ->shouldBeCalled();

        $this->authenticationCheckerMock
            ->checkAuthentication($this->userMock->reveal(), $this->tokenMock->reveal())
            ->willThrow(new \Exception($expectedExceptionMessage))
            ->shouldBeCalled();

        $this->chainAuthenticationChecker->checkAuthentication(
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

    public function testSupport()
    {
        $this->authenticationCheckerMock
            ->support(true)
            ->willReturn(true)
            ->shouldBeCalled();

        $this->assertTrue($this->chainAuthenticationChecker->support($this->tokenMock->reveal()));
    }
}
