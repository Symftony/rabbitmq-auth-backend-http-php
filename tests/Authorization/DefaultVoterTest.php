<?php

namespace RabbitMQAuth\Tests\Authorization;

use Psr\Log\LoggerInterface;
use RabbitMQAuth\Authentication\Token\UserToken;
use RabbitMQAuth\Authorization\DefaultVoter;

class DefaultVoterTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var LoggerInterface
     */
    private $loggerMock;

    public function setUp()
    {
        $this->loggerMock = $this->prophesize(LoggerInterface::class);
    }

    public function testVoteAdmin()
    {
        $defaultVoter = new DefaultVoter(array(
            'my_fake_admin' => array(
                'isAdmin' => true,
            ),
        ));
        $defaultVoter->setLogger($this->loggerMock->reveal());
        $tokenMock = $this->prophesize(UserToken::class);
        $tokenMock
            ->getUsername()
            ->willReturn('my_fake_admin')
            ->shouldBeCalled();

        $this->loggerMock
            ->info('Token allow: Admin has all grant.', array('subject' => null, 'attributes' => array()))
            ->shouldBeCalled();

        $this->assertTrue($defaultVoter->vote($tokenMock->reveal(), null, array()));
    }

    public function testVoteSubjectUnknow()
    {
        $defaultVoter = new DefaultVoter(array());
        $defaultVoter->setLogger($this->loggerMock->reveal());
        $tokenMock = $this->prophesize(UserToken::class);
        $tokenMock
            ->getUsername()
            ->willReturn(null)
            ->shouldBeCalled();

        $this->loggerMock
            ->notice('Token deny: subject unknow "my_unknow_subject".', array('subject' => 'my_unknow_subject', 'attributes' => array()))
            ->shouldBeCalled();

        $this->assertFalse($defaultVoter->vote($tokenMock->reveal(), 'my_unknow_subject', array()));
    }

    public function testVotePermissionNotConfigure()
    {
        $defaultVoter = new DefaultVoter(array());
        $defaultVoter->setLogger($this->loggerMock->reveal());
        $tokenMock = $this->prophesize(UserToken::class);
        $tokenMock
            ->getUsername()
            ->willReturn(null)
            ->shouldBeCalled();
        $tokenMock
            ->getVhost()
            ->willReturn('my_fake_vhost')
            ->shouldBeCalled();

        $this->loggerMock
            ->notice('Token deny: permission "my_fake_vhost->ip" not configured.', array('subject' => 'vhost', 'attributes' => array('ip' => 'my_fake_ip')))
            ->shouldBeCalled();

        $this->assertFalse($defaultVoter->vote($tokenMock->reveal(), 'vhost', array('ip' => 'my_fake_ip')));
    }

    public function testVoteVhost()
    {
        $defaultVoter = new DefaultVoter(array(
            'my_fake_user' => array(
                'my_fake_vhost' => array(
                    'ip' => '.*',
                ),
            ),
        ));
        $defaultVoter->setLogger($this->loggerMock->reveal());
        $tokenMock = $this->prophesize(UserToken::class);
        $tokenMock
            ->getUsername()
            ->willReturn('my_fake_user')
            ->shouldBeCalled();
        $tokenMock
            ->getVhost()
            ->willReturn('my_fake_vhost')
            ->shouldBeCalled();

        $this->loggerMock
            ->info('Token allow.', array('subject' => 'vhost', 'attributes' => array('ip' => 'my_fake_ip')))
            ->shouldBeCalled();

        $this->assertTrue($defaultVoter->vote($tokenMock->reveal(), 'vhost', array('ip' => 'my_fake_ip')));
    }

    public function testVoteResource()
    {
        $defaultVoter = new DefaultVoter(array(
            'my_fake_user' => array(
                'my_fake_vhost' => array(
                    'read' => '.*',
                ),
            ),
        ));
        $defaultVoter->setLogger($this->loggerMock->reveal());
        $tokenMock = $this->prophesize(UserToken::class);
        $tokenMock
            ->getUsername()
            ->willReturn('my_fake_user')
            ->shouldBeCalled();
        $tokenMock
            ->getVhost()
            ->willReturn('my_fake_vhost')
            ->shouldBeCalled();

        $this->loggerMock
            ->info('Token allow.', array('subject' => 'resource', 'attributes' => array('permission' => 'read', 'name' => 'my_fake_attribute_name')))
            ->shouldBeCalled();

        $this->assertTrue(
            $defaultVoter->vote(
                $tokenMock->reveal(),
                'resource',
                array(
                    'permission' => 'read',
                    'name' => 'my_fake_attribute_name'
                )
            )
        );
    }
}
