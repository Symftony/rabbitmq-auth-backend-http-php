<?php

require_once '../vendor/autoload.php';
require_once 'bootstrap.php';

$authController->vhostAction(
    \Symfony\Component\HttpFoundation\Request::createFromGlobals()
)->send();
