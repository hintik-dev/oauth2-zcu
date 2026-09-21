<?php declare(strict_types = 1);

namespace HintikDev\OAuth2\Client\Tests\Support;

use Nette\Http\Request;
use Nette\Http\Response;
use Nette\Http\Session;
use Nette\Http\UrlScript;

/**
 * Session double that keeps data in $_SESSION without ever starting a real PHP session.
 */
final class ArraySession extends Session
{

	public function __construct()
	{
		parent::__construct(new Request(new UrlScript('https://example.test/')), new Response());

		$_SESSION = ['__NF' => ['DATA' => []]];
	}

	public function start(): void
	{
		// no-op
	}

	public function autoStart(bool $forWrite): void
	{
		// no-op
	}

	public function isStarted(): bool
	{
		return true;
	}

}
