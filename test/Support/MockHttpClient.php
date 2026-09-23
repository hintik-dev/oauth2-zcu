<?php declare(strict_types = 1);

namespace Hintik\OAuth2\Client\Tests\Support;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

/**
 * Guzzle client queued with canned responses, recording every request it sends.
 */
final class MockHttpClient
{

	/** @var array<int, array{request: RequestInterface, options: mixed[]}> */
	public array $history = [];

	public readonly Client $client;

	/**
	 * @param Response[] $responses
	 */
	public function __construct(array $responses)
	{
		$stack = HandlerStack::create(new MockHandler($responses));
		$stack->push(Middleware::history($this->history));

		$this->client = new Client(['handler' => $stack]);
	}

	/**
	 * @param mixed[] $body
	 */
	public static function json(array $body, int $status = 200): Response
	{
		return new Response($status, ['Content-Type' => 'application/json'], (string) json_encode($body));
	}

	public function lastRequest(): RequestInterface
	{
		$last = end($this->history);

		if ($last === false) {
			throw new \RuntimeException('No request was recorded.');
		}

		return $last['request'];
	}

	public function requestAt(int $index): RequestInterface
	{
		return $this->history[$index]['request'];
	}

	public function requestCount(): int
	{
		return count($this->history);
	}

}
