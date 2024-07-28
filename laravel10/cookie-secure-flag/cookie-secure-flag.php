<?php 

/**
 * Author: Alker
 * Framework: Laravel 10
 * Used for Vuln: TLS cookie without secure flag set 
 * Revision: 1
 */

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;
use Symfony\Component\HttpFoundation\Cookie;

class VerifyCsrfToken extends Middleware
{
    /**
     * The names of the cookies that should be sent with the request.
     *
     * @var array
     */
    protected $addHttpCookie = true;

    /**
     * Default Construct of the parameters for the Cookie class Constructor
     * 
     * public function __construct(
     *  string $name, 
     *  string $value = null, 
     *  int $expire = 0, 
     *  string $path = '/', 
     *  string $domain = null, 
     *  bool $secure = false, 
     *  bool $httpOnly = true, 
     *  bool $raw = false, 
     *  string $sameSite = null
     * )
     */
    
    /**
     * Add the CSRF token to the response cookies.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Http\Response|\Illuminate\Http\JsonResponse  $response
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse
     */
    protected function addCookieToResponse($request, $response)
    {
        $config = config('session');

        /**
         * The parameters are:
         *
         * name: Name of the cookie.
         * value: Value of the cookie.
         * expire: Expiration time of the cookie.
         * path: Path on the server where the cookie will be available.
         * domain: Domain that the cookie is available to.
         * secure: Indicates that the cookie should only be transmitted over a secure HTTPS connection.
         * httpOnly: When true, the cookie will be made accessible only through the HTTP protocol.
         * raw: When true, the cookie's value will not be URL-encoded.
         * sameSite: Restricts how cookies are sent with cross-site requests.
        */

        $response->headers->setCookie(
            new Cookie(
                'XSRF-TOKEN',                       // Name of the cookie
                $request->session()->token(),       // Value of the cookie
                time() + 60 * $config['lifetime'],  // Expiration time
                $config['path'],                    // Path
                $config['domain'],                  // Domain
                true,                               // Secure flag
                $config['http_only'],               // HttpOnly flag
                false,                              // Raw flag
                $config['same_site'] ?? null        // SameSite attribute
            )
        );

        return $response;
    }
}
