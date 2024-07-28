<?php 

/**
 * Author: Alker
 * Framework: Laravel 10
 * Used for Vuln: Content Security Policy
 * Revision: 1
 */

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Str;

class ContentSecurityPolicy
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return \Illuminate\Http\Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // Generate a random nonce
        $nonce = Str::random(16);

        /**
         * Penggunaan Nonce agar CSP tetap bisa digunakan dalam file yang sama
         * 
         * Jika ingin mengunakan inline CSS (<style>) atau inline JS (<script>) gunakan nonce
         * Jika tidak menggunakan inline CSS atau inline JS (<script>) abaikan nonce
         * Silahkan sesuaikan jika digunakan pada img-src, font-src seperti pada format script-src
         * Silahkan tambahkan atau kurangi directive sesuai kebutuhan
         */


        // Define your CSP with nonce and multiple domains
        $csp = "default-src 'self'; 
                script-src 'self' 'nonce-$nonce' https://cdn.jsdelivr.net https://another-trusteddomain.com; 
                style-src 'self' 'nonce-$nonce' https://stackpath.bootstrapcdn.com https://another-trusteddomain.com; 
                img-src 'self' data:; 
                connect-src 'self'; 
                font-src 'self'; 
                object-src 'none'; 
                frame-ancestors 'none'; 
                form-action 'self'; 
                base-uri 'self';";

        // Add the CSP header to the response
        $response->headers->set('Content-Security-Policy', $csp);

        // Pass the nonce to views
        view()->share('cspNonce', $nonce);

        return $response;
    }
}
