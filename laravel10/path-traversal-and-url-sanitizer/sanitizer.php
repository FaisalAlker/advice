<?php

/**
 * Author: Alker
 * Framework: Laravel 10
 * Used for Vuln: Path Traversal and XSS
 * Revision: 2
 */

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class SanitizeUrl
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // Decode URL to handle any encoded characters like %2e%2e
        $decodedPath = urldecode($request->path());

        // Sanitize the path by removing any path traversal attempts (e.g., ../ or ..\\)
        if (strpos($decodedPath, '../') !== false || strpos($decodedPath, '..\\') !== false) {
            return response()->json(['error' => 'Invalid URL'], 400);
        }

        // Optionally: You can sanitize query parameters to avoid malicious input
        $queryParams = $request->query();
        foreach ($queryParams as $key => $value) {
            // Strip tags and remove special characters in query parameters
            $queryParams[$key] = filter_var($value, FILTER_SANITIZE_STRING);
        }

        // You can set sanitized query parameters back to the request if needed
        $request->query->replace($queryParams);

        return $next($request);
    }
}
