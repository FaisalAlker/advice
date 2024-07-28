<?php

/**
 * Author: Alker
 * Framework: Laravel 10
 * Used for Vuln: False SQLInjection Tool Scan in "?v=" Attack Pattern
 * Revision: 1
 */

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Use this class in
 * path: app/Http/Kernel.php
 * 
 * --------------------------------------------------------------------
 * 
 * Jika menggunakan SanitizeVersionParameter
 * pastikan query parameter v= tidak digunakan untuk query parameter lain
 */

class SanitizeVersionParameter
{
    public function handle(Request $request, Closure $next)
    {
        $version = $request->query('v');
        
        // Validate the version parameter
        if ($version && !preg_match('/^\d+\.\d+$/', $version)) {
            // If invalid, return a 400 Bad Request response
            return response('Invalid version parameter', 400);
        }

        return $next($request);
    }
}
