<?php

namespace Zizaco\Entrust\Middleware;

/*
 * This file is part of Entrust,
 * a role & permission management solution for Laravel.
 *
 * @license MIT
 * @package Zizaco\Entrust
 */

use Illuminate\Contracts\Auth\Guard;

class EntrustRole
{
    public const DELIMITER = '|';

    protected $auth;

    /**
     * Creates a new instance of the middleware.
     */
    public function __construct(Guard $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     */
    public function handle($request, \Closure $next, $roles)
    {
        if (!is_array($roles)) {
            $roles = explode(self::DELIMITER, $roles ?? '');
        }

        if ($this->auth->guest() || !$request->user()->hasRole($roles)) {
            abort(403);
        }

        return $next($request);
    }
}
