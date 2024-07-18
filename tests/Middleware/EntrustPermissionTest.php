<?php

use Mockery as m;
use Zizaco\Entrust\Middleware\EntrustPermission;

class EntrustPermissionTest extends MiddlewareBase
{
    public function testHandleIsGuestWithNoPermissionShouldAbort403()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $guard = m::mock('Illuminate\Contracts\Auth\Guard[guest]');
        $request = $this->mockRequest();

        $middleware = new EntrustPermission($guard);

        /*
        |------------------------------------------------------------
        | Expectation
        |------------------------------------------------------------
        */
        $guard->shouldReceive('guest')->andReturn(true);
        $request->user()->shouldReceive('can')->andReturn(false);

        $middleware->handle($request, function () {}, null, null, true);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertAbortCode(403);
    }

    public function testHandleIsGuestWithPermissionShouldAbort403()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $guard = m::mock('Illuminate\Contracts\Auth\Guard');
        $request = $this->mockRequest();

        $middleware = new EntrustPermission($guard);

        /*
        |------------------------------------------------------------
        | Expectation
        |------------------------------------------------------------
        */
        $guard->shouldReceive('guest')->andReturn(true);
        $request->user()->shouldReceive('can')->andReturn(true);

        $middleware->handle($request, function () {}, null, null);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertAbortCode(403);
    }

    public function testHandleIsLoggedInWithNoPermissionShouldAbort403()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $guard = m::mock('Illuminate\Contracts\Auth\Guard');
        $request = $this->mockRequest();

        $middleware = new EntrustPermission($guard);

        /*
        |------------------------------------------------------------
        | Expectation
        |------------------------------------------------------------
        */
        $guard->shouldReceive('guest')->andReturn(false);
        $request->user()->shouldReceive('can')->andReturn(false);

        $middleware->handle($request, function () {}, null, null);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertAbortCode(403);
    }

    public function testHandleIsLoggedInWithPermissionShouldNotAbort()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $guard = m::mock('Illuminate\Contracts\Auth\Guard');
        $request = $this->mockRequest();

        $middleware = new EntrustPermission($guard);

        /*
        |------------------------------------------------------------
        | Expectation
        |------------------------------------------------------------
        */
        $guard->shouldReceive('guest')->andReturn(false);
        $request->user()->shouldReceive('can')->andReturn(true);

        $middleware->handle($request, function () {}, null, null);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertDidNotAbort();
    }
}
