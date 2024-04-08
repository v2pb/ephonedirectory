<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\Response;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Throwable;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that are not reported.
     *
     * @var array<int, class-string<Throwable>>
     */
    protected $dontReport = [
        //
    ];

    /**
     * A list of the inputs that are never flashed for validation exceptions.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    /**
     * Register the exception handling callbacks for the application.
     *
     * @return void
     */
    public function register()
    {
        $this->reportable(function (Throwable $e) {
            //
        });
    }

    public function render($request, Throwable $exception)
    {
        if ($exception instanceof MethodNotAllowedHttpException) {
            return response()->json(['message' => 'The requested method is not allowed.'], 405);
        }else if($exception instanceof AuthorizationException) {
            return response()->json(['message' => 'You do not have permission to access this resource.'], 403);
        }else if ($exception instanceof ThrottleRequestsException) {
            // $response->header('Content-Type', 'application/zip');
            return response()->json(['error' => 'Too many requests, please try again later.'], Response::HTTP_TOO_MANY_REQUESTS);
        }else if($exception instanceof \Exception) {
            return response()->json(['message' => 'Something went wrong.'], 400); //bad request
        }
 
        return parent::render($request, $exception);
    }

}
