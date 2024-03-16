<?php

use App\Http\Controllers\ApiController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|5
*/
//role related
// Route::post('100/getProfileData', [ApiController::class, 'getProfileData']);

Route::post('100/admin_register', [ApiController::class, 'admin_register']);

Route::middleware('jwt.verify')->group(function () {
    //100
    //profile

    //role
    Route::post('100/create_role', [ApiController::class, 'create_role']);
    Route::post('100/get_role', [ApiController::class, 'get_role']);
    Route::post('100/get_all_role', [ApiController::class, 'get_all_role']);
    Route::post('100/getRoleById', [ApiController::class, 'getRoleById']);
    Route::post('100/role_update', [ApiController::class, 'role_update']);



    //ImportPhoneDirectoryFormHome
    Route::post('100/importFile', [ApiController::class, 'importFile']);
    Route::post('100/deleteDataById', [ApiController::class, 'deleteDataById']);

    //PhoneDirectory
    Route::post('100/create_phone_dir', [ApiController::class, 'create_phone_dir']);
    Route::post('100/get_phone_dir', [ApiController::class, 'get_phone_dir']);
    Route::post('100/get_role_', [ApiController::class, 'get_role_']);
    Route::post('100/get_phone_dir_detail', [ApiController::class, 'get_phone_dir_detail']);
    Route::post('100/phone_dir_update', [ApiController::class, 'phone_dir_update']);


    //User Management
    Route::post('100/getUsersByRoleId', [ApiController::class, 'getUsersByRoleId']);

    Route::post('100/getUserById', [ApiController::class, 'getUserById']);
    Route::post('100/updateUser', [ApiController::class, 'updateUser']);

    //200
    Route::post('200/get_phone_dir', [ApiController::class, 'get_phone_dir']);
});
//auth
Route::post('register', [ApiController::class, 'register']);
Route::post('login', [ApiController::class, 'login']);
