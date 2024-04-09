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

Route::middleware('ephone_admin')->group(function () {
    Route::post('admin_register', [ApiController::class, 'admin_register']);
    //role
    Route::post('create_role', [ApiController::class, 'create_role']);
    Route::post('get_role', [ApiController::class, 'get_role']);
    Route::post('get_all_role', [ApiController::class, 'get_all_role']);
    Route::post('getRoleById', [ApiController::class, 'getRoleById']);
    Route::post('role_update', [ApiController::class, 'role_update']);

    //ImportPhoneDirectoryFormHome
    Route::post('importFile', [ApiController::class, 'importFile']);
    Route::post('deleteDataById', [ApiController::class, 'deleteDataById']);

    //PhoneDirectory
    Route::post('create_phone_dir', [ApiController::class, 'create_phone_dir']);
    Route::post('get_main_phone_dir', [ApiController::class, 'get_phone_dir']); //dup
    Route::post('get_role_', [ApiController::class, 'get_role_']);
    Route::post('get_phone_dir_detail', [ApiController::class, 'get_phone_dir_detail']);
    Route::post('phone_dir_update', [ApiController::class, 'phone_dir_update']);

    //User Management
    Route::post('getUsersByRoleId', [ApiController::class, 'getUsersByRoleId']);

    Route::post('getUserById', [ApiController::class, 'getUserById']);
    Route::post('updateUser', [ApiController::class, 'updateUser']);
});


Route::middleware('ephone_user')->group(function () {
    Route::post('get_phone_dir', [ApiController::class, 'get_phone_dir']);  //dup
});
//auth
Route::post('register', [ApiController::class, 'register']);
Route::post('login', [ApiController::class, 'login'])->name('login');
// Route::post('/login', [ApiController::class, 'login'])->middleware("throttle:3,1,login")->name('login');