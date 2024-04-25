<?php

namespace App\Http\Controllers;

use App\Models\PhoneDirectory;
use App\Models\Roles;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use App\Models\User;
use App\Models\TokenManagement;
use App\Models\UserLog;
use Tymon\JWTAuth\Facades\JWTAuth;
use Maatwebsite\Excel\Facades\Excel;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\DB;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;

class ApiController extends Controller
{
    // public function register(Request $request)
    // {
    //     //! ADD validation check for the role_id table in status (exists rule)

    //     $encryptedPassword = base64_decode($request->input('password'));
    //     $iv = base64_decode($request->input('iv'));
    //     $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');
    //     $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    //     if ($decryptedPassword == false) {
    //         return response()->json(["msg" => "Password decryption failed"]);
    //     }
    //     $dataToValidate = $request->all();
    //     $dataToValidate['password'] =  $decryptedPassword;
    //     $rules = [
    //         'name' => 'required|string|name_rule|max:255',
    //         'phone' => 'required|numeric|phone_rule|unique:users,phone',
    //         'password' => 'required|string|min:6|password_rule',
    //         'ac' => 'required|integer',
    //         'district' => 'required|integer',
    //         // 'role_id' => 'required|integer',
    //         'designation' => 'required|string|name_rule|max:255',
    //         'email' => 'required|email|max:255',
    //         // 'psno' => 'required|integer',
    //         'iv' => ['required', 'string',  Rule::notIn(['<script>', '</script>', 'min:16'])],
    //     ];

    //     // Define the allowed parameters
    //     $allowedParams = array_keys($rules); //['name','phone', ....];

    //     // Check if the request only contains the allowed parameters
    //     if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
    //         return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
    //     }

    //     // return response()->json(['request_data' => $request->all()], 200);
    //     $validator = Validator::make($dataToValidate,  $rules);

    //     if ($validator->fails()) {
    //         $firstErrorMessage = $validator->errors()->first();
    //         return response()->json(['msg' => $firstErrorMessage], 400);
    //     }

    //     $user = new User([
    //         'name' => $request->name,
    //         'phone' => $request->phone,
    //         'password' => bcrypt($request->password),
    //         'ac' => $request->ac,
    //         // 'role_id' => $request->role_id,
    //         'role_id' => 200, //fix role_id for user
    //         'designation' => $request->designation,
    //         'email' => $request->email,
    //         'district' => $request->district,
    //         // 'psno' => $request->psno,
    //     ]);

    //     $user->save();

    //     return response()->json(['msg' => "Success"], 201);
    // }

    //! need to fixed this function for other project ecell
    public function login(Request $request)
    {
        // Define the allowed parameters
        $allowedParams = ['iv', 'phone', 'password']; //remove user_role

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        try {
            $encryptedPhone = base64_decode($request->input('phone'));
            $encryptedPassword = base64_decode($request->input('password'));
            $user_role_string = $request->input('user_role');
            $iv = base64_decode($request->input('iv'));
            $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');

            $decryptedPhone = openssl_decrypt($encryptedPhone, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

            $validator = Validator::make(
                ['phone' => $decryptedPhone, 'password' => $decryptedPassword, 'iv' => $request->input('iv')],
                [
                    'phone' => 'required|numeric|phone_rule|exists:users,phone',
                    'password' => 'required|string|password_rule|min:6',
                    'iv' => ['required', 'string',  Rule::notIn(['<script>', '</script>', 'min:16'])],
                ]
            );

            if ($validator->fails()) {
                // Return the very first error message directly
                $firstErrorMessage = $validator->errors()->first();
                return response()->json(['msg' => $firstErrorMessage], 400);
            }

            $user = User::where('phone', $decryptedPhone)->first();

            if (!$user) {
                return response()->json(['msg' => 'User not found'], 404);
            }

            if ($user->is_active !== true) {
                return response()->json(['msg' => 'User not activated'], 401);
            }

            // form validated....check credentials now..
            $log_user = new UserLog();
            $log_user->user_id = $decryptedPhone;
            $log_user->user_ip = $request->getClientIp();
            $log_user->mac_id =exec('getmac');

            if (User::where('phone', $decryptedPhone)->count() != 0) {
                $log_user->phone_number = $decryptedPhone;
                $log_user->user_name = User::select('name')->where('phone', $decryptedPhone)->first()->name;
                $log_user->user_role = User::select('role_id')->where('phone', $decryptedPhone)->first()->role_id;
                // $log_user->phone_number = User::where('phone', $decryptedPhone)->first()->phone;
                // $log_user->email = User::where('phone', $decryptedPhone)->first()->email;

            } else {
                $log_user->phone_number = $decryptedPhone;
                $log_user->user_name = "Un-registered User";
                $log_user->user_role = "NA";
            }

            $credentials = ['phone' => $decryptedPhone, 'password' => $decryptedPassword];
            if (!$token = JWTAuth::attempt($credentials)) {
                $log_user->is_login_successful = false;
                $log_user->save();
                return response()->json(['msg' => 'Unauthorized'], 401);
            }

            //before login attempt check if user already has active token, if yes make it invalid also delete the entry from token management table
            if (TokenManagement::where('userid', $decryptedPhone)->count() > 0) {
                $oldToken = TokenManagement::where('userid', $decryptedPhone)->first()->active_token;
                try { //check if the token is already expired
                    JWTAuth::setToken($oldToken)->invalidate();
                } catch (TokenExpiredException $e) {
                    //token has already expired
                }
                TokenManagement::where('userid', $decryptedPhone)->firstorfail()->delete();
            }

            //before sending response store the new token in the token management table
            $tokenEntry = new TokenManagement();
            $tokenEntry->userid = $decryptedPhone;
            $tokenEntry->active_token = $token;

            //log 
            $log_user->is_login_successful = true;
            $log_user->save();
            
            if ($tokenEntry->save()) {
                $user = User::where('phone', $decryptedPhone)->first();
                return response()->json(['token' => $token, 'role' => $user['role_id'], "name" => $user["name"], "ac_name" => $user->acdetail->ac_name, "msg" => "Successful"], 200);
            } else {
                return response()->json(['msg' => 'The Token details could not be saved!'], 401);
            }
        } catch (\Exception $e) {

            return response()->json(['msg' => 'Something went wrong!'], 400);
        }
    }



    public function getProfileData(Request $request)
    {
        $rules = [
            'uuid' => 'required|numeric|phone_rule|exists:users,phone'
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['uuid'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(),  $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }

        $user = User::where('phone', $request->uuid)->firstOrFail();
        return response()->json($user);
    }

    // public function PhoneDirectory(Request $request)
    // {
    //     $rules = [
    //         'slno' => 'required|integer',
    //         'name' => 'required|name_rule',
    //         'designation' => 'required|name_rule',
    //         'role_name' => 'required|name_rule',
    //         'contact_no' => 'required|numeric|phone_rule',
    //         'email' => 'required|email',
    //         // 'psno' => 'required|integer', //newly added
    //     ];

    //     // Define the allowed parameters
    //     $allowedParams = array_keys($rules); //['slno', 'name', ...];

    //     // Check if the request only contains the allowed parameters
    //     if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
    //         return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
    //     }

    //     $validator = Validator::make($request->all(), $rules);

    //     if ($validator->fails()) {
    //         return response()->json(['msg' => $validator->errors()->first()], 400);
    //     }

    //     $phoneDir = PhoneDirectory::create($rules);

    //     return response()->json($phoneDir, 201);
    // }

    public function create_role(Request $request)
    {
        $rules = [
            'slno' => 'required|integer',
            'role_name' => 'required|string|name_rule|max:255',
            'created_by' => 'required|numeric|phone_rule|exists:users,phone',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['slno', ..];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $roleData = $validator->validated();

        $user = User::where('phone', $roleData['created_by'])->first();



        if (!$user || is_null($user->district) || is_null($user->ac)) {
            return response()->json(['error' => 'User not found or district_id not available'], 404);
        }
        $roleData['district_id'] = $user->district;
        $roleData['ac'] = $user->ac;


        $role = Roles::create($roleData);

        return response()->json($role, 201);
    }

    public function create_phone_dir(Request $request)
    {
        // Validation rules
        $rules = [
            'slno' => 'required|integer',
            'name' => 'required|string|name_rule|max:255',
            'designation' => 'required|string|name_rule|max:255',
            'role_id' => 'required|integer',
            'contact_no' => 'required|numeric|phone_rule',
            'email' => 'required|string|email|max:255',
            'created_by' => 'required|numeric|phone_rule|exists:users,phone',
            'psno' => 'required|integer', //newly added
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['slno', ...];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);


        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $userDistrictId = User::where('phone', $request->created_by)->value('district');
        $userACId = User::where('phone', $request->created_by)->value('ac');

        if (!$userACId) {
            return response()->json(['message' => 'User or district not found'], 404);
        }


        $roleData = $validator->validated();
        $roleData['district'] = $userDistrictId;
        $roleData['ac'] = $userACId;


        $role = PhoneDirectory::create($roleData);


        return response()->json($role, 201);
    }

    public function get_role(Request $request)
    {
        $rules = [
            'uuid' => 'required|numeric|phone_rule|exists:users,phone',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['uuid'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $data = $validator->validated();

        $userACId = User::where('phone', $data['uuid'])->value('ac');
        if (!$userACId) {
            return response()->json(['message' => 'User or district not found'], 404);
        }
        $roles = Roles::where("ac", $userACId)->get();
        return response()->json($roles);
    }

    public function get_role_(Request $request)
    {
        $rules = [
            'uuid' => 'required|numeric|phone_rule|exists:users,phone',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['uuid'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $data = $validator->validated();
        $userACId = User::where('phone', $data['uuid'])->value('ac');

        if (!$userACId) {
            return response()->json(['message' => 'User or Ac not found'], 404);
        }

        $roles = Roles::where("ac", $userACId)->get();
        $transformedRoles = $roles->map(function ($role) {
            return [
                'opt_id' => $role->id,
                'opt_name' => $role->role_name,
            ];
        });

        return response()->json($transformedRoles);
    }

    public function get_all_role(Request $request)
    {
        $rules = [
            'uuid' => 'required|numeric|phone_rule|exists:users,phone',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['uuid'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $data = $validator->validated();
        $userACId = User::where('phone', $data['uuid'])->value('ac');

        if (!$userACId) {
            return response()->json(['message' => 'User or district not found'], 404);
        }
        $roles = Roles::where("ac", $userACId)
            ->select('id as opt_id', 'role_name as opt_name')
            ->get();

        return response()->json($roles);
    }

    public function getRoleById(Request $request)
    {
        $rules = [
            'id' => 'required|integer|exists:roles,id',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['id'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }

        $data = $validator->validated();

        $id = Roles::where('id',  $data['id'])->first();
        return response()->json($id);
    }

    public function role_update(Request $request)
    {
        $rules = [
            'slno' => 'required|integer',
            'id' => 'required|integer|exists:roles,id',
            'role_name' => 'required|string|name_rule|max:255',
            'updated_by' => 'required|numeric|phone_rule',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['slno', 'id',...];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $role = Roles::findOrFail($request->input('id'));
        $role->update([
            'slno' => $request->input('slno'),
            'role_name' => $request->input('role_name'),
            'updated_by' => $request->input('updated_by'),
        ]);


        return response()->json($role);
    }

    public function phone_dir_update(Request $request)
    {

        $rules = [
            'id' => 'required|integer|exists:phone_dir,id',
            'slno' => 'required|integer',
            'name' => 'required|name_rule|max:255',
            'designation' => 'required|name_rule|max:255',
            'role_id' => 'required|integer|exists:roles,id',
            'contact_no' => 'required|numeric|phone_rule',
            'email' => 'required|email',
            'updated_by' => 'required|numeric|phone_rule|exists:users,phone',
            'psno' => 'required|integer', //newly added
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['id', 'slno',...];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);
        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $role = PhoneDirectory::findOrFail($request->input('id'));


        $role->update([
            'slno' => $request->input('slno'),
            'name' => $request->input('name'),
            'designation' => $request->input('designation'),
            'role_id' => $request->input('role_id'),
            'contact_no' => $request->input('contact_no'),
            'email' => $request->input('email'),
            'updated_by' => $request->input('updated_by'),
            'psno' => $request->input('psno'),
        ]);


        return response()->json($role);
    }

    public function get_phone_dir(Request $request)
    {
        $rules = [
            'uuid' => 'required|numeric|phone_rule|exists:users,phone',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['uuid'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $data = $validator->validated();

        $userACId = User::where('phone', $data['uuid'])->value('ac');
        $phoneDirs = PhoneDirectory::where('ac', $userACId)
            ->with('role')
            ->get();


        $transformed = $phoneDirs->map(function ($item) {
            return [
                'id' => $item->id,
                'slno' => $item->slno,
                'name' => $item->name,
                'designation' => $item->designation,
                'role_name' => $item->role ? $item->role->role_name : null, // Check for null role
                'contact_no' => $item->contact_no,
                'email' => $item->email,
                'psno' => $item->psno
            ];
        });

        // Return the transformed list
        return response()->json($transformed);
    }

    public function get_main_phone_dir(Request $request)
    {
        $rules = [
            'uuid' => 'required|numeric|phone_rule|exists:users,phone',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['uuid'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $data = $validator->validated();

        $userACId = User::where('phone', $data['uuid'])->value('ac');
        $phoneDirs = PhoneDirectory::where('ac', $userACId)
            ->with('role')
            ->get();


        $transformed = $phoneDirs->map(function ($item) {
            return [
                'id' => $item->id,
                'slno' => $item->slno,
                'name' => $item->name,
                'designation' => $item->designation,
                'role_name' => $item->role ? $item->role->role_name : null, // Check for null role
                'contact_no' => $item->contact_no,
                'email' => $item->email,
                'psno' => $item->psno
            ];
        });

        // Return the transformed list
        return response()->json($transformed);
    }

    public function get_phone_dir_detail(Request $request)
    {
        $rules = [
            'id' => 'required|integer|exists:phone_dir,id',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['id'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $data = $validator->validated();



        $phoneDir = PhoneDirectory::where('id', $data['id'])->first();

        if (!$phoneDir) {

            return response()->json(['message' => 'Phone directory entry not found.'], 404);
        }

        $transformedData = [
            'id' => $phoneDir->id,
            'slno' => $phoneDir->slno,
            'name' => $phoneDir->name,
            'designation' => $phoneDir->designation,
            'role_name' => $phoneDir->role ? $phoneDir->role->role_name : null,
            'role_id' => $phoneDir->role ? $phoneDir->role->id : null,
            'contact_no' => $phoneDir->contact_no,
            'email' => $phoneDir->email,
            'psno' => $phoneDir->psno
        ];
        return response()->json($transformedData);
    }
    public function starts_with($haystack, $needle)
    {
        return substr($haystack, 0, strlen($needle)) === $needle;
    }

    public function importFile(Request $request)
    {
        $rules = [
            'phoneFile' => ['required', 'string', 'regex:/^[a-zA-Z0-9\/\r\n+]*={0,2}$/'], // Base64 validation
            'created_by' => 'required|numeric|exists:users,phone',
        ];
    
        $validator = Validator::make($request->all(), $rules);

        $validator->after(function ($validator) use ($request) { // Add custom validation to check the file size
            $fileSizeInBytes = strlen(base64_decode($request->phoneFile)) / 1024; // Convert bytes to KB

            if ($fileSizeInBytes > 200) { // Check if file size exceeds 200KB
                $validator->errors()->add('phoneFile', 'The file size must be less than or equal to 200KB.');
            }
        });

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()->all()], 400);
        }
    
        // Decode Base64 and check if it's likely an Excel file
        $fileContent = base64_decode($request->input('phoneFile'), true);
        if ($fileContent === false || !$this->starts_with($fileContent, "PK\x03\x04")) {
            return response()->json(['error' => 'Invalid Excel file'], 422);
        }
    
        $filePath = tempnam(sys_get_temp_dir(), 'import') . '.xlsx';
        file_put_contents($filePath, $fileContent);
    
        $user = User::where('phone', $request->input('created_by'))->first();
        if (!$user) {
            unlink($filePath);
            return response()->json(['error' => 'User not found'], 404);
        }
    
        DB::beginTransaction();
        try {
            $import = new PhoneDirectory();
            $import->setCreatedBy($user->id, $user->district, $user->ac);
            Excel::import($import, $filePath);
            if ($import->getRowCount() > 5000) {
                return response()->json(['msg' =>'Import stopped after processing 5000 entries.']);
            }
            DB::commit();
            unlink($filePath);
            return response()->json(['success' => 'Data imported successfully'], 200);
        } catch (\Maatwebsite\Excel\Validators\ValidationException $e) {
            $errorMessages = collect($e->failures())->map(function ($failure) {
                return [
                    'row' => $failure->row(),
                    'attribute' => $failure->attribute(),
                    'errors' => $failure->errors(),
                    'values' => $failure->values(),
                ];
            });
            DB::rollBack();
            unlink($filePath);
            return response()->json(['error' => 'Import failed with data validation errors', 'details' => $errorMessages], 400);
        } catch (\Throwable $e) {
            DB::rollBack();
            unlink($filePath);
            return response()->json(['error' => 'Import failed',$e->getMessage() ], 400);
        }
    }
    

    public function admin_register(Request $request)
    {
        $encryptedPassword = base64_decode($request->input('password'));
        $iv = base64_decode($request->input('iv'));
        $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');
        $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        if ($decryptedPassword == false) {
            return response()->json(["msg" => "Password decryption failed"]);
        }
        $dataToValidate = $request->all();
        $dataToValidate['password'] =  $decryptedPassword;

        $rules = [
            'name' => 'required|string|name_rule|max:255',
            'phone' => 'required|numeric|phone_rule|unique:users,phone',
            'password' => [
                'required',
                'min:6',
                'password_rule',
            ],
            'ac' => 'required|integer',
            'district' => 'required|integer',
            // 'role_id' => 'required|integer',
            'designation' => 'required|string|name_rule|max:255',
            'email' => 'required|email|max:255',
            // 'psno' => 'required|integer',
            'iv' => ['required', 'string',  Rule::notIn(['<script>', '</script>', 'min:16'])],
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['name', 'phone',];


        // !$dataToValidate is $request->all() need to check this works fine or not 
        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($dataToValidate, $rules);

        if ($validator->fails()) {
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        // Proceed to save the user with the decrypted and then hashed password
        $user = new User([
            'name' => $request->name,
            'phone' => $request->phone,
            'password' => bcrypt($decryptedPassword), // Hash the decrypted password
            'ac' => $request->ac,
            // 'role_id' => $request->role_id,
            'role_id' => 200, //fix role_id for Admin
            'designation' => $request->designation,
            'email' => $request->email,
            'district' => $request->district,
            'is_active' => true,
            // 'psno' =>  $request->psno,
        ]);

        $user->save();

        return response()->json(['message' => "Success"], 201);
    }


    public function getUsersByRoleId(Request $request)
    {
        $rules = [
            'uuid' => 'required|numeric|phone_rule|exists:users,phone',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['uuid'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $data = $validator->validated();

        $userExists = User::where('phone', $data['uuid'])
            ->where('role_id', "100")
            ->exists();

        if (!$userExists) {
            return response()->json(['message' => 'User with the specified UUID not found or does not have the required role'], 404);
        }

        $userACId = User::where('phone', $data['uuid'])->value('ac');

        // If the user exists and has the correct role_id, fetch other users excluding this one
        $users = User::where('phone', '<>', $data['uuid'])
            ->where('ac', $userACId)
            ->get(); // Execute the query and get the results

        if ($users->isEmpty()) {
            return response()->json(['message' => 'No other users found'], 404);
        }

        return response()->json($users);
    }

    public function getUserById(Request $request)
    {
        $rules = [
            'id' => 'required|integer|exists:users,id',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['id'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $data = $validator->validated();

        $user = User::where('id', $data['id'])->first();

        if ($user === null) {
            return response()->json(['message' => 'No user found'], 404);
        }

        return response()->json($user);
    }

    public function deleteDataById(Request $request)
    {
        $rules = [
            'uuid' => 'required|numeric|phone_rule|exists:users,phone',
        ];

        // Define the allowed parameters
        $allowedParams = array_keys($rules); //['uuid'];

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $data = $validator->validated();


        $exists = PhoneDirectory::where('created_by', $data['uuid'])->exists();

        if (!$exists) {

            return response()->json(['message' => 'No entries found for the specified creator.'], 404);
        }
        PhoneDirectory::where('created_by', $data['uuid'])->delete();

        // Return a success response.
        return response()->json(['message' => 'Entries deleted successfully.']);
    }

    // password_c
    public function updateUser(Request $request) //encrypt password ?????
    {
        $rules = [
            'id' => 'required|integer|exists:users,id',
            'name' => 'required|string|name_rule|max:255',
            'phone' => [
                'sometimes',
                'required',
                'phone_rule',
                'numeric',
                Rule::unique('users', 'phone')->ignore(User::where('id', $request->id)->first() ? User::where('id', $request->id)->first()->id : null, 'id'), // Ignore the current user's phone number
            ],
            'designation' => 'required|name_rule|max:255',
            'ac' => 'required|integer',
            'email' => 'required|email|max:255',
            'is_active' => 'required|in:true,false',
            'role_id' => 'required|integer',
            // 'psno' => 'required|integer',
            'password' => ['nullable', 'string',  'regex:/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', Rule::notIn(['<script>', '</script>'])],
            'iv' => ['nullable', 'string', Rule::notIn(['<script>', '</script>', 'min:16'])],
        ];


        // Define the allowed parameters
        $allowedParams = array_keys($rules);

        // Check if the request only contains the allowed parameters
        if (count($request->all()) !== count($allowedParams) || !empty(array_diff(array_keys($request->all()), $allowedParams))) {
            return response()->json(['error' => 'Invalid number of parameters or unrecognized parameter provided.'], 422);
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }

        $user = User::find($request->id);
        if (!$user) {
            return response()->json(['msg' => 'User not found'], 404);
        }

        // Decrypt password if provided
        if ($request->filled('password')) {
            $iv = base64_decode($request->input('iv'));
            $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');
            $encryptedPassword = base64_decode($request->input('password'));

            // Decrypt the password
            $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

            $passwordValidationRules = [
                'password' => ['required', 'string', 'min:6', 'password_rule'],
                // 'iv' => ['required', 'string', Rule::notIn(['<script>', '</script>', 'min:16'])],
            ];
            $passwordValidator = Validator::make(['password' => $decryptedPassword], $passwordValidationRules);
    
            if ($passwordValidator->fails()) {
                $firstErrorMessage = $passwordValidator->errors()->first('password');
                return response()->json(['msg' => $firstErrorMessage], 400);
            }
            $user->password = bcrypt($decryptedPassword);
        }
        $user->name = $request->input('name');
        $user->phone = $request->input('phone');
        $user->designation = $request->input('designation');
        $user->ac = $request->input('ac');
        $user->email = $request->input('email');
        $user->is_active = $request->input('is_active') === 'true'; // Convert string boolean to actual boolean
        $user->role_id = $request->input('role_id');
        // $user->psno = $request->input('psno');

        $user->save();
        return response()->json(['message' => 'User updated successfully']);
    }
}
