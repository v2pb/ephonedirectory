<?php

namespace App\Http\Controllers;

use App\Models\PhoneDirectory;
use App\Models\Roles;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Maatwebsite\Excel\Facades\Excel;
use Illuminate\Support\Str;

use Illuminate\Support\Facades\DB;

class ApiController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255', // Ensure name does not exceed typical DB column length
            'phone' => 'required|string|regex:/^[\d\s\-\+\(\)]{10,}$/|unique:users', // Allow formatting but ensure at least 10 characters that could be digits or formatting symbols
            'password' => [
                'required',
                'min:6',
                'regex:/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$/',
            ],
            'ac' => 'nullable|integer',
            'role_id' => 'required|integer',
            'designation' => 'required|string|max:255',
            'email' => 'required|email|max:255', // Email also should not exceed typical DB column length
        ]);

        if ($validator->fails()) {
            // Return the very first error message directly
            $firstErrorMessage = $validator->errors()->first();
            return response()->json(['msg' => $firstErrorMessage], 400);
        }

        $user = new User([
            'name' => $request->name,
            'phone' => $request->phone,
            'password' => bcrypt($request->password),
            'ac' => $request->ac,
            'role_id' => $request->role_id,
            'designation' => $request->designation,
            'email' => $request->email,
        ]);

        $user->save();

        return response()->json(['msg' => "Success"], 201);
    }


    public function login(Request $request)
    {
        $encryptedPhone = base64_decode($request->input('phone'));
        $encryptedPassword = base64_decode($request->input('password'));
        $user_role_string = $request->input('user_role'); // This is the role string from the request
        $iv = base64_decode($request->input('iv'));
        $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');

        $decryptedPhone = openssl_decrypt($encryptedPhone, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);


        $validator = Validator::make(
            ['phone' => $decryptedPhone, 'password' => $decryptedPassword],
            [
                'phone' => 'required|string|regex:/^[\d\s\-\+\(\)]{10,}$/|exists:users,phone',
                'password' => 'required|string|min:6',
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

        // Check if the user is active
        if ($user->is_active !== true) {
            return response()->json(['msg' => 'User not activated'], 401);
        }

        if ($user->role_id != $user_role_string) {
            return response()->json(['msg' => 'Role mismatch, unauthorized'], 401);
        }

        $credentials = ['phone' => $decryptedPhone, 'password' => $decryptedPassword];
        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['msg' => 'Unauthorized'], 401);
        }

        $user = User::where('phone', $decryptedPhone)->first();


        return response()->json(['token' => $token, 'role' => $user['role_id'], "name" => $user["name"], "msg" => "Successful"], 200);
    }
    public function getProfileData(Request $request)
    {
        $id = $request->input("uuid");
        $user = User::where('phone', $id)->first(); // Assuming $id is properly passed in the request

        if ($user === null) {
            return response()->json(['message' => 'No user found'], 404);
        }

        return response()->json($user);
    }


    protected function getRoleIdFromRoleString($roleString)
    {

        $role = User::where('role_id', $roleString)->first();
        return $role ? $role->id : null;
    }


    public function PhoneDirectory(Request $request)
    {
        // Define the validation rules
        $data = [
            'slno' => 'required',
            'name' => 'required',
            'designation' => 'required',
            'role_name' => 'required',
            'contact_no' => 'required',
            'email' => 'required',
        ];

        // Validate the incoming request
        $validator = Validator::make($request->all(), $data);

        if ($validator->fails()) {

            return response()->json($validator->errors(), 422);
        }



        $phoneDir = PhoneDirectory::create($data);


        return response()->json($phoneDir, 201);
    }
    public function create_role(Request $request)
    {
        $rules = [
            'slno' => 'required|integer',
            'role_name' => 'required|string|max:255',
            'created_by' => 'required|string|max:255',
        ];


        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }


        $roleData = $validator->validated();



        $role = Roles::create($roleData);

        return response()->json($role, 201);
    }

    public function create_phone_dir(Request $request)
    {

        $rules = [
            'slno' => 'required|integer',
            'name' => 'required|string|max:255',
            'designation' => 'required|string|max:255',
            'role_id' => 'required|integer|max:255',
            'contact_no' => 'required|integer|min:10|regex:/^[\d\s\-\+\(\)]+$/',
            'email' => 'required|string|email|max:255|unique:phone_dir,email',
            "created_by" => 'required'
        ];


        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }


        $roleData = $validator->validated();



        $role = PhoneDirectory::create($roleData);

        return response()->json($role, 201);
    }

    public function get_role()
    {
        $role = Roles::select('id as opt_id', 'role_name as opt_name')
            ->orderBy("id")
            ->get();
        return response()->json($role);
    }
    public function getRoleById(Request $request)
    {

        $id = $request->input("id");


        $data = Roles::where('id', $id)->first();

        // Return the data as a JSON response
        return response()->json($data);
    }
    public function role_update(Request $request)
    {
        $rules = [
            'slno' => 'required|integer',
            'id' => 'required|integer',
            'role_name' => 'required|string|max:255',
            'updated_by' => 'required|regex:/^\d{10}$/',
        ];

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        $role = Roles::findOrFail($request->input('id'));

        // Update the role with validated data
        $role->update([
            'slno' => $request->input('slno'), // Correctly access the validated data
            'role_name' => $request->input('role_name'), // Correctly access the validated data
            'updated_by' => $request->input('updated_by'), // Correctly access the validated data
        ]);


        return response()->json($role);
    }
    public function phone_dir_update(Request $request)
    {

        $rules = [
            'id' => 'required',
            'slno' => 'required',
            'name' => 'required',
            'designation' => 'required',
            'role_id' => 'required',
            'contact_no' => 'required',
            'email' => 'required',
            "updated_by" => 'required'
        ];


        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
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
        ]);


        return response()->json($role);
    }



    public function get_phone_dir()
    {
        $phoneDirs = PhoneDirectory::with('role')->get();

        $transformed = $phoneDirs->map(function ($item) {
            return [
                'id' => $item->id,
                'slno' => $item->slno,
                'name' => $item->name,
                'designation' => $item->designation,
                'role_name' => $item->role ? $item->role->role_name : null, // Ensure there's a check for null
                'contact_no' => $item->contact_no,
                'email' => $item->email,
            ];
        });

        return $transformed;
    }
    public function get_phone_dir_detail(Request $request)
    {
        $id = $request->input("id");

        // Attempt to find the phone directory entry with the given ID, including the role relationship
        $phoneDir = PhoneDirectory::where('id', $id)->first();

        if (!$phoneDir) {

            return response()->json(['message' => 'Phone directory entry not found.'], 404);
        }

        // Transform the phone directory entry to the desired format
        // Transform the phone directory entry to the desired format
        $transformedData = [
            'id' => $phoneDir->id,
            'slno' => $phoneDir->slno,
            'name' => $phoneDir->name,
            'designation' => $phoneDir->designation,

            'role_name' => $phoneDir->role ? $phoneDir->role->role_name : null,

            'role_id' => $phoneDir->role ? $phoneDir->role->id : null,
            'contact_no' => $phoneDir->contact_no,
            'email' => $phoneDir->email,
        ];


        // Return the transformed data as a JSON response
        return response()->json($transformedData);
    }


    public function importFile(Request $request)
    {
        $rules = [
            'phoneFile' => 'required|string',
            "created_by" => 'required|regex:/^\d{10}$/',
        ];

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        // Decode the Base64 file content
        $fileContent = base64_decode($request->phoneFile);
        $filePath = tempnam(sys_get_temp_dir(), 'import') . '.xlsx';
        file_put_contents($filePath, $fileContent);

        DB::beginTransaction();

        try {
            // Adjusted to use an instance of PhoneDirectory for importing
            $import = (new PhoneDirectory())->setCreatedBy($request->created_by);
            Excel::import($import, $filePath);

            DB::commit();
            unlink($filePath); // Cleanup the temporary file
            return response()->json(['success' => 'Data imported successfully'], 200);
        } catch (\Throwable $e) {
            DB::rollBack();
            unlink($filePath); // Cleanup the temporary file
            // Consider logging the exception here for debugging
            return response()->json(['error' => 'Import failed: ' . $e->getMessage()], 500);
        }
    }

    public function admin_req(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'phone' => 'required|unique:users',
            'password' => 'required|min:6',
            'ac' => 'nullable',
            'role_id' => 'required|integer', // Ensure role_id is validated as an integer
            'designation' => 'required|string', // Ensure designation is validated as a string
            'email' => 'required|email|unique:users', // Ensure email is validated correctly and is unique
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 400);
        }

        $user = new User([
            'name' => $request->name,
            'phone' => $request->phone,
            'password' => bcrypt($request->password),
            'ac' => $request->ac,
            'role_id' => $request->role_id,
            'designation' => $request->designation,
            'email' => $request->email,
            'is_active' => true, // Set is_active to true
        ]);

        $user->save();

        return response()->json(['message' => "Success"], 201);
    }

    public function getUsersByRoleId(Request $request)
    {
        $excludeUserId = $request->input("uuid");

        // First, check if the user with the given UUID exists and has a role_id of 100
        $userExists = User::where('phone', $excludeUserId)
            ->where('role_id', "100")
            ->exists();

        if (!$userExists) {
            // If no such user exists, return an appropriate message
            return response()->json(['message' => 'User with the specified UUID not found or does not have the required role'], 404);
        }

        // If the user exists and has the correct role_id, fetch other users excluding this one
        $users = User::where('phone', '<>', $excludeUserId)->get();

        if ($users->isEmpty()) {
            return response()->json(['message' => 'No other users found'], 404);
        }
        return response()->json($users);
    }

    public function getUserById(Request $request)
    {
        $id = $request->input("id");
        $user = User::where('id', $id)->first(); // Assuming $id is properly passed in the request

        if ($user === null) {
            return response()->json(['message' => 'No user found'], 404);
        }

        return response()->json($user);
    }
    public function deleteDataById(Request $request)
    {
        $uuid = $request->input('uuid');


        $exists = PhoneDirectory::where('created_by', $uuid)->exists();

        if (!$exists) {

            return response()->json(['message' => 'No entries found for the specified creator.'], 404);
        }


        PhoneDirectory::where('created_by', $uuid)->delete();

        // Return a success response.
        return response()->json(['message' => 'Entries deleted successfully.']);
    }



    public function updateUser(Request $request)
    {

        $request->validate([
            'id' => 'required',
            'name' => 'required|string|max:255',
            'phone' => 'required|string|max:255',
            'designation' => 'required|string|max:255',
            'ac' => 'required',
            'email' => 'required|email|max:255',
            'password' => 'nullable|string|min:6',
            'is_active' => 'required',
        ]);

        $user = User::find($request->id);
        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $user->name = $request->input('name');
        $user->phone = $request->input('phone');
        $user->designation = $request->input('designation');
        $user->ac = $request->input('ac');
        $user->email = $request->input('email');
        $user->is_active = $request->input('is_active');


        if ($request->filled('password')) {
            $user->password = bcrypt($request->input('password'));
        }
        $user->save();
        return response()->json(['message' => 'User updated successfully']);
    }
}
