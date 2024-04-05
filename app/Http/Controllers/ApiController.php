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

        //! ADD validation check for the role_id table in status (exists rule)
        $rules = [
            'name' => 'required|string|name_rule|max:255',
            'phone' => 'required|string|phone_rule|unique:users,phone',
            'password' => 'required|string|min:6|password_rule',
            'ac' => 'required|integer',
            'district' => 'required|integer',
            'role_id' => 'required|integer',
            'designation' => 'required|string|max:255',
            'email' => 'required|email|max:255',
            'psno' => 'required|integer'
        ];

        // return response()->json(['request_data' => $request->all()], 200);
        $validator = Validator::make($request->all(),  $rules);

        if ($validator->fails()) {

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
            'district' => $request->district,
            'psno' => $request->psno,
        ]);


        $user->save();

        return response()->json(['msg' => "Success"], 201);
    }

    //! need to fixed this function for other project ecell
    public function login(Request $request)
    {
        $encryptedPhone = base64_decode($request->input('phone'));
        $encryptedPassword = base64_decode($request->input('password'));
        $user_role_string = $request->input('user_role');
        $iv = base64_decode($request->input('iv'));
        $key = base64_decode('XBMJwH94BHjSiVhICx3MfS9i5CaLL5HQjuRt9hiXfIc=');

        $decryptedPhone = openssl_decrypt($encryptedPhone, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $decryptedPassword = openssl_decrypt($encryptedPassword, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);


        $validator = Validator::make(
            ['phone' => $decryptedPhone, 'password' => $decryptedPassword],
            [
                'phone' => 'required|string|phone_rule|exists:users,phone',
                'password' => 'required|string|password_rule|min:6',
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
        $validator = Validator::make($request->all(), [
            "uuid" => "required|exists:users,phone",
        ]);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }

        $user = User::where('phone', $request->uuid)->firstOrFail();
        return response()->json($user);
    }





    public function PhoneDirectory(Request $request)
    {

        $rules = [
            'slno' => 'required|integer',
            'name' => 'required|name_rule',
            'designation' => 'required|name_rule',
            'role_name' => 'required|name_rule',
            'contact_no' => 'required|phone_rule',
            'email' => 'required|email',
        ];


        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }
        $phoneDir = PhoneDirectory::create($rules);

        return response()->json($phoneDir, 201);
    }
    public function create_role(Request $request)
    {
        $rules = [
            'slno' => 'required|integer',
            'role_name' => 'required|string|name_rule|max:255',
            'created_by' => 'required|phone_rule|exists:users,phone',
        ];

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
            'designation' => 'required|string|max:255',
            'role_id' => 'required|integer',
            'contact_no' => 'required|phone_rule',
            'email' => 'required|string|email|max:255',
            "created_by" => 'required|phone_rule|exists:users,phone'
        ];


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
            "uuid" => 'required|phone_rule|exists:users,phone',
        ];

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
            "uuid" => 'required|phone_rule|exists:users,phone',
        ];

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
            "uuid" => 'required|phone_rule|exists:users,phone',
        ];


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
            "id" => 'required|integer|exists:roles,id',
        ];
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
            'updated_by' => 'required|phone_rule',
        ];

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
            'contact_no' => 'required|phone_rule',
            'email' => 'required|email',
            "updated_by" => 'required|phone_rule|exists:users,phone'
        ];
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
        ]);


        return response()->json($role);
    }


    public function get_phone_dir(Request $request)
    {
        $rules = [
            "uuid" => 'required|integer|exists:users,phone',
        ];


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
            ];
        });

        // Return the transformed list
        return response()->json($transformed);
    }

    public function get_phone_dir_detail(Request $request)
    {
        $rules = [
            "id" => 'required|integer|exists:phone_dir,id',
        ];


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
        ];

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
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }

        // Decode the Base64 file content
        $fileContent = base64_decode($request->phoneFile);
        $filePath = tempnam(sys_get_temp_dir(), 'import') . '.xlsx';
        file_put_contents($filePath, $fileContent);

        DB::beginTransaction();
        $userACId = User::where('phone', $request->created_by)->value('ac');
        try {
            // Adjusted to use an instance of PhoneDirectory for importing
            $import = (new PhoneDirectory())->setCreatedBy($request->created_by, $userACId);
            Excel::import($import, $filePath);

            DB::commit();
            unlink($filePath);
            return response()->json(['success' => 'Data imported successfully'], 200);
        } catch (\Throwable $e) {
            DB::rollBack();
            unlink($filePath);
            return response()->json(['error' => 'Import failed: ' . $e->getMessage()], 500);
        }
    }

    public function admin_register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|name_rule|max:255',
            'phone' => 'required|string|regex:/^[\d\s\-\+\(\)]{10,}$/|unique:users', // Allow formatting but ensure at least 10 characters that could be digits or formatting symbols
            'password' => [
                'required',
                'min:6',
                'regex:/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).+$/',
            ],
            'ac' => 'nullable|integer',
            'district' => 'required|integer',
            'role_id' => 'required|integer',
            'designation' => 'required|string|name_rule|max:255',
            'email' => 'required|email|max:255',
            'psno' => 'required|integer'
        ]);

        if ($validator->fails()) {

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
            'district' => $request->district,
            'is_active' => true,
            "psno" =>  $request->psno,
        ]);

        $user->save();

        return response()->json(['message' => "Success"], 201);
    }

    public function getUsersByRoleId(Request $request)
    {
        $rules = [
            "uuid" => 'required|integer|exists:users,phone',
        ];


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
            "uuid" => 'required|integer|exists:users,phone',
        ];

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
            "uuid" => 'required|phone_rule|exists:users,phone',
        ];


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



    public function updateUser(Request $request)
    {

        $rules = [
            'id' => 'required|integer|exists:user,id',
            'name' => 'required|string||max:255',
            'phone' => 'required|phone_rule|max:255',
            'designation' => 'required|name_rule|max:255',
            'ac' => 'required|integer',
            'email' => 'required|email|max:255',
            'password' => 'nullable|password_rule|min:6',
            'is_active' => 'required|in:true,false', //! check the validation is correct or not 
            'role_id' => 'required|integer', //! create status model for role based user type
        ];


        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['msg' => $validator->errors()->first()], 400);
        }

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
        $user->role_id = $request->input('role_id');


        if ($request->filled('password')) {
            $user->password = bcrypt($request->input('password'));
        }
        $user->save();
        return response()->json(['message' => 'User updated successfully']);
    }
}
