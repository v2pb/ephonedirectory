<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Maatwebsite\Excel\Concerns\ToModel;
use Maatwebsite\Excel\Concerns\WithHeadingRow;
use Maatwebsite\Excel\Concerns\WithValidation;
use App\Models\Role;

class PhoneDirectory extends Model implements ToModel, WithHeadingRow, WithValidation
{
    use HasFactory;

    protected $table = 'phone_dir';

    protected $guarded = [];
    private $createdBy;

    public function setCreatedBy($createdBy)
    {
        $this->createdBy = $createdBy;
        return $this;
    }
    public function role()
    {
        return $this->belongsTo(Roles::class, 'role_id');
    }

    public function model(array $row)
    {

        $roleName = strtolower($row['role']);
        $existingRole = Roles::whereRaw('lower(role_name) = ?', [$roleName])->first();

        if (!$existingRole) {
            $existingRole = Roles::create([
                'role_name' => $row['role'],
                'created_by' => $this->createdBy,
            ]);
        }

        // Check if 'slno' is provided, otherwise generate or fetch the next one
        $slno = $row['slno'] ?? $this->generateSlno();

        return new PhoneDirectory([
            'slno' => $slno,
            'name' => $row['name'],
            'designation' => $row['designation'],
            'role_id' => $existingRole->id,
            'contact_no' => $row['contact_no'],
            'email' => $row['email'],
        ]);
    }
    public function rules(): array
    {
        return [
            'name' => 'required|string',
            'contact_no' => 'required|regex:/^\d{10}$/',
            'email' => 'required|email',
            'designation' => 'required|string',
            'role' => 'required|string',
        ];
    }
}
