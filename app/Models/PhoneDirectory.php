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
    protected $createdBy;
    protected $district_id;
    protected $ac;
    private $rows =0;
    public function setCreatedBy($createdBy, $district_id, $ac)
    {
        $this->createdBy = $createdBy;
        $this->district_id = $district_id;
        $this->ac = $ac;
        return $this;
    }

    public function role()
    {
        return $this->belongsTo(Roles::class, 'role_id');
    }

    public function model(array $row)
    {
       if ($this->rows > 5000) {
        return null; 
        }

        $this->rows++;

        // Normalize the input to match your database column names
        $normalizedRow = [];
        foreach ($row as $key => $value) {
            // Replace spaces with underscores and convert to lowercase
            $normalizedKey = strtolower(str_replace(' ', '_', $key));
            $normalizedRow[$normalizedKey] = $value;
        }

        // Check and correct specific cases for sl no
        // Ensure 'sl_no' is correctly converted to 'slno'
        // if (isset($normalizedRow['sl_no'])) {
        //     $normalizedRow['slno'] = $normalizedRow['sl_no'];
        // }

        $roleName = strtolower($normalizedRow['role']);
        $existingRole = Roles::whereRaw('lower(role_name) = ?', [$roleName])->first();

        if (!$existingRole) {
            $existingRole = Roles::create([
                'role_name' => $normalizedRow['role'],
                'created_by' => $this->createdBy,
                'district_id' => $this->district_id,
                'ac' => $this->ac,
            ]);
        }

        // Use 'slno' directly from the normalized row
        return new PhoneDirectory([
            // 'slno' => $normalizedRow['slno'],
            'name' => $normalizedRow['name'],
            'designation' => $normalizedRow['designation'],
            'role_id' => $existingRole->id,
            'contact_no' => $normalizedRow['contact_no'],
            'email' => $normalizedRow['email'],
            "created_by" => $this->createdBy,
            "district" => $this->district_id,
            "ac" => $this->ac,
            "psno" => $normalizedRow['psno'],
        ]);
    }

    public function rules(): array
    {
        return [
            'name' => 'required|string|name_rule',
            'contact_no' => 'required|phone_rule',
            'email' => 'required|email',
            'designation' => 'required|remarks_rule',
            'role' => 'required|string|remarks_rule',
            'psno' => 'required|integer',
        ];
    }
    public function getRowCount(){
        return $this->rows;
    }
}
