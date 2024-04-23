<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class AssemblyConstituencySeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        DB::table('assembly_constituencies')->insert([
            [
                'ac_id' => 19,
                'ac_name' => 'Sidli',
                'status' => true,
            ],
            [
                'ac_id' => 20,
                'ac_name' => 'Bijni',
                'status' => true,
            ]
        ]);
    }
}
