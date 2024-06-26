<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('phone_dir', function (Blueprint $table) {
            $table->id();
            $table->string('slno')->nullable();
            $table->string('name');
            $table->string('designation');
            $table->unsignedBigInteger('role_id');
            $table->string('contact_no');
            $table->string('email');
            $table->string('district');
            $table->string('ac');
            $table->string('psno'); //newly added
            $table->string('created_by')->nullable();
            $table->string('updated_by')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('phone_dir');
    }
};
